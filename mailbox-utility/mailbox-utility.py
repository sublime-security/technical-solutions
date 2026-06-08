#!/usr/bin/python3

"""
Mailbox Utility Script (Comprehensive Mailbox Management)
Version: 2026.06.08.1
Author: Sergio Gonzalez (sergio@sublimesecurity.com)

A comprehensive utility script for managing mailboxes in Sublime Security.
This script allows users to:
1. Activate all mailboxes
2. Activate mailboxes by domain
3. Export mailboxes to CSV
4. Import CSV to activate mailboxes
5. Deactivate mailboxes by domain (with warnings)
6. Mass deactivate all mailboxes (dangerous operation)
7. Create HIP jobs for newly activated mailboxes

Features:
- Dynamic region discovery with DNS lookup
- SSL fallback for corporate environments
- Comprehensive error handling and API error display
- Debug mode for detailed logging
- Interactive menu system with mailbox URL display
- Safety confirmations for deactivation operations
- Progress tracking for batch operations
- Per-email status report exported to a timestamped CSV after activate/deactivate operations

Usage:
    python mailbox-utility.py [options]

Options:
    --help, -h             Show this help message
    --region REGION        Specify the region directly (mutually exclusive with --base-url)
    --base-url URL         Full API base URL (e.g. https://na-east-4.platform.sublime.security)
    --debug                Enable debug mode for detailed logging
    --disable-region-lookup Disable DNS region discovery
    --disable-auto-update  Disable automatic git pull update check
"""

import argparse
import getpass
import asyncio
import os
import re
import sys
import shutil
import socket
import subprocess
import csv
import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urlparse, urlencode
import json
import ssl
import urllib.request
import urllib.error
import concurrent.futures

# Check and setup virtual environment BEFORE importing external dependencies
def is_virtual_env() -> bool:
    """
    Check if the script is running inside a virtual environment.

    Returns:
        True if running in virtual environment, False otherwise
    """
    return (
        hasattr(sys, 'real_prefix') or
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) or
        os.environ.get('VIRTUAL_ENV') is not None
    )

def setup_virtual_environment() -> bool:
    """
    Create and activate a virtual environment in the script directory.
    If not in venv, creates .venv and re-launches the script inside it.

    Returns:
        True if setup successful or already in venv, False on failure
    """
    try:
        if is_virtual_env():
            return True

        # Create .venv in the script's directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        venv_path = os.path.join(script_dir, ".venv")

        if os.name == 'nt':  # Windows
            python_bin = os.path.join(venv_path, "Scripts", "python.exe")
        else:  # Unix-like
            python_bin = os.path.join(venv_path, "bin", "python3")

        if not os.path.exists(python_bin):
            print("📦 Creating virtual environment for self-contained operation...")
            try:
                subprocess.check_call([sys.executable, "-m", "venv", venv_path],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                print("✅ Virtual environment created successfully")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to create virtual environment: {e}")
                return False

        print("🚀 Re-launching script inside virtual environment...")
        os.execv(python_bin, [python_bin] + sys.argv)

    except Exception as e:
        print(f"❌ Virtual environment setup failed: {e}")
        return False

def install_venv_dependencies() -> bool:
    """
    Verify runtime dependencies.

    This utility runs entirely on the Python standard library, so there are no
    third-party packages to install. This function is retained so the existing
    startup flow keeps working and, importantly, so the script runs in
    locked-down environments that have no access to PyPI (e.g. behind a
    restrictive proxy/firewall).

    certifi is used opportunistically for SSL if it happens to be present, but
    is no longer required or installed; SSL falls back to the system trust
    store when certifi is absent (see APIClient._create_session).

    Returns:
        True always.
    """
    return True


# Setup virtual environment and install dependencies
if __name__ == "__main__":
    setup_virtual_environment()
    if not install_venv_dependencies():
        print("❌ Failed to setup dependencies. Exiting.")
        sys.exit(1)

# No third-party imports required: this utility runs on the Python standard
# library only (urllib for HTTP, asyncio for concurrency).


class Colors:
    """ANSI color codes for terminal output formatting."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'
    LIGHT_BLUE = '\033[94m'
    END = '\033[0m'

    @classmethod
    def red(cls, text):
        return f"{cls.RED}{text}{cls.END}"

    @classmethod
    def green(cls, text):
        return f"{cls.GREEN}{text}{cls.END}"

    @classmethod
    def yellow(cls, text):
        return f"{cls.YELLOW}{text}{cls.END}"

    @classmethod
    def blue(cls, text):
        return f"{cls.BLUE}{text}{cls.END}"

    @classmethod
    def light_blue(cls, text):
        return f"{cls.LIGHT_BLUE}{text}{cls.END}"

    @classmethod
    def magenta(cls, text):
        return f"{cls.MAGENTA}{text}{cls.END}"

    @classmethod
    def cyan(cls, text):
        return f"{cls.CYAN}{text}{cls.END}"

    @classmethod
    def white(cls, text):
        return f"{cls.WHITE}{text}{cls.END}"

    @classmethod
    def bold(cls, text):
        return f"{cls.BOLD}{text}{cls.END}"

    @classmethod
    def gray(cls, text):
        return f"{cls.GRAY}{text}{cls.END}"

    @classmethod
    def red_bold(cls, text):
        return f"{cls.RED}{cls.BOLD}{text}{cls.END}"

    @classmethod
    def green_bold(cls, text):
        return f"{cls.GREEN}{cls.BOLD}{text}{cls.END}"

    @classmethod
    def yellow_bold(cls, text):
        return f"{cls.YELLOW}{cls.BOLD}{text}{cls.END}"


class APIError(Exception):
    """Custom exception for API-related errors."""
    pass


class RateLimitError(APIError):
    """Custom exception for API rate limiting errors."""
    def __init__(self, message: str, retry_after: float = None):
        super().__init__(message)
        self.retry_after = retry_after


def check_for_updates_and_restart() -> None:
    """
    Check for script updates using git and restart if updates are found.
    Uses git fetch + diff to detect changes, then git checkout to update the current file.
    Preserves command line arguments during restart.
    """
    try:
        print(f"{Colors.bold('Checking for updates...')}")

        # Run git fetch to get latest changes (timeout after 10 seconds)
        fetch_result = subprocess.run(
            ['git', 'fetch', '--quiet'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True,
            text=True,
            timeout=10
        )

        if fetch_result.returncode != 0:
            # git fetch failed - continue without updating
            print(f"{Colors.yellow('Auto-updating is not available (git fetch failed or no git repository found). Continuing with current version.')}")
            if fetch_result.stderr:
                print(f"{Colors.yellow(f'Git error: {fetch_result.stderr.strip()}')}")
            return

        # Get git repository root
        current_script = os.path.abspath(__file__)
        script_dir = os.path.dirname(current_script)

        try:
            git_root_result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                cwd=script_dir,
                capture_output=True,
                text=True,
                timeout=5
            )
            if git_root_result.returncode != 0:
                print(f"{Colors.yellow('Auto-updating is not available (could not determine git repo root). Continuing with current version.')}")
                return
            git_root = git_root_result.stdout.strip()
        except Exception as e:
            print(f"{Colors.yellow(f'Auto-updating is not available (could not find git root: {str(e)}). Continuing with current version.')}")
            return

        # Get relative path from git root to script file
        try:
            script_relative_path = os.path.relpath(current_script, git_root)
        except Exception as e:
            print(f"{Colors.yellow(f'Auto-updating is not available (could not calculate relative path: {str(e)}). Continuing with current version.')}")
            return

        # Check if the current script file has been updated on the remote
        diff_result = subprocess.run(
            ['git', 'diff', '--quiet', 'HEAD', f'origin/main', '--', script_relative_path],
            cwd=git_root,
            capture_output=True,
            text=True,
            timeout=5
        )

        if diff_result.returncode != 0:
            print(f"{Colors.yellow('Auto-updating is not available (could not check for script updates). Continuing with current version.')}")
            return

        # If no diff output, the script file is up to date
        if diff_result.returncode == 0:
            print(f"{Colors.green('✓ Script is up to date')}")
            return

        # Script has updates available
        print(f"{Colors.green('✓ Updates found! Restarting with new version...')}")

        # Update the script file specifically using relative path from git root
        checkout_result = subprocess.run(
            ['git', 'checkout', 'origin/main', '--', script_relative_path],
            cwd=git_root,
            capture_output=True,
            text=True,
            timeout=10
        )

        if checkout_result.returncode != 0:
            print(f"{Colors.yellow('Auto-updating is not available (failed to update script file). Continuing with current version.')}")
            if checkout_result.stderr:
                print(f"{Colors.yellow(f'Git error: {checkout_result.stderr.strip()}')}")
            return

        # Restart the script with the same arguments
        args = [sys.executable] + sys.argv

        # Replace the current process with the updated script
        os.execv(sys.executable, args)

    except subprocess.TimeoutExpired:
        print(f"{Colors.yellow('Auto-updating is not available (git operation timed out). Continuing with current version.')}")
        return
    except FileNotFoundError:
        print(f"{Colors.yellow('Auto-updating is not available (git command not found). Continuing with current version.')}")
        return
    except Exception as e:
        print(f"{Colors.yellow(f'Auto-updating is not available (update check failed: {str(e)}). Continuing with current version.')}")
        return


def discover_sublime_regions(debug: bool = False, disable_region_lookup: bool = False) -> List[Tuple[str, str, str]]:
    """
    Discover available Sublime Security regions dynamically via DNS resolution.

    Args:
        debug: Enable debug output
        disable_region_lookup: Skip DNS discovery and use only hardcoded regions

    Returns:
        List of tuples: (display_name, full_hostname, base_url)
    """
    if disable_region_lookup:
        if debug:
            print("DNS region discovery disabled by user")
        return get_hardcoded_regions()

    if debug:
        print(f"{Colors.bold('Starting Sublime Security Region Discovery...')}")
        print("Using built-in Python socket module for DNS resolution\n")

    # Generate optimized list of platform subdomains only
    candidates = ['platform']  # Virginia region (no geographic prefix)

    # Add all known geographic regions with .platform suffix
    known_regions = ['na-east-2', 'na-east-3', 'na-east-4', 'na-west', 'na-west-2', 'ca', 'eu', 'uk', 'au']
    for region in known_regions:
        candidates.append(f"{region}.platform")

    # Add numbered variations for discovery (4-9 to catch new regions)
    for base in ['na-east', 'na-west', 'ca', 'eu', 'uk', 'au']:
        for i in range(5, 10):  # 5-9 to catch future regions (4 is already in known_regions)
            candidates.append(f"{base}-{i}.platform")

    # Remove duplicates while preserving order
    seen = set()
    unique_candidates = []
    for candidate in candidates:
        if candidate not in seen:
            unique_candidates.append(candidate)
            seen.add(candidate)
    candidates = unique_candidates

    if debug:
        print(f"Generated {len(candidates)} optimized platform candidates")
        print(f"Testing {len(candidates)} potential subdomains")
        for candidate in candidates:
            print(f"  - {candidate}")

    discovered_regions = []
    key_regions = ['platform', 'na-east-2.platform', 'na-east-3.platform', 'na-west.platform', 'na-west-2.platform', 'ca.platform', 'eu.platform', 'uk.platform', 'au.platform']

    if debug:
        print(f"Testing {len(candidates)} potential subdomains...")

    for i, subdomain in enumerate(candidates):
        full_hostname = f"{subdomain}.sublime.security"

        try:
            # Use socket.getaddrinfo for more reliable DNS resolution
            result = socket.getaddrinfo(full_hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if result:
                ip_address = result[0][4][0]

                # Check if we already have this IP (avoid duplicates)
                existing_ips = [region[3] for region in discovered_regions if len(region) > 3]
                if ip_address in existing_ips:
                    if debug:
                        print(f"[{i+1:2d}/{len(candidates)}] Testing {full_hostname}... {Colors.cyan(f'✓ Found -> {ip_address} (duplicate, skipped)')}")
                    continue

                # Create display name and base URL
                display_name = create_display_name(subdomain)
                base_url = f"https://{full_hostname}"

                discovered_regions.append((display_name, full_hostname, base_url, ip_address))

                if debug:
                    print(f"[{i+1:2d}/{len(candidates)}] Testing {full_hostname}... {Colors.green(f'✓ Found -> {ip_address}')}")

        except (socket.gaierror, socket.timeout, OSError):
            if debug:
                print(f"[{i+1:2d}/{len(candidates)}] Testing {full_hostname}... {Colors.red('✗ Not found')}")
        except Exception as e:
            if debug:
                print(f"[{i+1:2d}/{len(candidates)}] Testing {full_hostname}... {Colors.red(f'✗ Error: {str(e)}')}")

    # Sort regions: North American first, then others descending alphabetically
    def sort_regions(region_tuple):
        display_name = region_tuple[0].lower()
        if 'north america' in display_name:
            return (0, display_name)  # North American regions first
        else:
            return (1, display_name[::-1])  # Others in descending alphabetical order

    discovered_regions.sort(key=sort_regions)

    if debug:
        print(f"\nDiscovered {len(discovered_regions)} accessible regions")

        # Verify key regions were found
        print("\n" + "="*50)
        print("KEY REGIONS TESTING SUMMARY:")
        print("="*50)
        found_hostnames = [region[1] for region in discovered_regions]

        for key_region in key_regions:
            expected_hostname = f"{key_region}.sublime.security"
            if expected_hostname in found_hostnames:
                region_data = next(r for r in discovered_regions if r[1] == expected_hostname)
                # Display clean region name (strip .platform suffix for display)
                display_name = key_region.replace('.platform', '') if key_region != 'platform' else key_region
                print(f"{display_name:<12} ✓ Found -> {region_data[3]:<15} ✓ In results")
            else:
                # Display clean region name (strip .platform suffix for display)
                display_name = key_region.replace('.platform', '') if key_region != 'platform' else key_region
                print(f"{display_name:<12} ✗ Not found or not accessible")
        print("="*50)

    if discovered_regions:
        # Return without IP address for final list
        return [(name, hostname, base_url) for name, hostname, base_url, _ in discovered_regions]
    else:
        # Fallback to hardcoded regions if discovery fails
        if debug:
            print("DNS discovery failed, falling back to hardcoded regions")
        return get_hardcoded_regions()


def create_display_name(subdomain: str) -> str:
    """Create user-friendly display name from subdomain."""
    region_map = {
        'platform': 'North America East (Virginia)',
        'na-east-2': 'North America East 2 (Ohio)',
        'na-east-3': 'North America East 3 (Ohio)',
        'na-east-4': 'North America East 4 (Ohio)',
        'na-west': 'North America West (Oregon)',
        'na-west-2': 'North America West 2 (Oregon)',
        'ca': 'Canada (Montréal)',
        'eu': 'Europe (Dublin)',
        'uk': 'United Kingdom (London)',
        'au': 'Australia (Sydney)'
    }

    # Handle .platform suffix
    clean_subdomain = subdomain.replace('.platform', '')

    return region_map.get(clean_subdomain, f"Region ({clean_subdomain})")


def get_hardcoded_regions() -> List[Tuple[str, str, str]]:
    """Fallback hardcoded regions if DNS discovery fails."""
    return [
        ('North America East (Virginia)', 'platform.sublime.security', 'https://platform.sublime.security'),
        ('North America East 2 (Ohio)', 'na-east-2.platform.sublime.security', 'https://na-east-2.platform.sublime.security'),
        ('North America East 3 (Ohio)', 'na-east-3.platform.sublime.security', 'https://na-east-3.platform.sublime.security'),
        ('North America West (Oregon)', 'na-west.platform.sublime.security', 'https://na-west.platform.sublime.security'),
        ('North America West 2 (Oregon)', 'na-west-2.platform.sublime.security', 'https://na-west-2.platform.sublime.security'),
        ('Canada (Montréal)', 'ca.platform.sublime.security', 'https://ca.platform.sublime.security'),
        ('Europe (Dublin)', 'eu.platform.sublime.security', 'https://eu.platform.sublime.security'),
        ('United Kingdom (London)', 'uk.platform.sublime.security', 'https://uk.platform.sublime.security'),
        ('Australia (Sydney)', 'au.platform.sublime.security', 'https://au.platform.sublime.security'),
    ]


class MailboxUtilityAPI:
    """
    API client for Sublime Security with comprehensive error handling and retry logic.
    Adapted from hip-utility patterns with mailbox-specific functionality.
    """

    def __init__(self, base_url: str, api_token: str, debug: bool = False):
        """
        Initialize the API client.

        Args:
            base_url: Base URL for the API (e.g., 'https://platform.sublime.security')
            api_token: API authentication token
            debug: Enable debug logging
        """
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.debug = debug
        self.session = None
        self._executor = None
        self._ssl_context = None
        self._headers = {}

    async def __aenter__(self):
        """Async context manager entry."""
        await self._create_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None
        self.session = None

    async def _create_session(self):
        """Set up the SSL context, default headers, and request thread pool.

        Uses only the Python standard library. Blocking urllib requests are run
        in a thread pool via loop.run_in_executor, so the existing asyncio-based
        parallelism (Semaphore + gather) keeps working unchanged.
        """
        # Prefer certifi's CA bundle if it happens to be installed; otherwise
        # fall back to the system trust store. certifi is no longer required.
        try:
            import certifi
            self._ssl_context = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            self._ssl_context = ssl.create_default_context()

        self._headers = {
            'Authorization': f'Bearer {self.api_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'Mailbox-Utility/2026.06.08.1'
        }

        # Sized to comfortably cover the maximum parallel worker count (15).
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)

        # Truthy marker so _make_request knows the session is initialized.
        self.session = True

    def _perform_request(self, method: str, url: str, body: Optional[bytes]):
        """Execute a single blocking HTTP request via urllib (runs in a thread).

        Returns (status_code, reason, response_text, headers). HTTP error
        responses (4xx/5xx) are returned like normal responses rather than
        raised, so the async caller can apply its retry policy uniformly.
        Network-level failures propagate as exceptions to the caller.
        """
        request = urllib.request.Request(url, data=body, method=method)
        for key, value in self._headers.items():
            request.add_header(key, value)

        try:
            with urllib.request.urlopen(request, timeout=60, context=self._ssl_context) as response:
                text = response.read().decode('utf-8', errors='replace')
                return response.status, response.reason, text, response.headers
        except urllib.error.HTTPError as e:
            text = e.read().decode('utf-8', errors='replace') if e.fp else ''
            return e.code, (e.reason or ''), text, (e.headers or {})

    async def _make_request(self, method: str, endpoint: str, params: Optional[Dict] = None,
                          json_data: Optional[Dict] = None, max_retries: int = 3) -> Dict:
        """
        Make HTTP request with retry logic and comprehensive error handling.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without leading slash)
            params: Query parameters
            json_data: JSON payload for POST/PUT requests
            max_retries: Maximum number of retry attempts

        Returns:
            Response data as dictionary

        Raises:
            APIError: On API errors or network failures
        """
        if not self.session:
            await self._create_session()

        url = f"{self.base_url}/{endpoint}"
        if params:
            url = f"{url}?{urlencode(params)}"

        body = json.dumps(json_data).encode('utf-8') if json_data is not None else None

        backoff_factor = 1.5
        loop = asyncio.get_running_loop()

        for attempt in range(max_retries + 1):
            try:
                if self.debug:
                    print(f"\n{Colors.cyan('API Request:')} {method} {url}")
                    if params:
                        print(f"{Colors.cyan('Query Parameters:')} {json.dumps(params, indent=2)}")
                    if json_data:
                        print(f"{Colors.cyan('Request Body (JSON):')} {json.dumps(json_data, indent=2)}")

                # Run the blocking urllib request in the thread pool so multiple
                # requests can be in flight concurrently under asyncio.
                status, reason, response_text, response_headers = await loop.run_in_executor(
                    self._executor, self._perform_request, method, url, body
                )

                if self.debug:
                    print(f"{Colors.cyan('Response Status:')} {status}")
                    print(f"{Colors.cyan('Response Body:')} {response_text[:500]}{'...' if len(response_text) > 500 else ''}")

                # Mirror aiohttp's raise_for_status() behavior for error statuses.
                if status >= 400:
                    # Don't retry 404 errors - resource not found is permanent
                    if status == 404:
                        error_message = self._format_error_message(method, endpoint, f"{status} {reason}", response_text)
                        print(error_message)
                        raise APIError(f"Request failed: {status} {reason}")

                    # Handle rate limiting with longer backoff
                    if status == 429:
                        if attempt == max_retries:
                            error_message = self._format_error_message(method, endpoint, f"{status} {reason}", response_text)
                            print(error_message)
                            # Extract retry-after header if available
                            retry_after = response_headers.get('Retry-After')
                            retry_after_seconds = float(retry_after) if retry_after else None
                            raise RateLimitError(f"Rate limited: {status} {reason}", retry_after_seconds)

                        # Longer backoff for rate limiting
                        wait_time = min(60, backoff_factor * (3 ** attempt))  # Cap at 60 seconds
                        if self.debug:
                            print(f"Rate limited, retry {attempt + 1}/{max_retries} after {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue

                    if attempt == max_retries:
                        error_message = self._format_error_message(method, endpoint, f"{status} {reason}", response_text)
                        print(error_message)
                        raise APIError(f"Request failed: {status} {reason}")

                    wait_time = backoff_factor * (2 ** attempt)
                    if self.debug:
                        print(f"Retry {attempt + 1}/{max_retries} after {wait_time}s")
                    await asyncio.sleep(wait_time)
                    continue

                # Handle empty responses
                if not response_text.strip():
                    return {}

                try:
                    return json.loads(response_text)
                except json.JSONDecodeError:
                    if self.debug:
                        print(f"{Colors.yellow('Warning: Non-JSON response received')}")
                    return {'raw_response': response_text}

            except APIError:
                # Already-formatted terminal error (404, final 429, final 4xx/5xx) - propagate.
                raise

            except Exception as e:
                # Network-level failure (timeout, connection error, SSL, etc.)
                if attempt == max_retries:
                    error_message = self._format_error_message(method, endpoint, str(e), "")
                    print(error_message)
                    raise APIError(f"Request failed: {str(e)}")

                wait_time = backoff_factor * (2 ** attempt)
                if self.debug:
                    print(f"Network error, retry {attempt + 1}/{max_retries} after {wait_time}s: {str(e)}")
                await asyncio.sleep(wait_time)

    def _format_error_message(self, method: str, endpoint: str, error: str, response_body: str) -> str:
        """Format comprehensive error message for display."""
        message = f"\n{Colors.red_bold('API Error Details:')}\n"
        message += f"  {Colors.bold('Method:')} {method}\n"
        message += f"  {Colors.bold('Endpoint:')} {endpoint}\n"
        message += f"  {Colors.bold('Error:')} {error}\n"

        if response_body:
            try:
                # Try to parse as JSON for pretty formatting
                response_json = json.loads(response_body)
                message += f"  {Colors.bold('Response:')} {json.dumps(response_json, indent=4)}\n"
            except json.JSONDecodeError:
                message += f"  {Colors.bold('Response:')} {response_body}\n"

        return message

    async def test_connection(self) -> bool:
        """Test API connection and authentication."""
        try:
            await self._make_request('GET', 'v1/message-sources', params={'limit': 1})
            return True
        except Exception:
            return False

    async def get_message_sources(self) -> List[Dict]:
        """Get all message sources."""
        response = await self._make_request('GET', 'v1/message-sources')
        return response.get('message_sources', [])

    async def get_message_source_info(self, message_source_id: str) -> Dict:
        """Get information for a specific message source."""
        return await self._make_request('GET', f'v1/message-sources/{message_source_id}')

    async def get_mailboxes(self, message_source_id: str, offset: int = 0, limit: int = 500) -> Dict:
        """
        Get mailboxes for a message source with pagination.

        Args:
            message_source_id: The message source ID
            offset: Pagination offset
            limit: Number of mailboxes per request (max 500)

        Returns:
            API response with mailboxes data
        """
        params = {
            'message_source_id': message_source_id,
            'offset': offset,
            'limit': limit
        }
        return await self._make_request('GET', 'v1/mailboxes', params=params)

    async def activate_mailbox(self, mailbox_id: str) -> Dict:
        """Activate a single mailbox."""
        return await self._make_request('POST', f'v1/mailboxes/{mailbox_id}/activate')

    async def deactivate_mailbox(self, mailbox_id: str) -> Dict:
        """Deactivate a single mailbox."""
        return await self._make_request('POST', f'v1/mailboxes/{mailbox_id}/deactivate')

    async def mass_deactivate_mailboxes(self, all_message_sources: bool, message_source_ids: Optional[List[str]] = None) -> Dict:
        """
        Mass deactivate mailboxes.

        Args:
            all_message_sources: If True, deactivate all mailboxes across all message sources
            message_source_ids: List of message source IDs (required if all_message_sources is False)

        Returns:
            API response
        """
        payload = {"all_message_sources": all_message_sources}
        if not all_message_sources and message_source_ids:
            payload["message_source_ids"] = message_source_ids

        return await self._make_request('POST', 'v1/mailboxes/mass-deactivate-all', json_data=payload)

    async def create_hip_job(self, message_source_id: str, mode: str = "HISTORICALLY_MATCH",
                           active_mailboxes_only: bool = None, mailbox_ids: List[str] = None,
                           days_back: int = 90) -> Dict:
        """
        Create a HIP job for mailboxes.

        Args:
            message_source_id: The message source ID
            mode: HIP job mode (default: HISTORICALLY_MATCH)
            active_mailboxes_only: Only process active mailboxes (for all active mailboxes)
            mailbox_ids: Specific mailbox IDs to process (for targeted processing)
            days_back: Number of days to go back for historical processing

        Returns:
            API response with job details
        """
        payload = {
            "message_source_id": message_source_id,
            "mode": mode,
            "days_back": days_back
        }

        # Handle different targeting modes
        if mailbox_ids:
            # Specific mailbox targeting (domain-specific, sampling scenarios)
            payload["mailbox_ids"] = mailbox_ids
        elif active_mailboxes_only is True:
            # All active mailboxes targeting (legacy behavior)
            payload["active_mailboxes_only"] = True
        elif active_mailboxes_only is None:
            # Default to active mailboxes only if neither specified
            payload["active_mailboxes_only"] = True
        else:
            # active_mailboxes_only is False - process all mailboxes
            payload["active_mailboxes_only"] = False

        return await self._make_request('POST', 'v1/historical-ingestion', json_data=payload)

    async def get_user_groups(self, limit: int = 500, message_source_id: Optional[str] = None) -> List[Dict]:
        """
        Get all user groups with pagination handling.

        Note: The message_source_id parameter is kept for API consistency but not used
        for server-side filtering as the API doesn't support it. Filtering should be
        done client-side by the caller.

        Args:
            limit: Number of groups per page (default 500)
            message_source_id: Not used (API doesn't support filtering)

        Returns:
            List of user group dictionaries (unfiltered)
        """
        all_groups = []
        offset = 0

        while True:
            params = {'limit': limit, 'offset': offset, 'include_count': 'true'}
            # Note: message_source_id NOT sent as query param - API doesn't support server-side filtering
            # Filtering will be done client-side by caller
            response = await self._make_request('GET', 'v1/user-groups', params=params)

            groups = response if isinstance(response, list) else []
            if not groups:
                break

            all_groups.extend(groups)

            # Check if we got fewer results than requested (last page)
            if len(groups) < limit:
                break

            offset += limit

        return all_groups

    async def get_user_group_details(self, group_id: str) -> Dict:
        """
        Get detailed information about a specific user group.

        Args:
            group_id: The ID of the user group

        Returns:
            User group details dictionary
        """
        return await self._make_request('GET', f'v1/user-groups/{group_id}')

    async def activate_user_group(self, group_id: str) -> Dict:
        """
        Activate a user group, which activates all mailboxes in the group.

        Args:
            group_id: The ID of the user group to activate

        Returns:
            API response with activation results
        """
        return await self._make_request('POST', f'v1/user-groups/{group_id}/activate')

    async def deactivate_user_group(self, group_id: str) -> Dict:
        """
        Deactivate a user group, which deactivates mailboxes in the group
        that are not members of other active groups.

        Args:
            group_id: The ID of the user group to deactivate

        Returns:
            API response with deactivation results
        """
        return await self._make_request('POST', f'v1/user-groups/{group_id}/deactivate')


class ProgressiveGroupSearch:
    """
    Progressive search functionality for user groups with caching and real-time filtering.
    """

    def __init__(self, api: MailboxUtilityAPI):
        self.api = api
        self.cached_groups = []
        self.last_refresh = None
        self.cache_duration = 300  # 5 minutes

    def clear_cache(self) -> None:
        """Clear cached groups and force refresh on next load."""
        self.cached_groups = []
        self.last_refresh = None

    async def _ensure_groups_loaded(self, message_source_id: Optional[str] = None, force_refresh: bool = False) -> None:
        """
        Ensure user groups are loaded and cached.

        Args:
            message_source_id: Optional message source ID to filter groups
            force_refresh: Force refresh even if cache is valid
        """
        import time

        current_time = time.time()
        cache_valid = (self.last_refresh and
                      (current_time - self.last_refresh) < self.cache_duration)

        if not force_refresh and cache_valid and self.cached_groups:
            return

        print(f"{Colors.cyan('Gathering group information... this may take a moment')}", end='', flush=True)
        try:
            all_groups = await self.api.get_user_groups(message_source_id=message_source_id)

            # Client-side filtering by message_source_id (API doesn't support server-side filtering)
            if message_source_id:
                self.cached_groups = [
                    group for group in all_groups
                    if group.get('message_source_id') == message_source_id
                ]
            else:
                self.cached_groups = all_groups

            self.last_refresh = current_time
            print(f" ✓ Found {len(self.cached_groups)} groups")
        except Exception as e:
            print(f" {Colors.red('Failed to load groups:')} {str(e)}")
            raise

    def _filter_groups(self, query: str) -> List[Dict]:
        """
        Filter cached groups based on query string.

        Args:
            query: Search query string

        Returns:
            Filtered list of groups
        """
        if len(query) < 2:
            # Show first 50 groups if query too short
            return self.cached_groups[:50]

        query_lower = query.lower()

        # Priority matching: exact name match, then substring, then description
        exact_matches = [g for g in self.cached_groups
                        if g.get('name', '').lower() == query_lower]

        name_matches = [g for g in self.cached_groups
                       if query_lower in g.get('name', '').lower() and g not in exact_matches]

        desc_matches = [g for g in self.cached_groups
                       if query_lower in g.get('description', '').lower()
                       and g not in exact_matches and g not in name_matches]

        # Combine results with priority ordering
        return exact_matches + name_matches + desc_matches

    def _display_live_results(self, groups: List[Dict], query: str) -> None:
        """
        Display live search results with highlighting.

        Args:
            groups: List of matching groups
            query: Current search query
        """
        import sys

        # Clear previous results (move cursor up and clear lines)
        if hasattr(self, '_last_result_count'):
            for _ in range(self._last_result_count + 2):
                sys.stdout.write('\033[1A')  # Move up one line
                sys.stdout.write('\033[2K')  # Clear entire line
            sys.stdout.write('\r')  # Return to start of line

        # Display current query and results with explicit \r\n for raw mode
        sys.stdout.write(f"\r\nSearch groups: {query}\r\n")

        if not groups:
            sys.stdout.write(f"{Colors.yellow('No matching groups found.')}\r\n")
            sys.stdout.flush()
            self._last_result_count = 1
            return

        sys.stdout.write(f"\r\n{Colors.cyan('Live Results')} ({len(groups)} matches):\r\n")

        # Show top 10 results
        display_groups = groups[:10]
        for i, group in enumerate(display_groups, 1):
            name = group.get('name', 'Unknown')
            member_count = group.get('member_count', 0)
            active_status = group.get('active', False)
            status_color = Colors.green if active_status else Colors.yellow
            status_text = 'Active' if active_status else 'Inactive'

            sys.stdout.write(f"  {i}. {name} ({member_count} members) - {status_color(status_text)}\r\n")

        if len(groups) > 10:
            sys.stdout.write(f"  ... and {len(groups) - 10} more matches\r\n")

        sys.stdout.write(f"\r\n{Colors.blue('Press 1-10 to select, Enter for first match, ESC to cancel, or continue typing...')}\r\n")
        sys.stdout.flush()

        self._last_result_count = len(display_groups) + 4  # Results + headers + footer

    async def search_groups_interactive(self, action_type: str = "activate", message_source_id: Optional[str] = None) -> Optional[Dict]:
        """
        Interactive progressive search for user groups.

        Args:
            action_type: Type of action ('activate' or 'deactivate')
            message_source_id: Optional message source ID to filter groups

        Returns:
            Selected group dictionary or None if cancelled
        """
        import sys
        import tty
        import termios

        await self._ensure_groups_loaded(message_source_id=message_source_id)

        if not self.cached_groups:
            print(f"{Colors.red('No user groups found.')}")
            return None

        print(f"\n{Colors.bold(f'=== {action_type.title()} Mailboxes by User Group ===')}")
        print(f"{Colors.blue('Start typing to search through')} {len(self.cached_groups)} {Colors.blue('available groups...')}")

        query = ""

        # Get terminal settings for character-by-character input
        try:
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setraw(sys.stdin.fileno())

            while True:
                # Display current results
                matches = self._filter_groups(query)
                self._display_live_results(matches, query)

                # Wait for character input
                char = sys.stdin.read(1)

                if ord(char) == 27:  # ESC key
                    print(f"\n{Colors.yellow('Search cancelled.')}")
                    return None
                elif ord(char) == 13:  # Enter key
                    if matches:
                        return matches[0]  # Return first match
                    continue
                elif ord(char) == 127:  # Backspace
                    if query:
                        query = query[:-1]
                elif ord(char).to_bytes(1, 'big').isascii() and char.isprintable():
                    # Regular character - check for number selection
                    if char.isdigit():
                        digit = int(char)
                        if 1 <= digit <= min(10, len(matches)):
                            return matches[digit - 1]
                        else:
                            # Add digit to query if not valid selection
                            query += char
                    else:
                        query += char

        except Exception as e:
            print(f"\n{Colors.red('Progressive search error:')} {str(e)}")
            # Fallback to simple input
            return await self._fallback_search(action_type)

        finally:
            # Restore terminal settings
            try:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            except:
                pass

    async def _fallback_search(self, action_type: str) -> Optional[Dict]:
        """
        Fallback to simple search if progressive search fails.

        Args:
            action_type: Type of action ('activate' or 'deactivate')

        Returns:
            Selected group dictionary or None if cancelled
        """
        print(f"\n{Colors.yellow('Falling back to simple search mode...')}")

        while True:
            query = input(f"\n{Colors.blue('Enter group name to search (or press Enter to cancel):')} ").strip()

            if not query:
                return None

            matches = self._filter_groups(query)

            if not matches:
                print(f"{Colors.yellow('No matching groups found. Try a different search term.')}")
                continue

            # Display matches
            print(f"\nFound {len(matches)} matching groups:")
            display_matches = matches[:10]

            for i, group in enumerate(display_matches, 1):
                name = group.get('name', 'Unknown')
                member_count = group.get('member_count', 0)
                active_status = group.get('active', False)
                status_color = Colors.green if active_status else Colors.yellow
                status_text = 'Active' if active_status else 'Inactive'

                print(f"  {i}. {name} ({member_count} members) - {status_color(status_text)}")

            if len(matches) > 10:
                print(f"  ... and {len(matches) - 10} more matches (refine search to see more)")

            # Get user selection
            try:
                choice = input(f"\n{Colors.blue('Select group number (1-{min(10, len(matches))}) or press Enter to search again:')} ").strip()

                if not choice:
                    continue

                choice_num = int(choice)
                if 1 <= choice_num <= min(10, len(matches)):
                    return matches[choice_num - 1]
                else:
                    print(f"{Colors.red('Invalid selection. Please choose a number between 1 and {min(10, len(matches))}.')}")

            except ValueError:
                print(f"{Colors.red('Invalid input. Please enter a number.')}")


class MailboxUtility:
    """
    Main application class for comprehensive mailbox management.
    Handles user interaction, mailbox operations, and workflow coordination.
    """

    def __init__(self, api: MailboxUtilityAPI, base_url: str):
        """
        Initialize the mailbox utility.

        Args:
            api: Configured API client
            base_url: Base URL for the Sublime instance
        """
        self.api = api
        self.base_url = base_url
        self.message_sources = {}
        self.selected_message_source_id = None
        self.all_mailboxes = []
        self.domains = {}
        self.group_search = ProgressiveGroupSearch(api)

    def _get_mailbox_url(self) -> str:
        """Generate URL for viewing mailboxes in Sublime platform."""
        return f"{self.base_url}/mailboxes"

    async def initialize(self) -> bool:
        """
        Initialize the utility by discovering message sources and selecting one.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            print(f"\n{Colors.bold('Discovering message sources...')}")

            # Get all message sources
            message_sources_list = await self.api.get_message_sources()

            if not message_sources_list:
                print(f"{Colors.red('Error: No message sources found in this organization.')}")
                print(f"{Colors.yellow('Please ensure you have at least one message source configured.')}")
                return False

            # Store message sources info
            for ms in message_sources_list:
                self.message_sources[ms['id']] = ms

            # Auto-select if only one message source, otherwise prompt user
            if len(message_sources_list) == 1:
                self.selected_message_source_id = message_sources_list[0]['id']
                ms_info = message_sources_list[0]
                print(f"\n{Colors.green('Auto-selected message source:')}")
                print(f"  Name: {ms_info.get('name', 'Unknown')}")
                print(f"  Type: {ms_info.get('type', 'Unknown')}")
                print(f"  ID: {self.selected_message_source_id}")
            else:
                print(f"\n{Colors.bold('Multiple message sources found. Please select one:')}")
                for i, ms in enumerate(message_sources_list, 1):
                    print(f"{i}. {ms.get('name', 'Unknown')} ({ms.get('type', 'Unknown')}) - {ms['id']}")

                while True:
                    try:
                        choice = input(f"\nSelect message source (1-{len(message_sources_list)}): ")
                        index = int(choice) - 1
                        if 0 <= index < len(message_sources_list):
                            self.selected_message_source_id = message_sources_list[index]['id']
                            break
                        else:
                            print(f"{Colors.red('Invalid selection. Please choose 1-')}{len(message_sources_list)}")
                    except ValueError:
                        print(f"{Colors.red('Invalid input. Please enter a number.')}")
                    except KeyboardInterrupt:
                        print(f"\n{Colors.yellow('Operation cancelled by user.')}")
                        return False

            return True

        except Exception as e:
            print(f"{Colors.red('Error during initialization:')} {str(e)}")
            return False

    async def fetch_all_mailboxes(self) -> bool:
        """
        Fetch all mailboxes for the selected message source.

        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"\n{Colors.bold('Fetching all mailboxes...')}")

            self.all_mailboxes = []
            self.domains = {}
            offset = 0
            limit = 500

            while True:
                response = await self.api.get_mailboxes(self.selected_message_source_id, offset=offset, limit=limit)
                mailboxes = response.get('mailboxes', [])

                if not mailboxes:
                    break

                self.all_mailboxes.extend(mailboxes)
                print(f"Fetched {len(self.all_mailboxes)} mailboxes so far...")

                # Check if we have more pages
                if len(mailboxes) < limit:
                    break

                offset += limit

            # Analyze domains
            for mailbox in self.all_mailboxes:
                email = mailbox.get('email_address', '')
                if '@' in email:
                    domain = email.split('@')[1].lower()
                    if domain not in self.domains:
                        self.domains[domain] = {'total': 0, 'active': 0, 'inactive': 0}

                    self.domains[domain]['total'] += 1
                    if mailbox.get('active', False):
                        self.domains[domain]['active'] += 1
                    else:
                        self.domains[domain]['inactive'] += 1

            total = len(self.all_mailboxes)
            active_count = len([mb for mb in self.all_mailboxes if mb.get('active', False)])
            inactive_count = total - active_count

            print(f"\n{Colors.green_bold('Mailbox Summary:')}")
            print(f"  Total Mailboxes: {total:,}")
            print(f"  Active: {Colors.green(str(active_count))}")
            print(f"  Inactive: {Colors.yellow(str(inactive_count))}")
            print(f"  Domains Found: {len(self.domains)}")

            return True

        except Exception as e:
            print(f"{Colors.red('Error fetching mailboxes:')} {str(e)}")
            return False

    async def switch_message_source(self) -> bool:
        """
        Switch to a different message source and clear cached data.

        Returns:
            True if switched successfully, False if cancelled
        """
        print(f"\n{Colors.bold('=== Switch Message Source ===')}")
        print(f"Current message source: {self.message_sources[self.selected_message_source_id].get('name', 'Unknown')}")

        # Get list of message sources
        message_sources_list = list(self.message_sources.values())

        if len(message_sources_list) <= 1:
            print(f"{Colors.yellow('Only one message source available. Cannot switch.')}")
            return False

        print(f"\n{Colors.bold('Available message sources:')}")
        for i, ms in enumerate(message_sources_list, 1):
            current_marker = " (current)" if ms['id'] == self.selected_message_source_id else ""
            print(f"{i}. {ms.get('name', 'Unknown')} ({ms.get('type', 'Unknown')}) - {ms['id']}{current_marker}")

        while True:
            try:
                choice = input(f"\n{Colors.blue('Select message source (1-' + str(len(message_sources_list)) + ', or press Enter to cancel):')} ").strip()

                if not choice:
                    print("Switch cancelled.")
                    return False

                index = int(choice) - 1
                if 0 <= index < len(message_sources_list):
                    new_source_id = message_sources_list[index]['id']

                    # Don't switch if same as current
                    if new_source_id == self.selected_message_source_id:
                        print(f"{Colors.yellow('Already using this message source.')}")
                        return False

                    # Confirm switch
                    new_source_name = message_sources_list[index].get('name', 'Unknown')
                    confirm = input(f"\n{Colors.blue(f'Switch to {new_source_name}? This will clear cached data. (y/N):')} ").strip().lower()

                    if confirm != 'y':
                        print("Switch cancelled.")
                        return False

                    # Clear all cached data
                    self.selected_message_source_id = new_source_id
                    self.all_mailboxes = []
                    self.domains = {}
                    self.group_search.clear_cache()

                    print(f"\n{Colors.green_bold('✓ Switched to:')} {new_source_name}")
                    print(f"{Colors.yellow('Note: Mailbox and group data will be fetched when needed.')}")

                    return True
                else:
                    print(f"{Colors.red('Invalid selection. Please choose 1-' + str(len(message_sources_list)))}")
            except ValueError:
                print(f"{Colors.red('Invalid input. Please enter a number.')}")
            except KeyboardInterrupt:
                print(f"\n{Colors.yellow('Switch cancelled.')}")
                return False

    async def display_main_menu(self):
        """Display the dynamic main menu with counts and availability."""
        # Get counts for dynamic menu
        counts = await self.get_menu_option_counts()

        # Build available options list
        self.available_menu_options = []

        print(f"\n{Colors.light_blue('View Mailboxes:')} {self._get_mailbox_url()}")
        print(f"\n{Colors.bold('Mailbox Utility - Main Menu:')}")

        # Option 1: Activate All Mailboxes
        option1_available = self.is_option_available('activate_all', counts)
        option1_text = self.format_menu_option("1. Activate All Mailboxes", f"{counts['mailboxes']['inactive']:,} inactive", option1_available)
        print(option1_text)
        if option1_available:
            self.available_menu_options.append('1')

        # Option 2: Activate by Domain
        option2_available = self.is_option_available('activate_by_domain', counts)
        option2_text = self.format_menu_option("2. Activate by Domain", f"{counts['domains']['with_inactive']} domains with inactive", option2_available)
        print(option2_text)
        if option2_available:
            self.available_menu_options.append('2')

        # Option 3: Export Mailboxes to CSV (always show)
        option3_text = self.format_menu_option("3. Export Mailboxes to CSV", f"{counts['mailboxes']['total']:,} total", True)
        print(option3_text)
        self.available_menu_options.append('3')

        # Option 4: Import CSV to Activate (always show)
        print("4. Import CSV to Activate")
        self.available_menu_options.append('4')

        # Option 5: Start HIP for Mailboxes (new option)
        option5_available = self.is_option_available('hip_jobs', counts)
        option5_text = self.format_menu_option("5. Start HIP for Mailboxes", f"{counts['mailboxes']['active']:,} active", option5_available)
        print(option5_text)
        if option5_available:
            self.available_menu_options.append('5')

        # Option 6: Activate by User Group
        option6_available = self.is_option_available('activate_by_group', counts)
        groups_count = counts.get('groups', {}).get('available', 0)
        groups_display = "click to check" if groups_count == -1 else f"{groups_count} groups"
        option6_text = self.format_menu_option("6. Activate Mailboxes by User Group", groups_display, option6_available)
        print(option6_text)
        if option6_available:
            self.available_menu_options.append('6')

        # Option 7: Deactivate by Domain
        option7_available = self.is_option_available('deactivate_by_domain', counts)
        option7_text = self.format_menu_option(f"7. {Colors.yellow('Deactivate Specific Mailboxes by Domain')} ⚠️", f"{counts['domains']['with_active']} domains with active", option7_available)
        print(option7_text)
        if option7_available:
            self.available_menu_options.append('7')

        # Option 8: Deactivate by User Group
        option8_available = self.is_option_available('deactivate_by_group', counts)
        # Use same groups_display from option 6 (groups_count already set above)
        option8_text = self.format_menu_option(f"8. {Colors.yellow('Deactivate Mailboxes by User Group')} ⚠️", groups_display, option8_available)
        print(option8_text)
        if option8_available:
            self.available_menu_options.append('8')

        # Option 9: Deactivate All Mailboxes
        option9_available = self.is_option_available('deactivate_all', counts)
        option9_text = self.format_menu_option(f"9. {Colors.red('Deactivate All Mailboxes (Dangerous)')} 🚨", f"{counts['mailboxes']['active']:,} active", option9_available)
        print(option9_text)
        if option9_available:
            self.available_menu_options.append('9')

        # Option 10: Switch Message Source (conditional)
        option10_available = len(self.message_sources) > 1
        if option10_available:
            current_source_name = self.message_sources[self.selected_message_source_id].get('name', 'Unknown')
            option10_text = f"10. Switch Message Source (currently: {current_source_name})"
            print(option10_text)
            self.available_menu_options.append('10')

        # Option 11: Exit (always available)
        print("11. Exit")
        self.available_menu_options.append('11')

    async def run_interactive_menu(self):
        """Run the main interactive menu loop."""
        while True:
            try:
                await self.display_main_menu()

                # Show available options in prompt
                if self.available_menu_options:
                    options_text = ", ".join(sorted(self.available_menu_options, key=lambda x: int(x)))
                    prompt = f"\n{Colors.blue(f'Select an option ({options_text}):')} "
                else:
                    prompt = f"\n{Colors.blue('No options available:')} "

                choice = input(prompt).strip()

                # Validate choice against available options
                if choice not in self.available_menu_options:
                    print(f"{Colors.red('Invalid selection or option not available.')}")
                    continue

                completed = False
                if choice == '1':
                    completed = await self.activate_all_mailboxes()
                elif choice == '2':
                    completed = await self.activate_by_domain()
                elif choice == '3':
                    completed = await self.export_mailboxes_csv()
                elif choice == '4':
                    completed = await self.import_csv_activate()
                elif choice == '5':
                    completed = await self.start_hip_for_mailboxes()  # New HIP menu
                elif choice == '6':
                    completed = await self.activate_by_user_group()  # New group activation
                elif choice == '7':
                    completed = await self.deactivate_by_domain()
                elif choice == '8':
                    completed = await self.deactivate_by_user_group()  # New group deactivation
                elif choice == '9':
                    completed = await self.mass_deactivate_all()
                elif choice == '10':
                    completed = await self.switch_message_source()
                elif choice == '11':
                    print(f"\n{Colors.green('Thank you for using Mailbox Utility!')}")
                    break

                # Only wait for user if operation completed (not cancelled)
                if choice != '11' and completed:
                    input(f"\n{Colors.blue('Press Enter to continue...')}")

            except KeyboardInterrupt:
                print(f"\n\n{Colors.yellow('Operation cancelled by user. Goodbye!')}")
                break
            except Exception as e:
                print(f"\n{Colors.red('Unexpected error:')} {str(e)}")
                input(f"{Colors.blue('Press Enter to continue...')}")

    async def activate_all_mailboxes(self):
        """Activate all inactive mailboxes."""
        print(f"\n{Colors.bold('=== Activate All Mailboxes ===')}")

        inactive_mailboxes = [mb for mb in self.all_mailboxes if not mb.get('active', False)]

        if not inactive_mailboxes:
            print(f"{Colors.green('All mailboxes are already active!')}")
            return True

        print(f"\nFound {Colors.yellow(str(len(inactive_mailboxes)))} inactive mailboxes to activate.")

        # Confirmation
        confirm = input(f"\n{Colors.blue('Are you sure you want to activate all inactive mailboxes? (y/N, or press Enter to cancel):')} ").strip().lower()
        if confirm != 'y':
            print("Returning to main menu.")
            return False

        # Activate mailboxes
        successful = 0
        failed = 0
        status_records = []

        print(f"\n{Colors.bold('Activating mailboxes...')}")

        for i, mailbox in enumerate(inactive_mailboxes, 1):
            email = mailbox.get('email_address', 'Unknown')
            try:
                print(f"\rActivating mailbox {i}/{len(inactive_mailboxes)}: {email}", end='', flush=True)
                await self.api.activate_mailbox(mailbox['id'])
                successful += 1
                status_records.append({'email_address': email, 'id': mailbox.get('id', ''), 'status': 'activated'})
            except Exception as e:
                failed += 1
                status_records.append({'email_address': email, 'id': mailbox.get('id', ''), 'status': 'failed', 'error': str(e)})
                if self.api.debug:
                    print(f"\nFailed to activate {email}: {str(e)}")

        print(f"\n\n{Colors.green_bold('Activation Results:')}")
        print(f"  Successful: {Colors.green(str(successful))}")
        if failed > 0:
            print(f"  Failed: {Colors.red(str(failed))}")

        report_file = self._export_status_report(status_records, 'activate')
        if report_file:
            print(f"  Status report: {Colors.cyan(report_file)}")

        # Offer HIP job creation
        if successful > 0:
            await self.offer_hip_job_creation(successful)

        return True

    async def activate_by_domain(self):
        """Activate mailboxes by selected domains."""
        print(f"\n{Colors.bold('=== Activate by Domain ===')}")

        if not self.domains:
            print(f"{Colors.yellow('No domains found.')}")
            return True

        # Display domains with counts
        domain_list = sorted(self.domains.items(), key=lambda x: x[1]['total'], reverse=True)

        print(f"\nAvailable domains (showing inactive mailbox counts):")
        for i, (domain, counts) in enumerate(domain_list, 1):
            if counts['inactive'] > 0:
                print(f"{i}. {domain} - {Colors.yellow(str(counts['inactive']))} inactive, {Colors.green(str(counts['active']))} active")
            else:
                print(f"{i}. {domain} - {Colors.green('All active')} ({counts['total']} total)")

        # Domain selection
        selected_domains = []
        while True:
            try:
                choice = input(f"\nSelect domain numbers (comma-separated), 'all' for all domains, or press Enter to cancel: ").strip()

                if not choice:
                    print("Returning to main menu.")
                    return False
                elif choice.lower() == 'all':
                    selected_domains = [domain for domain, counts in domain_list if counts['inactive'] > 0]
                    break
                else:
                    indices = [int(x.strip()) - 1 for x in choice.split(',')]
                    selected_domains = [domain_list[i][0] for i in indices if 0 <= i < len(domain_list)]
                    break
            except (ValueError, IndexError):
                print(f"{Colors.red('Invalid selection. Please enter valid domain numbers.')}")

        if not selected_domains:
            print("No domains selected.")
            return False

        # Get mailboxes for selected domains
        mailboxes_to_activate = []
        for mailbox in self.all_mailboxes:
            if not mailbox.get('active', False):  # Only inactive mailboxes
                email = mailbox.get('email_address', '')
                if '@' in email:
                    domain = email.split('@')[1].lower()
                    if domain in selected_domains:
                        mailboxes_to_activate.append(mailbox)

        if not mailboxes_to_activate:
            print(f"{Colors.green('No inactive mailboxes found for selected domains.')}")
            return True

        print(f"\nFound {Colors.yellow(str(len(mailboxes_to_activate)))} inactive mailboxes to activate from {len(selected_domains)} domains.")

        # Show preview
        print(f"\nPreview (first 10 mailboxes):")
        for mailbox in mailboxes_to_activate[:10]:
            print(f"  • {mailbox.get('email_address', 'Unknown')}")
        if len(mailboxes_to_activate) > 10:
            print(f"  ... and {len(mailboxes_to_activate) - 10} more")

        # Confirmation
        confirm = input(f"\n{Colors.blue('Proceed with activation? (y/N, or press Enter to cancel):')} ").strip().lower()
        if confirm != 'y':
            print("Returning to main menu.")
            return False

        # Activate mailboxes
        successful = 0
        failed = 0
        status_records = []

        print(f"\n{Colors.bold('Activating mailboxes...')}")

        for i, mailbox in enumerate(mailboxes_to_activate, 1):
            email = mailbox.get('email_address', 'Unknown')
            try:
                print(f"\rActivating mailbox {i}/{len(mailboxes_to_activate)}: {email}", end='', flush=True)
                await self.api.activate_mailbox(mailbox['id'])
                successful += 1
                status_records.append({'email_address': email, 'id': mailbox.get('id', ''), 'status': 'activated'})
            except Exception as e:
                failed += 1
                status_records.append({'email_address': email, 'id': mailbox.get('id', ''), 'status': 'failed', 'error': str(e)})
                if self.api.debug:
                    print(f"\nFailed to activate {email}: {str(e)}")

        print(f"\n\n{Colors.green_bold('Activation Results:')}")
        print(f"  Successful: {Colors.green(str(successful))}")
        if failed > 0:
            print(f"  Failed: {Colors.red(str(failed))}")

        report_file = self._export_status_report(status_records, 'activate')
        if report_file:
            print(f"  Status report: {Colors.cyan(report_file)}")

        # Offer HIP job creation
        if successful > 0:
            await self.offer_hip_job_creation(successful)

        return True

    async def activate_by_user_group(self):
        """Activate mailboxes by selecting a user group using progressive search."""
        selected_group = await self.group_search.search_groups_interactive("activate", message_source_id=self.selected_message_source_id)

        if not selected_group:
            return False

        # Get detailed group information
        try:
            group_details = await self.api.get_user_group_details(selected_group['id'])
        except Exception as e:
            print(f"{Colors.red('Failed to get group details:')} {str(e)}")
            return False

        # Display group preview
        print(f"\n{Colors.bold('Group Preview:')}")
        print(f"  Name: {Colors.green(group_details.get('name', 'Unknown'))}")
        print(f"  Members: {group_details.get('member_count', 0)} mailboxes")
        print(f"  Status: {'Active' if group_details.get('active', False) else 'Inactive'}")
        if group_details.get('description'):
            print(f"  Description: {group_details.get('description')}")

        # Confirmation
        member_count = group_details.get('member_count', 0)
        group_name = group_details.get('name', 'this group')
        confirm_text = f'Activate {group_name} with {member_count} members? (y/N):'
        confirm = input(f"\n{Colors.blue(confirm_text)} ").strip().lower()

        if confirm != 'y':
            print("Group activation cancelled.")
            return False

        # Activate the group
        try:
            print(f"\n{Colors.cyan('Activating user group...')}")
            result = await self.api.activate_user_group(selected_group['id'])

            print(f"\n{Colors.green_bold('✓ Group Activation Successful!')}")
            print(f"  Group: {group_details.get('name', 'Unknown')}")
            print(f"  Activated: {member_count} mailboxes")

            # Offer HIP job creation if significant number of mailboxes
            if member_count > 0:
                await self.offer_hip_job_creation(member_count)

            return True

        except Exception as e:
            print(f"\n{Colors.red('Failed to activate group:')} {str(e)}")
            return False

    async def deactivate_by_user_group(self):
        """Deactivate mailboxes by selecting a user group with extensive safety warnings."""
        print(f"\n{Colors.red_bold('⚠️  WARNING: Group Deactivation Impact')}")
        print(f"{Colors.yellow('Deactivating a user group will deactivate member mailboxes that are not')}")
        print(f"{Colors.yellow('members of other active groups. This will impact email detection.')}")
        print(f"\n{Colors.yellow('Appropriate use cases:')}")
        print(f"  • Security incidents requiring group-level isolation")
        print(f"  • POC setup and testing scenarios")
        print(f"  • Organizational changes (department deactivation)")
        print(f"  • Before Live Flow configuration")

        proceed = input(f"\n{Colors.blue('Do you want to proceed with group deactivation? (y/N):')} ").strip().lower()
        if proceed != 'y':
            print("Group deactivation cancelled.")
            return False

        selected_group = await self.group_search.search_groups_interactive("deactivate", message_source_id=self.selected_message_source_id)

        if not selected_group:
            return False

        # Get detailed group information
        try:
            group_details = await self.api.get_user_group_details(selected_group['id'])
        except Exception as e:
            print(f"{Colors.red('Failed to get group details:')} {str(e)}")
            return False

        # Display group preview with impact assessment
        member_count = group_details.get('member_count', 0)
        print(f"\n{Colors.bold('Group Deactivation Preview:')}")
        print(f"  Name: {Colors.yellow(group_details.get('name', 'Unknown'))}")
        print(f"  Members: {Colors.red(str(member_count))} mailboxes")
        print(f"  Current Status: {'Active' if group_details.get('active', False) else 'Inactive'}")
        if group_details.get('description'):
            print(f"  Description: {group_details.get('description')}")

        print(f"\n{Colors.red_bold('⚠️  IMPACT ASSESSMENT:')}")
        print(f"  • Up to {Colors.red(str(member_count))} mailboxes may be deactivated")
        print(f"  • Mailboxes in other active groups will remain active")
        print(f"  • Email detection will be impacted for deactivated mailboxes")
        print(f"  • This action affects group-level mail processing")

        # Double confirmation
        group_name = group_details.get('name', 'selected')
        confirm1_text = f'This will deactivate the "{group_name}" group. Continue? (y/N):'
        confirm1 = input(f"\n{Colors.blue(confirm1_text)} ").strip().lower()
        if confirm1 != 'y':
            print("Group deactivation cancelled.")
            return False

        # Typed confirmation
        deactivate_text = 'Type "DEACTIVATE GROUP" to confirm this operation:'
        confirm2 = input(f"\n{Colors.red(deactivate_text)} ").strip()
        if confirm2 != "DEACTIVATE GROUP":
            print("Group deactivation cancelled - confirmation text did not match.")
            return False

        # Deactivate the group
        try:
            print(f"\n{Colors.cyan('Deactivating user group...')}")
            result = await self.api.deactivate_user_group(selected_group['id'])

            print(f"\n{Colors.green_bold('✓ Group Deactivation Completed!')}")
            print(f"  Group: {group_details.get('name', 'Unknown')}")
            print(f"  Processed: {member_count} mailboxes")
            print(f"\n{Colors.yellow('Note: Only mailboxes not in other active groups were deactivated.')}")

            return True

        except Exception as e:
            print(f"\n{Colors.red('Failed to deactivate group:')} {str(e)}")
            return False

    async def export_mailboxes_csv(self):
        """Export mailboxes to CSV with various filter options."""
        print(f"\n{Colors.bold('=== Export Mailboxes to CSV ===')}")

        # Get counts for dynamic menu
        counts = await self.get_menu_option_counts()

        # Build available options list
        available_options = []

        print("\nExport options:")

        # Option 1: All mailboxes (always available if any mailboxes exist)
        option1_available = self.is_option_available('export_all', counts)
        option1_text = self.format_menu_option("1. All mailboxes", f"{counts['mailboxes']['total']:,} total", option1_available)
        print(option1_text)
        if option1_available:
            available_options.append('1')

        # Option 2: Active mailboxes only
        option2_available = self.is_option_available('export_active', counts)
        option2_text = self.format_menu_option("2. Active mailboxes only", f"{counts['mailboxes']['active']:,} active", option2_available)
        print(option2_text)
        if option2_available:
            available_options.append('2')

        # Option 3: Inactive mailboxes only
        option3_available = self.is_option_available('export_inactive', counts)
        option3_text = self.format_menu_option("3. Inactive mailboxes only", f"{counts['mailboxes']['inactive']:,} inactive", option3_available)
        print(option3_text)
        if option3_available:
            available_options.append('3')

        # Option 4: Mailboxes by domain
        option4_available = self.is_option_available('export_by_domain', counts)
        option4_text = self.format_menu_option("4. Mailboxes by domain", f"{counts['domains']['total']} domains", option4_available)
        print(option4_text)
        if option4_available:
            available_options.append('4')

        # Show available options in prompt
        if available_options:
            options_text = ", ".join(available_options)
            prompt = f"\n{Colors.blue(f'Select export option ({options_text}, or press Enter to cancel):')} "
        else:
            prompt = f"\n{Colors.blue('No export options available (press Enter to cancel):')} "

        try:
            choice = input(prompt).strip()

            if not choice:
                print("Returning to main menu.")
                return False

            # Validate choice against available options
            if choice not in available_options:
                print(f"{Colors.red('Invalid selection or option not available.')}")
                return False

            mailboxes_to_export = []
            filename_suffix = ""

            if choice == '1':
                mailboxes_to_export = self.all_mailboxes
                filename_suffix = "all"
            elif choice == '2':
                mailboxes_to_export = [mb for mb in self.all_mailboxes if mb.get('active', False)]
                filename_suffix = "active"
            elif choice == '3':
                mailboxes_to_export = [mb for mb in self.all_mailboxes if not mb.get('active', False)]
                filename_suffix = "inactive"
            elif choice == '4':
                # Domain selection for export
                domain_list = sorted(self.domains.keys())
                print(f"\nAvailable domains:")
                for i, domain in enumerate(domain_list, 1):
                    counts = self.domains[domain]
                    print(f"{i}. {domain} - {counts['total']} total ({Colors.green(str(counts['active']))} active, {Colors.yellow(str(counts['inactive']))} inactive)")

                domain_choice = input(f"\nSelect domain number (1-{len(domain_list)}, or press Enter to cancel): ").strip()

                if not domain_choice:
                    print("Returning to main menu.")
                    return False

                domain_index = int(domain_choice) - 1

                if 0 <= domain_index < len(domain_list):
                    selected_domain = domain_list[domain_index]
                    mailboxes_to_export = [
                        mb for mb in self.all_mailboxes
                        if '@' in mb.get('email_address', '') and
                        mb.get('email_address', '').split('@')[1].lower() == selected_domain
                    ]
                    filename_suffix = f"domain_{selected_domain.replace('.', '_')}"
                else:
                    print(f"{Colors.red('Invalid domain selection.')}")
                    return False

            if not mailboxes_to_export:
                print(f"{Colors.yellow('No mailboxes found matching the selected criteria.')}")
                return True

            # Create export directory if it doesn't exist
            export_dir = "export"
            os.makedirs(export_dir, exist_ok=True)

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"mailboxes_{filename_suffix}_{timestamp}.csv"
            full_path = os.path.join(export_dir, filename)

            # Export to CSV
            self._export_mailboxes_to_csv(mailboxes_to_export, full_path)

            print(f"\n{Colors.green_bold('Export completed successfully!')}")
            print(f"  File: {full_path}")
            print(f"  Records: {len(mailboxes_to_export):,}")
            return True

        except (ValueError, IndexError):
            print(f"{Colors.red('Invalid input.')}")
            return False
        except Exception as e:
            print(f"{Colors.red('Export failed:')} {str(e)}")
            return False

    def _export_mailboxes_to_csv(self, mailboxes: List[Dict], filename: str):
        """Export mailboxes to CSV file with all specified fields."""
        # Fields to export (18 total as specified)
        fields = [
            'active', 'created_at', 'display_name', 'email_address', 'external_created_at',
            'external_id', 'external_subscription_error_status', 'first_name', 'full_name',
            'has_unresolved_errors', 'id', 'is_external_admin', 'last_name',
            'license_activated_at', 'marked_active', 'message_source_id', 'message_source_type', 'org_id'
        ]

        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow(fields)

            # Write data
            for mailbox in mailboxes:
                row = [mailbox.get(field, '') for field in fields]
                writer.writerow(row)

    def _export_status_report(self, records: List[Dict], action: str) -> Optional[str]:
        """Export a per-email status report to a timestamped CSV file.

        Each record is written as a row capturing the specific email address that
        was attempted and the resulting status ('activated'/'deactivated' or
        'failed'). The report is written to disk only; it is not printed to the CLI.

        Args:
            records: List of dicts with keys 'email_address', 'id', 'status', and
                optional 'error'.
            action: The operation performed ('activate' or 'deactivate'), used to
                build the filename.

        Returns:
            The filename written, or None if there were no records or the write failed.
        """
        if not records:
            return None

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"mailbox_{action}_status_{timestamp}.csv"
        fields = ['email_address', 'id', 'status', 'error']

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(fields)
                for record in records:
                    writer.writerow([record.get(field, '') for field in fields])
            return filename
        except OSError as e:
            print(f"\n{Colors.red('Failed to write status report:')} {str(e)}")
            return None

    async def parallel_activate_mailboxes(self, mailboxes: List[Dict], max_workers: int = 10,
                                        rate_limit_backoff: float = 2.0) -> Dict[str, int]:
        """
        Activate mailboxes in parallel with dynamic worker management and retry logic.

        Args:
            mailboxes: List of mailbox dictionaries to activate
            max_workers: Maximum number of concurrent workers
            rate_limit_backoff: Backoff multiplier for rate limiting

        Returns:
            Dictionary with success/failure/retry counts and statistics
        """
        import time
        from collections import defaultdict

        # Initialize counters and tracking
        results = {
            'successful': 0,
            'failed': 0,
            'retries': 0,
            'rate_limit_events': 0,
            'start_time': time.time(),
            'total_mailboxes': len(mailboxes),
            'status_records': []  # Per-email outcome for the CSV status report
        }

        def record_status(result_item: Dict, status: str):
            """Append a per-email status record from a worker result."""
            mailbox = result_item.get('mailbox')
            if isinstance(mailbox, dict):
                results['status_records'].append({
                    'email_address': mailbox.get('email_address', 'Unknown'),
                    'id': mailbox.get('id', ''),
                    'status': status,
                    'error': result_item.get('error', '')
                })
            else:
                results['status_records'].append({
                    'email_address': 'Unknown',
                    'id': '',
                    'status': status,
                    'error': result_item.get('error', '')
                })

        # Worker management
        current_workers = min(max_workers, len(mailboxes))
        consecutive_success = 0
        retry_queue = []
        failed_permanent = []

        # Progress tracking
        completed = 0
        last_progress_update = 0

        def update_progress():
            nonlocal last_progress_update, completed
            now = time.time()
            if now - last_progress_update >= 1.0:  # Update every second
                elapsed = now - results['start_time']
                rate = completed / elapsed if elapsed > 0 else 0
                print(f"\rActivating {completed}/{len(mailboxes)} mailboxes "
                     f"({current_workers} workers, {rate:.1f}/sec)",
                     end='', flush=True)
                last_progress_update = now

        async def activate_single_mailbox(semaphore: asyncio.Semaphore, mailbox: Dict, attempt: int = 1):
            nonlocal current_workers, consecutive_success, results

            async with semaphore:
                try:
                    await self.api.activate_mailbox(mailbox['id'])
                    consecutive_success += 1
                    results['successful'] += 1
                    return {'status': 'success', 'mailbox': mailbox, 'attempt': attempt}

                except RateLimitError as e:
                    results['rate_limit_events'] += 1
                    consecutive_success = 0

                    # Reduce workers on rate limiting
                    if current_workers > 1:
                        current_workers = max(1, current_workers // 2)
                        print(f"\n{Colors.yellow(f'Rate limiting detected, reducing to {current_workers} workers')}")

                    return {'status': 'rate_limited', 'mailbox': mailbox, 'attempt': attempt,
                           'retry_after': e.retry_after or rate_limit_backoff * (2 ** attempt)}

                except APIError as e:
                    if "404" in str(e):
                        # Mailbox not found - permanent failure
                        results['failed'] += 1
                        return {'status': 'not_found', 'mailbox': mailbox, 'error': str(e)}
                    else:
                        # Other API error - could be temporary, add to retry queue
                        return {'status': 'error', 'mailbox': mailbox, 'attempt': attempt, 'error': str(e)}

                except Exception as e:
                    # Network or other error - add to retry queue
                    return {'status': 'error', 'mailbox': mailbox, 'attempt': attempt, 'error': str(e)}

        # Initial activation batch
        semaphore = asyncio.Semaphore(current_workers)
        tasks = [activate_single_mailbox(semaphore, mailbox) for mailbox in mailboxes]

        print(f"\n{Colors.bold('Activating mailboxes in parallel...')}")
        print(f"Starting with {current_workers} workers for {len(mailboxes)} mailboxes")

        # Process initial batch
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and handle retries
        for result in batch_results:
            completed += 1
            update_progress()

            if isinstance(result, Exception):
                failed_permanent.append({'mailbox': 'unknown', 'error': str(result)})
                results['failed'] += 1
                record_status({'error': str(result)}, 'failed')
            elif result['status'] == 'success':
                record_status(result, 'activated')
            elif result['status'] in ['rate_limited', 'error']:
                if result['attempt'] < 3:  # Max 3 attempts
                    retry_queue.append(result)
                else:
                    failed_permanent.append(result)
                    results['failed'] += 1
                    record_status(result, 'failed')
            elif result['status'] == 'not_found':
                record_status(result, 'failed')  # Already counted as failed

        # Process retry queue
        while retry_queue:
            print(f"\n{Colors.yellow(f'Retrying {len(retry_queue)} failed mailboxes...')}")
            current_batch = retry_queue.copy()
            retry_queue.clear()

            # Wait before retrying (especially important for rate limiting)
            if current_batch and 'retry_after' in current_batch[0]:
                wait_time = min(30, current_batch[0]['retry_after'])
                print(f"{Colors.yellow(f'Waiting {wait_time:.1f}s before retry...')}")
                await asyncio.sleep(wait_time)
            else:
                await asyncio.sleep(2)  # Brief pause for other errors

            # Update semaphore for current worker count
            semaphore = asyncio.Semaphore(current_workers)
            retry_tasks = [
                activate_single_mailbox(semaphore, item['mailbox'], item['attempt'] + 1)
                for item in current_batch
            ]

            retry_batch_results = await asyncio.gather(*retry_tasks, return_exceptions=True)
            results['retries'] += len(retry_tasks)

            for result in retry_batch_results:
                if isinstance(result, Exception):
                    failed_permanent.append({'mailbox': 'unknown', 'error': str(result)})
                    results['failed'] += 1
                    record_status({'error': str(result)}, 'failed')
                elif result['status'] == 'success':
                    consecutive_success += 1
                    results['successful'] += 1
                    record_status(result, 'activated')
                elif result['status'] in ['rate_limited', 'error']:
                    if result['attempt'] < 3:
                        retry_queue.append(result)
                    else:
                        failed_permanent.append(result)
                        results['failed'] += 1
                        record_status(result, 'failed')
                elif result['status'] == 'not_found':
                    record_status(result, 'failed')  # Already counted as failed

            # Gradually increase workers on sustained success
            if consecutive_success >= 50 and current_workers < max_workers:
                current_workers = min(max_workers, current_workers + 1)
                print(f"\n{Colors.green(f'Increasing to {current_workers} workers due to stable performance')}")
                consecutive_success = 0

        # Final progress update
        elapsed = time.time() - results['start_time']
        results['elapsed_time'] = elapsed
        results['rate'] = completed / elapsed if elapsed > 0 else 0

        print(f"\n\n{Colors.green_bold('Parallel Activation Results:')}")
        print(f"  Successful: {Colors.green(str(results['successful']))}")
        if results['failed'] > 0:
            print(f"  Failed: {Colors.red(str(results['failed']))}")
        if results['retries'] > 0:
            print(f"  Retries: {Colors.yellow(str(results['retries']))}")
        if results['rate_limit_events'] > 0:
            print(f"  Rate limit events: {Colors.yellow(str(results['rate_limit_events']))}")
        time_text = f'{elapsed:.1f}s'
        print(f"  Total time: {Colors.cyan(time_text)}")
        rate_text = f'{results["rate"]:.1f} mailboxes/sec'
        print(f"  Average rate: {Colors.cyan(rate_text)}")

        return results

    async def import_csv_activate(self):
        """Import email addresses from CSV and activate corresponding mailboxes."""
        print(f"\n{Colors.bold('=== Import CSV to Activate ===')}")

        filename = input(f"{Colors.blue('Enter CSV filename (or press Enter to cancel):')} ").strip()

        if not filename:
            print("Returning to main menu.")
            return False

        if not os.path.exists(filename):
            print(f"{Colors.red('File not found:')} {filename}")
            return False

        try:
            # Read CSV and extract email addresses
            emails_to_activate = set()

            with open(filename, 'r', encoding='utf-8') as csvfile:
                # Try to detect if there's a header
                sample = csvfile.read(1024)
                csvfile.seek(0)

                reader = csv.reader(csvfile)

                # Skip header if it looks like one
                first_row = next(reader)
                if not any('@' in cell for cell in first_row):
                    # Likely a header row, skip it
                    pass
                else:
                    # First row contains data, process it
                    csvfile.seek(0)
                    reader = csv.reader(csvfile)

                # Extract emails from all columns
                for row in reader:
                    for cell in row:
                        if isinstance(cell, str) and '@' in cell and '.' in cell:
                            emails_to_activate.add(cell.strip().lower())

            print(f"Found {len(emails_to_activate)} unique email addresses in CSV.")

            # Find matching mailboxes
            mailboxes_to_activate = []
            emails_found = set()

            for mailbox in self.all_mailboxes:
                email = mailbox.get('email_address', '').lower()
                if email in emails_to_activate and not mailbox.get('active', False):
                    mailboxes_to_activate.append(mailbox)
                    emails_found.add(email)

            emails_not_found = emails_to_activate - emails_found
            already_active = []

            # Check for already active mailboxes
            for mailbox in self.all_mailboxes:
                email = mailbox.get('email_address', '').lower()
                if email in emails_to_activate and mailbox.get('active', False):
                    already_active.append(email)

            # Report findings
            print(f"\n{Colors.bold('Import Analysis:')}")
            print(f"  Emails in CSV: {len(emails_to_activate)}")
            print(f"  Found and inactive: {Colors.yellow(str(len(mailboxes_to_activate)))}")
            print(f"  Already active: {Colors.green(str(len(already_active)))}")
            print(f"  Not found: {Colors.red(str(len(emails_not_found)))}")

            if emails_not_found:
                print(f"\n{Colors.yellow('Emails not found in system:')}")
                for email in sorted(emails_not_found)[:10]:
                    print(f"  • {email}")
                if len(emails_not_found) > 10:
                    print(f"  ... and {len(emails_not_found) - 10} more")

            if not mailboxes_to_activate:
                print(f"{Colors.green('No inactive mailboxes found to activate.')}")
                return True

            # Confirmation
            confirm = input(f"\n{Colors.blue(f'Proceed to activate {len(mailboxes_to_activate)} mailboxes? (y/N, or press Enter to cancel):')} ").strip().lower()
            if confirm != 'y':
                print("Returning to main menu.")
                return False

            # Determine optimal worker count based on mailbox count
            if len(mailboxes_to_activate) >= 1000:
                max_workers = 15  # More aggressive for large datasets
                print(f"\n{Colors.cyan(f'Large dataset detected ({len(mailboxes_to_activate)} mailboxes), using up to 15 workers')}")
            elif len(mailboxes_to_activate) >= 500:
                max_workers = 10  # Standard for medium datasets
            elif len(mailboxes_to_activate) >= 100:
                max_workers = 8   # Conservative for smaller datasets
            else:
                max_workers = 5   # Very conservative for small datasets

            # Activate mailboxes using parallel processing
            results = await self.parallel_activate_mailboxes(mailboxes_to_activate, max_workers=max_workers)

            report_file = self._export_status_report(results.get('status_records', []), 'activate')
            if report_file:
                print(f"  Status report: {Colors.cyan(report_file)}")

            # Offer HIP job creation
            if results['successful'] > 0:
                await self.offer_hip_job_creation(results['successful'])
            return True

        except Exception as e:
            print(f"{Colors.red('Import failed:')} {str(e)}")
            return False

    async def deactivate_by_domain(self):
        """Deactivate mailboxes by selected domains with warnings."""
        print(f"\n{Colors.bold('=== Deactivate Specific Mailboxes by Domain ===')}")
        print(f"{Colors.yellow_bold('⚠️  WARNING: Deactivating mailboxes should only be used in rare cases')}")
        print(f"{Colors.yellow('(incidents, POC setup, before Live Flow) and will impact email detection.')}")

        if not self.domains:
            print(f"{Colors.yellow('No domains found.')}")
            return True

        # Display domains with active counts only
        domain_list = [(domain, counts) for domain, counts in sorted(self.domains.items()) if counts['active'] > 0]

        if not domain_list:
            print(f"{Colors.green('No domains have active mailboxes to deactivate.')}")
            return True

        print(f"\nDomains with active mailboxes:")
        for i, (domain, counts) in enumerate(domain_list, 1):
            print(f"{i}. {domain} - {Colors.red(str(counts['active']))} active mailboxes")

        # Domain selection
        try:
            choice = input(f"\nSelect domain number (1-{len(domain_list)}, or press Enter to cancel): ").strip()

            if not choice:
                print("Returning to main menu.")
                return False

            domain_index = int(choice) - 1

            if not (0 <= domain_index < len(domain_list)):
                print(f"{Colors.red('Invalid selection.')}")
                return False

            selected_domain = domain_list[domain_index][0]
            active_count = domain_list[domain_index][1]['active']

        except (ValueError, IndexError):
            print(f"{Colors.red('Invalid input.')}")
            return False

        # Get active mailboxes for selected domain
        mailboxes_to_deactivate = []
        for mailbox in self.all_mailboxes:
            if mailbox.get('active', False):  # Only active mailboxes
                email = mailbox.get('email_address', '')
                if '@' in email and email.split('@')[1].lower() == selected_domain:
                    mailboxes_to_deactivate.append(mailbox)

        if not mailboxes_to_deactivate:
            print(f"{Colors.green('No active mailboxes found for domain')}: {selected_domain}")
            return True

        # Double confirmation with warnings
        print(f"\n{Colors.red_bold('This will deactivate')}{Colors.bold(f' {len(mailboxes_to_deactivate)} mailboxes')}{Colors.red_bold(' from domain:')}{Colors.bold(f' {selected_domain}')}")
        print(f"{Colors.yellow('This will impact email detection for these users.')}")

        confirm1 = input(f"\n{Colors.blue(f'Are you sure you want to deactivate {len(mailboxes_to_deactivate)} mailboxes from {selected_domain}? (y/N, or press Enter to cancel):')} ").strip().lower()
        if confirm1 != 'y':
            print("Returning to main menu.")
            return False

        confirm2 = input(f"{Colors.red('Type')} {Colors.bold('DEACTIVATE')} {Colors.red('to confirm this operation (or press Enter to cancel):')}\n").strip()
        if confirm2 != 'DEACTIVATE':
            print("Returning to main menu.")
            return False

        # Deactivate mailboxes
        successful = 0
        failed = 0
        status_records = []

        print(f"\n{Colors.bold('Deactivating mailboxes...')}")

        for i, mailbox in enumerate(mailboxes_to_deactivate, 1):
            email = mailbox.get('email_address', 'Unknown')
            try:
                print(f"\rDeactivating mailbox {i}/{len(mailboxes_to_deactivate)}: {email}", end='', flush=True)
                await self.api.deactivate_mailbox(mailbox['id'])
                successful += 1
                status_records.append({'email_address': email, 'id': mailbox.get('id', ''), 'status': 'deactivated'})
            except Exception as e:
                failed += 1
                status_records.append({'email_address': email, 'id': mailbox.get('id', ''), 'status': 'failed', 'error': str(e)})
                if self.api.debug:
                    print(f"\nFailed to deactivate {email}: {str(e)}")

        print(f"\n\n{Colors.red_bold('Deactivation Results:')}")
        print(f"  Successful: {Colors.red(str(successful))}")
        if failed > 0:
            print(f"  Failed: {Colors.yellow(str(failed))}")

        report_file = self._export_status_report(status_records, 'deactivate')
        if report_file:
            print(f"  Status report: {Colors.cyan(report_file)}")

        return True

    async def mass_deactivate_all(self):
        """Mass deactivate all mailboxes with extensive warnings."""
        print(f"\n{Colors.bold('=== Mass Deactivate All Mailboxes (DANGEROUS) ===')}")
        print(f"{Colors.red_bold('🚨 DANGER: This will deactivate ALL mailboxes and severely impact email detection!')}")
        print(f"{Colors.red('This should ONLY be used for incidents, POC setup, or before Live Flow configuration.')}")

        # Show current active mailbox count
        active_count = len([mb for mb in self.all_mailboxes if mb.get('active', False)])

        if active_count == 0:
            print(f"{Colors.green('All mailboxes are already inactive.')}")
            return True

        print(f"\n{Colors.red_bold(f'This will deactivate {active_count:,} active mailboxes.')}")

        # Determine message source configuration
        all_message_sources = len(self.message_sources) == 1

        if all_message_sources:
            print(f"\n{Colors.bold('Configuration:')} Single message source - will deactivate ALL mailboxes")
        else:
            print(f"\n{Colors.bold('Configuration:')} Multiple message sources found")
            print(f"Available message sources:")
            for ms_id, ms_info in self.message_sources.items():
                print(f"  • {ms_info.get('name', 'Unknown')} ({ms_info.get('type', 'Unknown')})")
            print(f"\nWill only deactivate mailboxes from selected message source: {self.message_sources[self.selected_message_source_id].get('name', 'Unknown')}")

        # Triple confirmation
        confirm1 = input(f"\n{Colors.red('Are you sure you want to deactivate ALL mailboxes? This will severely impact email detection! (y/N, or press Enter to cancel):')} ").strip().lower()
        if confirm1 != 'y':
            print("Returning to main menu.")
            return False

        confirm2 = input(f"{Colors.red('This is a dangerous operation that should only be used for incidents or POC setup. Continue? (y/N, or press Enter to cancel):')} ").strip().lower()
        if confirm2 != 'y':
            print("Returning to main menu.")
            return False

        confirm3 = input(f"{Colors.red_bold('Type')} {Colors.bold('MASS DEACTIVATE')} {Colors.red_bold('to confirm this dangerous operation (or press Enter to cancel):')}\n").strip()
        if confirm3 != 'MASS DEACTIVATE':
            print("Returning to main menu.")
            return False

        # Execute mass deactivation
        try:
            print(f"\n{Colors.bold('Executing mass deactivation...')}")

            message_source_ids = None if all_message_sources else [self.selected_message_source_id]

            result = await self.api.mass_deactivate_mailboxes(
                all_message_sources=all_message_sources,
                message_source_ids=message_source_ids
            )

            print(f"\n{Colors.red_bold('Mass Deactivation Completed')}")
            print(f"API Response: {json.dumps(result, indent=2)}")
            return True

        except Exception as e:
            print(f"\n{Colors.red('Mass deactivation failed:')} {str(e)}")
            return False

    async def offer_hip_job_creation(self, activated_count: int):
        """Offer to create HIP job for newly activated mailboxes."""
        print(f"\n{Colors.bold('HIP Job Creation')}")

        # Check if activation count is high
        if activated_count > 2000:
            print(f"{Colors.yellow_bold('⚠️  WARNING: You activated more than 2,000 mailboxes!')}")
            print(f"{Colors.yellow('Processing all mailboxes in a single HIP job may impact system performance.')}")

            print(f"\nOptions:")
            print(f"1. Create HIP job for all {activated_count:,} activated mailboxes")
            print(f"2. Create HIP job for a specific number of mailboxes")
            print(f"3. Skip HIP job creation")

            choice = input(f"\n{Colors.blue('Select option (1-3, or press Enter to cancel):')} ").strip()

            if not choice:
                print("Returning to main menu.")
                return
            elif choice == '1':
                # Process all
                pass
            elif choice == '2':
                # Process specific count - for now, just inform user
                print(f"{Colors.yellow('Note: Specific count processing will be available in a future version.')}")
                print(f"{Colors.yellow('For now, the HIP job will process all active mailboxes.')}")
            elif choice == '3':
                print("Skipping HIP job creation.")
                return
            else:
                print("Invalid selection. Skipping HIP job creation.")
                return

        # Ask if user wants to create HIP job
        create_hip = input(f"\n{Colors.blue('Would you like to create a HIP job for the newly activated mailboxes? (y/N, or press Enter to skip):')} ").strip().lower()

        if create_hip == 'y':
            try:
                print(f"\n{Colors.bold('Creating HIP job...')}")

                result = await self.api.create_hip_job(
                    message_source_id=self.selected_message_source_id,
                    mode="HISTORICALLY_MATCH",
                    active_mailboxes_only=True
                )

                print(f"{Colors.green_bold('HIP Job Created Successfully!')}")

                # Display job details
                if 'id' in result:
                    print(f"  Job ID: {result['id']}")
                if 'status' in result:
                    print(f"  Status: {result['status']}")

                print(f"  Mode: HISTORICALLY_MATCH")
                print(f"  Active Mailboxes Only: Yes")

            except Exception as e:
                print(f"{Colors.red('Failed to create HIP job:')} {str(e)}")

    async def start_hip_for_mailboxes(self) -> bool:
        """Main HIP job creation menu with comprehensive options."""
        print(f"\n{Colors.bold('=== Start HIP for Mailboxes ===')}")

        print("\nHIP Job Options:")
        print("1. HIP by Domain (with sampling if needed)")
        print("2. HIP by Multiple Domains (with per-domain sampling)")
        print("3. HIP by Mailbox Count (cross-domain sampling)")
        print("4. HIP for All Active Mailboxes")

        try:
            choice = input(f"\n{Colors.blue('Select HIP option (1-4, or press Enter to cancel):')} ").strip()

            if not choice:
                print("Returning to main menu.")
                return False

            if choice == '1':
                return await self.hip_by_domain()
            elif choice == '2':
                return await self.hip_by_multiple_domains()
            elif choice == '3':
                return await self.hip_by_mailbox_count()
            elif choice == '4':
                return await self.hip_for_all_active()
            else:
                print(f"{Colors.red('Invalid selection.')}")
                return False

        except Exception as e:
            print(f"{Colors.red('Error in HIP menu:')} {str(e)}")
            return False

    async def hip_by_domain(self) -> bool:
        """Create HIP job for a specific domain with sampling if needed."""
        print(f"\n{Colors.bold('=== HIP by Domain ===')}")

        # Get domains with active mailboxes
        domains_with_active = [(domain, counts) for domain, counts in self.domains.items() if counts['active'] > 0]

        if not domains_with_active:
            print(f"{Colors.yellow('No domains have active mailboxes.')}")
            return True

        print(f"\nAvailable domains with active mailboxes:")
        for i, (domain, counts) in enumerate(domains_with_active, 1):
            warning = ""
            if counts['active'] > 2000:
                warning = f" {Colors.yellow('⚠️ (sampling recommended)')}"
            print(f"{i}. {domain} - {Colors.green(str(counts['active']))} active mailboxes{warning}")

        try:
            domain_choice = input(f"\nSelect domain (1-{len(domains_with_active)}, or press Enter to cancel): ").strip()

            if not domain_choice:
                print("Returning to main menu.")
                return False

            domain_index = int(domain_choice) - 1
            if not (0 <= domain_index < len(domains_with_active)):
                print(f"{Colors.red('Invalid domain selection.')}")
                return False

            selected_domain = domains_with_active[domain_index][0]
            active_count = domains_with_active[domain_index][1]['active']

            # Get mailboxes for selected domain
            domain_mailboxes = [
                mb for mb in self.all_mailboxes
                if mb.get('active', False) and '@' in mb.get('email_address', '') and
                mb.get('email_address', '').split('@')[1].lower() == selected_domain
            ]

            print(f"\nDomain: {selected_domain} ({active_count:,} active mailboxes)")

            # Check if sampling is recommended
            if active_count > 2000:
                print(f"{Colors.yellow_bold('⚠️ WARNING: Domain has >2000 mailboxes! Sampling recommended.')}")
                print(f"\nSampling options for {selected_domain}:")
                print("1. Process all mailboxes (may impact performance)")
                print("2. Smart sampling (VIP priority + random)  ← recommended")
                print("3. Custom sample size")

                sample_choice = input(f"\n{Colors.blue('Select sampling option (1-3, or press Enter to cancel):')} ").strip()

                if not sample_choice:
                    print("Returning to main menu.")
                    return False

                if sample_choice == '1':
                    # Process all mailboxes
                    selected_mailboxes = domain_mailboxes
                elif sample_choice == '2':
                    # Smart sampling
                    selected_mailboxes = await self.smart_sample_domain(selected_domain, domain_mailboxes, 2000)
                elif sample_choice == '3':
                    # Custom sample size
                    try:
                        custom_size = int(input(f"Enter sample size (max {active_count}): "))
                        if custom_size <= 0 or custom_size > active_count:
                            print(f"{Colors.red('Invalid sample size.')}")
                            return False
                        selected_mailboxes = await self.smart_sample_domain(selected_domain, domain_mailboxes, custom_size)
                    except ValueError:
                        print(f"{Colors.red('Invalid input.')}")
                        return False
                else:
                    print(f"{Colors.red('Invalid selection.')}")
                    return False
            else:
                selected_mailboxes = domain_mailboxes

            # Confirm HIP job creation
            print(f"\n{Colors.bold('HIP Job Summary:')}")
            print(f"  Domain: {selected_domain}")
            print(f"  Mailboxes: {len(selected_mailboxes):,}")
            print(f"  Mode: HISTORICALLY_MATCH")

            confirm = input(f"\n{Colors.blue('Proceed with HIP job creation? (y/N, or press Enter to cancel):')} ").strip().lower()
            if confirm != 'y':
                print("Returning to main menu.")
                return False

            # Create HIP job
            try:
                print(f"\n{Colors.bold('Creating HIP job...')}")
                mailbox_ids = [mb['id'] for mb in selected_mailboxes]

                result = await self.api.create_hip_job(
                    message_source_id=self.selected_message_source_id,
                    mode="HISTORICALLY_MATCH",
                    mailbox_ids=mailbox_ids
                )

                print(f"{Colors.green_bold('HIP Job Created Successfully!')}")
                if 'id' in result:
                    print(f"  Job ID: {result['id']}")
                if 'status' in result:
                    print(f"  Status: {result['status']}")
                print(f"  Domain: {selected_domain}")
                print(f"  Mailboxes: {len(selected_mailboxes):,}")

                return True

            except Exception as e:
                print(f"{Colors.red('Failed to create HIP job:')} {str(e)}")
                return False

        except (ValueError, IndexError):
            print(f"{Colors.red('Invalid input.')}")
            return False

    async def hip_by_multiple_domains(self) -> bool:
        """Create HIP job for multiple domains."""
        print(f"\n{Colors.bold('=== HIP by Multiple Domains ===')}")
        print(f"{Colors.blue('This feature will be implemented in the next update.')}")
        return True

    async def hip_by_mailbox_count(self) -> bool:
        """Create HIP job for specific mailbox count."""
        print(f"\n{Colors.bold('=== HIP by Mailbox Count ===')}")
        print(f"{Colors.blue('This feature will be implemented in the next update.')}")
        return True

    async def hip_for_all_active(self) -> bool:
        """Create HIP job for all active mailboxes."""
        print(f"\n{Colors.bold('=== HIP for All Active Mailboxes ===')}")

        active_mailboxes = [mb for mb in self.all_mailboxes if mb.get('active', False)]
        active_count = len(active_mailboxes)

        print(f"\nFound {active_count:,} active mailboxes.")

        if active_count > 2000:
            print(f"{Colors.yellow_bold('⚠️ WARNING: You have more than 2,000 active mailboxes!')}")
            print(f"{Colors.yellow('Processing all mailboxes may impact system performance.')}")
            print(f"\nRecommendation: Use 'HIP by Domain' with sampling for better performance.")

            proceed = input(f"\n{Colors.blue('Do you want to proceed anyway? (y/N, or press Enter to cancel):')} ").strip().lower()
            if proceed != 'y':
                print("Returning to main menu.")
                return False

        # Confirm HIP job creation
        print(f"\n{Colors.bold('HIP Job Summary:')}")
        print(f"  Scope: All active mailboxes")
        print(f"  Mailboxes: {active_count:,}")
        print(f"  Mode: HISTORICALLY_MATCH")

        confirm = input(f"\n{Colors.blue('Proceed with HIP job creation? (y/N, or press Enter to cancel):')} ").strip().lower()
        if confirm != 'y':
            print("Returning to main menu.")
            return False

        # Create HIP job
        try:
            print(f"\n{Colors.bold('Creating HIP job...')}")

            result = await self.api.create_hip_job(
                message_source_id=self.selected_message_source_id,
                mode="HISTORICALLY_MATCH",
                active_mailboxes_only=True
            )

            print(f"{Colors.green_bold('HIP Job Created Successfully!')}")
            if 'id' in result:
                print(f"  Job ID: {result['id']}")
            if 'status' in result:
                print(f"  Status: {result['status']}")
            print(f"  Scope: All active mailboxes")
            print(f"  Mailboxes: {active_count:,}")

            return True

        except Exception as e:
            print(f"{Colors.red('Failed to create HIP job:')} {str(e)}")
            return False

    async def smart_sample_domain(self, domain: str, domain_mailboxes: List[Dict], sample_size: int) -> List[Dict]:
        """Smart sampling with VIP priority for domain-specific mailboxes."""
        print(f"\n{Colors.bold('Performing smart sampling...')}")

        if len(domain_mailboxes) <= sample_size:
            return domain_mailboxes

        # Get VIP users for this domain
        vip_mailboxes = await self.get_domain_vips(domain, domain_mailboxes)

        # Start with VIP users
        sampled_mailboxes = list(vip_mailboxes)
        remaining_slots = sample_size - len(vip_mailboxes)

        print(f"Found {len(vip_mailboxes)} VIP users in {domain}")

        if remaining_slots > 0:
            # Get non-VIP mailboxes for random sampling
            non_vip_mailboxes = [mb for mb in domain_mailboxes if mb not in vip_mailboxes]

            if non_vip_mailboxes:
                # Randomly sample from non-VIP mailboxes
                random_sample_size = min(remaining_slots, len(non_vip_mailboxes))
                random_sample = random.sample(non_vip_mailboxes, random_sample_size)
                sampled_mailboxes.extend(random_sample)

                print(f"Added {len(random_sample)} random mailboxes from {domain}")

        print(f"Total sample size: {len(sampled_mailboxes):,} mailboxes from {domain}")
        return sampled_mailboxes

    async def get_domain_vips(self, domain: str, domain_mailboxes: List[Dict]) -> List[Dict]:
        """Get VIP users for a specific domain."""
        try:
            # Get org VIPs from the API
            vip_emails, org_vips_id, vip_source_id = await self.get_org_vips()

            if not vip_emails:
                print(f"No org VIPs found")
                return []

            # Filter VIP emails to only those in the specified domain
            domain_vip_emails = [email for email in vip_emails if email.lower().endswith(f"@{domain.lower()}")]

            # Find matching mailboxes
            domain_vips = [
                mb for mb in domain_mailboxes
                if mb.get('email_address', '').lower() in [email.lower() for email in domain_vip_emails]
            ]

            return domain_vips

        except Exception as e:
            print(f"{Colors.yellow(f'Warning: Could not retrieve VIP users: {str(e)}')}")
            return []

    async def get_org_vips(self) -> Tuple[List[str], str, str]:
        """Get org VIP emails from the API (similar to hip-sampling logic)."""
        try:
            # Get user groups
            response = await self.api.make_request('GET', '/v1/lists', params={'list_types': 'user_group'})

            if not response:
                return [], "", ""

            # Find the org_vips group by name
            org_vips_group = next((group for group in response if group.get('name') == 'org_vips'), None)
            if not org_vips_group:
                return [], "", ""

            org_vips_id = org_vips_group['id']
            message_source_id = org_vips_group.get('message_source_id', "")

            # Get the VIP list entries
            vip_response = await self.api.make_request('GET', f'/v1/lists/{org_vips_id}')

            if not vip_response or 'entries' not in vip_response or vip_response['entries'] is None:
                return [], org_vips_id, message_source_id

            vip_emails = [entry['email'] for entry in vip_response['entries']]
            return vip_emails, org_vips_id, message_source_id

        except Exception as e:
            print(f"{Colors.yellow(f'Warning: Could not retrieve org VIPs: {str(e)}')}")
            return [], "", ""

    async def get_menu_option_counts(self) -> Dict[str, Dict[str, int]]:
        """Calculate counts for dynamic menu options."""
        total_mailboxes = len(self.all_mailboxes)
        active_mailboxes = len([mb for mb in self.all_mailboxes if mb.get('active', False)])
        inactive_mailboxes = len([mb for mb in self.all_mailboxes if not mb.get('active', False)])

        # Count domains with inactive/active mailboxes
        domains_with_inactive = len([domain for domain, counts in self.domains.items() if counts['inactive'] > 0])
        domains_with_active = len([domain for domain, counts in self.domains.items() if counts['active'] > 0])
        total_domains = len(self.domains)

        # Count user groups (cached only on menu display to avoid hanging)
        groups_available = 0
        groups_cached = False
        try:
            if hasattr(self.group_search, 'cached_groups') and self.group_search.cached_groups:
                groups_available = len(self.group_search.cached_groups)
                groups_cached = True
                if self.api.debug:
                    print(f"[DEBUG] Using cached groups: {groups_available}")
            else:
                # Don't fetch groups on menu display - assume available and fetch when user selects option
                # This prevents the menu from hanging while checking the user groups API
                # Set to -1 to indicate "not yet checked but likely available"
                groups_available = -1
                groups_cached = False
                if self.api.debug:
                    print(f"[DEBUG] User groups not cached, will check when selected")
        except Exception as e:
            # If group check fails, show as unavailable
            if self.api.debug:
                print(f"[DEBUG] User groups check failed: {str(e)}")
            groups_available = 0
            groups_cached = False

        return {
            'mailboxes': {
                'total': total_mailboxes,
                'active': active_mailboxes,
                'inactive': inactive_mailboxes
            },
            'domains': {
                'total': total_domains,
                'with_active': domains_with_active,
                'with_inactive': domains_with_inactive
            },
            'groups': {
                'available': groups_available,
                'cached': groups_cached
            }
        }

    def is_option_available(self, option_key: str, counts: Dict[str, Dict[str, int]]) -> bool:
        """Check if a menu option should be available based on data counts."""
        # For groups: -1 means "not yet checked but available", >0 means known count, 0 means unavailable
        groups_avail = counts.get('groups', {}).get('available', 0)
        groups_enabled = groups_avail != 0  # True if -1 (not checked) or >0 (known count)

        availability_rules = {
            'activate_all': counts['mailboxes']['inactive'] > 0,
            'activate_by_domain': counts['domains']['with_inactive'] > 0,
            'export_csv': counts['mailboxes']['total'] > 0,
            'import_csv': True,  # Always available
            'hip_jobs': counts['mailboxes']['active'] > 0,  # New HIP menu
            'activate_by_group': groups_enabled,  # New group activation
            'deactivate_by_domain': counts['domains']['with_active'] > 0,
            'deactivate_by_group': groups_enabled,  # New group deactivation
            'deactivate_all': counts['mailboxes']['active'] > 0,
            'export_all': counts['mailboxes']['total'] > 0,
            'export_active': counts['mailboxes']['active'] > 0,
            'export_inactive': counts['mailboxes']['inactive'] > 0,
            'export_by_domain': counts['domains']['total'] > 0
        }

        return availability_rules.get(option_key, True)

    def format_menu_option(self, option_text: str, count_text: str, available: bool) -> str:
        """Format a menu option with counts and availability styling."""
        if available:
            return f"{option_text} {Colors.blue(f'({count_text})')}"
        else:
            return Colors.gray(f"{option_text} ({count_text})")


async def main(args):
    """Main function to run the Mailbox Utility."""
    # Auto-update check now happens before main() is called

    try:
        # Region selection
        if args.base_url:
            candidate = args.base_url.strip().rstrip("/")
            if not candidate.lower().startswith(("http://", "https://")):
                print(f"{Colors.red('Invalid --base-url:')} must start with http:// or https://")
                return
            parsed = urlparse(candidate)
            if not parsed.netloc:
                print(f"{Colors.red('Invalid --base-url:')} missing hostname (e.g. https://prefix.platform.sublime.security)")
                return
            base_url = candidate
            print(f"{Colors.green('Using custom base URL:')} {base_url}")
        elif args.region:
            # Use specified region
            region_map = {
                'na-east': 'platform.sublime.security',
                'na-east-2': 'na-east-2.platform.sublime.security',
                'na-east-3': 'na-east-3.platform.sublime.security',
                'na-west': 'na-west.platform.sublime.security',
                'na-west-2': 'na-west-2.platform.sublime.security',
                'canada': 'ca.platform.sublime.security',
                'europe': 'eu.platform.sublime.security',
                'uk': 'uk.platform.sublime.security',
                'australia': 'au.platform.sublime.security'
            }

            hostname = region_map.get(args.region)
            if hostname:
                base_url = f"https://{hostname}"
                print(f"{Colors.green('Using specified region:')} {args.region} ({hostname})")
            else:
                print(f"{Colors.red('Invalid region specified:')} {args.region}")
                print(f"Available regions: {', '.join(region_map.keys())}")
                return
        else:
            # Interactive region selection
            regions = discover_sublime_regions(debug=args.debug, disable_region_lookup=args.disable_region_lookup)

            print(f"\nSelect a region for the platform:")
            for i, (display_name, hostname, base_url) in enumerate(regions, 1):
                print(f"{i}. {display_name} [{hostname}]")
            print(f"{len(regions) + 1}. Custom")

            while True:
                try:
                    choice = input(f"\nSelect region (1-{len(regions) + 1}): ").strip()

                    if choice == str(len(regions) + 1):  # Custom
                        custom_url = input("Enter custom base URL (e.g., https://custom.platform.sublime.security): ").strip()
                        if custom_url.startswith('http'):
                            base_url = custom_url.rstrip('/')
                            break
                        else:
                            print(f"{Colors.red('Please enter a valid URL starting with http:// or https://')}")
                    else:
                        index = int(choice) - 1
                        if 0 <= index < len(regions):
                            display_name, hostname, base_url = regions[index]
                            print(f"{Colors.green('Selected:')} {display_name}")
                            break
                        else:
                            print(f"{Colors.red('Invalid selection. Please choose 1-')}{len(regions) + 1}")

                except ValueError:
                    print(f"{Colors.red('Invalid input. Please enter a number.')}")
                except KeyboardInterrupt:
                    print(f"\n{Colors.yellow('Operation cancelled by user.')}")
                    return

        # Get API token
        api_token = os.environ.get('SUBLIME_API_TOKEN')
        if not api_token:
            api_token = getpass.getpass(f"{Colors.blue('Enter your Sublime Security API token:')} ")
            if not api_token:
                print(f"{Colors.red('API token is required.')}")
                return
        else:
            print(f"{Colors.green('Using API token from environment variable.')}")

        # Initialize API client and utility
        async with MailboxUtilityAPI(base_url, api_token, debug=args.debug) as api:
            print(f"\n{Colors.bold('Testing API connection...')}")

            if not await api.test_connection():
                print(f"{Colors.red('Failed to connect to the API. Please check your credentials and try again.')}")
                return

            print(f"{Colors.green('✓ API connection successful')}")

            # Initialize utility
            utility = MailboxUtility(api, base_url)

            if not await utility.initialize():
                return

            # Fetch all mailboxes
            if not await utility.fetch_all_mailboxes():
                return

            # Run interactive menu
            await utility.run_interactive_menu()

    except KeyboardInterrupt:
        print(f"\n{Colors.yellow('Operation cancelled by user.')}")
    except Exception as e:
        print(f"{Colors.red('Unexpected error:')} {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    # Parse arguments FIRST to check for --disable-auto-update flag
    parser = argparse.ArgumentParser(
        description='Mailbox Utility Script for comprehensive mailbox management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode with region discovery
  python mailbox-utility.py

  # Specify region directly
  python mailbox-utility.py --region na-east-2

  # Custom host (any {prefix}.platform.sublime.security or other deployment URL)
  python mailbox-utility.py --base-url https://na-east-4.platform.sublime.security

  # Enable debug mode
  python mailbox-utility.py --debug

  # Disable region discovery
  python mailbox-utility.py --disable-region-lookup
        """
    )

    region_group = parser.add_mutually_exclusive_group()
    region_group.add_argument(
        '--region',
        help='Specify the region directly',
        type=str
    )
    region_group.add_argument(
        '--base-url',
        dest='base_url',
        metavar='URL',
        help='Full API base URL (overrides region menu; e.g. https://eu.platform.sublime.security)',
        type=str
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode for detailed logging'
    )

    parser.add_argument(
        '--disable-region-lookup',
        action='store_true',
        help='Disable DNS region discovery and use only hardcoded regions'
    )

    parser.add_argument(
        '--disable-auto-update',
        action='store_true',
        help='Disable automatic git pull update check at startup'
    )

    args = parser.parse_args()

    # Check for updates BEFORE venv setup (may restart script entirely)
    # Only run auto-update if NOT already in venv (prevents double execution)
    if not is_virtual_env() and not args.disable_auto_update:
        check_for_updates_and_restart()

    # Setup virtual environment after auto-update check
    if not setup_virtual_environment():
        print("❌ Failed to setup virtual environment. Exiting.")
        sys.exit(1)

    # Install dependencies in virtual environment
    if not install_venv_dependencies():
        print("❌ Failed to install dependencies. Exiting.")
        sys.exit(1)

    # Run main with parsed args
    asyncio.run(main(args))
