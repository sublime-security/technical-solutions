"""
API client for interacting with the Sublime Security API.
"""

import asyncio
from datetime import datetime, timedelta
import json
import logging
import random
from typing import Dict, List, Optional, Any, Tuple
import urllib.parse

import aiohttp
from aiohttp import ClientTimeout

from .data_models import MessageGroup, OrgStats, DateRange, UserReport, Message
from .rate_limiter import DynamicSemaphore, AdaptiveConcurrencyController

logger = logging.getLogger(__name__)

class APIError(Exception):
    """Base exception for API related errors."""
    pass

class RateLimitError(APIError):
    """Raised when API rate limit is hit."""
    pass

class AuthenticationError(APIError):
    """Raised when API authentication fails."""
    pass

class APIClient:
    """Client for interacting with the Sublime Security API."""
    
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: int = 1,
        initial_concurrency: int = 10,
        min_concurrency: int = 1,
        max_concurrency: int = 50
    ):
        """
        Initialize the API client.
        
        Args:
            base_url: Base URL for the API
            api_key: API key for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            initial_concurrency: Initial number of concurrent requests
            min_concurrency: Minimum concurrent requests allowed
            max_concurrency: Maximum concurrent requests allowed
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Initialize concurrency control
        self.adaptive_controller = AdaptiveConcurrencyController(
            initial_concurrency=initial_concurrency,
            min_concurrency=min_concurrency,
            max_concurrency=max_concurrency
        )
        self._semaphore: Optional[DynamicSemaphore] = None
    
    async def __aenter__(self):
        """Set up async context manager."""
        self.session = aiohttp.ClientSession(
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self.api_key}"
            },
            timeout=self.timeout
        )
        # Initialize semaphore
        self._semaphore = DynamicSemaphore(self.adaptive_controller.current_concurrency)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up async context manager."""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Make an API request with retry logic.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            params: Query parameters
            **kwargs: Additional arguments for the request
        
        Returns:
            API response data
        
        Raises:
            APIError: If the request fails after all retries
        """
        if not self.session:
            raise RuntimeError("API client must be used as an async context manager")
        
        url = f"{self.base_url}{endpoint}"
        attempt = 0
        
        logger.debug(f"Making {method} request to {url}")
        
        while attempt < self.max_retries:
            try:
                async with self.session.request(method, url, params=params, **kwargs) as response:
                    if response.status == 429:  # Rate limit
                        retry_after = int(response.headers.get('Retry-After', self.retry_delay))
                        logger.warning(f"Rate limit hit, waiting {retry_after} seconds")
                        await asyncio.sleep(retry_after)
                        attempt += 1
                        continue
                    
                    if response.status == 401:
                        raise AuthenticationError("Invalid API key")
                    
                    response.raise_for_status()
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Handle text/plain responses
                    if 'text/plain' in content_type:
                        return await response.text()
                    
                    # Handle JSON responses
                    try:
                        return await response.json()
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse JSON response. Content-Type: {content_type}")
                        raise APIError(f"Invalid JSON response from API (Content-Type: {content_type})")
                    
            except aiohttp.ClientError as e:
                attempt += 1
                if attempt == self.max_retries:
                    raise APIError(f"Request failed after {self.max_retries} attempts: {e}")
                
                await asyncio.sleep(self.retry_delay * attempt)
        
        raise APIError(f"Request failed after {self.max_retries} attempts")
    
    async def get_asa_reports_batch(self, message_ids: List[str], batch_size: int = 25) -> Dict[str, str]:
        """
        Fetch ASA report final verdicts for multiple messages in batches.
        
        Args:
            message_ids: List of message IDs to fetch ASA reports for
            batch_size: Size of each batch (default 25)
            
        Returns:
            Dictionary mapping message IDs to their ASA verdicts
        """
        if not self._semaphore:
            raise RuntimeError("API client must be used as an async context manager")
        
        results: Dict[str, str] = {}
        total_count = len(message_ids)
        successful_count = 0
        
        # Process in batches
        for i in range(0, len(message_ids), batch_size):
            batch = message_ids[i:i + batch_size]
            tasks = []
            
            # Create tasks for each message in the batch
            for msg_id in batch:
                tasks.append(self._get_single_asa_report(msg_id))
            
            # Execute batch
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for msg_id, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.warning(f"Failed to fetch ASA report for message {msg_id}: {type(result).__name__} - {str(result)}")
                    if isinstance(result, RateLimitError):
                        self.adaptive_controller.record_error("rate_limit")
                    else:
                        self.adaptive_controller.record_error("unknown")
                else:
                    results[msg_id] = result
                    successful_count += 1
                    self.adaptive_controller.record_success()
            
            # Log progress
            progress = (i + len(batch)) / total_count * 100
            logger.debug(f"ASA Report batch progress: {progress:.1f}% ({successful_count}/{total_count} successful)")
            
            # Check if we need to adjust concurrency
            new_concurrency = self.adaptive_controller.current_concurrency
            if self._semaphore and new_concurrency != self._semaphore.current_limit:
                logger.debug(f"Adjusting ASA concurrency: {self._semaphore.current_limit} -> {new_concurrency}")
                self._semaphore.adjust_to(new_concurrency)
        
        logger.info(f"ASA Report batch completed: {successful_count}/{total_count} successful ({(successful_count/total_count)*100:.1f}%)")
        return results

    async def _get_single_asa_report(self, message_id: str) -> str:
        """
        Fetch ASA report for a single message with rate limiting.
        
        Args:
            message_id: Message ID to fetch ASA report for
            
        Returns:
            ASA verdict string
            
        Raises:
            Exception if the request fails
        """
        if not self._semaphore:
            raise RuntimeError("API client must be used as an async context manager")
        
        async with self._semaphore:
            # Step 1: Set justification to access message contents
            logger.debug(f"Setting justification for message access: {message_id}")
            justification_payload = {
                "justification": "Automated ASA verdict retrieval for security analysis and reporting"
            }
            await self._make_request(
                'POST',
                f'/v0/messages/{message_id}/justification',
                json=justification_payload,
                headers={'Content-Type': 'application/json'}
            )
            
            # Step 2: Call ASA report endpoint
            logger.debug(f"Fetching ASA report for message: {message_id}")
            response = await self._make_request('GET', f'/v0/messages/{message_id}/asa-report')
            
            if response and isinstance(response, dict):
                # Log full response for debugging
                logger.debug(f"ASA report response for {message_id}: {json.dumps(response, indent=2)}")
                
                verdict = response.get('final_verdict', '')
                if not verdict:
                    logger.warning(f"No final_verdict in ASA report for message {message_id}")
                    # Check if verdict is in a different field
                    if 'verdict' in response:
                        verdict = response['verdict']
                        logger.debug(f"Found verdict in 'verdict' field instead: {verdict}")
                    elif 'asa_verdict' in response:
                        verdict = response['asa_verdict']
                        logger.debug(f"Found verdict in 'asa_verdict' field instead: {verdict}")
                else:
                    logger.debug(f"Got ASA verdict for message {message_id}: {verdict}")
                return verdict
            
            return ""

    async def get_message_groups(
        self,
        date_range: DateRange,
        limit: int = 500,
        fetch_asa_verdicts: bool = True,
        ignore_ids: Optional[List[str]] = None
    ) -> List[MessageGroup]:
        """
        Fetch message groups from the API.
        
        Args:
            date_range: Date range to fetch messages for
            limit: Number of results per page
            fetch_asa_verdicts: Whether to fetch ASA verdicts for each message
        
        Returns:
            List of message groups
        """
        endpoint = "/v1/messages/groups"
        params = {
            "created_at__gte": date_range.start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "created_at__lte": date_range.end.strftime("%Y-%m-%dT%H:%M:%S.999Z"),
            "flagged__eq": "true",
            "limit": limit,
            "offset": 0
        }
        logger.debug(f"Fetching messages between {date_range.start} and {date_range.end}")
        
        all_groups = []
        has_more = True
        
        page = 1
        while has_more:
            logger.debug(f"Fetching page {page} (offset: {params['offset']}, limit: {params['limit']})")
            data = await self._make_request("GET", endpoint, params=params)
            
            if data is None:
                logger.error("Received null response from API")
                break
                
            groups = data.get("message_groups")
            if groups is None:
                logger.error("Response missing 'message_groups' key")
                break
                
            if not groups:
                logger.info("No more message groups to fetch")
                break
                
            logger.info(f"Retrieved {len(groups)} groups on page {page}")
            
            # Count user-reported groups (must have user_reports with non-empty reporter)
            user_reported_groups = [
                g for g in groups 
                if g.get("user_reports") and 
                any(report.get("reporter") for report in g.get("user_reports", []))
            ]
            user_reported_count = len(user_reported_groups)
            
            if user_reported_count > 0:
                logger.info(f"Found {user_reported_count} user-reported groups on this page")
                for group in user_reported_groups:
                    logger.debug(
                        f"Group {group['id']} has {len(group['user_reports'])} reports: " + 
                        ", ".join(f"{r.get('reporter', 'unknown')} ({r.get('channel', 'unknown')})" 
                                for r in group['user_reports'])
                    )
            
            # Track ignored groups for logging
            ignored_count = 0
            ignored_with_reports = 0
            
            # Convert API response to MessageGroup objects
            for group in groups:
                try:
                    # Extract and validate required fields
                    group_id = group.get("id")
                    if not group_id:
                        logger.warning("Skipping message group with missing ID")
                        continue
                        
                    # Skip if in ignore list
                    if ignore_ids and group_id in ignore_ids:
                        ignored_count += 1
                        
                        # Log details about ignored group
                        user_reports = group.get("user_reports", [])
                        if user_reports:
                            ignored_with_reports += 1
                            reporters = [r.get("reporter") for r in user_reports if r.get("reporter")]
                            logger.info(
                                f"Skipping ignored group {group_id} with {len(user_reports)} reports "
                                f"from: {', '.join(reporters)}"
                            )
                        else:
                            logger.debug(f"Skipping ignored group {group_id} (no user reports)")
                        continue

                    # Process flagged rules safely
                    flagged_rules = []
                    rule_severities = set()
                    attack_types = set()
                    tactics_and_techniques = set()
                    detection_methods = set()
                    
                    logger.debug(f"Processing flagged rules for group {group['id']}")
                    for rule in (group.get("flagged_rules") or []):
                        if not rule:
                            continue
                        rule_meta = rule.get("rule_meta", {})
                        logger.debug(f"Rule meta: {json.dumps(rule_meta, indent=2)}")
                        name = rule_meta.get("name", "")
                        severity = rule_meta.get("severity", "")
                        
                        # Extract attack types, tactics, and detection methods - only if explicitly set
                        if rule_meta.get("attack_types"):
                            attack_types.update(rule_meta["attack_types"])
                            logger.debug(f"Group {group['id']}: Found attack types in rule {name}: {rule_meta['attack_types']}")
                        else:
                            logger.debug(f"Group {group['id']}: Rule {name} has no attack types")
                        
                        if rule_meta.get("tactics_and_techniques"):
                            tactics_and_techniques.update(rule_meta["tactics_and_techniques"])
                            logger.debug(f"Group {group['id']}: Found tactics in rule {name}: {rule_meta['tactics_and_techniques']}")
                        else:
                            logger.debug(f"Group {group['id']}: Rule {name} has no tactics")
                        
                        if rule_meta.get("detection_methods"):
                            detection_methods.update(rule_meta["detection_methods"])
                            logger.debug(f"Group {group['id']}: Found detection methods in rule {name}: {rule_meta['detection_methods']}")
                        else:
                            logger.debug(f"Group {group['id']}: Rule {name} has no detection methods")
                        
                        if name:
                            flagged_rules.append({
                                "name": name,
                                "severity": severity,
                                "attack_types": rule_meta.get("attack_types", []),
                                "tactics_and_techniques": rule_meta.get("tactics_and_techniques", [])
                            })
                        if severity:
                            rule_severities.add(severity)

                    # Process user reports
                    user_reports = []
                    reports_data = group.get("user_reports")
                    if reports_data:  # Changed from is not None to truthiness check
                        logger.info(f"Found user_reports in group {group['id']}")
                        for report in reports_data:
                            try:
                                reporter = report.get("reporter", "")
                                if reporter:
                                    logger.info(
                                        f"Processing report in group {group['id']}: "
                                        f"reporter={reporter}, channel={report.get('channel')}"
                                    )
                                    user_reports.append(UserReport(
                                        reporter=reporter,
                                        channel=report.get("channel", ""),
                                        reported_at=datetime.fromisoformat(
                                            report.get("reported_at", datetime.now().isoformat()).replace('Z', '+00:00')
                                        ),
                                        reported_by_message_id=report.get("reported_by_message_id", "")
                                    ))
                                else:
                                    logger.warning(f"Found report without reporter in group {group['id']}")
                            except Exception as e:
                                logger.error(
                                    f"Failed to process user report in group {group['id']}: "
                                    f"{type(e).__name__} - {str(e)}"
                                )
                                continue

                    # Process ASA verdict with deduplication
                    asa_verdict = group.get("asa_verdict", "")
                    if asa_verdict:
                        logger.debug(f"Processing ASA verdict: {asa_verdict}")
                        # Define severity ranking (lower index = higher severity)
                        severity_ranking = [
                            'malicious',
                            'spam', 
                            'graymail',
                            'benign',
                            'likely_benign',
                            'unknown'
                        ]
                        
                        # Split by semicolon and normalize verdicts
                        verdicts = [v.strip().lower() for v in asa_verdict.split(';') if v.strip()]
                        
                        if verdicts:
                            # Find the highest severity verdict
                            highest_severity_index = float('inf')
                            highest_verdict = ''
                            
                            for verdict in verdicts:
                                try:
                                    severity_index = severity_ranking.index(verdict)
                                    if severity_index < highest_severity_index:
                                        highest_severity_index = severity_index
                                        highest_verdict = verdict
                                except ValueError:
                                    # Unknown verdict type - treat as lowest priority
                                    if highest_severity_index == float('inf'):
                                        highest_verdict = verdict  # Use unknown verdict if nothing else found
                            
                            asa_verdict = highest_verdict.capitalize() if highest_verdict else ''
                            logger.debug(f"Selected highest severity ASA verdict: {asa_verdict} (from {verdicts})")

                    # Process messages in the group and fetch ASA verdicts
                    messages = []
                    message_ids = []
                    
                    # Check if this is a user-reported group
                    is_user_reported = any(report.reporter for report in user_reports)
                    
                    if "previews" in group:
                        # Only log preview data for user-reported groups
                        if is_user_reported:
                            logger.debug(f"Processing user-reported group {group['id']} ({len(group.get('previews', []))} messages)")
                        
                        # For user-reported groups, sample up to 5 messages for ASA verdicts
                        sample_size = 5
                        previews = group.get("previews", [])
                        
                        # Process all messages first
                        for preview in previews:
                            message_id = preview.get("id")
                            if message_id:
                                message = Message(id=message_id)
                                messages.append(message)
                        
                        # Then handle ASA verdict sampling for user-reported messages
                        if fetch_asa_verdicts and is_user_reported:
                            # Take up to sample_size random messages
                            sampled_messages = random.sample(messages, min(sample_size, len(messages)))
                            for message in sampled_messages:
                                message_ids.append(message.id)
                                logger.debug(f"Added message {message.id} to ASA fetch list (sampled) for group {group['id']}")
                        
                        # Fetch ASA verdicts in batches if enabled and this is a user-reported group
                        if fetch_asa_verdicts and is_user_reported and message_ids:
                            #logger.debug(f"Group {group['id']}: Fetching ASA verdicts for {len(message_ids)} messages")
                            asa_verdicts = await self.get_asa_reports_batch(message_ids)
                            
                            # Log verdict counts
                            verdict_counts = {}
                            for verdict in asa_verdicts.values():
                                if verdict:
                                    verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                            logger.debug(f"Group {group['id']}: ASA verdict distribution: {verdict_counts}")
                            
                            # Update messages with verdicts and determine group verdict
                            severity_ranking = [
                                'malicious',
                                'spam', 
                                'graymail',
                                'benign',
                                'likely_benign',
                                'unknown'
                            ]
                            
                            # First, update all messages with their verdicts
                            for message in messages:
                                verdict = asa_verdicts.get(message.id, "")
                                message.asa_verdict = verdict
                                #logger.debug(f"Group {group['id']}, Message {message.id}: ASA verdict = '{verdict}'")
                            
                            # Then, analyze sampled verdicts to determine group verdict
                            sampled_verdicts = [v.lower() for v in asa_verdicts.values() if v]
                            if sampled_verdicts:
                                # If all verdicts match, use that verdict
                                if len(set(sampled_verdicts)) == 1:
                                    group_verdict = sampled_verdicts[0]
                                    logger.debug(f"Group {group['id']}: All sampled verdicts match: {group_verdict}")
                                else:
                                    # Otherwise, take highest severity verdict
                                    highest_severity_index = float('inf')
                                    group_verdict = ''
                                    
                                    for verdict in sampled_verdicts:
                                        try:
                                            severity_index = severity_ranking.index(verdict)
                                            if severity_index < highest_severity_index:
                                                highest_severity_index = severity_index
                                                group_verdict = verdict
                                        except ValueError:
                                            if highest_severity_index == float('inf'):
                                                group_verdict = verdict
                                    
                                    logger.debug(f"Group {group['id']}: Mixed verdicts, using highest severity: {group_verdict} (from {sampled_verdicts})")
                                
                                # Update all messages in the group with the determined verdict
                                for message in messages:
                                    if not message.asa_verdict:  # Only update messages that weren't sampled
                                        message.asa_verdict = group_verdict.capitalize()
                                        logger.debug(f"Group {group['id']}, Message {message.id}: Assigned group verdict = '{group_verdict}'")
                    
                    message_group = MessageGroup(
                        id=group["id"],
                        created_at=datetime.fromisoformat(
                            group.get("first_created_at", datetime.now().isoformat()).replace('Z', '+00:00')
                        ),
                        attack_score_verdict=group.get("attack_score_verdict", ""),
                        classification=group.get("classification", ""),
                        review_status=group.get("review_status", ""),
                        review_label=group.get("review_label", ""),
                        review_comment=group.get("review_comment", ""),
                        subjects=group.get("subjects") or [],
                        sender_email_addresses=group.get("sender_email_addresses") or [],
                        recipient_count=len(group.get("recipients") or []),
                        message_count=group.get("number_of_messages_lower_bound", 0),
                        flagged_rules=flagged_rules,
                        rule_severities=list(rule_severities),
                        attack_types=list(attack_types),
                        tactics_and_techniques=list(tactics_and_techniques),
                        detection_methods=list(detection_methods),
                        user_reports=user_reports,
                        messages=messages
                    )
                    all_groups.append(message_group)
                except Exception as e:
                    logger.warning(f"Failed to process message group {group.get('id', 'unknown')}: {type(e).__name__} - {str(e)}")
                    if isinstance(e, TypeError):
                        logger.debug("Stack trace:", exc_info=True)
            
            # Log summary of ignored groups for this page
            if ignored_count > 0:
                logger.info(
                    f"Page {page}: Ignored {ignored_count} groups "
                    f"({ignored_with_reports} with user reports)"
                )
            
            # Update pagination
            params["offset"] += limit
            page += 1
            has_more = len(groups) == limit
        
        return all_groups
    
    async def get_org_stats(self, date_range: DateRange) -> OrgStats:
        """
        Fetch organization statistics from the API.
        
        Args:
            date_range: Date range to fetch stats for
        
        Returns:
            Organization statistics
        """
        endpoint = "/v1/stats/org"
        params = {
            "from": date_range.start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "to": date_range.end.strftime("%Y-%m-%dT%H:%M:%S.999Z")
        }
        
        data = await self._make_request("GET", endpoint, params=params)
        
        return OrgStats(
            messages_processed_count=data.get("messages_processed_count", 0),
            active_mailbox_count=data.get("active_mailbox_count", 0),
            active_detection_rule_count=data.get("active_detection_rule_count", 0)
        )
    
    async def fetch_all_data(
        self,
        date_range: DateRange,
        fetch_asa_verdicts: bool = True,
        ignore_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Fetch all required data from the API in parallel.
        
        Args:
            date_range: Date range to fetch data for
            fetch_asa_verdicts: Whether to fetch ASA verdicts for each message
        
        Returns:
            Dictionary containing message groups and org stats
        """
        try:
            logger.debug("Fetching message groups and org stats in parallel...")
            message_groups, org_stats = await asyncio.gather(
                self.get_message_groups(
                    date_range,
                    fetch_asa_verdicts=fetch_asa_verdicts,
                    ignore_ids=ignore_ids
                ),
                self.get_org_stats(date_range)
            )
            
            logger.debug(f"Retrieved {len(message_groups) if message_groups else 0} message groups")
            logger.debug(f"Active mailboxes: {org_stats.active_mailbox_count if org_stats else 0}")
            logger.debug(f"Active detection rules: {org_stats.active_detection_rule_count if org_stats else 0}")
            
            return {
                "message_groups": message_groups,
                "org_stats": org_stats
            }
        except TypeError as e:
            # Handle specific case of None values
            logger.error(f"Data processing error: {str(e).split(':', 1)[0]}")
            return None
        except Exception as e:
            logger.error(f"Error fetching data: {type(e).__name__} - {str(e)}")
            return None
