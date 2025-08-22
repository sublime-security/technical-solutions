"""
API client for interacting with the Sublime Security API.
"""

import asyncio
from datetime import datetime, timedelta
import json
import logging
from typing import Dict, List, Optional, Any
import urllib.parse

import aiohttp
from aiohttp import ClientTimeout

from .data_models import MessageGroup, OrgStats, DateRange

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
        retry_delay: int = 1
    ):
        """
        Initialize the API client.
        
        Args:
            base_url: Base URL for the API
            api_key: API key for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Set up async context manager."""
        self.session = aiohttp.ClientSession(
            headers={
                "accept": "application/json",
                "authorization": f"Bearer {self.api_key}"
            },
            timeout=self.timeout
        )
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
                    try:
                        return await response.json()
                    except json.JSONDecodeError as e:
                        logger.error("Failed to parse JSON response")
                        raise APIError("Invalid JSON response from API")
                    
            except aiohttp.ClientError as e:
                attempt += 1
                if attempt == self.max_retries:
                    raise APIError(f"Request failed after {self.max_retries} attempts: {e}")
                
                await asyncio.sleep(self.retry_delay * attempt)
        
        raise APIError(f"Request failed after {self.max_retries} attempts")
    
    async def get_message_groups(
        self,
        date_range: DateRange,
        limit: int = 500
    ) -> List[MessageGroup]:
        """
        Fetch message groups from the API.
        
        Args:
            date_range: Date range to fetch messages for
            limit: Number of results per page
        
        Returns:
            List of message groups
        """
        endpoint = "/v1/messages/groups"
        params = {
            "created_at__gte": date_range.start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "flagged__eq": "true",
            "limit": limit,
            "offset": 0
        }
        
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
                
            logger.debug(f"Retrieved {len(groups)} groups on page {page}")
            
            # Convert API response to MessageGroup objects
            for group in groups:
                try:
                    # Extract and validate required fields
                    if not group.get("id"):
                        logger.warning("Skipping message group with missing ID")
                        continue

                    # Process flagged rules safely
                    flagged_rules = []
                    rule_severities = set()
                    for rule in (group.get("flagged_rules") or []):
                        if not rule:
                            continue
                        rule_meta = rule.get("rule_meta", {})
                        name = rule_meta.get("name", "")
                        severity = rule_meta.get("severity", "")
                        if name:
                            flagged_rules.append({"name": name, "severity": severity})
                        if severity:
                            rule_severities.add(severity)

                    message_group = MessageGroup(
                        id=group["id"],
                        created_at=datetime.fromisoformat(
                            group.get("first_created_at", datetime.now().isoformat()).replace('Z', '+00:00')
                        ),
                        attack_score_verdict=group.get("attack_score_verdict", ""),
                        asa_verdict=group.get("asa_verdict", ""),
                        classification=group.get("classification", ""),
                        review_status=group.get("review_status", ""),
                        review_label=group.get("review_label", ""),
                        review_comment=group.get("review_comment", ""),
                        subjects=group.get("subjects") or [],
                        sender_email_addresses=group.get("sender_email_addresses") or [],
                        recipient_count=len(group.get("recipients") or []),
                        message_count=group.get("number_of_messages_lower_bound", 0),
                        flagged_rules=flagged_rules,
                        rule_severities=list(rule_severities)
                    )
                    all_groups.append(message_group)
                except Exception as e:
                    logger.warning(f"Failed to process message group: {type(e).__name__}")
            
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
    
    async def fetch_all_data(self, date_range: DateRange) -> Dict[str, Any]:
        """
        Fetch all required data from the API in parallel.
        
        Args:
            date_range: Date range to fetch data for
        
        Returns:
            Dictionary containing message groups and org stats
        """
        try:
            logger.debug("Fetching message groups and org stats in parallel...")
            message_groups, org_stats = await asyncio.gather(
                self.get_message_groups(date_range),
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
