"""
Rate limiting and concurrency control for API requests.
"""

import asyncio
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class DynamicSemaphore:
    """A semaphore that can be dynamically adjusted."""
    
    def __init__(self, initial_value: int):
        """Initialize the semaphore with an initial value."""
        self._semaphore = asyncio.Semaphore(initial_value)
        self.current_limit = initial_value
    
    async def __aenter__(self):
        """Enter the async context manager."""
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit the async context manager."""
        self.release()
    
    async def acquire(self):
        """Acquire a permit."""
        await self._semaphore.acquire()
    
    def release(self):
        """Release a permit."""
        self._semaphore.release()
    
    def adjust_to(self, new_limit: int):
        """
        Adjust semaphore to new limit by adding/removing permits.
        
        Args:
            new_limit: New maximum concurrent operations
        """
        if new_limit > self.current_limit:
            # Add permits
            for _ in range(new_limit - self.current_limit):
                self._semaphore.release()
        elif new_limit < self.current_limit:
            # Remove permits by acquiring them
            async def remove_permits():
                for _ in range(self.current_limit - new_limit):
                    await self._semaphore.acquire()
            asyncio.create_task(remove_permits())
        
        self.current_limit = new_limit

class AdaptiveConcurrencyController:
    """
    Adaptive concurrency controller that dynamically adjusts concurrent request limits
    based on error rates and response times.
    """
    
    def __init__(
        self,
        initial_concurrency: int = 10,
        min_concurrency: int = 1,
        max_concurrency: int = 50
    ):
        """
        Initialize the controller.
        
        Args:
            initial_concurrency: Starting concurrent request limit
            min_concurrency: Minimum concurrent requests allowed
            max_concurrency: Maximum concurrent requests allowed
        """
        self.current_concurrency = initial_concurrency
        self.min_concurrency = min_concurrency
        self.max_concurrency = max_concurrency
        
        # Track error counts
        self.error_counts: Dict[str, int] = {
            "rate_limit": 0,
            "server_error": 0,
            "timeout": 0,
            "client_error": 0,
            "unknown": 0
        }
        self.total_requests = 0
    
    def record_success(self):
        """Record a successful request."""
        self.total_requests += 1
        
        # If we're doing well, gradually increase concurrency
        if self.total_requests % 100 == 0:  # Check every 100 requests
            error_rate = sum(self.error_counts.values()) / self.total_requests
            if error_rate < 0.01:  # Less than 1% errors
                self._increase_concurrency("Low error rate")
    
    def record_error(self, error_type: str):
        """
        Record an error of the specified type.
        
        Args:
            error_type: Type of error ("rate_limit", "server_error", "timeout", "client_error", "unknown")
        """
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        self.total_requests += 1
        
        # Check if we need to adjust concurrency
        self._adjust_for_errors()
    
    def _adjust_for_errors(self):
        """Adjust concurrency based on error patterns."""
        if self.total_requests < 10:
            return  # Not enough data
            
        # Check rate limits
        if self.error_counts["rate_limit"] > 0:
            rate_limit_ratio = self.error_counts["rate_limit"] / self.total_requests
            if rate_limit_ratio > 0.1:  # More than 10% rate limits
                self._decrease_concurrency("High rate limiting", factor=0.5)
            elif rate_limit_ratio > 0.05:  # More than 5% rate limits
                self._decrease_concurrency("Moderate rate limiting", factor=0.8)
        
        # Check other errors
        total_error_ratio = sum(self.error_counts.values()) / self.total_requests
        if total_error_ratio > 0.2:  # More than 20% errors
            self._decrease_concurrency("High error rate", factor=0.7)
    
    def _increase_concurrency(self, reason: str):
        """
        Attempt to increase concurrency.
        
        Args:
            reason: Reason for the increase
        """
        if self.current_concurrency < self.max_concurrency:
            new_concurrency = min(
                self.max_concurrency,
                self.current_concurrency + max(1, self.current_concurrency // 4)
            )
            if new_concurrency != self.current_concurrency:
                logger.debug(
                    f"Increasing concurrency from {self.current_concurrency} to {new_concurrency} "
                    f"({reason})"
                )
                self.current_concurrency = new_concurrency
    
    def _decrease_concurrency(self, reason: str, factor: float = 0.8):
        """
        Decrease concurrency by the specified factor.
        
        Args:
            reason: Reason for the decrease
            factor: Multiplication factor (0.8 = reduce to 80%)
        """
        new_concurrency = max(
            self.min_concurrency,
            int(self.current_concurrency * factor)
        )
        if new_concurrency != self.current_concurrency:
            logger.debug(
                f"Decreasing concurrency from {self.current_concurrency} to {new_concurrency} "
                f"({reason})"
            )
            self.current_concurrency = new_concurrency
