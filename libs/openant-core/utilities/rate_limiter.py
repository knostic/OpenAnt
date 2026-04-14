"""
Process-level rate limiter with coordinated backoff.

When any worker hits a 429 rate limit error, ALL workers pause for a
configurable backoff period (default 30s). This prevents thundering herd
and ensures the rate limit window has time to reset.

Usage:
    from utilities.rate_limiter import get_rate_limiter, configure_rate_limiter

    # At startup (once)
    configure_rate_limiter(backoff_seconds=30)

    # Before every API call
    rate_limiter = get_rate_limiter()
    rate_limiter.wait_if_needed()

    # When catching RateLimitError
    except anthropic.RateLimitError as e:
        retry_after = float(e.response.headers.get("retry-after", 0))
        rate_limiter.report_rate_limit(retry_after)
        raise
"""

import random
import sys
import threading
import time


class GlobalRateLimiter:
    """
    Singleton rate limiter with coordinated backoff across all threads.

    When any thread reports a rate limit error, all threads pause until
    the backoff period expires. This ensures the organization-wide rate
    limit window has time to reset.
    """

    _instance = None
    _init_lock = threading.Lock()

    def __new__(cls, backoff_seconds: float = 30.0):
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._lock = threading.Lock()
                    instance._backoff_until = 0.0
                    instance._backoff_seconds = backoff_seconds
                    instance._total_waits = 0
                    instance._total_wait_time = 0.0
                    cls._instance = instance
        return cls._instance

    @property
    def backoff_seconds(self) -> float:
        return self._backoff_seconds

    @backoff_seconds.setter
    def backoff_seconds(self, value: float):
        self._backoff_seconds = value

    def wait_if_needed(self) -> float:
        """
        Block if currently in a backoff period.

        Call this before every API request. Returns the time waited (0 if none).
        """
        with self._lock:
            now = time.monotonic()
            if now >= self._backoff_until:
                return 0.0

            wait_time = self._backoff_until - now
            # Add jitter (0-2s) to prevent thundering herd when backoff expires
            jitter = random.uniform(0, 2.0)
            total_wait = wait_time + jitter

        # Sleep outside the lock so other threads can also read backoff_until
        time.sleep(total_wait)

        with self._lock:
            self._total_waits += 1
            self._total_wait_time += total_wait

        return total_wait

    def report_rate_limit(self, retry_after: float | None = None):
        """
        Report a rate limit error and trigger global backoff.

        Call this when any worker receives a 429 error. All workers will
        pause until the backoff period expires.

        Args:
            retry_after: The retry-after header value from the API response.
                If provided, uses max(retry_after, backoff_seconds).
        """
        with self._lock:
            # Use the larger of retry_after and our configured backoff
            backoff = max(retry_after or 0.0, self._backoff_seconds)
            new_backoff_until = time.monotonic() + backoff

            # Only extend if this is later than current backoff
            if new_backoff_until > self._backoff_until:
                self._backoff_until = new_backoff_until
                print(
                    f"[RateLimiter] Global backoff triggered: {backoff:.0f}s",
                    file=sys.stderr,
                    flush=True,
                )

    def is_in_backoff(self) -> bool:
        """Check if currently in a backoff period (for diagnostics)."""
        with self._lock:
            return time.monotonic() < self._backoff_until

    def time_until_ready(self) -> float:
        """Seconds until backoff expires (0 if not in backoff)."""
        with self._lock:
            remaining = self._backoff_until - time.monotonic()
            return max(0.0, remaining)

    def get_stats(self) -> dict:
        """Get statistics about rate limiting (for diagnostics)."""
        with self._lock:
            return {
                "total_waits": self._total_waits,
                "total_wait_time": round(self._total_wait_time, 2),
                "backoff_seconds": self._backoff_seconds,
                "currently_in_backoff": time.monotonic() < self._backoff_until,
            }

    def reset(self):
        """Reset backoff state. For testing."""
        with self._lock:
            self._backoff_until = 0.0
            self._total_waits = 0
            self._total_wait_time = 0.0


# Module-level singleton access
_rate_limiter: GlobalRateLimiter | None = None
_config_lock = threading.Lock()


def configure_rate_limiter(backoff_seconds: float = 30.0) -> GlobalRateLimiter:
    """
    Configure the global rate limiter. Call once at startup.

    Args:
        backoff_seconds: How long to pause all workers on rate limit (default: 30s).

    Returns:
        The configured GlobalRateLimiter singleton.
    """
    global _rate_limiter
    with _config_lock:
        if _rate_limiter is None:
            _rate_limiter = GlobalRateLimiter(backoff_seconds)
        else:
            _rate_limiter.backoff_seconds = backoff_seconds
        return _rate_limiter


def get_rate_limiter() -> GlobalRateLimiter:
    """
    Get the global rate limiter singleton.

    If not configured, creates one with default settings (30s backoff).
    """
    global _rate_limiter
    if _rate_limiter is None:
        with _config_lock:
            if _rate_limiter is None:
                _rate_limiter = GlobalRateLimiter(30.0)
    return _rate_limiter


def reset_rate_limiter():
    """Reset the rate limiter singleton. For testing."""
    global _rate_limiter
    with _config_lock:
        if _rate_limiter is not None:
            _rate_limiter.reset()


def is_rate_limit_error(error_info: dict | str | None) -> bool:
    """
    Check if an error dict/string represents a rate limit error.

    Args:
        error_info: The error field from agent_context or similar.

    Returns:
        True if this is a rate limit error that should be retried.
    """
    if not error_info:
        return False
    if isinstance(error_info, dict):
        return error_info.get("type") == "rate_limit"
    return "rate_limit" in str(error_info).lower()


def is_retryable_error(error_info: dict | str | None) -> bool:
    """
    Check if an error is retryable (transient network/server issues).

    Retryable errors include:
    - rate_limit: API rate limiting (429)
    - connection: Network connectivity issues
    - timeout: Request timeout
    - api_status with 500+: Server errors (not client errors like 400)

    Args:
        error_info: The error field from agent_context or similar.

    Returns:
        True if this error should be retried.
    """
    if not error_info:
        return False
    
    if isinstance(error_info, dict):
        error_type = error_info.get("type", "")
        
        # Always retry these transient error types
        if error_type in ("rate_limit", "connection", "timeout"):
            return True
        
        # Retry server errors (5xx), but not client errors (4xx)
        if error_type == "api_status":
            status_code = error_info.get("status_code", 0)
            return status_code >= 500
        
        return False
    
    # String-based error checking
    error_str = str(error_info).lower()
    return any(term in error_str for term in (
        "rate_limit", "connection", "timeout", "500", "502", "503", "504"
    ))
