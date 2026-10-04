"""
Simple in-memory sliding-window rate limiter.
Note: If this app scales to multiple server instances, this in-memory
approach won't share state across instances and should be replaced
with a shared store (such as Redis) at that point.
"""

import time
from typing import Dict, List
from fastapi import Request, HTTPException, status
from app.utils.logger import setup_logger

logger = setup_logger(__name__)

# Storage format: { rate_limit_key: [timestamp1, timestamp2, ...] }
_REQUEST_TIMESTAMPS: Dict[str, List[float]] = {}


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """
    Check if a key has exceeded max_requests within window_seconds.
    Returns True if allowed, False if limit exceeded.
    """
    allowed, _ = check_rate_limit_with_retry(key, max_requests, window_seconds)
    return allowed


def check_rate_limit_with_retry(key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
    """
    Check rate limit and calculate retry-after seconds if exceeded.
    Returns (True, 0) if allowed, or (False, retry_after_seconds) if exceeded.
    """
    now = time.time()
    cutoff = now - window_seconds

    # Retrieve existing timestamps or initialize
    timestamps = _REQUEST_TIMESTAMPS.get(key, [])

    # Filter out timestamps older than the window (sliding window cleanup)
    timestamps = [ts for ts in timestamps if ts > cutoff]

    if len(timestamps) >= max_requests:
        _REQUEST_TIMESTAMPS[key] = timestamps
        retry_after = max(1, int(timestamps[0] + window_seconds - now))
        return False, retry_after

    timestamps.append(now)
    _REQUEST_TIMESTAMPS[key] = timestamps
    return True, 0


def get_client_ip(request: Request) -> str:
    """Extract real client IP from request headers or direct client host."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # First IP in X-Forwarded-For is the client IP
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


def rate_limit(max_requests: int = 10, window_seconds: int = 60):
    """
    FastAPI dependency factory for rate limiting by client IP.
    Returns HTTP 429 with Retry-After header when exceeded.
    """
    async def dependency(request: Request):
        client_ip = get_client_ip(request)
        rate_key = f"{request.url.path}:{client_ip}"
        
        allowed, retry_after = check_rate_limit_with_retry(rate_key, max_requests, window_seconds)
        if not allowed:
            logger.warning(f"Rate limit exceeded for IP {client_ip} on {request.url.path} (retry in {retry_after}s)")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Please try again in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)}
            )

    return dependency
