"""
Rate Limiting Middleware

Per-user rate limiting using Redis (in-memory fallback for development).
"""

from __future__ import annotations

import time
from typing import Optional, Callable
from collections import defaultdict
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-user rate limiting middleware
    
    Limits requests based on user ID (from JWT token) or IP address.
    Uses in-memory storage (can be upgraded to Redis).
    """
    
    def __init__(
        self,
        app,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_size: int = 10,
    ):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_size = burst_size
        
        # In-memory storage (replace with Redis in production)
        self._minute_buckets: dict[str, list[float]] = defaultdict(list)
        self._hour_buckets: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()
    
    def _get_client_id(self, request: Request) -> str:
        """Get client identifier from request"""
        # Try to get user ID from Authorization header
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            # Extract user ID from token (simplified - in production decode JWT)
            return f"user:{auth_header[7:20]}"  # Use first 20 chars as identifier
        
        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"
    
    def _cleanup_old_entries(self) -> None:
        """Cleanup old entries periodically"""
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        
        self._last_cleanup = now
        
        # Cleanup minute buckets (keep last 60 seconds)
        cutoff_minute = now - 60
        for key in list(self._minute_buckets.keys()):
            self._minute_buckets[key] = [
                t for t in self._minute_buckets[key] if t > cutoff_minute
            ]
            if not self._minute_buckets[key]:
                del self._minute_buckets[key]
        
        # Cleanup hour buckets (keep last 3600 seconds)
        cutoff_hour = now - 3600
        for key in list(self._hour_buckets.keys()):
            self._hour_buckets[key] = [
                t for t in self._hour_buckets[key] if t > cutoff_hour
            ]
            if not self._hour_buckets[key]:
                del self._hour_buckets[key]
    
    def _check_rate_limit(self, client_id: str) -> tuple[bool, Optional[str]]:
        """
        Check if client has exceeded rate limit
        
        Returns:
            (allowed, retry_after_seconds)
        """
        now = time.time()
        
        # Check minute limit
        minute_key = f"{client_id}:minute"
        minute_requests = self._minute_buckets[minute_key]
        
        # Remove old entries
        cutoff_minute = now - 60
        self._minute_buckets[minute_key] = [t for t in minute_requests if t > cutoff_minute]
        
        if len(self._minute_buckets[minute_key]) >= self.requests_per_minute:
            oldest = min(self._minute_buckets[minute_key])
            retry_after = 60 - (now - oldest)
            return False, str(int(retry_after) + 1)
        
        # Check hour limit
        hour_key = f"{client_id}:hour"
        hour_requests = self._hour_buckets[hour_key]
        
        # Remove old entries
        cutoff_hour = now - 3600
        self._hour_buckets[hour_key] = [t for t in hour_requests if t > cutoff_hour]
        
        if len(self._hour_buckets[hour_key]) >= self.requests_per_hour:
            oldest = min(self._hour_buckets[hour_key])
            retry_after = 3600 - (now - oldest)
            return False, str(int(retry_after) + 1)
        
        # Check burst limit (10 requests per second)
        burst_key = f"{client_id}:burst"
        burst_requests = self._minute_buckets.get(burst_key, [])
        cutoff_burst = now - 1
        burst_requests = [t for t in burst_requests if t > cutoff_burst]
        
        if len(burst_requests) >= self.burst_size:
            return False, "1"
        
        # Record this request
        self._minute_buckets[minute_key].append(now)
        self._hour_buckets[hour_key].append(now)
        self._minute_buckets[burst_key].append(now)
        
        return True, None
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting"""
        # Skip rate limiting for health check, docs, and in debug mode
        if request.url.path in ["/health", "/", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)

        # Skip rate limiting in debug mode for development convenience
        from app.config import settings
        if settings.DEBUG:
            return await call_next(request)
        
        # Cleanup old entries periodically
        self._cleanup_old_entries()
        
        # Get client ID
        client_id = self._get_client_id(request)
        
        # Check rate limit
        allowed, retry_after = self._check_rate_limit(client_id)
        
        if not allowed:
            from fastapi.responses import JSONResponse
            headers = {"Retry-After": retry_after} if retry_after else {}
            # Must include CORS headers since this response bypasses CORSMiddleware
            headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
            headers["Access-Control-Allow-Credentials"] = "true"
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded"},
                headers=headers,
            )
        
        # Add rate limit headers to response
        response = await call_next(request)
        
        # Add rate limit info headers
        minute_key = f"{client_id}:minute"
        hour_key = f"{client_id}:hour"
        
        minute_remaining = max(0, self.requests_per_minute - len(self._minute_buckets.get(minute_key, [])))
        hour_remaining = max(0, self.requests_per_hour - len(self._hour_buckets.get(hour_key, [])))
        
        response.headers["X-RateLimit-Limit-Minute"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining-Minute"] = str(minute_remaining)
        response.headers["X-RateLimit-Limit-Hour"] = str(self.requests_per_hour)
        response.headers["X-RateLimit-Remaining-Hour"] = str(hour_remaining)
        
        return response


def create_rate_limit_middleware(
    requests_per_minute: int = 60,
    requests_per_hour: int = 1000,
    burst_size: int = 10,
) -> RateLimitMiddleware:
    """
    Factory function to create rate limit middleware
    
    Args:
        requests_per_minute: Max requests per minute per client
        requests_per_hour: Max requests per hour per client
        burst_size: Max burst requests per second
    """
    return RateLimitMiddleware(
        requests_per_minute=requests_per_minute,
        requests_per_hour=requests_per_hour,
        burst_size=burst_size,
    )
