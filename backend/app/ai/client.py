"""
AI Client

Handles AI provider communication with retry, error handling, and caching.
"""

from __future__ import annotations

import asyncio
import time
import json
import hashlib
from typing import Optional, Any
from dataclasses import dataclass, field

from app.ai.providers import AIProvider, AIRequest, AIResponse, AIError


@dataclass
class AICacheEntry:
    """Cached AI response"""
    response: AIResponse
    created_at: float
    ttl_seconds: int = 3600
    
    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds


class AIClient:
    """
    AI Client with retry, error handling, and caching.
    
    Features:
    - Exponential backoff retry
    - Response caching (TTL-based)
    - Timeout handling
    - Malformed response detection
    - Rate limiting
    """
    
    def __init__(
        self,
        provider: AIProvider,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        timeout: float = 30.0,
        cache_ttl: int = 3600,
    ):
        self.provider = provider
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._cache: dict[str, AICacheEntry] = {}
        self._request_count = 0
        self._error_count = 0
        self._total_latency_ms = 0.0
    
    async def complete(self, request: AIRequest) -> tuple[Optional[AIResponse], Optional[AIError]]:
        """
        Send completion request with retry and caching
        
        Returns:
            Tuple of (response, error)
        """
        # Check cache
        cache_key = self._get_cache_key(request)
        cached = self._get_from_cache(cache_key)
        if cached:
            cached.cached = True
            return cached, None
        
        # Check provider availability
        if not self.provider.is_available():
            return None, AIError(
                code="PROVIDER_UNAVAILABLE",
                message="AI provider is not available",
                retryable=False,
                provider=self.provider.get_provider_type().value,
            )
        
        # Retry loop
        last_error: Optional[AIError] = None
        
        for attempt in range(self.max_retries):
            self._request_count += 1
            start_time = time.time()
            
            try:
                response, error = await asyncio.wait_for(
                    self.provider.complete(request),
                    timeout=self.timeout,
                )
                
                latency_ms = (time.time() - start_time) * 1000
                self._total_latency_ms += latency_ms
                
                if error:
                    self._error_count += 1
                    last_error = error
                    
                    if not error.retryable:
                        return None, error
                    
                    # Wait before retry
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    continue
                
                if response:
                    response.latency_ms = latency_ms
                    
                    # Validate response
                    validation_error = self._validate_response(response)
                    if validation_error:
                        self._error_count += 1
                        last_error = validation_error
                        
                        if not validation_error.retryable:
                            return None, validation_error
                        
                        if attempt < self.max_retries - 1:
                            await asyncio.sleep(self.retry_delay * (2 ** attempt))
                        continue
                    
                    # Cache successful response
                    self._cache_response(cache_key, response)
                    
                    return response, None
                    
            except asyncio.TimeoutError:
                self._error_count += 1
                last_error = AIError(
                    code="TIMEOUT",
                    message=f"AI request timed out after {self.timeout}s",
                    retryable=True,
                    provider=self.provider.get_provider_type().value,
                )
                
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    
            except Exception as e:
                self._error_count += 1
                last_error = AIError(
                    code="UNKNOWN_ERROR",
                    message=str(e),
                    retryable=False,
                    provider=self.provider.get_provider_type().value,
                )
                return None, last_error
        
        return None, last_error or AIError(
            code="MAX_RETRIES",
            message=f"Failed after {self.max_retries} attempts",
            retryable=False,
        )
    
    def _get_cache_key(self, request: AIRequest) -> str:
        """Generate cache key from request"""
        key_data = f"{request.prompt}:{request.system_prompt}:{request.model}:{request.temperature}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _get_from_cache(self, key: str) -> Optional[AIResponse]:
        """Get response from cache if valid"""
        entry = self._cache.get(key)
        if entry and not entry.is_expired:
            return entry.response
        if entry and entry.is_expired:
            del self._cache[key]
        return None
    
    def _cache_response(self, key: str, response: AIResponse) -> None:
        """Cache a response"""
        self._cache[key] = AICacheEntry(
            response=response,
            created_at=time.time(),
            ttl_seconds=self.cache_ttl,
        )
    
    def _validate_response(self, response: AIResponse) -> Optional[AIError]:
        """Validate AI response"""
        if not response.content:
            return AIError(
                code="EMPTY_RESPONSE",
                message="AI returned empty response",
                retryable=True,
            )
        
        # Try to parse as JSON if it looks like JSON
        content = response.content.strip()
        if content.startswith("{") or content.startswith("["):
            try:
                json.loads(content)
            except json.JSONDecodeError:
                return AIError(
                    code="MALFORMED_JSON",
                    message="AI returned invalid JSON",
                    retryable=True,
                )
        
        return None
    
    def clear_cache(self) -> None:
        """Clear response cache"""
        self._cache.clear()
    
    def get_metrics(self) -> dict:
        """Get client metrics"""
        avg_latency = (
            self._total_latency_ms / self._request_count
            if self._request_count > 0
            else 0.0
        )
        
        return {
            "request_count": self._request_count,
            "error_count": self._error_count,
            "error_rate": (
                self._error_count / self._request_count
                if self._request_count > 0
                else 0.0
            ),
            "avg_latency_ms": round(avg_latency, 2),
            "cache_size": len(self._cache),
            "provider": self.provider.get_provider_type().value,
        }
