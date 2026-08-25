"""
OpenAI Provider

Real OpenAI API integration for AI-powered analysis.
"""

from __future__ import annotations

import time
from typing import Optional
import httpx

from app.ai.providers import AIProvider, AIRequest, AIResponse, AIError, AIProviderType


class OpenAIProvider(AIProvider):
    """
    OpenAI API provider
    
    Uses the OpenAI API for AI-powered configuration analysis.
    Supports GPT-4, GPT-3.5-turbo, and other OpenAI models.
    """
    
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4",
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(self.timeout),
            )
        return self._client
    
    async def complete(self, request: AIRequest) -> tuple[Optional[AIResponse], Optional[AIError]]:
        """
        Send completion request to OpenAI API
        
        Returns:
            Tuple of (response, error)
        """
        try:
            client = await self._get_client()
            
            # Build messages
            messages = []
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            messages.append({"role": "user", "content": request.prompt})
            
            # Build request body
            body = {
                "model": request.model or self.model,
                "messages": messages,
                "temperature": request.temperature,
                "max_tokens": request.max_tokens,
            }
            
            # Add JSON mode if requested
            if request.response_format == "json":
                body["response_format"] = {"type": "json_object"}
            
            start_time = time.time()
            
            # Send request
            response = await client.post("/chat/completions", json=body)
            
            latency_ms = (time.time() - start_time) * 1000
            
            if response.status_code != 200:
                error_data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
                error_message = error_data.get("error", {}).get("message", f"HTTP {response.status_code}")
                
                # Determine if retryable
                retryable = response.status_code in [429, 500, 502, 503, 504]
                
                return None, AIError(
                    code=f"HTTP_{response.status_code}",
                    message=error_message,
                    retryable=retryable,
                    provider="openai",
                )
            
            data = response.json()
            
            # Extract response
            choice = data.get("choices", [{}])[0]
            content = choice.get("message", {}).get("content", "")
            finish_reason = choice.get("finish_reason", "")
            usage = data.get("usage", {})
            
            return AIResponse(
                content=content,
                model=data.get("model", self.model),
                usage=usage,
                finish_reason=finish_reason,
                latency_ms=latency_ms,
            ), None
            
        except httpx.TimeoutException:
            return None, AIError(
                code="TIMEOUT",
                message=f"OpenAI request timed out after {self.timeout}s",
                retryable=True,
                provider="openai",
            )
        except httpx.ConnectError as e:
            return None, AIError(
                code="CONNECTION_ERROR",
                message=f"Failed to connect to OpenAI: {str(e)}",
                retryable=True,
                provider="openai",
            )
        except Exception as e:
            return None, AIError(
                code="UNKNOWN_ERROR",
                message=f"OpenAI error: {str(e)}",
                retryable=False,
                provider="openai",
            )
    
    def is_available(self) -> bool:
        """Check if provider is available"""
        return bool(self.api_key)
    
    def get_provider_type(self) -> AIProviderType:
        """Get provider type"""
        return AIProviderType.OPENAI
    
    async def close(self) -> None:
        """Close HTTP client"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()


def create_openai_provider(
    api_key: str,
    model: str = "gpt-4",
    base_url: str = "https://api.openai.com/v1",
) -> OpenAIProvider:
    """
    Factory function to create OpenAI provider
    
    Args:
        api_key: OpenAI API key
        model: Model to use (gpt-4, gpt-3.5-turbo, etc.)
        base_url: API base URL (for proxies)
        
    Returns:
        Configured OpenAIProvider
    """
    return OpenAIProvider(
        api_key=api_key,
        model=model,
        base_url=base_url,
    )
