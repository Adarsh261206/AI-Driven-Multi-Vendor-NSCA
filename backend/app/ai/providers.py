"""
AI Provider Abstraction

Abstract base class for AI providers.
Supports OpenAI, mock providers for testing, and future providers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class AIProviderType(str, Enum):
    """AI provider types"""
    OPENAI = "openai"
    MOCK = "mock"
    AZURE = "azure"


@dataclass
class AIRequest:
    """Request to AI provider"""
    prompt: str
    system_prompt: str = ""
    model: str = "gpt-4"
    temperature: float = 0.3
    max_tokens: int = 2000
    response_format: Optional[str] = None  # "json" for structured output


@dataclass
class AIResponse:
    """Response from AI provider"""
    content: str
    model: str = ""
    usage: dict = field(default_factory=dict)
    finish_reason: str = ""
    latency_ms: float = 0.0
    cached: bool = False
    
    @property
    def total_tokens(self) -> int:
        return self.usage.get("total_tokens", 0)


@dataclass
class AIError:
    """AI provider error"""
    code: str
    message: str
    retryable: bool = False
    provider: str = ""


class AIProvider(ABC):
    """Abstract AI provider interface"""
    
    @abstractmethod
    async def complete(self, request: AIRequest) -> tuple[Optional[AIResponse], Optional[AIError]]:
        """
        Send completion request to AI provider
        
        Returns:
            Tuple of (response, error) - one will be None
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available"""
        pass
    
    @abstractmethod
    def get_provider_type(self) -> AIProviderType:
        """Get provider type"""
        pass


class MockAIProvider(AIProvider):
    """
    Mock AI provider for testing
    
    Returns predefined responses based on input patterns.
    """
    
    def __init__(self):
        self.responses: dict[str, dict] = {}
        self.call_count = 0
        self.should_fail = False
        self.fail_error: Optional[AIError] = None
        self._unavailable = False
    
    def set_response(self, pattern: str, response: dict) -> None:
        """Set a mock response for a pattern"""
        self.responses[pattern] = response
    
    def set_failure(self, error: Optional[AIError] = None, unavailable: bool = False) -> None:
        """Configure the mock to fail"""
        self.should_fail = True
        self._unavailable = unavailable
        self.fail_error = error or AIError(
            code="MOCK_ERROR",
            message="Mock AI failure",
            retryable=True,
        )
    
    def reset(self) -> None:
        """Reset mock state"""
        self.call_count = 0
        self.should_fail = False
        self._unavailable = False
        self.fail_error = None
        self.responses.clear()
    
    async def complete(self, request: AIRequest) -> tuple[Optional[AIResponse], Optional[AIError]]:
        """Return mock response"""
        import json
        self.call_count += 1
        
        if self.should_fail:
            return None, self.fail_error
        
        # Find matching response
        for pattern, resp in self.responses.items():
            if pattern.lower() in request.prompt.lower():
                content = json.dumps(resp) if isinstance(resp, dict) else str(resp)
                return AIResponse(
                    content=content,
                    model="mock-model",
                    usage={"prompt_tokens": 10, "completion_tokens": 50, "total_tokens": 60},
                    finish_reason="stop",
                    latency_ms=10.0,
                ), None
        
        # Default response
        return AIResponse(
            content='{"meaning": "unknown network device configuration command", "confidence": 0.3, "reasoning": "Mock response - no pattern match", "security_relevance": "low", "universal_model_path": "general.unknown", "alternatives": []}',
            model="mock-model",
            usage={"prompt_tokens": 10, "completion_tokens": 30, "total_tokens": 40},
            finish_reason="stop",
            latency_ms=10.0,
        ), None
    
    def is_available(self) -> bool:
        return not self._unavailable
    
    def get_provider_type(self) -> AIProviderType:
        return AIProviderType.MOCK
