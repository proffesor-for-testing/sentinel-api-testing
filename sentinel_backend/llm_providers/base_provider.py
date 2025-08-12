"""
Base LLM Provider Interface

Defines the abstract interface that all LLM providers must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime


class LLMProvider(str, Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    MISTRAL = "mistral"
    OLLAMA = "ollama"
    VLLM = "vllm"
    HUGGINGFACE = "huggingface"


class ModelCapability(str, Enum):
    """Model capabilities for feature detection"""
    TEXT_GENERATION = "text_generation"
    CODE_GENERATION = "code_generation"
    FUNCTION_CALLING = "function_calling"
    VISION = "vision"
    STREAMING = "streaming"
    LONG_CONTEXT = "long_context"  # >32k tokens
    REASONING = "reasoning"  # For models like DeepSeek-R1


@dataclass
class LLMConfig:
    """Configuration for LLM providers"""
    provider: LLMProvider
    model: str
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    temperature: float = 0.5
    max_tokens: Optional[int] = None
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    timeout: int = 60
    max_retries: int = 3
    cache_enabled: bool = True
    cache_ttl: int = 3600  # seconds
    
    # Provider-specific options
    extra_params: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.extra_params is None:
            self.extra_params = {}


@dataclass
class LLMResponse:
    """Standardized response from LLM providers"""
    content: str
    model: str
    provider: LLMProvider
    usage: Dict[str, int]  # tokens used, cost, etc.
    metadata: Dict[str, Any]  # provider-specific metadata
    created_at: datetime
    cache_hit: bool = False
    
    @property
    def total_tokens(self) -> int:
        """Get total tokens used"""
        return self.usage.get("total_tokens", 0)
    
    @property
    def estimated_cost(self) -> float:
        """Get estimated cost in USD"""
        return self.usage.get("cost", 0.0)


@dataclass
class Message:
    """Chat message format"""
    role: str  # "system", "user", "assistant"
    content: str
    name: Optional[str] = None
    function_call: Optional[Dict[str, Any]] = None


class BaseLLMProvider(ABC):
    """
    Abstract base class for all LLM providers.
    
    Each provider implementation must handle:
    - Authentication
    - Request formatting
    - Response parsing
    - Error handling
    - Rate limiting
    """
    
    def __init__(self, config: LLMConfig):
        self.config = config
        self._validate_config()
    
    @abstractmethod
    def _validate_config(self) -> None:
        """Validate provider-specific configuration"""
        pass
    
    @abstractmethod
    async def generate(
        self, 
        messages: List[Message],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response from the LLM.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional provider-specific parameters
            
        Returns:
            LLMResponse object with generated content
        """
        pass
    
    @abstractmethod
    async def stream_generate(
        self,
        messages: List[Message],
        **kwargs
    ) -> Any:  # AsyncIterator[str]
        """
        Stream response from the LLM.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional provider-specific parameters
            
        Yields:
            Chunks of generated text
        """
        pass
    
    @abstractmethod
    def get_capabilities(self) -> List[ModelCapability]:
        """Get the capabilities of the current model"""
        pass
    
    @abstractmethod
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for the given text"""
        pass
    
    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the current model.
        
        Returns:
            Dictionary with model details (context window, pricing, etc.)
        """
        pass
    
    async def health_check(self) -> bool:
        """
        Check if the provider is healthy and accessible.
        
        Returns:
            True if provider is healthy, False otherwise
        """
        try:
            response = await self.generate([
                Message(role="user", content="Hi")
            ], max_tokens=5)
            return bool(response.content)
        except Exception:
            return False
    
    def format_messages(self, messages: List[Message]) -> Any:
        """
        Format messages for the specific provider.
        Override in subclasses if needed.
        """
        return [
            {
                "role": msg.role,
                "content": msg.content,
                **({"name": msg.name} if msg.name else {}),
                **({"function_call": msg.function_call} if msg.function_call else {})
            }
            for msg in messages
        ]