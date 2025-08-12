"""
OpenAI Provider Implementation

Implements the LLM provider interface for OpenAI's GPT models.
"""

import asyncio
import json
from typing import List, Dict, Any, Optional, AsyncIterator
from datetime import datetime
import structlog
import tiktoken

from ..base_provider import (
    BaseLLMProvider,
    LLMConfig,
    LLMResponse,
    Message,
    LLMProvider,
    ModelCapability
)
from ..model_registry import get_model_spec

logger = structlog.get_logger(__name__)


class OpenAIProvider(BaseLLMProvider):
    """
    OpenAI provider implementation.
    
    Supports:
    - GPT-4, GPT-4 Turbo, GPT-3.5 Turbo
    - Function calling
    - Vision (for supported models)
    - Streaming responses
    """
    
    # Model pricing per 1K tokens (USD)
    PRICING = {
        "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-32k": {"input": 0.06, "output": 0.12},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "gpt-3.5-turbo-16k": {"input": 0.001, "output": 0.002},
    }
    
    def __init__(self, config: LLMConfig):
        """Initialize OpenAI provider."""
        super().__init__(config)
        self.client = None
        self.async_client = None
        self._setup_client()
    
    def _validate_config(self) -> None:
        """Validate OpenAI-specific configuration."""
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required")
        
        if not self.config.api_key.startswith("sk-"):
            logger.warning("OpenAI API key format may be invalid")
    
    def _setup_client(self):
        """Set up OpenAI client."""
        try:
            import openai
            from openai import AsyncOpenAI, OpenAI
            
            # Set up async client for async methods
            self.async_client = AsyncOpenAI(
                api_key=self.config.api_key,
                base_url=self.config.api_base,
                timeout=self.config.timeout,
                max_retries=self.config.max_retries
            )
            
            # Set up sync client for sync methods
            self.client = OpenAI(
                api_key=self.config.api_key,
                base_url=self.config.api_base,
                timeout=self.config.timeout,
                max_retries=self.config.max_retries
            )
            
            logger.info(f"OpenAI client initialized for model: {self.config.model}")
            
        except ImportError:
            raise ImportError(
                "OpenAI library not installed. Install with: pip install openai"
            )
    
    async def generate(
        self,
        messages: List[Message],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response using OpenAI's API.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters (functions, tools, etc.)
            
        Returns:
            LLMResponse with generated content
        """
        if not self.async_client:
            raise RuntimeError("OpenAI client not initialized")
        
        # Format messages for OpenAI
        formatted_messages = self.format_messages(messages)
        
        # Prepare request parameters
        request_params = {
            "model": self.config.model,
            "messages": formatted_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "frequency_penalty": kwargs.get("frequency_penalty", self.config.frequency_penalty),
            "presence_penalty": kwargs.get("presence_penalty", self.config.presence_penalty),
        }
        
        # Add optional parameters
        if "functions" in kwargs:
            request_params["functions"] = kwargs["functions"]
        if "function_call" in kwargs:
            request_params["function_call"] = kwargs["function_call"]
        if "tools" in kwargs:
            request_params["tools"] = kwargs["tools"]
        if "tool_choice" in kwargs:
            request_params["tool_choice"] = kwargs["tool_choice"]
        if "response_format" in kwargs:
            request_params["response_format"] = kwargs["response_format"]
        
        # Remove None values
        request_params = {k: v for k, v in request_params.items() if v is not None}
        
        try:
            # Make API call
            response = await self.async_client.chat.completions.create(**request_params)
            
            # Extract content
            content = response.choices[0].message.content or ""
            
            # Calculate usage and cost
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
            
            # Calculate cost
            model_pricing = self.PRICING.get(
                self.config.model,
                self.PRICING.get("gpt-3.5-turbo")  # Default pricing
            )
            cost = (
                (usage["prompt_tokens"] / 1000) * model_pricing["input"] +
                (usage["completion_tokens"] / 1000) * model_pricing["output"]
            )
            usage["cost"] = round(cost, 6)
            
            # Prepare metadata
            metadata = {
                "model": response.model,
                "finish_reason": response.choices[0].finish_reason,
                "system_fingerprint": getattr(response, "system_fingerprint", None),
            }
            
            # Add function call if present
            if response.choices[0].message.function_call:
                metadata["function_call"] = {
                    "name": response.choices[0].message.function_call.name,
                    "arguments": response.choices[0].message.function_call.arguments
                }
            
            # Add tool calls if present
            if response.choices[0].message.tool_calls:
                metadata["tool_calls"] = [
                    {
                        "id": tool_call.id,
                        "type": tool_call.type,
                        "function": {
                            "name": tool_call.function.name,
                            "arguments": tool_call.function.arguments
                        }
                    }
                    for tool_call in response.choices[0].message.tool_calls
                ]
            
            return LLMResponse(
                content=content,
                model=self.config.model,
                provider=LLMProvider.OPENAI,
                usage=usage,
                metadata=metadata,
                created_at=datetime.now(),
                cache_hit=False
            )
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise
    
    async def stream_generate(
        self,
        messages: List[Message],
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream response from OpenAI.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters
            
        Yields:
            Chunks of generated text
        """
        if not self.async_client:
            raise RuntimeError("OpenAI client not initialized")
        
        # Format messages
        formatted_messages = self.format_messages(messages)
        
        # Prepare request parameters
        request_params = {
            "model": self.config.model,
            "messages": formatted_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "stream": True,
        }
        
        # Remove None values
        request_params = {k: v for k, v in request_params.items() if v is not None}
        
        try:
            # Create streaming response
            stream = await self.async_client.chat.completions.create(**request_params)
            
            # Yield chunks
            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
                    
        except Exception as e:
            logger.error(f"OpenAI streaming error: {e}")
            raise
    
    def get_capabilities(self) -> List[ModelCapability]:
        """Get model capabilities."""
        model_spec = get_model_spec(self.config.model)
        if model_spec:
            return model_spec.capabilities
        
        # Default capabilities for GPT models
        capabilities = [
            ModelCapability.TEXT_GENERATION,
            ModelCapability.CODE_GENERATION,
            ModelCapability.STREAMING
        ]
        
        # Add model-specific capabilities
        if "gpt-4" in self.config.model:
            capabilities.extend([
                ModelCapability.FUNCTION_CALLING,
                ModelCapability.LONG_CONTEXT
            ])
            if "vision" in self.config.model or "turbo" in self.config.model:
                capabilities.append(ModelCapability.VISION)
        elif "gpt-3.5" in self.config.model:
            capabilities.append(ModelCapability.FUNCTION_CALLING)
        
        return capabilities
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count using tiktoken.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Estimated token count
        """
        try:
            # Get the appropriate encoding for the model
            if "gpt-4" in self.config.model:
                encoding = tiktoken.encoding_for_model("gpt-4")
            elif "gpt-3.5" in self.config.model:
                encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
            else:
                # Default to cl100k_base encoding
                encoding = tiktoken.get_encoding("cl100k_base")
            
            return len(encoding.encode(text))
            
        except Exception as e:
            logger.warning(f"Error estimating tokens: {e}")
            # Fallback to rough estimation (1 token ≈ 4 characters)
            return len(text) // 4
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        model_spec = get_model_spec(self.config.model)
        
        if model_spec:
            return {
                "provider": "OpenAI",
                "model": self.config.model,
                "display_name": model_spec.display_name,
                "context_window": model_spec.context_window,
                "max_output_tokens": model_spec.max_output_tokens,
                "supports_functions": model_spec.supports_functions,
                "supports_vision": model_spec.supports_vision,
                "supports_streaming": model_spec.supports_streaming,
                "pricing": {
                    "input_per_1k": model_spec.input_cost_per_1k,
                    "output_per_1k": model_spec.output_cost_per_1k
                }
            }
        
        # Fallback info
        return {
            "provider": "OpenAI",
            "model": self.config.model,
            "display_name": self.config.model,
            "context_window": 4096 if "gpt-3.5" in self.config.model else 8192,
            "max_output_tokens": 4096,
            "supports_functions": True,
            "supports_vision": "vision" in self.config.model or "gpt-4-turbo" in self.config.model,
            "supports_streaming": True,
            "pricing": self.PRICING.get(
                self.config.model,
                {"input": 0.001, "output": 0.002}
            )
        }
    
    async def health_check(self) -> bool:
        """
        Check if OpenAI API is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Try a minimal API call
            response = await self.async_client.chat.completions.create(
                model=self.config.model,
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=5
            )
            return bool(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"OpenAI health check failed: {e}")
            return False