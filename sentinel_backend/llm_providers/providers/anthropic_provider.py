"""
Anthropic (Claude) Provider Implementation

Implements the LLM provider interface for Anthropic's Claude models.
"""

import asyncio
import json
from typing import List, Dict, Any, Optional, AsyncIterator
from datetime import datetime
import structlog

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


class AnthropicProvider(BaseLLMProvider):
    """
    Anthropic provider implementation for Claude models.
    
    Supports:
    - Claude Opus 4/4.1
    - Claude Sonnet 4/4.1
    - Claude Haiku 3.5
    - Vision capabilities
    - Streaming responses
    - Long context (200k tokens)
    """
    
    # Model pricing per 1K tokens (USD)
    PRICING = {
        # Claude 4 models (2025 releases)
        "claude-opus-4-1-20250805": {"input": 0.015, "output": 0.075},
        "claude-opus-4-20250514": {"input": 0.015, "output": 0.075},
        "claude-sonnet-4-20250514": {"input": 0.003, "output": 0.015},
        # Claude 3.5 models (late 2024)
        "claude-3-5-sonnet-20241022": {"input": 0.003, "output": 0.015},
        "claude-3-5-haiku-20241022": {"input": 0.001, "output": 0.005},
        # Claude 3 models (early 2024)
        "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
        "claude-3-sonnet-20240229": {"input": 0.003, "output": 0.015},
        "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
        # Aliases for convenience
        "claude-opus-4.1": {"input": 0.015, "output": 0.075},
        "claude-opus-4": {"input": 0.015, "output": 0.075},
        "claude-sonnet-4": {"input": 0.003, "output": 0.015},
        "claude-3.5-sonnet": {"input": 0.003, "output": 0.015},
        "claude-3.5-haiku": {"input": 0.001, "output": 0.005},
    }
    
    # Model ID mappings
    MODEL_MAPPINGS = {
        # Claude 4 models
        "claude-opus-4.1": "claude-opus-4-1-20250805",
        "claude-opus-4": "claude-opus-4-20250514",
        "claude-sonnet-4": "claude-sonnet-4-20250514",
        # Claude 3.5 models
        "claude-3.5-sonnet": "claude-3-5-sonnet-20241022",
        "claude-3.5-haiku": "claude-3-5-haiku-20241022",
        "claude-sonnet-3.5": "claude-3-5-sonnet-20241022",  # Alternative alias
        "claude-haiku-3.5": "claude-3-5-haiku-20241022",    # Alternative alias
        # Claude 3 models
        "claude-3-opus": "claude-3-opus-20240229",
        "claude-3-sonnet": "claude-3-sonnet-20240229",
        "claude-3-haiku": "claude-3-haiku-20240307",
        "claude-opus-3": "claude-3-opus-20240229",          # Alternative alias
    }
    
    def __init__(self, config: LLMConfig):
        """Initialize Anthropic provider."""
        super().__init__(config)
        self.client = None
        self.async_client = None
        self._setup_client()
    
    def _validate_config(self) -> None:
        """Validate Anthropic-specific configuration."""
        if not self.config.api_key:
            raise ValueError("Anthropic API key is required")
        
        if not self.config.api_key.startswith("sk-ant-"):
            logger.warning("Anthropic API key format may be invalid")
    
    def _setup_client(self):
        """Set up Anthropic client."""
        try:
            import anthropic
            from anthropic import AsyncAnthropic, Anthropic
            
            # Map model names if needed
            if self.config.model in self.MODEL_MAPPINGS:
                actual_model = self.MODEL_MAPPINGS[self.config.model]
                logger.info(f"Mapping model {self.config.model} to {actual_model}")
                self.config.model = actual_model
            
            # Set up async client
            self.async_client = AsyncAnthropic(
                api_key=self.config.api_key,
                base_url=self.config.api_base,
                timeout=self.config.timeout,
                max_retries=self.config.max_retries
            )
            
            # Set up sync client
            self.client = Anthropic(
                api_key=self.config.api_key,
                base_url=self.config.api_base,
                timeout=self.config.timeout,
                max_retries=self.config.max_retries
            )
            
            logger.info(f"Anthropic client initialized for model: {self.config.model}")
            
        except ImportError:
            raise ImportError(
                "Anthropic library not installed. Install with: pip install anthropic"
            )
    
    def format_messages(self, messages: List[Message]) -> tuple:
        """
        Format messages for Anthropic API.
        
        Anthropic uses a different format:
        - System message is separate
        - Messages must alternate between user and assistant
        
        Returns:
            Tuple of (system_prompt, messages)
        """
        system_prompt = ""
        formatted_messages = []
        
        for msg in messages:
            if msg.role == "system":
                # Anthropic puts system messages in a separate parameter
                system_prompt = msg.content
            else:
                formatted_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
        
        # Ensure messages alternate properly
        formatted_messages = self._ensure_alternating_messages(formatted_messages)
        
        return system_prompt, formatted_messages
    
    def _ensure_alternating_messages(self, messages: List[Dict]) -> List[Dict]:
        """
        Ensure messages alternate between user and assistant.
        
        Anthropic requires strict alternation.
        """
        if not messages:
            return messages
        
        result = []
        last_role = None
        
        for msg in messages:
            current_role = msg["role"]
            
            # If same role appears twice, merge the contents
            if last_role == current_role and result:
                result[-1]["content"] += "\n\n" + msg["content"]
            else:
                result.append(msg)
                last_role = current_role
        
        # Ensure first message is from user
        if result and result[0]["role"] != "user":
            result.insert(0, {"role": "user", "content": "Continue the conversation."})
        
        # Ensure last message is from user (for generation)
        if result and result[-1]["role"] != "user":
            result.append({"role": "user", "content": "Please respond."})
        
        return result
    
    async def generate(
        self,
        messages: List[Message],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response using Anthropic's API.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters
            
        Returns:
            LLMResponse with generated content
        """
        if not self.async_client:
            raise RuntimeError("Anthropic client not initialized")
        
        # Format messages for Anthropic
        system_prompt, formatted_messages = self.format_messages(messages)
        
        # Prepare request parameters
        request_params = {
            "model": self.config.model,
            "messages": formatted_messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens or 4096),
            "temperature": kwargs.get("temperature", self.config.temperature),
            "top_p": kwargs.get("top_p", self.config.top_p),
        }
        
        # Add system prompt if present
        if system_prompt:
            request_params["system"] = system_prompt
        
        # Add optional parameters
        if "stop_sequences" in kwargs:
            request_params["stop_sequences"] = kwargs["stop_sequences"]
        
        # Anthropic-specific parameters
        if "top_k" in kwargs:
            request_params["top_k"] = kwargs["top_k"]
        
        try:
            # Make API call
            response = await self.async_client.messages.create(**request_params)
            
            # Extract content
            content = ""
            for content_block in response.content:
                if content_block.type == "text":
                    content += content_block.text
            
            # Calculate usage and cost
            usage = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            }
            
            # Calculate cost
            model_pricing = self.PRICING.get(
                self.config.model,
                {"input": 0.001, "output": 0.005}  # Default pricing
            )
            cost = (
                (usage["prompt_tokens"] / 1000) * model_pricing["input"] +
                (usage["completion_tokens"] / 1000) * model_pricing["output"]
            )
            usage["cost"] = round(cost, 6)
            
            # Prepare metadata
            metadata = {
                "model": response.model,
                "stop_reason": response.stop_reason,
                "stop_sequence": response.stop_sequence,
            }
            
            return LLMResponse(
                content=content,
                model=self.config.model,
                provider=LLMProvider.ANTHROPIC,
                usage=usage,
                metadata=metadata,
                created_at=datetime.now(),
                cache_hit=False
            )
            
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise
    
    async def stream_generate(
        self,
        messages: List[Message],
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream response from Anthropic.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters
            
        Yields:
            Chunks of generated text
        """
        if not self.async_client:
            raise RuntimeError("Anthropic client not initialized")
        
        # Format messages
        system_prompt, formatted_messages = self.format_messages(messages)
        
        # Prepare request parameters
        request_params = {
            "model": self.config.model,
            "messages": formatted_messages,
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens or 4096),
            "temperature": kwargs.get("temperature", self.config.temperature),
            "stream": True,
        }
        
        # Add system prompt if present
        if system_prompt:
            request_params["system"] = system_prompt
        
        try:
            # Create streaming response
            async with self.async_client.messages.stream(**request_params) as stream:
                async for text in stream.text_stream:
                    yield text
                    
        except Exception as e:
            logger.error(f"Anthropic streaming error: {e}")
            raise
    
    def get_capabilities(self) -> List[ModelCapability]:
        """Get model capabilities."""
        model_spec = get_model_spec(self.config.model)
        if model_spec:
            return model_spec.capabilities
        
        # Default capabilities for Claude models
        capabilities = [
            ModelCapability.TEXT_GENERATION,
            ModelCapability.CODE_GENERATION,
            ModelCapability.LONG_CONTEXT,
            ModelCapability.STREAMING
        ]
        
        # Add model-specific capabilities
        if "opus" in self.config.model.lower():
            capabilities.extend([
                ModelCapability.VISION,
                ModelCapability.REASONING
            ])
        elif "sonnet" in self.config.model.lower():
            capabilities.append(ModelCapability.VISION)
        
        return capabilities
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for Anthropic models.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Estimated token count
        """
        try:
            # Use Anthropic's token counting if available
            if self.client:
                # Anthropic uses a similar tokenization to OpenAI
                # but exact counting requires their API
                pass
            
            # Fallback to rough estimation
            # Claude models use roughly 1 token per 3.5 characters
            return len(text) // 3.5
            
        except Exception as e:
            logger.warning(f"Error estimating tokens: {e}")
            return len(text) // 4
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        model_spec = get_model_spec(self.config.model)
        
        if model_spec:
            return {
                "provider": "Anthropic",
                "model": self.config.model,
                "display_name": model_spec.display_name,
                "context_window": model_spec.context_window,
                "max_output_tokens": model_spec.max_output_tokens,
                "supports_vision": model_spec.supports_vision,
                "supports_streaming": model_spec.supports_streaming,
                "pricing": {
                    "input_per_1k": model_spec.input_cost_per_1k,
                    "output_per_1k": model_spec.output_cost_per_1k
                },
                "notes": model_spec.notes
            }
        
        # Fallback info
        return {
            "provider": "Anthropic",
            "model": self.config.model,
            "display_name": self.config.model,
            "context_window": 200000,  # All current Claude models support 200k
            "max_output_tokens": 4096,
            "supports_vision": "opus" in self.config.model.lower() or "sonnet" in self.config.model.lower(),
            "supports_streaming": True,
            "pricing": self.PRICING.get(
                self.config.model,
                {"input": 0.001, "output": 0.005}
            )
        }
    
    async def health_check(self) -> bool:
        """
        Check if Anthropic API is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Try a minimal API call
            response = await self.async_client.messages.create(
                model=self.config.model,
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=5
            )
            return bool(response.content)
        except Exception as e:
            logger.error(f"Anthropic health check failed: {e}")
            return False