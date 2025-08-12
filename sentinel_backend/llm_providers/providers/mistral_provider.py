"""Mistral AI provider implementation for Sentinel API Testing Platform."""

import os
import json
import logging
from typing import List, Dict, Any, Optional, AsyncGenerator
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage

from ..base_provider import BaseLLMProvider, LLMConfig, LLMResponse, Message

logger = logging.getLogger(__name__)


class MistralProvider(BaseLLMProvider):
    """Mistral AI provider implementation."""

    def __init__(self, config: LLMConfig):
        """Initialize Mistral provider with configuration."""
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("SENTINEL_APP_MISTRAL_API_KEY")
        
        if not self.api_key:
            raise ValueError("Mistral API key not provided in config or environment")
        
        # Initialize Mistral client
        self.client = MistralClient(api_key=self.api_key)
        
        # Model name mapping
        self.model_mapping = {
            "mistral-large": "mistral-large-latest",
            "mistral-large-2": "mistral-large-2411",
            "mistral-medium": "mistral-medium-latest",
            "mistral-small": "mistral-small-latest",
            "mistral-small-3": "mistral-small-3-2025",
            "codestral": "codestral-latest",
            "codestral-mamba": "codestral-mamba-latest",
            "mistral-7b": "open-mistral-7b",
            "mixtral-8x7b": "open-mixtral-8x7b",
            "mixtral-8x22b": "open-mixtral-8x22b",
        }
        
        # Get the actual model name
        self.model_name = self.model_mapping.get(config.model, config.model)

    def _convert_message_to_mistral(self, message: Message) -> ChatMessage:
        """Convert a Message to Mistral ChatMessage format."""
        return ChatMessage(role=message.role, content=message.content)

    def _convert_messages_to_mistral(self, messages: List[Message]) -> List[ChatMessage]:
        """Convert messages to Mistral format."""
        mistral_messages = []
        
        for message in messages:
            # Mistral expects specific role names
            if message.role == "system":
                mistral_messages.append(ChatMessage(role="system", content=message.content))
            elif message.role == "user":
                mistral_messages.append(ChatMessage(role="user", content=message.content))
            elif message.role == "assistant":
                mistral_messages.append(ChatMessage(role="assistant", content=message.content))
        
        return mistral_messages

    def _convert_tools_to_mistral(self, tools: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        """Convert tools to Mistral function format."""
        if not tools:
            return None
        
        mistral_tools = []
        for tool in tools:
            mistral_tool = {
                "type": "function",
                "function": {
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "parameters": tool.get("parameters", {})
                }
            }
            mistral_tools.append(mistral_tool)
        
        return mistral_tools

    async def generate(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> LLMResponse:
        """Generate a response using Mistral AI."""
        try:
            # Convert messages to Mistral format
            mistral_messages = self._convert_messages_to_mistral(messages)
            
            # Prepare the request
            request_params = {
                "model": self.model_name,
                "messages": mistral_messages,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            }
            
            # Add tools if provided
            if tools and self.supports_function_calling:
                request_params["tools"] = self._convert_tools_to_mistral(tools)
            
            # Add additional parameters from kwargs
            if "top_p" in kwargs:
                request_params["top_p"] = kwargs["top_p"]
            elif hasattr(self.config, 'top_p'):
                request_params["top_p"] = self.config.top_p
            
            # Make the API call
            response = self.client.chat(**request_params)
            
            # Extract content from response
            content = ""
            function_call = None
            
            if response.choices and len(response.choices) > 0:
                choice = response.choices[0]
                if choice.message:
                    content = choice.message.content or ""
                    
                    # Check for function calls
                    if hasattr(choice.message, 'tool_calls') and choice.message.tool_calls:
                        function_call = {
                            "name": choice.message.tool_calls[0].function.name,
                            "arguments": choice.message.tool_calls[0].function.arguments
                        }
            
            # Extract usage information
            usage = {}
            if hasattr(response, 'usage') and response.usage:
                usage = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }
            else:
                # Estimate tokens if not provided
                prompt_tokens = sum(len(msg.content.split()) * 1.3 for msg in messages)
                completion_tokens = len(content.split()) * 1.3
                usage = {
                    "prompt_tokens": int(prompt_tokens),
                    "completion_tokens": int(completion_tokens),
                    "total_tokens": int(prompt_tokens + completion_tokens)
                }
            
            return LLMResponse(
                content=content,
                role="assistant",
                model=self.model_name,
                usage=usage,
                function_call=function_call,
                raw_response=response.model_dump() if hasattr(response, 'model_dump') else str(response)
            )
            
        except Exception as e:
            logger.error(f"Mistral generation failed: {e}")
            raise

    async def stream_generate(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream a response from Mistral AI."""
        try:
            # Convert messages to Mistral format
            mistral_messages = self._convert_messages_to_mistral(messages)
            
            # Prepare the request
            request_params = {
                "model": self.model_name,
                "messages": mistral_messages,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "stream": True
            }
            
            # Add tools if provided
            if tools and self.supports_function_calling:
                request_params["tools"] = self._convert_tools_to_mistral(tools)
            
            # Add additional parameters
            if "top_p" in kwargs:
                request_params["top_p"] = kwargs["top_p"]
            elif hasattr(self.config, 'top_p'):
                request_params["top_p"] = self.config.top_p
            
            # Stream the response
            stream_response = self.client.chat_stream(**request_params)
            
            for chunk in stream_response:
                if chunk.choices and len(chunk.choices) > 0:
                    delta = chunk.choices[0].delta
                    if delta and delta.content:
                        yield delta.content
                        
        except Exception as e:
            logger.error(f"Mistral streaming failed: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if the Mistral provider is healthy."""
        try:
            # Try to list available models
            models = self.client.list_models()
            return models is not None and hasattr(models, 'data') and len(models.data) > 0
        except Exception as e:
            logger.error(f"Mistral health check failed: {e}")
            return False

    @property
    def supports_function_calling(self) -> bool:
        """Check if this provider supports function calling."""
        # Mistral Large and Mixtral models support function calling
        function_models = ["mistral-large", "mixtral"]
        return any(model in self.model_name.lower() for model in function_models)

    @property
    def supports_vision(self) -> bool:
        """Check if this provider supports vision inputs."""
        # Mistral doesn't currently have vision models in their API
        return False

    @property
    def max_context_window(self) -> int:
        """Get the maximum context window for this provider."""
        # Context windows for different models
        context_windows = {
            "mistral-large": 128000,  # 128k tokens
            "mistral-small-3": 128000,  # 128k tokens (Jan 2025 model)
            "mistral-medium": 32768,  # 32k tokens
            "mistral-small": 32768,  # 32k tokens
            "codestral": 32768,  # 32k tokens
            "mistral-7b": 32768,  # 32k tokens
            "mixtral-8x7b": 32768,  # 32k tokens
            "mixtral-8x22b": 65536,  # 64k tokens
        }
        
        for model_key, window_size in context_windows.items():
            if model_key in self.model_name.lower():
                return window_size
        
        return 32768  # Default context window