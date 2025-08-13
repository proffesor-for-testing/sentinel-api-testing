"""Google (Gemini) provider implementation for Sentinel API Testing Platform."""

import os
import json
import logging
from typing import List, Dict, Any, Optional, AsyncGenerator
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from ..base_provider import BaseLLMProvider, LLMConfig, LLMResponse, Message

logger = logging.getLogger(__name__)


class GoogleProvider(BaseLLMProvider):
    """Google Gemini provider implementation."""

    def __init__(self, config: LLMConfig):
        """Initialize Google provider with configuration."""
        super().__init__(config)
        self.api_key = config.api_key or os.getenv("SENTINEL_APP_GOOGLE_API_KEY")
        
        if not self.api_key:
            raise ValueError("Google API key not provided in config or environment")
        
        # Configure the Google AI SDK
        genai.configure(api_key=self.api_key)
        
        # Safety settings to allow most content (can be adjusted based on needs)
        self.safety_settings = {
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_ONLY_HIGH,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_ONLY_HIGH,
        }
        
        # Model name mapping
        self.model_mapping = {
            # Gemini 2.5 series (latest)
            "gemini-2.5-pro": "gemini-2.5-pro",
            "gemini-2.5-flash": "gemini-2.5-flash",
            "gemini-2.0-flash": "gemini-2.0-flash-exp",
            # Legacy models (limited availability from April 2025)
            "gemini-1.5-pro": "gemini-1.5-pro",
            "gemini-1.5-pro-latest": "gemini-1.5-pro-latest",
            "gemini-1.5-flash": "gemini-1.5-flash",
            "gemini-1.5-flash-latest": "gemini-1.5-flash-latest",
            "gemini-pro": "gemini-pro",
            "gemini-pro-vision": "gemini-pro-vision",
        }
        
        # Get the actual model name
        self.model_name = self.model_mapping.get(config.model, config.model)
        
        # Initialize the model
        try:
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                safety_settings=self.safety_settings,
                generation_config={
                    "temperature": config.temperature,
                    "max_output_tokens": config.max_tokens,
                    "top_p": config.top_p if hasattr(config, 'top_p') else 0.95,
                }
            )
        except Exception as e:
            logger.error(f"Failed to initialize Google model {self.model_name}: {e}")
            raise

    def _convert_messages_to_prompt(self, messages: List[Message]) -> str:
        """Convert messages to a single prompt for Gemini."""
        prompt_parts = []
        
        for message in messages:
            if message.role == "system":
                prompt_parts.append(f"System: {message.content}")
            elif message.role == "user":
                prompt_parts.append(f"User: {message.content}")
            elif message.role == "assistant":
                prompt_parts.append(f"Assistant: {message.content}")
        
        return "\n\n".join(prompt_parts)

    def _convert_messages_to_chat_format(self, messages: List[Message]) -> tuple:
        """Convert messages to Gemini chat format."""
        # Separate system prompt from conversation
        system_prompt = None
        chat_history = []
        
        for message in messages:
            if message.role == "system":
                if system_prompt:
                    system_prompt += "\n" + message.content
                else:
                    system_prompt = message.content
            elif message.role == "user":
                chat_history.append({"role": "user", "parts": [message.content]})
            elif message.role == "assistant":
                chat_history.append({"role": "model", "parts": [message.content]})
        
        # If there's a system prompt, prepend it to the first user message
        if system_prompt and chat_history:
            if chat_history[0]["role"] == "user":
                chat_history[0]["parts"][0] = f"{system_prompt}\n\n{chat_history[0]['parts'][0]}"
            else:
                # Insert a user message with the system prompt
                chat_history.insert(0, {"role": "user", "parts": [system_prompt]})
        
        return chat_history

    async def generate(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> LLMResponse:
        """Generate a response using Google Gemini."""
        try:
            # Convert messages to chat format
            chat_history = self._convert_messages_to_chat_format(messages)
            
            # Create a chat session
            chat = self.model.start_chat(history=chat_history[:-1] if len(chat_history) > 1 else [])
            
            # Get the last message (the actual prompt)
            if chat_history:
                last_message = chat_history[-1]["parts"][0]
            else:
                last_message = ""
            
            # Generate response
            response = await chat.send_message_async(last_message)
            
            # Extract text from response
            content = response.text if hasattr(response, 'text') else str(response)
            
            # Calculate token usage (approximation)
            # Google doesn't provide exact token counts in the same way
            prompt_tokens = sum(len(msg.content.split()) * 1.3 for msg in messages)
            completion_tokens = len(content.split()) * 1.3
            
            return LLMResponse(
                content=content,
                role="assistant",
                model=self.model_name,
                usage={
                    "prompt_tokens": int(prompt_tokens),
                    "completion_tokens": int(completion_tokens),
                    "total_tokens": int(prompt_tokens + completion_tokens)
                },
                raw_response=response.__dict__ if hasattr(response, '__dict__') else str(response)
            )
            
        except Exception as e:
            logger.error(f"Google generation failed: {e}")
            raise

    async def stream_generate(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream a response from Google Gemini."""
        try:
            # Convert messages to chat format
            chat_history = self._convert_messages_to_chat_format(messages)
            
            # Create a chat session
            chat = self.model.start_chat(history=chat_history[:-1] if len(chat_history) > 1 else [])
            
            # Get the last message
            if chat_history:
                last_message = chat_history[-1]["parts"][0]
            else:
                last_message = ""
            
            # Stream the response
            response = await chat.send_message_async(last_message, stream=True)
            
            async for chunk in response:
                if hasattr(chunk, 'text'):
                    yield chunk.text
                elif hasattr(chunk, 'parts'):
                    for part in chunk.parts:
                        if hasattr(part, 'text'):
                            yield part.text
                        
        except Exception as e:
            logger.error(f"Google streaming failed: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if the Google provider is healthy."""
        try:
            # Try to list available models
            models = genai.list_models()
            return len(list(models)) > 0
        except Exception as e:
            logger.error(f"Google health check failed: {e}")
            return False

    @property
    def supports_function_calling(self) -> bool:
        """Check if this provider supports function calling."""
        # Gemini 1.5 models support function calling
        return "gemini-1.5" in self.model_name.lower()

    @property
    def supports_vision(self) -> bool:
        """Check if this provider supports vision inputs."""
        # Gemini Pro Vision and 1.5 models support vision
        return "vision" in self.model_name.lower() or "gemini-1.5" in self.model_name.lower()

    @property
    def max_context_window(self) -> int:
        """Get the maximum context window for this provider."""
        # Context windows for different models
        context_windows = {
            "gemini-1.5-pro": 2000000,  # 2M tokens
            "gemini-1.5-flash": 1000000,  # 1M tokens
            "gemini-pro": 32768,  # 32k tokens
            "gemini-pro-vision": 16384,  # 16k tokens
        }
        
        for model_key, window_size in context_windows.items():
            if model_key in self.model_name.lower():
                return window_size
        
        return 32768  # Default context window