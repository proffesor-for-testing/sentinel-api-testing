"""vLLM provider implementation for high-performance local model serving."""

import os
import json
import logging
import aiohttp
from typing import List, Dict, Any, Optional, AsyncGenerator

from ..base_provider import BaseLLMProvider, LLMConfig, LLMResponse, Message

logger = logging.getLogger(__name__)


class VLLMProvider(BaseLLMProvider):
    """vLLM provider for high-performance local model serving."""

    def __init__(self, config: LLMConfig):
        """Initialize vLLM provider with configuration."""
        super().__init__(config)
        
        # Get base URL from config or environment
        self.base_url = os.getenv("SENTINEL_APP_VLLM_BASE_URL", "http://localhost:8000")
        if self.base_url.endswith('/'):
            self.base_url = self.base_url[:-1]
        
        # vLLM uses OpenAI-compatible API
        self.api_endpoint = f"{self.base_url}/v1/chat/completions"
        self.models_endpoint = f"{self.base_url}/v1/models"
        
        # Model name - vLLM serves the model that was loaded at startup
        self.model_name = config.model
        
        # API key (optional for local vLLM)
        self.api_key = config.api_key or os.getenv("SENTINEL_APP_VLLM_API_KEY")
        
        # Session for async requests
        self.session = None

    async def _ensure_session(self):
        """Ensure aiohttp session is created."""
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def _close_session(self):
        """Close aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None

    def _convert_messages(self, messages: List[Message]) -> List[Dict[str, str]]:
        """Convert messages to vLLM format (OpenAI-compatible)."""
        return [{"role": msg.role, "content": msg.content} for msg in messages]

    async def generate(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> LLMResponse:
        """Generate a response using vLLM."""
        await self._ensure_session()
        
        try:
            # Prepare the request payload (OpenAI-compatible)
            payload = {
                "model": self.model_name,
                "messages": self._convert_messages(messages),
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "stream": False
            }
            
            # Add optional parameters
            if "top_p" in kwargs:
                payload["top_p"] = kwargs["top_p"]
            elif hasattr(self.config, 'top_p'):
                payload["top_p"] = self.config.top_p
            
            if "frequency_penalty" in kwargs:
                payload["frequency_penalty"] = kwargs["frequency_penalty"]
            
            if "presence_penalty" in kwargs:
                payload["presence_penalty"] = kwargs["presence_penalty"]
            
            # vLLM-specific parameters
            if "best_of" in kwargs:
                payload["best_of"] = kwargs["best_of"]
            
            if "use_beam_search" in kwargs:
                payload["use_beam_search"] = kwargs["use_beam_search"]
            
            # Note: vLLM doesn't support function calling directly
            # Tools would need to be handled at a higher level
            if tools:
                logger.warning("vLLM provider doesn't support native function calling")
            
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            # Make the request
            async with self.session.post(
                self.api_endpoint,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=300)  # 5 minutes timeout
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"vLLM API error: {response.status} - {error_text}")
                
                result = await response.json()
            
            # Extract the response
            content = ""
            if result.get("choices") and len(result["choices"]) > 0:
                content = result["choices"][0]["message"]["content"]
            
            # Extract usage information
            usage = {}
            if "usage" in result:
                usage = {
                    "prompt_tokens": result["usage"].get("prompt_tokens", 0),
                    "completion_tokens": result["usage"].get("completion_tokens", 0),
                    "total_tokens": result["usage"].get("total_tokens", 0)
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
                raw_response=result
            )
            
        except Exception as e:
            logger.error(f"vLLM generation failed: {e}")
            raise

    async def stream_generate(
        self,
        messages: List[Message],
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        """Stream a response from vLLM."""
        await self._ensure_session()
        
        try:
            # Prepare the request payload
            payload = {
                "model": self.model_name,
                "messages": self._convert_messages(messages),
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "stream": True  # Enable streaming
            }
            
            # Add optional parameters
            if "top_p" in kwargs:
                payload["top_p"] = kwargs["top_p"]
            elif hasattr(self.config, 'top_p'):
                payload["top_p"] = self.config.top_p
            
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            # Make the streaming request
            async with self.session.post(
                self.api_endpoint,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=300)
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"vLLM API error: {response.status} - {error_text}")
                
                # Process the stream
                async for line in response.content:
                    line = line.decode('utf-8').strip()
                    if line.startswith("data: "):
                        data_str = line[6:]  # Remove "data: " prefix
                        
                        if data_str == "[DONE]":
                            break
                        
                        try:
                            data = json.loads(data_str)
                            if data.get("choices") and len(data["choices"]) > 0:
                                delta = data["choices"][0].get("delta", {})
                                if "content" in delta:
                                    yield delta["content"]
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse streaming response: {data_str}")
                            continue
                            
        except Exception as e:
            logger.error(f"vLLM streaming failed: {e}")
            raise

    async def health_check(self) -> bool:
        """Check if the vLLM server is healthy."""
        await self._ensure_session()
        
        try:
            # Check the models endpoint
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            async with self.session.get(
                self.models_endpoint,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    # Check if any models are available
                    return "data" in result and len(result["data"]) > 0
                return False
                
        except Exception as e:
            logger.error(f"vLLM health check failed: {e}")
            return False

    @property
    def supports_function_calling(self) -> bool:
        """Check if this provider supports function calling."""
        # vLLM doesn't natively support function calling
        # This would need to be implemented at a higher level
        return False

    @property
    def supports_vision(self) -> bool:
        """Check if this provider supports vision inputs."""
        # Depends on the loaded model
        # Some models like LLaVA support vision
        vision_models = ["llava", "qwen-vl", "cogvlm"]
        return any(model in self.model_name.lower() for model in vision_models)

    @property
    def max_context_window(self) -> int:
        """Get the maximum context window for this provider."""
        # This depends on the model loaded in vLLM
        # Common context windows for popular models
        context_windows = {
            "llama-3": 8192,
            "llama-3.1": 131072,  # 128k for Llama 3.1
            "llama-3.3": 131072,  # 128k for Llama 3.3
            "mistral": 32768,
            "mixtral": 32768,
            "deepseek": 32768,
            "deepseek-r1": 65536,  # 64k for DeepSeek-R1
            "qwen": 32768,
            "qwen-2.5": 131072,  # 128k for Qwen 2.5
            "yi": 200000,  # 200k for Yi models
            "command-r": 128000,  # 128k for Command R
        }
        
        # Check model name against known patterns
        model_lower = self.model_name.lower()
        for model_key, window_size in context_windows.items():
            if model_key in model_lower:
                return window_size
        
        # Default context window
        return 4096

    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self._close_session()