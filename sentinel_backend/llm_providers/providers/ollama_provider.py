"""
Ollama Provider Implementation

Implements the LLM provider interface for locally-hosted open-source models via Ollama.
"""

import asyncio
import aiohttp
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


class OllamaProvider(BaseLLMProvider):
    """
    Ollama provider implementation for open-source models.
    
    Supports:
    - DeepSeek-R1 (671B, 70B, 32B, 14B, 8B)
    - Llama 3.3 (70B)
    - Qwen 2.5 (72B, 32B, 7B)
    - Mistral (7B)
    - Phi-3 (14B)
    - Gemma 2 (27B)
    - Command R (35B)
    - Any other model available in Ollama
    
    Features:
    - Local inference (no API costs)
    - Streaming responses
    - Model management (pull, list, delete)
    - Custom model parameters
    """
    
    # Popular model configurations
    DEFAULT_MODELS = {
        "deepseek-r1": "deepseek-r1:671b",
        "deepseek-r1-70b": "deepseek-r1:70b",
        "llama3.3": "llama3.3:70b",
        "qwen2.5": "qwen2.5:72b",
        "qwen2.5-coder": "qwen2.5-coder:32b",
        "mistral": "mistral:7b",
        "phi3": "phi3:14b",
        "gemma2": "gemma2:27b",
        "command-r": "command-r:35b",
    }
    
    def __init__(self, config: LLMConfig):
        """Initialize Ollama provider."""
        super().__init__(config)
        self.base_url = config.api_base or "http://localhost:11434"
        self._validate_model_name()
    
    def _validate_config(self) -> None:
        """Validate Ollama-specific configuration."""
        # Ollama doesn't require API keys
        if not self.config.api_base:
            self.config.api_base = "http://localhost:11434"
            logger.info(f"Using default Ollama URL: {self.config.api_base}")
    
    def _validate_model_name(self):
        """Validate and normalize model name."""
        # Map common names to Ollama model tags
        if self.config.model in self.DEFAULT_MODELS:
            actual_model = self.DEFAULT_MODELS[self.config.model]
            logger.info(f"Mapping model {self.config.model} to {actual_model}")
            self.config.model = actual_model
    
    async def _make_request(
        self,
        endpoint: str,
        method: str = "POST",
        json_data: Optional[Dict] = None,
        stream: bool = False
    ) -> Any:
        """
        Make HTTP request to Ollama API.
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            json_data: Request body
            stream: Whether to stream response
            
        Returns:
            Response data or stream
        """
        url = f"{self.base_url}/api/{endpoint}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.request(
                    method,
                    url,
                    json=json_data,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if stream:
                        return response
                    
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_text = await response.text()
                        raise RuntimeError(f"Ollama API error ({response.status}): {error_text}")
                        
            except aiohttp.ClientError as e:
                logger.error(f"Ollama connection error: {e}")
                raise RuntimeError(f"Failed to connect to Ollama at {self.base_url}: {e}")
    
    async def pull_model(self, model_name: Optional[str] = None) -> bool:
        """
        Pull a model from Ollama registry.
        
        Args:
            model_name: Model to pull (uses config model if not specified)
            
        Returns:
            True if successful
        """
        model = model_name or self.config.model
        logger.info(f"Pulling model: {model}")
        
        try:
            await self._make_request(
                "pull",
                json_data={"name": model}
            )
            logger.info(f"Successfully pulled model: {model}")
            return True
        except Exception as e:
            logger.error(f"Failed to pull model {model}: {e}")
            return False
    
    async def list_models(self) -> List[Dict[str, Any]]:
        """
        List available models in Ollama.
        
        Returns:
            List of model information
        """
        try:
            response = await self._make_request("tags", method="GET")
            return response.get("models", [])
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []
    
    async def model_exists(self, model_name: Optional[str] = None) -> bool:
        """
        Check if a model exists locally.
        
        Args:
            model_name: Model to check (uses config model if not specified)
            
        Returns:
            True if model exists
        """
        model = model_name or self.config.model
        models = await self.list_models()
        
        for m in models:
            if m.get("name") == model:
                return True
        
        return False
    
    async def generate(
        self,
        messages: List[Message],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response using Ollama API.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters
            
        Returns:
            LLMResponse with generated content
        """
        # Check if model exists, offer to pull if not
        if not await self.model_exists():
            logger.warning(f"Model {self.config.model} not found locally")
            if kwargs.get("auto_pull", False):
                logger.info(f"Auto-pulling model {self.config.model}")
                await self.pull_model()
            else:
                raise RuntimeError(
                    f"Model {self.config.model} not found. "
                    f"Run 'ollama pull {self.config.model}' or set auto_pull=True"
                )
        
        # Format messages
        formatted_messages = self.format_messages(messages)
        
        # Prepare request
        request_data = {
            "model": self.config.model,
            "messages": formatted_messages,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", self.config.temperature),
                "top_p": kwargs.get("top_p", self.config.top_p),
                "seed": kwargs.get("seed"),
            }
        }
        
        # Add max tokens if specified
        if self.config.max_tokens:
            request_data["options"]["num_predict"] = self.config.max_tokens
        
        # Remove None values from options
        request_data["options"] = {
            k: v for k, v in request_data["options"].items() if v is not None
        }
        
        try:
            # Make API call
            start_time = datetime.now()
            response = await self._make_request("chat", json_data=request_data)
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            # Extract content
            content = response["message"]["content"]
            
            # Calculate token usage (Ollama provides these)
            usage = {
                "prompt_tokens": response.get("prompt_eval_count", 0),
                "completion_tokens": response.get("eval_count", 0),
                "total_tokens": (
                    response.get("prompt_eval_count", 0) + 
                    response.get("eval_count", 0)
                ),
                "cost": 0.0  # Local inference has no API cost
            }
            
            # Prepare metadata
            metadata = {
                "model": response.get("model", self.config.model),
                "total_duration_ms": response.get("total_duration", 0) / 1_000_000,
                "load_duration_ms": response.get("load_duration", 0) / 1_000_000,
                "prompt_eval_duration_ms": response.get("prompt_eval_duration", 0) / 1_000_000,
                "eval_duration_ms": response.get("eval_duration", 0) / 1_000_000,
                "tokens_per_second": (
                    response.get("eval_count", 0) / elapsed_time if elapsed_time > 0 else 0
                ),
            }
            
            return LLMResponse(
                content=content,
                model=self.config.model,
                provider=LLMProvider.OLLAMA,
                usage=usage,
                metadata=metadata,
                created_at=datetime.now(),
                cache_hit=False
            )
            
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            raise
    
    async def stream_generate(
        self,
        messages: List[Message],
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream response from Ollama.
        
        Args:
            messages: List of chat messages
            **kwargs: Additional parameters
            
        Yields:
            Chunks of generated text
        """
        # Check if model exists
        if not await self.model_exists():
            if kwargs.get("auto_pull", False):
                await self.pull_model()
            else:
                raise RuntimeError(f"Model {self.config.model} not found")
        
        # Format messages
        formatted_messages = self.format_messages(messages)
        
        # Prepare request
        request_data = {
            "model": self.config.model,
            "messages": formatted_messages,
            "stream": True,
            "options": {
                "temperature": kwargs.get("temperature", self.config.temperature),
                "top_p": kwargs.get("top_p", self.config.top_p),
            }
        }
        
        if self.config.max_tokens:
            request_data["options"]["num_predict"] = self.config.max_tokens
        
        url = f"{self.base_url}/api/chat"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, json=request_data) as response:
                    async for line in response.content:
                        if line:
                            try:
                                chunk = json.loads(line)
                                if "message" in chunk and "content" in chunk["message"]:
                                    yield chunk["message"]["content"]
                            except json.JSONDecodeError:
                                continue
                                
            except Exception as e:
                logger.error(f"Ollama streaming error: {e}")
                raise
    
    def get_capabilities(self) -> List[ModelCapability]:
        """Get model capabilities."""
        model_spec = get_model_spec(self.config.model)
        if model_spec:
            return model_spec.capabilities
        
        # Default capabilities for Ollama models
        capabilities = [
            ModelCapability.TEXT_GENERATION,
            ModelCapability.CODE_GENERATION,
            ModelCapability.STREAMING
        ]
        
        # Add model-specific capabilities
        model_lower = self.config.model.lower()
        
        if "deepseek-r1" in model_lower:
            capabilities.extend([
                ModelCapability.REASONING,
                ModelCapability.LONG_CONTEXT
            ])
        elif "llama" in model_lower or "qwen" in model_lower:
            capabilities.append(ModelCapability.LONG_CONTEXT)
        elif "coder" in model_lower or "codestral" in model_lower:
            # Code-specialized models
            pass
        elif "command-r" in model_lower:
            # RAG-optimized
            capabilities.append(ModelCapability.LONG_CONTEXT)
        
        return capabilities
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for open-source models.
        
        Most use similar tokenization to GPT models.
        """
        # Rough estimation: 1 token ≈ 4 characters
        return len(text) // 4
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        model_spec = get_model_spec(self.config.model)
        
        if model_spec:
            return {
                "provider": "Ollama (Local)",
                "model": self.config.model,
                "display_name": model_spec.display_name,
                "context_window": model_spec.context_window,
                "max_output_tokens": model_spec.max_output_tokens,
                "supports_streaming": True,
                "local_inference": True,
                "pricing": {
                    "input_per_1k": 0.0,
                    "output_per_1k": 0.0,
                    "note": "Local inference - no API costs"
                },
                "notes": model_spec.notes
            }
        
        # Fallback info
        return {
            "provider": "Ollama (Local)",
            "model": self.config.model,
            "display_name": self.config.model,
            "context_window": 32768,  # Conservative default
            "max_output_tokens": None,
            "supports_streaming": True,
            "local_inference": True,
            "pricing": {
                "input_per_1k": 0.0,
                "output_per_1k": 0.0,
                "note": "Local inference - no API costs"
            }
        }
    
    async def health_check(self) -> bool:
        """
        Check if Ollama service is accessible.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            # Check if Ollama service is running
            models = await self.list_models()
            
            # Check if our model exists
            if not await self.model_exists():
                logger.warning(f"Model {self.config.model} not available for health check")
                return False
            
            # Try a minimal generation
            response = await self.generate(
                [Message(role="user", content="Hi")],
                max_tokens=5
            )
            
            return bool(response.content)
            
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            return False