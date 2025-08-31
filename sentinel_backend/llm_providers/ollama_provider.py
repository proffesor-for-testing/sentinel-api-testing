"""
Ollama LLM Provider

Provides integration with locally-hosted Ollama models for fast, private inference.
"""

import json
import requests
from typing import Dict, List, Optional, Any
from .base_provider import BaseLLMProvider, LLMConfig, LLMResponse, ModelCapability


class OllamaProvider(BaseLLMProvider):
    """Ollama provider for local LLM inference"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        # Default Ollama API endpoint
        self.api_base = config.api_base or "http://localhost:11434"
        
    def generate(self, 
                 prompt: str, 
                 system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate response using Ollama"""
        
        # Prepare the request
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "top_p": self.config.top_p,
                "num_predict": self.config.max_tokens or 2048
            }
        }
        
        try:
            response = requests.post(
                f"{self.api_base}/api/chat",
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            
            result = response.json()
            
            # Extract the response
            content = result.get("message", {}).get("content", "")
            
            # Parse tokens from response if available
            eval_count = result.get("eval_count", 0)
            prompt_eval_count = result.get("prompt_eval_count", 0)
            
            return LLMResponse(
                content=content,
                model=self.config.model,
                usage={
                    "prompt_tokens": prompt_eval_count,
                    "completion_tokens": eval_count,
                    "total_tokens": prompt_eval_count + eval_count
                },
                raw_response=result,
                finish_reason="stop",
                provider=self.config.provider
            )
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Ollama API error: {str(e)}")
        except Exception as e:
            raise Exception(f"Error generating with Ollama: {str(e)}")
    
    async def generate_async(self, 
                            prompt: str,
                            system_prompt: Optional[str] = None,
                            **kwargs) -> LLMResponse:
        """Async generation using aiohttp"""
        import aiohttp
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "top_p": self.config.top_p,
                "num_predict": self.config.max_tokens or 2048
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.api_base}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                result = await response.json()
                
                content = result.get("message", {}).get("content", "")
                eval_count = result.get("eval_count", 0)
                prompt_eval_count = result.get("prompt_eval_count", 0)
                
                return LLMResponse(
                    content=content,
                    model=self.config.model,
                    usage={
                        "prompt_tokens": prompt_eval_count,
                        "completion_tokens": eval_count,
                        "total_tokens": prompt_eval_count + eval_count
                    },
                    raw_response=result,
                    finish_reason="stop",
                    provider=self.config.provider
                )
    
    def get_capabilities(self) -> List[ModelCapability]:
        """Get model capabilities based on model name"""
        capabilities = [
            ModelCapability.TEXT_GENERATION,
            ModelCapability.STREAMING
        ]
        
        # Add code generation for code-specific models
        if any(x in self.config.model.lower() for x in ["code", "deepseek", "codellama"]):
            capabilities.append(ModelCapability.CODE_GENERATION)
        
        # Add reasoning for models that support it
        if "deepseek" in self.config.model.lower():
            capabilities.append(ModelCapability.REASONING)
        
        # Most modern models support long context
        capabilities.append(ModelCapability.LONG_CONTEXT)
        
        return capabilities
    
    def validate_config(self) -> bool:
        """Validate Ollama is accessible and model exists"""
        try:
            # Check if Ollama is running
            response = requests.get(f"{self.api_base}/api/tags", timeout=2)
            if response.status_code != 200:
                return False
            
            # Check if model exists
            models = response.json().get("models", [])
            model_names = [m.get("name", "").split(":")[0] for m in models]
            
            # Handle model name with or without tag
            requested_model = self.config.model.split(":")[0]
            return requested_model in model_names
            
        except:
            return False
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate tokens (rough approximation)"""
        # Rough estimate: 1 token ≈ 4 characters
        return len(text) // 4
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the Ollama model"""
        try:
            response = requests.post(
                f"{self.api_base}/api/show",
                json={"name": self.config.model},
                timeout=5
            )
            
            if response.status_code == 200:
                info = response.json()
                return {
                    "provider": "ollama",
                    "model": self.config.model,
                    "parameters": info.get("parameters", ""),
                    "template": info.get("template", ""),
                    "capabilities": [cap.value for cap in self.get_capabilities()],
                    "local": True,
                    "api_base": self.api_base
                }
        except:
            pass
        
        return {
            "provider": "ollama",
            "model": self.config.model,
            "capabilities": [cap.value for cap in self.get_capabilities()],
            "local": True,
            "api_base": self.api_base
        }