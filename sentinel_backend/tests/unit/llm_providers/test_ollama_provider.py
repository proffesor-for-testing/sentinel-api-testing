"""
Comprehensive Unit Tests for Ollama Provider

This module provides extensive test coverage for the Ollama provider,
including initialization, local model management, generation, and streaming.
"""

import pytest
import asyncio
import aiohttp
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List
from datetime import datetime

from sentinel_backend.llm_providers.providers.ollama_provider import OllamaProvider
from sentinel_backend.llm_providers.base_provider import (
    LLMConfig, LLMResponse, Message, LLMProvider, ModelCapability
)


class TestOllamaProvider:
    """Comprehensive test suite for Ollama provider"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return LLMConfig(
            provider=LLMProvider.OLLAMA,
            model="deepseek-r1:70b",
            api_base="http://localhost:11434",
            temperature=0.7,
            max_tokens=1000,
            top_p=0.95
        )
    
    @pytest.fixture
    def messages(self):
        """Create test messages"""
        return [
            Message(role="system", content="You are a helpful assistant"),
            Message(role="user", content="Explain quantum computing"),
            Message(role="assistant", content="Quantum computing uses quantum mechanics"),
            Message(role="user", content="Tell me more about qubits")
        ]
    
    @pytest.fixture
    def mock_session(self):
        """Mock aiohttp session"""
        with patch('aiohttp.ClientSession') as mock:
            yield mock
    
    def test_initialization_with_base_url(self, config):
        """Test provider initialization with base URL"""
        provider = OllamaProvider(config)
        
        assert provider.base_url == "http://localhost:11434"
        assert provider.config.model == "deepseek-r1:70b"
    
    def test_initialization_default_url(self):
        """Test provider initialization with default URL"""
        config = LLMConfig(
            provider=LLMProvider.OLLAMA,
            model="llama3.3:70b"
        )
        
        provider = OllamaProvider(config)
        assert provider.base_url == "http://localhost:11434"
    
    def test_model_name_validation(self, config):
        """Test model name mapping for popular models"""
        test_cases = [
            ("deepseek-r1", "deepseek-r1:671b"),
            ("deepseek-r1-70b", "deepseek-r1:70b"),
            ("llama3.3", "llama3.3:70b"),
            ("qwen2.5", "qwen2.5:72b"),
            ("qwen2.5-coder", "qwen2.5-coder:32b"),
            ("mistral", "mistral:7b"),
            ("phi3", "phi3:14b"),
            ("gemma2", "gemma2:27b"),
            ("command-r", "command-r:35b"),
            ("custom-model", "custom-model")  # Unknown model passes through
        ]
        
        for input_model, expected_model in test_cases:
            config.model = input_model
            provider = OllamaProvider(config)
            assert provider.config.model == expected_model
    
    @pytest.mark.asyncio
    async def test_make_request_success(self, config, mock_session):
        """Test successful HTTP request to Ollama API"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"success": True})
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(return_value=mock_response)
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        result = await provider._make_request("test", json_data={"test": "data"})
        
        assert result == {"success": True}
    
    @pytest.mark.asyncio
    async def test_make_request_error(self, config, mock_session):
        """Test error handling in HTTP request"""
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Internal Server Error")
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(return_value=mock_response)
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        
        with pytest.raises(RuntimeError, match="Ollama API error.*500"):
            await provider._make_request("test")
    
    @pytest.mark.asyncio
    async def test_pull_model(self, config, mock_session):
        """Test pulling a model from Ollama registry"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"status": "success"})
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(return_value=mock_response)
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        success = await provider.pull_model("llama3.3:70b")
        
        assert success is True
        
        # Verify request was made correctly
        mock_session_instance.request.assert_called_once()
        call_args = mock_session_instance.request.call_args
        assert call_args[1]["json"] == {"name": "llama3.3:70b"}
    
    @pytest.mark.asyncio
    async def test_list_models(self, config, mock_session):
        """Test listing available models"""
        mock_models = [
            {"name": "llama3.3:70b", "size": 40000000000},
            {"name": "deepseek-r1:70b", "size": 42000000000}
        ]
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"models": mock_models})
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(return_value=mock_response)
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        models = await provider.list_models()
        
        assert len(models) == 2
        assert models[0]["name"] == "llama3.3:70b"
    
    @pytest.mark.asyncio
    async def test_model_exists(self, config, mock_session):
        """Test checking if a model exists locally"""
        mock_models = [
            {"name": "deepseek-r1:70b"},
            {"name": "llama3.3:70b"}
        ]
        
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"models": mock_models})
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(return_value=mock_response)
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        
        exists = await provider.model_exists("deepseek-r1:70b")
        assert exists is True
        
        exists = await provider.model_exists("nonexistent:model")
        assert exists is False
    
    @pytest.mark.asyncio
    async def test_generate_basic(self, config, messages, mock_session):
        """Test basic text generation"""
        # Mock model exists check
        mock_list_response = AsyncMock()
        mock_list_response.status = 200
        mock_list_response.json = AsyncMock(return_value={
            "models": [{"name": "deepseek-r1:70b"}]
        })
        
        # Mock chat response
        mock_chat_response = AsyncMock()
        mock_chat_response.status = 200
        mock_chat_response.json = AsyncMock(return_value={
            "message": {"content": "Qubits are quantum bits that can exist in superposition."},
            "model": "deepseek-r1:70b",
            "prompt_eval_count": 100,
            "eval_count": 50,
            "total_duration": 5000000000,
            "load_duration": 1000000000,
            "prompt_eval_duration": 2000000000,
            "eval_duration": 2000000000
        })
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(side_effect=[
            mock_list_response,  # For model_exists check
            mock_chat_response   # For actual generation
        ])
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        response = await provider.generate(messages)
        
        assert isinstance(response, LLMResponse)
        assert response.content == "Qubits are quantum bits that can exist in superposition."
        assert response.model == "deepseek-r1:70b"
        assert response.provider == LLMProvider.OLLAMA
        assert response.usage["prompt_tokens"] == 100
        assert response.usage["completion_tokens"] == 50
        assert response.usage["cost"] == 0.0  # Local inference has no cost
        assert response.metadata["total_duration_ms"] == 5000.0
    
    @pytest.mark.asyncio
    async def test_generate_auto_pull(self, config, messages, mock_session):
        """Test automatic model pulling when model doesn't exist"""
        # Mock model doesn't exist
        mock_list_response = AsyncMock()
        mock_list_response.status = 200
        mock_list_response.json = AsyncMock(return_value={"models": []})
        
        # Mock pull response
        mock_pull_response = AsyncMock()
        mock_pull_response.status = 200
        mock_pull_response.json = AsyncMock(return_value={"status": "success"})
        
        # Mock chat response
        mock_chat_response = AsyncMock()
        mock_chat_response.status = 200
        mock_chat_response.json = AsyncMock(return_value={
            "message": {"content": "Response after pulling"},
            "model": "deepseek-r1:70b",
            "prompt_eval_count": 50,
            "eval_count": 25
        })
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(side_effect=[
            mock_list_response,  # model_exists returns False
            mock_pull_response,  # pull_model
            mock_chat_response   # actual generation
        ])
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        response = await provider.generate(messages, auto_pull=True)
        
        assert response.content == "Response after pulling"
    
    @pytest.mark.asyncio
    async def test_generate_model_not_found(self, config, messages, mock_session):
        """Test error when model is not found and auto_pull is False"""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"models": []})
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(return_value=mock_response)
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        
        with pytest.raises(RuntimeError, match="Model.*not found"):
            await provider.generate(messages, auto_pull=False)
    
    @pytest.mark.asyncio
    async def test_stream_generate(self, config, messages, mock_session):
        """Test streaming text generation"""
        # Mock model exists
        mock_list_response = AsyncMock()
        mock_list_response.status = 200
        mock_list_response.json = AsyncMock(return_value={
            "models": [{"name": "deepseek-r1:70b"}]
        })
        
        # Create mock streaming response
        chunks = [
            json.dumps({"message": {"content": "Quantum"}}),
            json.dumps({"message": {"content": " computing"}}),
            json.dumps({"message": {"content": " is"}}),
            json.dumps({"message": {"content": " fascinating"}})
        ]
        
        mock_content = AsyncMock()
        async def mock_iter():
            for chunk in chunks:
                yield chunk.encode()
        mock_content.__aiter__ = mock_iter
        
        mock_stream_response = AsyncMock()
        mock_stream_response.content = mock_content
        
        mock_session_instance = AsyncMock()
        # First call for model_exists, second for streaming
        mock_session_instance.request.return_value = mock_list_response
        mock_session_instance.post.return_value.__aenter__.return_value = mock_stream_response
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        
        collected_chunks = []
        async for chunk in provider.stream_generate(messages):
            collected_chunks.append(chunk)
        
        assert collected_chunks == ["Quantum", " computing", " is", " fascinating"]
    
    def test_get_capabilities(self, config):
        """Test capability detection for different models"""
        provider = OllamaProvider(config)
        
        # Test DeepSeek-R1 capabilities
        config.model = "deepseek-r1:70b"
        provider = OllamaProvider(config)
        capabilities = provider.get_capabilities()
        assert ModelCapability.REASONING in capabilities
        assert ModelCapability.LONG_CONTEXT in capabilities
        assert ModelCapability.TEXT_GENERATION in capabilities
        
        # Test Llama capabilities
        config.model = "llama3.3:70b"
        provider = OllamaProvider(config)
        capabilities = provider.get_capabilities()
        assert ModelCapability.LONG_CONTEXT in capabilities
        assert ModelCapability.REASONING not in capabilities
        
        # Test coder model capabilities
        config.model = "qwen2.5-coder:32b"
        provider = OllamaProvider(config)
        capabilities = provider.get_capabilities()
        assert ModelCapability.CODE_GENERATION in capabilities
    
    def test_estimate_tokens(self, config):
        """Test token estimation"""
        provider = OllamaProvider(config)
        
        text = "This is a test string with some words."
        estimated = provider.estimate_tokens(text)
        
        # Rough estimation: 1 token ≈ 4 characters
        expected = len(text) // 4
        assert estimated == expected
    
    def test_get_model_info(self, config):
        """Test model information retrieval"""
        provider = OllamaProvider(config)
        info = provider.get_model_info()
        
        assert info["provider"] == "Ollama (Local)"
        assert info["model"] == "deepseek-r1:70b"
        assert info["local_inference"] is True
        assert info["supports_streaming"] is True
        assert info["pricing"]["input_per_1k"] == 0.0
        assert info["pricing"]["output_per_1k"] == 0.0
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, config, mock_session):
        """Test successful health check"""
        # Mock list models response
        mock_list_response = AsyncMock()
        mock_list_response.status = 200
        mock_list_response.json = AsyncMock(return_value={
            "models": [{"name": "deepseek-r1:70b"}]
        })
        
        # Mock minimal generation response
        mock_gen_response = AsyncMock()
        mock_gen_response.status = 200
        mock_gen_response.json = AsyncMock(return_value={
            "message": {"content": "Hi"},
            "model": "deepseek-r1:70b",
            "prompt_eval_count": 5,
            "eval_count": 2
        })
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(side_effect=[
            mock_list_response,  # list_models
            mock_list_response,  # model_exists
            mock_gen_response    # generate
        ])
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        is_healthy = await provider.health_check()
        
        assert is_healthy is True
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self, config, mock_session):
        """Test failed health check"""
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(side_effect=Exception("Connection failed"))
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        is_healthy = await provider.health_check()
        
        assert is_healthy is False
    
    @pytest.mark.asyncio
    async def test_generate_with_options(self, config, messages, mock_session):
        """Test generation with custom options"""
        mock_list_response = AsyncMock()
        mock_list_response.status = 200
        mock_list_response.json = AsyncMock(return_value={
            "models": [{"name": "deepseek-r1:70b"}]
        })
        
        mock_chat_response = AsyncMock()
        mock_chat_response.status = 200
        mock_chat_response.json = AsyncMock(return_value={
            "message": {"content": "Response with seed"},
            "model": "deepseek-r1:70b",
            "prompt_eval_count": 50,
            "eval_count": 25
        })
        
        mock_session_instance = AsyncMock()
        mock_session_instance.request = AsyncMock(side_effect=[
            mock_list_response,
            mock_chat_response
        ])
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session.return_value = mock_session_instance
        
        provider = OllamaProvider(config)
        response = await provider.generate(
            messages,
            temperature=0.5,
            top_p=0.8,
            seed=12345
        )
        
        # Verify the request included custom options
        call_args = mock_session_instance.request.call_args_list[1]
        request_data = call_args[1]["json"]
        assert request_data["options"]["temperature"] == 0.5
        assert request_data["options"]["top_p"] == 0.8
        assert request_data["options"]["seed"] == 12345