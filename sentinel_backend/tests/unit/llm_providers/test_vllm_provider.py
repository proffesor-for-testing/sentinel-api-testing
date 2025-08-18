"""
Comprehensive Unit Tests for vLLM Provider

This module provides extensive test coverage for the vLLM provider,
including initialization, high-performance local model serving, and streaming.
"""

import pytest
import asyncio
import aiohttp
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List

from sentinel_backend.llm_providers.providers.vllm_provider import VLLMProvider
from sentinel_backend.llm_providers.base_provider import LLMConfig, LLMResponse, Message


class TestVLLMProvider:
    """Comprehensive test suite for vLLM provider"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return LLMConfig(
            provider="vllm",
            model="llama-3.3-70b",
            api_key="test-vllm-key",
            api_base="http://localhost:8000",
            temperature=0.7,
            max_tokens=1000,
            top_p=0.95
        )
    
    @pytest.fixture
    def messages(self):
        """Create test messages"""
        return [
            Message(role="system", content="You are a helpful assistant"),
            Message(role="user", content="What is machine learning?"),
            Message(role="assistant", content="Machine learning is a subset of AI"),
            Message(role="user", content="Give me an example")
        ]
    
    @pytest.fixture
    async def mock_provider(self, config):
        """Create provider with mocked session"""
        provider = VLLMProvider(config)
        provider.session = AsyncMock(spec=aiohttp.ClientSession)
        return provider
    
    def test_initialization_with_api_key(self, config):
        """Test provider initialization with API key"""
        provider = VLLMProvider(config)
        
        assert provider.api_key == "test-vllm-key"
        assert provider.base_url == "http://localhost:8000"
        assert provider.model_name == "llama-3.3-70b"
        assert provider.api_endpoint == "http://localhost:8000/v1/chat/completions"
        assert provider.models_endpoint == "http://localhost:8000/v1/models"
    
    def test_initialization_from_environment(self):
        """Test provider initialization with environment variables"""
        with patch.dict('os.environ', {
            'SENTINEL_APP_VLLM_BASE_URL': 'http://vllm-server:8080',
            'SENTINEL_APP_VLLM_API_KEY': 'env-api-key'
        }):
            config = LLMConfig(provider="vllm", model="mistral-7b")
            provider = VLLMProvider(config)
            
            assert provider.base_url == "http://vllm-server:8080"
            assert provider.api_key == "env-api-key"
    
    def test_initialization_default_url(self):
        """Test provider initialization with default URL"""
        config = LLMConfig(provider="vllm", model="llama-3.3-70b")
        provider = VLLMProvider(config)
        
        assert provider.base_url == "http://localhost:8000"
    
    def test_url_cleanup(self):
        """Test that trailing slashes are removed from base URL"""
        config = LLMConfig(
            provider="vllm",
            model="test-model",
            api_base="http://localhost:8000/"
        )
        provider = VLLMProvider(config)
        
        assert provider.base_url == "http://localhost:8000"
        assert provider.api_endpoint == "http://localhost:8000/v1/chat/completions"
    
    def test_convert_messages(self, config):
        """Test message conversion to OpenAI-compatible format"""
        provider = VLLMProvider(config)
        
        messages = [
            Message(role="system", content="System prompt"),
            Message(role="user", content="User message"),
            Message(role="assistant", content="Assistant response")
        ]
        
        converted = provider._convert_messages(messages)
        
        assert len(converted) == 3
        assert converted[0] == {"role": "system", "content": "System prompt"}
        assert converted[1] == {"role": "user", "content": "User message"}
        assert converted[2] == {"role": "assistant", "content": "Assistant response"}
    
    @pytest.mark.asyncio
    async def test_ensure_session(self, config):
        """Test session creation"""
        provider = VLLMProvider(config)
        assert provider.session is None
        
        await provider._ensure_session()
        assert provider.session is not None
        
        # Clean up
        await provider._close_session()
    
    @pytest.mark.asyncio
    async def test_generate_basic(self, mock_provider, messages):
        """Test basic text generation"""
        mock_response = {
            "choices": [{
                "message": {
                    "content": "Machine learning examples include recommendation systems."
                }
            }],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": 20,
                "total_tokens": 70
            }
        }
        
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 200
        mock_post.__aenter__.return_value.json = AsyncMock(return_value=mock_response)
        mock_provider.session.post.return_value = mock_post
        
        response = await mock_provider.generate(messages)
        
        assert isinstance(response, LLMResponse)
        assert response.content == "Machine learning examples include recommendation systems."
        assert response.role == "assistant"
        assert response.model == "llama-3.3-70b"
        assert response.usage["prompt_tokens"] == 50
        assert response.usage["completion_tokens"] == 20
        assert response.usage["total_tokens"] == 70
    
    @pytest.mark.asyncio
    async def test_generate_with_vllm_params(self, mock_provider, messages):
        """Test generation with vLLM-specific parameters"""
        mock_response = {
            "choices": [{
                "message": {"content": "Response with vLLM params"}
            }],
            "usage": {"prompt_tokens": 30, "completion_tokens": 10, "total_tokens": 40}
        }
        
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 200
        mock_post.__aenter__.return_value.json = AsyncMock(return_value=mock_response)
        mock_provider.session.post.return_value = mock_post
        
        response = await mock_provider.generate(
            messages,
            best_of=2,
            use_beam_search=True,
            frequency_penalty=0.5,
            presence_penalty=0.3
        )
        
        # Verify the request included vLLM-specific params
        call_args = mock_provider.session.post.call_args
        payload = call_args[1]["json"]
        assert payload["best_of"] == 2
        assert payload["use_beam_search"] is True
        assert payload["frequency_penalty"] == 0.5
        assert payload["presence_penalty"] == 0.3
    
    @pytest.mark.asyncio
    async def test_generate_with_tools_warning(self, mock_provider, messages):
        """Test that tools generate a warning (vLLM doesn't support function calling)"""
        mock_response = {
            "choices": [{"message": {"content": "Response without tools"}}],
            "usage": {"prompt_tokens": 30, "completion_tokens": 10, "total_tokens": 40}
        }
        
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 200
        mock_post.__aenter__.return_value.json = AsyncMock(return_value=mock_response)
        mock_provider.session.post.return_value = mock_post
        
        tools = [{"name": "test_tool", "description": "Test"}]
        
        with patch('sentinel_backend.llm_providers.providers.vllm_provider.logger') as mock_logger:
            response = await mock_provider.generate(messages, tools=tools)
            mock_logger.warning.assert_called_with(
                "vLLM provider doesn't support native function calling"
            )
    
    @pytest.mark.asyncio
    async def test_generate_error_handling(self, mock_provider, messages):
        """Test error handling during generation"""
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 500
        mock_post.__aenter__.return_value.text = AsyncMock(
            return_value="Internal Server Error"
        )
        mock_provider.session.post.return_value = mock_post
        
        with pytest.raises(Exception, match="vLLM API error: 500"):
            await mock_provider.generate(messages)
    
    @pytest.mark.asyncio
    async def test_generate_token_estimation(self, mock_provider, messages):
        """Test token estimation when usage data is not provided"""
        mock_response = {
            "choices": [{"message": {"content": "Short response"}}]
            # No usage data provided
        }
        
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 200
        mock_post.__aenter__.return_value.json = AsyncMock(return_value=mock_response)
        mock_provider.session.post.return_value = mock_post
        
        response = await mock_provider.generate(messages)
        
        # Check that tokens were estimated
        assert response.usage["prompt_tokens"] > 0
        assert response.usage["completion_tokens"] > 0
        assert response.usage["total_tokens"] > 0
    
    @pytest.mark.asyncio
    async def test_stream_generate(self, mock_provider, messages):
        """Test streaming text generation"""
        # Create mock streaming response
        stream_data = [
            b'data: {"choices":[{"delta":{"content":"Machine"}}]}\n',
            b'data: {"choices":[{"delta":{"content":" learning"}}]}\n',
            b'data: {"choices":[{"delta":{"content":" is"}}]}\n',
            b'data: {"choices":[{"delta":{"content":" amazing"}}]}\n',
            b'data: [DONE]\n'
        ]
        
        mock_content = AsyncMock()
        async def mock_iter():
            for chunk in stream_data:
                yield chunk
        mock_content.__aiter__ = mock_iter
        
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 200
        mock_post.__aenter__.return_value.content = mock_content
        mock_provider.session.post.return_value = mock_post
        
        # Collect streamed chunks
        chunks = []
        async for chunk in mock_provider.stream_generate(messages):
            chunks.append(chunk)
        
        assert chunks == ["Machine", " learning", " is", " amazing"]
    
    @pytest.mark.asyncio
    async def test_stream_generate_error_handling(self, mock_provider, messages):
        """Test error handling during streaming"""
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 400
        mock_post.__aenter__.return_value.text = AsyncMock(return_value="Bad Request")
        mock_provider.session.post.return_value = mock_post
        
        with pytest.raises(Exception, match="vLLM API error: 400"):
            async for _ in mock_provider.stream_generate(messages):
                pass
    
    @pytest.mark.asyncio
    async def test_stream_generate_malformed_json(self, mock_provider, messages):
        """Test handling of malformed JSON in stream"""
        stream_data = [
            b'data: {"choices":[{"delta":{"content":"Valid"}}]}\n',
            b'data: {malformed json}\n',  # This should be skipped
            b'data: {"choices":[{"delta":{"content":" data"}}]}\n',
            b'data: [DONE]\n'
        ]
        
        mock_content = AsyncMock()
        async def mock_iter():
            for chunk in stream_data:
                yield chunk
        mock_content.__aiter__ = mock_iter
        
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 200
        mock_post.__aenter__.return_value.content = mock_content
        mock_provider.session.post.return_value = mock_post
        
        with patch('sentinel_backend.llm_providers.providers.vllm_provider.logger') as mock_logger:
            chunks = []
            async for chunk in mock_provider.stream_generate(messages):
                chunks.append(chunk)
            
            # Should skip malformed JSON and continue
            assert chunks == ["Valid", " data"]
            mock_logger.warning.assert_called()
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, mock_provider):
        """Test successful health check"""
        mock_models = {
            "data": [
                {"id": "llama-3.3-70b", "object": "model"},
                {"id": "mistral-7b", "object": "model"}
            ]
        }
        
        mock_get = AsyncMock()
        mock_get.__aenter__.return_value.status = 200
        mock_get.__aenter__.return_value.json = AsyncMock(return_value=mock_models)
        mock_provider.session.get.return_value = mock_get
        
        is_healthy = await mock_provider.health_check()
        
        assert is_healthy is True
        mock_provider.session.get.assert_called_once_with(
            mock_provider.models_endpoint,
            headers={},
            timeout=pytest.approx(10, abs=1)
        )
    
    @pytest.mark.asyncio
    async def test_health_check_with_auth(self, mock_provider):
        """Test health check with authentication"""
        mock_provider.api_key = "test-key"
        
        mock_models = {"data": [{"id": "model1"}]}
        mock_get = AsyncMock()
        mock_get.__aenter__.return_value.status = 200
        mock_get.__aenter__.return_value.json = AsyncMock(return_value=mock_models)
        mock_provider.session.get.return_value = mock_get
        
        is_healthy = await mock_provider.health_check()
        
        assert is_healthy is True
        call_args = mock_provider.session.get.call_args
        assert call_args[1]["headers"]["Authorization"] == "Bearer test-key"
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self, mock_provider):
        """Test failed health check"""
        mock_get = AsyncMock()
        mock_get.__aenter__.return_value.status = 500
        mock_provider.session.get.return_value = mock_get
        
        is_healthy = await mock_provider.health_check()
        assert is_healthy is False
    
    @pytest.mark.asyncio
    async def test_health_check_exception(self, mock_provider):
        """Test health check with exception"""
        mock_provider.session.get.side_effect = Exception("Connection error")
        
        is_healthy = await mock_provider.health_check()
        assert is_healthy is False
    
    def test_supports_function_calling(self, config):
        """Test function calling support (vLLM doesn't support it)"""
        provider = VLLMProvider(config)
        assert provider.supports_function_calling is False
    
    def test_supports_vision(self, config):
        """Test vision support detection"""
        provider = VLLMProvider(config)
        
        # Test vision models
        vision_models = ["llava-1.5", "qwen-vl-chat", "cogvlm-chat"]
        for model in vision_models:
            provider.model_name = model
            assert provider.supports_vision is True
        
        # Test non-vision models
        provider.model_name = "llama-3.3-70b"
        assert provider.supports_vision is False
    
    def test_max_context_window(self, config):
        """Test context window sizes for different models"""
        provider = VLLMProvider(config)
        
        test_cases = [
            ("llama-3-8b", 8192),
            ("llama-3.1-70b", 131072),
            ("llama-3.3-70b", 131072),
            ("mistral-7b", 32768),
            ("mixtral-8x7b", 32768),
            ("deepseek-coder", 32768),
            ("deepseek-r1-70b", 65536),
            ("qwen-72b", 32768),
            ("qwen-2.5-72b", 131072),
            ("yi-34b", 200000),
            ("command-r-plus", 128000),
            ("unknown-model", 4096)  # Default
        ]
        
        for model, expected_window in test_cases:
            provider.model_name = model
            assert provider.max_context_window == expected_window
    
    @pytest.mark.asyncio
    async def test_context_manager(self, config):
        """Test async context manager functionality"""
        provider = VLLMProvider(config)
        
        async with provider as p:
            assert p.session is not None
            assert isinstance(p.session, aiohttp.ClientSession)
        
        # Session should be closed after exiting context
        assert provider.session is None
    
    @pytest.mark.asyncio
    async def test_generate_with_authorization(self, mock_provider, messages):
        """Test that authorization header is included when API key is present"""
        mock_provider.api_key = "test-api-key"
        
        mock_response = {
            "choices": [{"message": {"content": "Authorized response"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        }
        
        mock_post = AsyncMock()
        mock_post.__aenter__.return_value.status = 200
        mock_post.__aenter__.return_value.json = AsyncMock(return_value=mock_response)
        mock_provider.session.post.return_value = mock_post
        
        await mock_provider.generate(messages)
        
        call_args = mock_provider.session.post.call_args
        headers = call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer test-api-key"
        assert headers["Content-Type"] == "application/json"