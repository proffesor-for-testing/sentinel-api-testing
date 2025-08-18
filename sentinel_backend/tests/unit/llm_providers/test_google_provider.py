"""
Comprehensive Unit Tests for Google (Gemini) Provider

This module provides extensive test coverage for the Google Gemini provider,
including initialization, generation, streaming, and error handling.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock, PropertyMock
from typing import Dict, Any, List
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from sentinel_backend.llm_providers.providers.google_provider import GoogleProvider
from sentinel_backend.llm_providers.base_provider import LLMConfig, LLMResponse, Message


class TestGoogleProvider:
    """Comprehensive test suite for Google Gemini provider"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return LLMConfig(
            provider="google",
            model="gemini-2.5-pro",
            api_key="test-google-api-key",
            temperature=0.7,
            max_tokens=1000,
            top_p=0.95
        )
    
    @pytest.fixture
    def messages(self):
        """Create test messages"""
        return [
            Message(role="system", content="You are a helpful assistant"),
            Message(role="user", content="Hello, how are you?"),
            Message(role="assistant", content="I'm doing well, thank you!"),
            Message(role="user", content="Can you help me with Python?")
        ]
    
    @pytest.fixture
    def mock_genai(self):
        """Mock the Google Generative AI module"""
        with patch('sentinel_backend.llm_providers.providers.google_provider.genai') as mock:
            yield mock
    
    def test_initialization_with_api_key(self, config, mock_genai):
        """Test provider initialization with API key"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        
        assert provider.api_key == "test-google-api-key"
        assert provider.model_name == "gemini-2.5-pro"
        mock_genai.configure.assert_called_once_with(api_key="test-google-api-key")
        mock_genai.GenerativeModel.assert_called_once()
    
    def test_initialization_from_environment(self, mock_genai):
        """Test provider initialization with environment variable"""
        with patch.dict('os.environ', {'SENTINEL_APP_GOOGLE_API_KEY': 'env-api-key'}):
            config = LLMConfig(provider="google", model="gemini-2.5-flash")
            
            mock_model = MagicMock()
            mock_genai.GenerativeModel.return_value = mock_model
            
            provider = GoogleProvider(config)
            
            assert provider.api_key == "env-api-key"
            mock_genai.configure.assert_called_once_with(api_key="env-api-key")
    
    def test_initialization_without_api_key(self):
        """Test initialization fails without API key"""
        config = LLMConfig(provider="google", model="gemini-2.5-pro")
        
        with pytest.raises(ValueError, match="Google API key not provided"):
            GoogleProvider(config)
    
    def test_model_name_mapping(self, config, mock_genai):
        """Test model name mapping for different Gemini versions"""
        test_cases = [
            ("gemini-2.5-pro", "gemini-2.5-pro"),
            ("gemini-2.5-flash", "gemini-2.5-flash"),
            ("gemini-2.0-flash", "gemini-2.0-flash-exp"),
            ("gemini-1.5-pro", "gemini-1.5-pro"),
            ("gemini-pro", "gemini-pro"),
            ("custom-model", "custom-model")  # Unknown model passes through
        ]
        
        for input_model, expected_model in test_cases:
            config.model = input_model
            mock_model = MagicMock()
            mock_genai.GenerativeModel.return_value = mock_model
            
            provider = GoogleProvider(config)
            assert provider.model_name == expected_model
    
    def test_safety_settings(self, config, mock_genai):
        """Test safety settings configuration"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        
        # Check safety settings are properly configured
        call_args = mock_genai.GenerativeModel.call_args
        safety_settings = call_args[1]['safety_settings']
        
        assert HarmCategory.HARM_CATEGORY_HATE_SPEECH in safety_settings
        assert safety_settings[HarmCategory.HARM_CATEGORY_HATE_SPEECH] == HarmBlockThreshold.BLOCK_ONLY_HIGH
    
    @pytest.mark.asyncio
    async def test_generate_basic(self, config, messages, mock_genai):
        """Test basic text generation"""
        # Setup mocks
        mock_model = MagicMock()
        mock_chat = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Hello! I'd be happy to help you with Python."
        
        mock_model.start_chat.return_value = mock_chat
        mock_chat.send_message_async = AsyncMock(return_value=mock_response)
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        response = await provider.generate(messages)
        
        assert isinstance(response, LLMResponse)
        assert response.content == "Hello! I'd be happy to help you with Python."
        assert response.role == "assistant"
        assert response.model == "gemini-2.5-pro"
        assert "prompt_tokens" in response.usage
        assert "completion_tokens" in response.usage
        assert "total_tokens" in response.usage
    
    @pytest.mark.asyncio
    async def test_generate_with_tools(self, config, messages, mock_genai):
        """Test generation with function calling tools"""
        mock_model = MagicMock()
        mock_chat = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "I'll help you with that function."
        
        mock_model.start_chat.return_value = mock_chat
        mock_chat.send_message_async = AsyncMock(return_value=mock_response)
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        
        tools = [
            {
                "name": "get_weather",
                "description": "Get weather information",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string"}
                    }
                }
            }
        ]
        
        response = await provider.generate(messages, tools=tools)
        
        assert isinstance(response, LLMResponse)
        assert response.content == "I'll help you with that function."
    
    @pytest.mark.asyncio
    async def test_stream_generate(self, config, messages, mock_genai):
        """Test streaming text generation"""
        # Setup streaming response
        mock_model = MagicMock()
        mock_chat = MagicMock()
        
        # Create async generator for streaming
        async def mock_stream():
            chunks = ["Hello", " there", "!", " How", " can", " I", " help?"]
            for chunk in chunks:
                mock_chunk = MagicMock()
                mock_chunk.text = chunk
                yield mock_chunk
        
        mock_response = mock_stream()
        mock_chat.send_message_async = AsyncMock(return_value=mock_response)
        mock_model.start_chat.return_value = mock_chat
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        
        # Collect streamed chunks
        chunks = []
        async for chunk in provider.stream_generate(messages):
            chunks.append(chunk)
        
        assert chunks == ["Hello", " there", "!", " How", " can", " I", " help?"]
    
    @pytest.mark.asyncio
    async def test_generate_error_handling(self, config, messages, mock_genai):
        """Test error handling during generation"""
        mock_model = MagicMock()
        mock_chat = MagicMock()
        mock_chat.send_message_async = AsyncMock(side_effect=Exception("API Error"))
        mock_model.start_chat.return_value = mock_chat
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        
        with pytest.raises(Exception, match="API Error"):
            await provider.generate(messages)
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, config, mock_genai):
        """Test successful health check"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        # Mock list_models to return some models
        mock_models = [MagicMock(), MagicMock()]
        mock_genai.list_models.return_value = mock_models
        
        provider = GoogleProvider(config)
        is_healthy = await provider.health_check()
        
        assert is_healthy is True
        mock_genai.list_models.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self, config, mock_genai):
        """Test failed health check"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_genai.list_models.side_effect = Exception("Connection error")
        
        provider = GoogleProvider(config)
        is_healthy = await provider.health_check()
        
        assert is_healthy is False
    
    def test_supports_function_calling(self, config, mock_genai):
        """Test function calling support detection"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        # Test Gemini 1.5 models (support function calling)
        config.model = "gemini-1.5-pro"
        provider = GoogleProvider(config)
        assert provider.supports_function_calling is True
        
        # Test non-1.5 models
        config.model = "gemini-pro"
        provider = GoogleProvider(config)
        assert provider.supports_function_calling is False
    
    def test_supports_vision(self, config, mock_genai):
        """Test vision support detection"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        # Test vision models
        config.model = "gemini-pro-vision"
        provider = GoogleProvider(config)
        assert provider.supports_vision is True
        
        # Test Gemini 1.5 models (also support vision)
        config.model = "gemini-1.5-flash"
        provider = GoogleProvider(config)
        assert provider.supports_vision is True
        
        # Test non-vision models
        config.model = "gemini-pro"
        provider = GoogleProvider(config)
        assert provider.supports_vision is False
    
    def test_max_context_window(self, config, mock_genai):
        """Test context window sizes for different models"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        test_cases = [
            ("gemini-1.5-pro", 2000000),    # 2M tokens
            ("gemini-1.5-flash", 1000000),  # 1M tokens
            ("gemini-pro", 32768),           # 32k tokens
            ("gemini-pro-vision", 16384),   # 16k tokens
            ("unknown-model", 32768)         # Default
        ]
        
        for model, expected_window in test_cases:
            config.model = model
            provider = GoogleProvider(config)
            assert provider.max_context_window == expected_window
    
    def test_convert_messages_to_chat_format(self, config, messages, mock_genai):
        """Test message conversion to Gemini chat format"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        chat_history = provider._convert_messages_to_chat_format(messages)
        
        # Check format
        assert len(chat_history) == 3  # System message gets prepended to first user message
        assert chat_history[0]["role"] == "user"
        assert "You are a helpful assistant" in chat_history[0]["parts"][0]
        assert "Hello, how are you?" in chat_history[0]["parts"][0]
        assert chat_history[1]["role"] == "model"
        assert chat_history[2]["role"] == "user"
    
    def test_convert_messages_to_prompt(self, config, messages, mock_genai):
        """Test message conversion to single prompt"""
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        prompt = provider._convert_messages_to_prompt(messages)
        
        assert "System: You are a helpful assistant" in prompt
        assert "User: Hello, how are you?" in prompt
        assert "Assistant: I'm doing well, thank you!" in prompt
        assert "User: Can you help me with Python?" in prompt
    
    @pytest.mark.asyncio
    async def test_token_usage_calculation(self, config, messages, mock_genai):
        """Test token usage calculation in response"""
        mock_model = MagicMock()
        mock_chat = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "This is a test response."
        
        mock_model.start_chat.return_value = mock_chat
        mock_chat.send_message_async = AsyncMock(return_value=mock_response)
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        response = await provider.generate(messages)
        
        # Check token usage is calculated
        assert response.usage["prompt_tokens"] > 0
        assert response.usage["completion_tokens"] > 0
        assert response.usage["total_tokens"] == (
            response.usage["prompt_tokens"] + response.usage["completion_tokens"]
        )
    
    @pytest.mark.asyncio
    async def test_stream_error_handling(self, config, messages, mock_genai):
        """Test error handling during streaming"""
        mock_model = MagicMock()
        mock_chat = MagicMock()
        
        # Create async generator that raises error
        async def mock_stream_error():
            yield MagicMock(text="First chunk")
            raise Exception("Streaming error")
        
        mock_chat.send_message_async = AsyncMock(return_value=mock_stream_error())
        mock_model.start_chat.return_value = mock_chat
        mock_genai.GenerativeModel.return_value = mock_model
        
        provider = GoogleProvider(config)
        
        chunks = []
        with pytest.raises(Exception, match="Streaming error"):
            async for chunk in provider.stream_generate(messages):
                chunks.append(chunk)
        
        assert chunks == ["First chunk"]  # Got first chunk before error