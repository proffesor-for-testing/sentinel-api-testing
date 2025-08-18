"""
Comprehensive Unit Tests for Mistral AI Provider

This module provides extensive test coverage for the Mistral AI provider,
including initialization, generation, streaming, function calling, and error handling.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List
from mistralai.models.chat_completion import ChatMessage

from sentinel_backend.llm_providers.providers.mistral_provider import MistralProvider
from sentinel_backend.llm_providers.base_provider import LLMConfig, LLMResponse, Message


class TestMistralProvider:
    """Comprehensive test suite for Mistral AI provider"""
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return LLMConfig(
            provider="mistral",
            model="mistral-large",
            api_key="test-mistral-api-key",
            temperature=0.7,
            max_tokens=1000,
            top_p=0.95
        )
    
    @pytest.fixture
    def messages(self):
        """Create test messages"""
        return [
            Message(role="system", content="You are a helpful assistant"),
            Message(role="user", content="What is Python?"),
            Message(role="assistant", content="Python is a programming language"),
            Message(role="user", content="Tell me more")
        ]
    
    @pytest.fixture
    def mock_client(self):
        """Mock the Mistral client"""
        with patch('sentinel_backend.llm_providers.providers.mistral_provider.MistralClient') as mock:
            yield mock
    
    def test_initialization_with_api_key(self, config, mock_client):
        """Test provider initialization with API key"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        assert provider.api_key == "test-mistral-api-key"
        assert provider.model_name == "mistral-large-latest"
        mock_client.assert_called_once_with(api_key="test-mistral-api-key")
    
    def test_initialization_from_environment(self, mock_client):
        """Test provider initialization with environment variable"""
        with patch.dict('os.environ', {'SENTINEL_APP_MISTRAL_API_KEY': 'env-api-key'}):
            config = LLMConfig(provider="mistral", model="mistral-small")
            
            mock_instance = MagicMock()
            mock_client.return_value = mock_instance
            
            provider = MistralProvider(config)
            
            assert provider.api_key == "env-api-key"
            mock_client.assert_called_once_with(api_key="env-api-key")
    
    def test_initialization_without_api_key(self):
        """Test initialization fails without API key"""
        config = LLMConfig(provider="mistral", model="mistral-large")
        
        with pytest.raises(ValueError, match="Mistral API key not provided"):
            MistralProvider(config)
    
    def test_model_name_mapping(self, config, mock_client):
        """Test model name mapping for different Mistral models"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        test_cases = [
            ("mistral-large", "mistral-large-latest"),
            ("mistral-large-2", "mistral-large-2411"),
            ("mistral-medium", "mistral-medium-latest"),
            ("mistral-small", "mistral-small-latest"),
            ("mistral-small-3", "mistral-small-3-2025"),
            ("codestral", "codestral-latest"),
            ("codestral-mamba", "codestral-mamba-latest"),
            ("mistral-7b", "open-mistral-7b"),
            ("mixtral-8x7b", "open-mixtral-8x7b"),
            ("mixtral-8x22b", "open-mixtral-8x22b"),
            ("custom-model", "custom-model")  # Unknown model passes through
        ]
        
        for input_model, expected_model in test_cases:
            config.model = input_model
            provider = MistralProvider(config)
            assert provider.model_name == expected_model
    
    def test_convert_message_to_mistral(self, config, mock_client):
        """Test message conversion to Mistral format"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        message = Message(role="user", content="Hello")
        mistral_msg = provider._convert_message_to_mistral(message)
        
        assert isinstance(mistral_msg, ChatMessage)
        assert mistral_msg.role == "user"
        assert mistral_msg.content == "Hello"
    
    def test_convert_messages_to_mistral(self, config, messages, mock_client):
        """Test batch message conversion to Mistral format"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        mistral_messages = provider._convert_messages_to_mistral(messages)
        
        assert len(mistral_messages) == 4
        assert all(isinstance(msg, ChatMessage) for msg in mistral_messages)
        assert mistral_messages[0].role == "system"
        assert mistral_messages[1].role == "user"
        assert mistral_messages[2].role == "assistant"
        assert mistral_messages[3].role == "user"
    
    def test_convert_tools_to_mistral(self, config, mock_client):
        """Test tool conversion to Mistral function format"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        tools = [
            {
                "name": "get_weather",
                "description": "Get weather information",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string"},
                        "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}
                    },
                    "required": ["location"]
                }
            }
        ]
        
        mistral_tools = provider._convert_tools_to_mistral(tools)
        
        assert len(mistral_tools) == 1
        assert mistral_tools[0]["type"] == "function"
        assert mistral_tools[0]["function"]["name"] == "get_weather"
        assert mistral_tools[0]["function"]["description"] == "Get weather information"
        assert mistral_tools[0]["function"]["parameters"] == tools[0]["parameters"]
    
    @pytest.mark.asyncio
    async def test_generate_basic(self, config, messages, mock_client):
        """Test basic text generation"""
        mock_instance = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        mock_usage = MagicMock()
        
        mock_message.content = "Python is a versatile programming language."
        mock_message.tool_calls = None
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        
        mock_usage.prompt_tokens = 50
        mock_usage.completion_tokens = 20
        mock_usage.total_tokens = 70
        mock_response.usage = mock_usage
        mock_response.model_dump.return_value = {"test": "data"}
        
        mock_instance.chat.return_value = mock_response
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        response = await provider.generate(messages)
        
        assert isinstance(response, LLMResponse)
        assert response.content == "Python is a versatile programming language."
        assert response.role == "assistant"
        assert response.model == "mistral-large-latest"
        assert response.usage["prompt_tokens"] == 50
        assert response.usage["completion_tokens"] == 20
        assert response.usage["total_tokens"] == 70
    
    @pytest.mark.asyncio
    async def test_generate_with_function_call(self, config, messages, mock_client):
        """Test generation with function calling"""
        mock_instance = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        mock_tool_call = MagicMock()
        mock_function = MagicMock()
        
        mock_function.name = "get_weather"
        mock_function.arguments = '{"location": "Paris"}'
        mock_tool_call.function = mock_function
        
        mock_message.content = ""
        mock_message.tool_calls = [mock_tool_call]
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        mock_response.usage = None
        mock_response.model_dump.return_value = {"test": "data"}
        
        mock_instance.chat.return_value = mock_response
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        tools = [
            {
                "name": "get_weather",
                "description": "Get weather",
                "parameters": {}
            }
        ]
        
        response = await provider.generate(messages, tools=tools)
        
        assert isinstance(response, LLMResponse)
        assert response.function_call is not None
        assert response.function_call["name"] == "get_weather"
        assert response.function_call["arguments"] == '{"location": "Paris"}'
    
    @pytest.mark.asyncio
    async def test_stream_generate(self, config, messages, mock_client):
        """Test streaming text generation"""
        mock_instance = MagicMock()
        
        # Create mock streaming response
        chunks = []
        for text in ["Hello", " there", "!", " How", " can", " I", " help?"]:
            mock_chunk = MagicMock()
            mock_choice = MagicMock()
            mock_delta = MagicMock()
            mock_delta.content = text
            mock_choice.delta = mock_delta
            mock_chunk.choices = [mock_choice]
            chunks.append(mock_chunk)
        
        mock_instance.chat_stream.return_value = chunks
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        # Collect streamed chunks
        collected_chunks = []
        async for chunk in provider.stream_generate(messages):
            collected_chunks.append(chunk)
        
        assert collected_chunks == ["Hello", " there", "!", " How", " can", " I", " help?"]
    
    @pytest.mark.asyncio
    async def test_generate_error_handling(self, config, messages, mock_client):
        """Test error handling during generation"""
        mock_instance = MagicMock()
        mock_instance.chat.side_effect = Exception("API Error")
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        with pytest.raises(Exception, match="API Error"):
            await provider.generate(messages)
    
    @pytest.mark.asyncio
    async def test_stream_error_handling(self, config, messages, mock_client):
        """Test error handling during streaming"""
        mock_instance = MagicMock()
        mock_instance.chat_stream.side_effect = Exception("Streaming Error")
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        with pytest.raises(Exception, match="Streaming Error"):
            async for _ in provider.stream_generate(messages):
                pass
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, config, mock_client):
        """Test successful health check"""
        mock_instance = MagicMock()
        mock_models = MagicMock()
        mock_models.data = [MagicMock(), MagicMock()]
        mock_instance.list_models.return_value = mock_models
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        is_healthy = await provider.health_check()
        
        assert is_healthy is True
        mock_instance.list_models.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self, config, mock_client):
        """Test failed health check"""
        mock_instance = MagicMock()
        mock_instance.list_models.side_effect = Exception("Connection error")
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        is_healthy = await provider.health_check()
        
        assert is_healthy is False
    
    def test_supports_function_calling(self, config, mock_client):
        """Test function calling support detection"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        # Test models that support function calling
        for model in ["mistral-large", "mixtral-8x7b", "mixtral-8x22b"]:
            config.model = model
            provider = MistralProvider(config)
            assert provider.supports_function_calling is True
        
        # Test models that don't support function calling
        for model in ["mistral-small", "codestral", "mistral-7b"]:
            config.model = model
            provider = MistralProvider(config)
            assert provider.supports_function_calling is False
    
    def test_supports_vision(self, config, mock_client):
        """Test vision support detection"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        # Mistral doesn't currently support vision in their API
        assert provider.supports_vision is False
    
    def test_max_context_window(self, config, mock_client):
        """Test context window sizes for different models"""
        mock_instance = MagicMock()
        mock_client.return_value = mock_instance
        
        test_cases = [
            ("mistral-large", 128000),      # 128k tokens
            ("mistral-small-3", 128000),    # 128k tokens
            ("mistral-medium", 32768),      # 32k tokens
            ("mistral-small", 32768),       # 32k tokens
            ("codestral", 32768),           # 32k tokens
            ("mistral-7b", 32768),          # 32k tokens
            ("mixtral-8x7b", 32768),        # 32k tokens
            ("mixtral-8x22b", 65536),       # 64k tokens
            ("unknown-model", 32768)        # Default
        ]
        
        for model, expected_window in test_cases:
            config.model = model
            provider = MistralProvider(config)
            assert provider.max_context_window == expected_window
    
    @pytest.mark.asyncio
    async def test_generate_with_additional_params(self, config, messages, mock_client):
        """Test generation with additional parameters"""
        mock_instance = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        
        mock_message.content = "Test response"
        mock_message.tool_calls = None
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        mock_response.usage = None
        mock_response.model_dump.return_value = {"test": "data"}
        
        mock_instance.chat.return_value = mock_response
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        
        # Test with additional kwargs
        response = await provider.generate(
            messages,
            top_p=0.8,
            frequency_penalty=0.5
        )
        
        # Verify the chat method was called with correct params
        call_kwargs = mock_instance.chat.call_args[1]
        assert call_kwargs["top_p"] == 0.8
        assert call_kwargs["temperature"] == 0.7
        assert call_kwargs["max_tokens"] == 1000
    
    @pytest.mark.asyncio
    async def test_token_estimation_fallback(self, config, messages, mock_client):
        """Test token estimation when usage data is not provided"""
        mock_instance = MagicMock()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        
        mock_message.content = "Short response"
        mock_message.tool_calls = None
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        mock_response.usage = None  # No usage data
        mock_response.model_dump.return_value = {"test": "data"}
        
        mock_instance.chat.return_value = mock_response
        mock_client.return_value = mock_instance
        
        provider = MistralProvider(config)
        response = await provider.generate(messages)
        
        # Check that tokens were estimated
        assert response.usage["prompt_tokens"] > 0
        assert response.usage["completion_tokens"] > 0
        assert response.usage["total_tokens"] > 0