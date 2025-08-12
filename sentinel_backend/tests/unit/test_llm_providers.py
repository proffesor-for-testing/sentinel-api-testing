"""
Unit tests for LLM Provider system
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
from typing import List, Dict, Any

from sentinel_backend.llm_providers import LLMProviderFactory, LLMConfig
from sentinel_backend.llm_providers.base_provider import (
    BaseLLMProvider, LLMProvider, LLMResponse, Message, ModelCapability
)
from sentinel_backend.llm_providers.provider_factory import FallbackLLMProvider
from sentinel_backend.llm_providers.model_registry import get_model_spec, get_models_by_provider


class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider for testing"""
    
    def _validate_config(self):
        pass
    
    async def generate(self, messages: List[Message], **kwargs) -> LLMResponse:
        return LLMResponse(
            content="Mock response",
            model=self.config.model,
            provider=self.config.provider,
            usage={"total_tokens": 100, "cost": 0.001},
            metadata={},
            created_at=datetime.now(),
            cache_hit=False
        )
    
    async def stream_generate(self, messages: List[Message], **kwargs):
        for word in ["Mock", "streaming", "response"]:
            yield word
    
    def get_capabilities(self) -> List[ModelCapability]:
        return [ModelCapability.TEXT_GENERATION, ModelCapability.STREAMING]
    
    def estimate_tokens(self, text: str) -> int:
        return len(text) // 4
    
    def get_model_info(self) -> Dict[str, Any]:
        return {
            "provider": "mock",
            "model": self.config.model,
            "context_window": 4096
        }


class TestLLMConfig:
    """Test LLM configuration"""
    
    def test_config_creation(self):
        """Test creating LLM configuration"""
        config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model="claude-sonnet-4",
            api_key="test-key",
            temperature=0.7,
            max_tokens=1000
        )
        
        assert config.provider == LLMProvider.ANTHROPIC
        assert config.model == "claude-sonnet-4"
        assert config.api_key == "test-key"
        assert config.temperature == 0.7  # Temperature was explicitly set to 0.7
        assert config.max_tokens == 1000
    
    def test_config_defaults(self):
        """Test configuration defaults"""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-3.5-turbo"
        )
        
        assert config.temperature == 0.5  # Default temperature is 0.5
        assert config.top_p == 1.0
        assert config.timeout == 60
        assert config.max_retries == 3
        assert config.cache_enabled == True
        assert config.cache_ttl == 3600


class TestLLMProviderFactory:
    """Test LLM Provider Factory"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Clear factory state before each test"""
        LLMProviderFactory._providers.clear()
        LLMProviderFactory._instances.clear()
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockLLMProvider)
    
    def test_register_provider(self):
        """Test registering a provider"""
        LLMProviderFactory.register_provider(LLMProvider.ANTHROPIC, MockLLMProvider)
        assert "anthropic" in LLMProviderFactory._providers
    
    def test_create_provider(self):
        """Test creating a provider instance"""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-3.5-turbo"
        )
        
        provider = LLMProviderFactory.create_provider(config)
        assert isinstance(provider, MockLLMProvider)
        assert provider.config == config
    
    def test_provider_caching(self):
        """Test that providers are cached"""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-3.5-turbo"
        )
        
        provider1 = LLMProviderFactory.create_provider(config)
        provider2 = LLMProviderFactory.create_provider(config)
        
        assert provider1 is provider2  # Same instance
    
    def test_invalid_provider(self):
        """Test error handling for invalid provider"""
        config = LLMConfig(
            provider=LLMProvider.GOOGLE,
            model="gemini-2.5-pro"
        )
        
        with pytest.raises(ValueError, match="Provider 'google' not supported"):
            LLMProviderFactory.create_provider(config)
    
    def test_clear_cache(self):
        """Test clearing provider cache"""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-3.5-turbo"
        )
        
        provider1 = LLMProviderFactory.create_provider(config)
        LLMProviderFactory.clear_cache()
        provider2 = LLMProviderFactory.create_provider(config)
        
        assert provider1 is not provider2  # Different instances


class TestFallbackProvider:
    """Test fallback provider functionality"""
    
    @pytest.mark.asyncio
    async def test_successful_primary(self):
        """Test successful generation with primary provider"""
        primary = Mock(spec=BaseLLMProvider)
        primary.config = Mock(provider=LLMProvider.OPENAI)
        primary.generate = AsyncMock(return_value=LLMResponse(
            content="Primary response",
            model="gpt-3.5-turbo",
            provider=LLMProvider.OPENAI,
            usage={"total_tokens": 50},
            metadata={},
            created_at=datetime.now()
        ))
        
        fallback_provider = FallbackLLMProvider([primary])
        response = await fallback_provider.generate([Message(role="user", content="test")])
        
        assert response.content == "Primary response"
        primary.generate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_fallback_on_primary_failure(self):
        """Test fallback when primary fails"""
        primary = Mock(spec=BaseLLMProvider)
        primary.config = Mock(provider=LLMProvider.OPENAI)
        primary.generate = AsyncMock(side_effect=Exception("Primary failed"))
        
        secondary = Mock(spec=BaseLLMProvider)
        secondary.config = Mock(provider=LLMProvider.ANTHROPIC)
        secondary.generate = AsyncMock(return_value=LLMResponse(
            content="Secondary response",
            model="claude-sonnet-4",
            provider=LLMProvider.ANTHROPIC,
            usage={"total_tokens": 60},
            metadata={},
            created_at=datetime.now()
        ))
        
        fallback_provider = FallbackLLMProvider([primary, secondary])
        response = await fallback_provider.generate([Message(role="user", content="test")])
        
        assert response.content == "Secondary response"
        assert response.provider == LLMProvider.ANTHROPIC
        primary.generate.assert_called_once()
        secondary.generate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_all_providers_fail(self):
        """Test error when all providers fail"""
        primary = Mock(spec=BaseLLMProvider)
        primary.config = Mock(provider=LLMProvider.OPENAI)
        primary.generate = AsyncMock(side_effect=Exception("Primary failed"))
        
        secondary = Mock(spec=BaseLLMProvider)
        secondary.config = Mock(provider=LLMProvider.ANTHROPIC)
        secondary.generate = AsyncMock(side_effect=Exception("Secondary failed"))
        
        fallback_provider = FallbackLLMProvider([primary, secondary])
        
        with pytest.raises(RuntimeError, match="All 2 providers failed"):
            await fallback_provider.generate([Message(role="user", content="test")])


class TestModelRegistry:
    """Test model registry functionality"""
    
    def test_get_model_spec(self):
        """Test retrieving model specification"""
        spec = get_model_spec("claude-sonnet-4")
        
        assert spec is not None
        assert spec.provider == LLMProvider.ANTHROPIC
        assert spec.model_id == "claude-sonnet-4-20250514"
        assert spec.context_window == 200000
    
    def test_get_models_by_provider(self):
        """Test retrieving models by provider"""
        anthropic_models = get_models_by_provider(LLMProvider.ANTHROPIC)
        
        assert len(anthropic_models) > 0
        assert "claude-sonnet-4" in anthropic_models
        assert "claude-opus-4.1" in anthropic_models
    
    def test_invalid_model(self):
        """Test retrieving invalid model"""
        spec = get_model_spec("invalid-model")
        assert spec is None


class TestMessage:
    """Test Message class"""
    
    def test_message_creation(self):
        """Test creating messages"""
        msg = Message(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"
        assert msg.name is None
        assert msg.function_call is None
    
    def test_message_with_optional_fields(self):
        """Test message with optional fields"""
        msg = Message(
            role="assistant",
            content="Response",
            name="bot",
            function_call={"name": "test", "arguments": "{}"}
        )
        
        assert msg.name == "bot"
        assert msg.function_call["name"] == "test"


class TestLLMResponse:
    """Test LLM Response class"""
    
    def test_response_creation(self):
        """Test creating LLM response"""
        response = LLMResponse(
            content="Test response",
            model="claude-sonnet-4",
            provider=LLMProvider.ANTHROPIC,
            usage={"total_tokens": 100, "cost": 0.002},
            metadata={"finish_reason": "stop"},
            created_at=datetime.now()
        )
        
        assert response.content == "Test response"
        assert response.model == "claude-sonnet-4"
        assert response.provider == LLMProvider.ANTHROPIC
        assert response.total_tokens == 100
        assert response.estimated_cost == 0.002
    
    def test_response_cache_hit(self):
        """Test response with cache hit"""
        response = LLMResponse(
            content="Cached response",
            model="gpt-3.5-turbo",
            provider=LLMProvider.OPENAI,
            usage={"total_tokens": 0, "cost": 0},
            metadata={},
            created_at=datetime.now(),
            cache_hit=True
        )
        
        assert response.cache_hit == True
        assert response.estimated_cost == 0


@pytest.mark.asyncio
class TestProviderIntegration:
    """Integration tests for LLM providers"""
    
    async def test_openai_provider_mock(self):
        """Test OpenAI provider with mocked responses"""
        with patch('openai.AsyncOpenAI') as mock_client:
            # Mock the OpenAI client
            mock_response = MagicMock()
            mock_response.choices = [MagicMock(message=MagicMock(content="Test response"))]
            mock_response.usage = MagicMock(
                prompt_tokens=10,
                completion_tokens=20,
                total_tokens=30
            )
            mock_response.model = "gpt-3.5-turbo"
            
            mock_client.return_value.chat.completions.create = AsyncMock(return_value=mock_response)
            
            from sentinel_backend.llm_providers.providers.openai_provider import OpenAIProvider
            
            config = LLMConfig(
                provider=LLMProvider.OPENAI,
                model="gpt-3.5-turbo",
                api_key="test-key"
            )
            
            provider = OpenAIProvider(config)
            response = await provider.generate([Message(role="user", content="test")])
            
            assert response.content == "Test response"
            assert response.total_tokens == 30
    
    async def test_anthropic_provider_mock(self):
        """Test Anthropic provider with mocked responses"""  
        with patch('anthropic.AsyncAnthropic') as mock_client:
            # Mock the Anthropic client
            mock_content = MagicMock()
            mock_content.type = "text"
            mock_content.text = "Claude response"
            
            mock_response = MagicMock()
            mock_response.content = [mock_content]
            mock_response.usage = MagicMock(
                input_tokens=15,
                output_tokens=25
            )
            mock_response.model = "claude-sonnet-4"
            mock_response.stop_reason = "stop"
            mock_response.stop_sequence = None
            
            mock_client.return_value.messages.create = AsyncMock(return_value=mock_response)
            
            from sentinel_backend.llm_providers.providers.anthropic_provider import AnthropicProvider
            
            config = LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model="claude-sonnet-4",
                api_key="test-key"
            )
            
            provider = AnthropicProvider(config)
            response = await provider.generate([Message(role="user", content="test")])
            
            assert response.content == "Claude response"
            assert response.total_tokens == 40


if __name__ == "__main__":
    pytest.main([__file__, "-v"])