"""
Comprehensive Unit Tests for LLM Provider Factory

This module provides extensive test coverage for the provider factory pattern,
including dynamic instantiation, fallback mechanisms, and configuration.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List

from sentinel_backend.llm_providers.provider_factory import (
    LLMProviderFactory, FallbackLLMProvider
)
from sentinel_backend.llm_providers.base_provider import (
    LLMConfig, LLMProvider, BaseLLMProvider, Message, LLMResponse
)


class MockProvider(BaseLLMProvider):
    """Mock provider for testing"""
    
    def _validate_config(self):
        pass
    
    async def generate(self, messages, **kwargs):
        return LLMResponse(
            content="Mock response",
            model=self.config.model,
            provider=self.config.provider,
            usage={"total_tokens": 10},
            metadata={},
            created_at=None,
            cache_hit=False
        )
    
    async def stream_generate(self, messages, **kwargs):
        yield "Mock"
        yield " stream"
    
    def get_capabilities(self):
        return []
    
    def estimate_tokens(self, text):
        return len(text) // 4
    
    def get_model_info(self):
        return {"model": self.config.model}
    
    async def health_check(self):
        return True


class TestLLMProviderFactory:
    """Comprehensive test suite for LLM Provider Factory"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Reset factory state before each test"""
        LLMProviderFactory._providers.clear()
        LLMProviderFactory._instances.clear()
        yield
        LLMProviderFactory._providers.clear()
        LLMProviderFactory._instances.clear()
    
    @pytest.fixture
    def config(self):
        """Create test configuration"""
        return LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-4",
            api_key="test-key",
            temperature=0.7,
            max_tokens=1000
        )
    
    def test_register_provider(self):
        """Test provider registration"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        
        assert LLMProvider.OPENAI.value in LLMProviderFactory._providers
        assert LLMProviderFactory._providers[LLMProvider.OPENAI.value] == MockProvider
    
    def test_create_provider_success(self, config):
        """Test successful provider creation"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        
        provider = LLMProviderFactory.create_provider(config)
        
        assert isinstance(provider, MockProvider)
        assert provider.config == config
    
    def test_create_provider_with_cache(self, config):
        """Test provider caching"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        
        # First creation
        provider1 = LLMProviderFactory.create_provider(config, use_cache=True)
        
        # Second creation should return cached instance
        provider2 = LLMProviderFactory.create_provider(config, use_cache=True)
        
        assert provider1 is provider2
        assert len(LLMProviderFactory._instances) == 1
    
    def test_create_provider_without_cache(self, config):
        """Test provider creation without caching"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        
        provider1 = LLMProviderFactory.create_provider(config, use_cache=False)
        provider2 = LLMProviderFactory.create_provider(config, use_cache=False)
        
        assert provider1 is not provider2
        assert len(LLMProviderFactory._instances) == 0
    
    def test_create_provider_auto_import(self, config):
        """Test automatic provider import"""
        with patch.object(LLMProviderFactory, '_auto_import_provider') as mock_import:
            # Mock the provider class after import
            LLMProviderFactory._providers[LLMProvider.OPENAI.value] = MockProvider
            
            provider = LLMProviderFactory.create_provider(config)
            
            mock_import.assert_called_once_with(LLMProvider.OPENAI)
            assert isinstance(provider, MockProvider)
    
    def test_create_provider_unsupported(self):
        """Test error for unsupported provider"""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-4"
        )
        
        with pytest.raises(ValueError, match="Provider 'openai' not supported"):
            LLMProviderFactory.create_provider(config)
    
    def test_create_with_fallback_single(self, config):
        """Test fallback provider with single provider"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        
        fallback_provider = LLMProviderFactory.create_with_fallback(config)
        
        assert isinstance(fallback_provider, FallbackLLMProvider)
        assert len(fallback_provider.providers) == 1
        assert fallback_provider.primary_provider.config == config
    
    def test_create_with_fallback_multiple(self, config):
        """Test fallback provider with multiple fallback configs"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        LLMProviderFactory.register_provider(LLMProvider.ANTHROPIC, MockProvider)
        
        fallback_config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model="claude-3",
            api_key="fallback-key"
        )
        
        fallback_provider = LLMProviderFactory.create_with_fallback(
            config,
            fallback_configs=[fallback_config]
        )
        
        assert len(fallback_provider.providers) == 2
        assert fallback_provider.providers[0].config.provider == LLMProvider.OPENAI
        assert fallback_provider.providers[1].config.provider == LLMProvider.ANTHROPIC
    
    def test_create_with_fallback_from_settings(self, config):
        """Test fallback provider creation from app settings"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        LLMProviderFactory.register_provider(LLMProvider.ANTHROPIC, MockProvider)
        
        mock_settings = MagicMock()
        mock_settings.llm_fallback_enabled = True
        mock_settings.llm_fallback_providers = ["anthropic"]
        mock_settings.llm_fallback_models = {"anthropic": "claude-3"}
        mock_settings.anthropic_api_key = "fallback-key"
        
        fallback_provider = LLMProviderFactory.create_with_fallback(
            config,
            app_settings=mock_settings
        )
        
        assert len(fallback_provider.providers) == 2
    
    def test_auto_import_openai(self):
        """Test auto-import for OpenAI provider"""
        with patch('sentinel_backend.llm_providers.provider_factory.OpenAIProvider') as mock_class:
            LLMProviderFactory._auto_import_provider(LLMProvider.OPENAI)
            assert LLMProvider.OPENAI.value in LLMProviderFactory._providers
    
    def test_auto_import_anthropic(self):
        """Test auto-import for Anthropic provider"""
        with patch('sentinel_backend.llm_providers.provider_factory.AnthropicProvider') as mock_class:
            LLMProviderFactory._auto_import_provider(LLMProvider.ANTHROPIC)
            assert LLMProvider.ANTHROPIC.value in LLMProviderFactory._providers
    
    def test_auto_import_google(self):
        """Test auto-import for Google provider"""
        with patch('sentinel_backend.llm_providers.provider_factory.GoogleProvider') as mock_class:
            LLMProviderFactory._auto_import_provider(LLMProvider.GOOGLE)
            assert LLMProvider.GOOGLE.value in LLMProviderFactory._providers
    
    def test_auto_import_failure(self):
        """Test handling of import failure"""
        with patch('sentinel_backend.llm_providers.provider_factory.logger') as mock_logger:
            # This should fail silently and log
            LLMProviderFactory._auto_import_provider(LLMProvider.OPENAI)
            mock_logger.debug.assert_called()
    
    def test_find_model_key_direct_match(self):
        """Test finding model key with direct match"""
        with patch('sentinel_backend.llm_providers.provider_factory.MODEL_REGISTRY') as mock_registry:
            mock_registry.__contains__.return_value = True
            mock_registry.__getitem__.return_value = MagicMock()
            
            key = LLMProviderFactory._find_model_key("gpt-4")
            assert key == "gpt-4"
    
    def test_find_model_key_by_id(self):
        """Test finding model key by model_id"""
        with patch('sentinel_backend.llm_providers.provider_factory.MODEL_REGISTRY') as mock_registry:
            mock_spec = MagicMock()
            mock_spec.model_id = "gpt-4-turbo-preview"
            mock_registry.__contains__.return_value = False
            mock_registry.items.return_value = [("gpt-4-turbo", mock_spec)]
            
            key = LLMProviderFactory._find_model_key("gpt-4-turbo-preview")
            assert key == "gpt-4-turbo"
    
    def test_find_model_key_partial_match(self):
        """Test finding model key with partial match"""
        with patch('sentinel_backend.llm_providers.provider_factory.MODEL_REGISTRY') as mock_registry:
            mock_spec = MagicMock()
            mock_spec.model_id = "claude-3-opus-20240229"
            mock_registry.__contains__.return_value = False
            mock_registry.items.return_value = [
                ("claude-3-opus", mock_spec),
                ("other-model", MagicMock(model_id="other"))
            ]
            
            key = LLMProviderFactory._find_model_key("claude-3")
            assert key == "claude-3-opus"
    
    def test_get_api_key_for_provider(self):
        """Test getting API key from settings"""
        mock_settings = MagicMock()
        mock_settings.openai_api_key = "openai-key"
        mock_settings.anthropic_api_key = "anthropic-key"
        mock_settings.google_api_key = "google-key"
        mock_settings.mistral_api_key = "mistral-key"
        
        assert LLMProviderFactory._get_api_key_for_provider("openai", mock_settings) == "openai-key"
        assert LLMProviderFactory._get_api_key_for_provider("anthropic", mock_settings) == "anthropic-key"
        assert LLMProviderFactory._get_api_key_for_provider("google", mock_settings) == "google-key"
        assert LLMProviderFactory._get_api_key_for_provider("mistral", mock_settings) == "mistral-key"
        assert LLMProviderFactory._get_api_key_for_provider("unknown", mock_settings) is None
    
    def test_list_available_providers(self):
        """Test listing available providers"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        LLMProviderFactory.register_provider(LLMProvider.ANTHROPIC, MockProvider)
        
        providers = LLMProviderFactory.list_available_providers()
        
        assert len(providers) == 2
        assert "openai" in providers
        assert "anthropic" in providers
    
    def test_clear_cache(self):
        """Test clearing provider cache"""
        LLMProviderFactory.register_provider(LLMProvider.OPENAI, MockProvider)
        
        config = LLMConfig(provider=LLMProvider.OPENAI, model="gpt-4")
        provider = LLMProviderFactory.create_provider(config, use_cache=True)
        
        assert len(LLMProviderFactory._instances) == 1
        
        LLMProviderFactory.clear_cache()
        
        assert len(LLMProviderFactory._instances) == 0


class TestFallbackLLMProvider:
    """Test suite for FallbackLLMProvider"""
    
    @pytest.fixture
    def mock_providers(self):
        """Create mock providers for testing"""
        providers = []
        for i in range(3):
            provider = MagicMock(spec=BaseLLMProvider)
            provider.config = LLMConfig(
                provider=LLMProvider.OPENAI,
                model=f"model-{i}"
            )
            providers.append(provider)
        return providers
    
    def test_initialization(self, mock_providers):
        """Test fallback provider initialization"""
        fallback = FallbackLLMProvider(mock_providers)
        
        assert fallback.providers == mock_providers
        assert fallback.primary_provider == mock_providers[0]
        assert fallback.config == mock_providers[0].config
    
    def test_initialization_empty(self):
        """Test initialization with empty provider list"""
        with pytest.raises(ValueError, match="At least one provider required"):
            FallbackLLMProvider([])
    
    @pytest.mark.asyncio
    async def test_generate_primary_success(self, mock_providers):
        """Test successful generation with primary provider"""
        mock_response = LLMResponse(
            content="Primary response",
            model="model-0",
            provider=LLMProvider.OPENAI,
            usage={},
            metadata={},
            created_at=None
        )
        mock_providers[0].generate = AsyncMock(return_value=mock_response)
        
        fallback = FallbackLLMProvider(mock_providers)
        response = await fallback.generate([])
        
        assert response == mock_response
        mock_providers[0].generate.assert_called_once()
        # Other providers should not be called
        for provider in mock_providers[1:]:
            provider.generate.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_generate_fallback_to_second(self, mock_providers):
        """Test fallback to second provider when first fails"""
        mock_providers[0].generate = AsyncMock(side_effect=Exception("Provider 1 failed"))
        
        mock_response = LLMResponse(
            content="Fallback response",
            model="model-1",
            provider=LLMProvider.OPENAI,
            usage={},
            metadata={},
            created_at=None
        )
        mock_providers[1].generate = AsyncMock(return_value=mock_response)
        
        fallback = FallbackLLMProvider(mock_providers)
        response = await fallback.generate([])
        
        assert response == mock_response
        mock_providers[0].generate.assert_called_once()
        mock_providers[1].generate.assert_called_once()
        mock_providers[2].generate.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_generate_all_fail(self, mock_providers):
        """Test error when all providers fail"""
        for i, provider in enumerate(mock_providers):
            provider.generate = AsyncMock(side_effect=Exception(f"Provider {i} failed"))
        
        fallback = FallbackLLMProvider(mock_providers)
        
        with pytest.raises(RuntimeError, match="All 3 providers failed"):
            await fallback.generate([])
        
        # All providers should have been tried
        for provider in mock_providers:
            provider.generate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_stream_generate_success(self, mock_providers):
        """Test successful streaming with primary provider"""
        async def mock_stream():
            yield "chunk1"
            yield "chunk2"
        
        mock_providers[0].stream_generate = mock_stream
        
        fallback = FallbackLLMProvider(mock_providers)
        
        chunks = []
        async for chunk in fallback.stream_generate([]):
            chunks.append(chunk)
        
        assert chunks == ["chunk1", "chunk2"]
    
    @pytest.mark.asyncio
    async def test_stream_generate_fallback(self, mock_providers):
        """Test streaming fallback to second provider"""
        async def failing_stream():
            raise Exception("Stream failed")
        
        async def working_stream():
            yield "fallback1"
            yield "fallback2"
        
        mock_providers[0].stream_generate = failing_stream
        mock_providers[1].stream_generate = working_stream
        
        fallback = FallbackLLMProvider(mock_providers)
        
        chunks = []
        async for chunk in fallback.stream_generate([]):
            chunks.append(chunk)
        
        assert chunks == ["fallback1", "fallback2"]
    
    def test_get_capabilities(self, mock_providers):
        """Test getting capabilities from primary provider"""
        mock_providers[0].get_capabilities.return_value = ["cap1", "cap2"]
        
        fallback = FallbackLLMProvider(mock_providers)
        capabilities = fallback.get_capabilities()
        
        assert capabilities == ["cap1", "cap2"]
        mock_providers[0].get_capabilities.assert_called_once()
    
    def test_estimate_tokens(self, mock_providers):
        """Test token estimation using primary provider"""
        mock_providers[0].estimate_tokens.return_value = 100
        
        fallback = FallbackLLMProvider(mock_providers)
        tokens = fallback.estimate_tokens("test text")
        
        assert tokens == 100
        mock_providers[0].estimate_tokens.assert_called_once_with("test text")
    
    def test_get_model_info(self, mock_providers):
        """Test getting model info from primary provider"""
        mock_info = {"model": "test", "context": 4096}
        mock_providers[0].get_model_info.return_value = mock_info
        
        fallback = FallbackLLMProvider(mock_providers)
        info = fallback.get_model_info()
        
        assert info == mock_info
        mock_providers[0].get_model_info.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_any_healthy(self, mock_providers):
        """Test health check returns True if any provider is healthy"""
        mock_providers[0].health_check = AsyncMock(side_effect=Exception("Unhealthy"))
        mock_providers[1].health_check = AsyncMock(return_value=True)
        mock_providers[2].health_check = AsyncMock(return_value=False)
        
        fallback = FallbackLLMProvider(mock_providers)
        is_healthy = await fallback.health_check()
        
        assert is_healthy is True
    
    @pytest.mark.asyncio
    async def test_health_check_all_unhealthy(self, mock_providers):
        """Test health check returns False if all providers are unhealthy"""
        for provider in mock_providers:
            provider.health_check = AsyncMock(return_value=False)
        
        fallback = FallbackLLMProvider(mock_providers)
        is_healthy = await fallback.health_check()
        
        assert is_healthy is False