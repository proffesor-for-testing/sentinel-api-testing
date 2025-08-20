"""
Unit tests for LLM provider configuration validation.

This module tests LLM provider settings, API key validation,
model configuration, and provider-specific settings.
"""

import os
import pytest
from unittest.mock import patch, MagicMock
import json

from sentinel_backend.config.settings import (
    ApplicationSettings,
    get_application_settings
)
from sentinel_backend.config.validation import ConfigurationValidator


class TestLLMProviderConfiguration:
    """Test suite for LLM provider configuration."""
    
    @pytest.fixture
    def app_settings(self):
        """Create ApplicationSettings instance."""
        return get_application_settings()
    
    def test_llm_provider_selection(self):
        """Test LLM provider selection configuration."""
        providers = ["openai", "anthropic", "google", "mistral", "ollama", "vllm", "none"]
        
        for provider in providers:
            with patch.dict(os.environ, {
                'SENTINEL_APP_LLM_PROVIDER': provider
            }):
                get_application_settings.cache_clear()
                settings = get_application_settings()
                assert settings.llm_provider == provider
    
    def test_openai_configuration(self):
        """Test OpenAI provider configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'openai',
            'SENTINEL_APP_OPENAI_API_KEY': 'sk-test-key',
            'SENTINEL_APP_LLM_MODEL': 'gpt-4-turbo',
            'SENTINEL_APP_LLM_TEMPERATURE': '0.7',
            'SENTINEL_APP_LLM_MAX_TOKENS': '2000'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_provider == 'openai'
            assert settings.openai_api_key == 'sk-test-key'
            assert settings.llm_model == 'gpt-4-turbo'
            assert settings.llm_temperature == 0.7
            assert settings.llm_max_tokens == 2000
    
    def test_anthropic_configuration(self):
        """Test Anthropic provider configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'anthropic',
            'SENTINEL_APP_ANTHROPIC_API_KEY': 'sk-ant-test-key',
            'SENTINEL_APP_LLM_MODEL': 'claude-sonnet-4',
            'SENTINEL_APP_LLM_MAX_TOKENS': '4000'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_provider == 'anthropic'
            assert settings.anthropic_api_key == 'sk-ant-test-key'
            assert settings.llm_model == 'claude-sonnet-4'
            assert settings.llm_max_tokens == 4000
    
    def test_google_gemini_configuration(self):
        """Test Google Gemini provider configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'google',
            'SENTINEL_APP_GOOGLE_API_KEY': 'google-api-key',
            'SENTINEL_APP_LLM_MODEL': 'gemini-2.5-pro',
            'SENTINEL_APP_LLM_TEMPERATURE': '0.5'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_provider == 'google'
            assert settings.google_api_key == 'google-api-key'
            assert settings.llm_model == 'gemini-2.5-pro'
            assert settings.llm_temperature == 0.5
    
    def test_mistral_configuration(self):
        """Test Mistral provider configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'mistral',
            'SENTINEL_APP_MISTRAL_API_KEY': 'mistral-api-key',
            'SENTINEL_APP_LLM_MODEL': 'mistral-large'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_provider == 'mistral'
            assert settings.mistral_api_key == 'mistral-api-key'
            assert settings.llm_model == 'mistral-large'
    
    def test_ollama_local_configuration(self):
        """Test Ollama local provider configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'ollama',
            'SENTINEL_APP_OLLAMA_BASE_URL': 'http://localhost:11434',
            'SENTINEL_APP_LLM_MODEL': 'llama3.3:70b'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_provider == 'ollama'
            assert settings.ollama_base_url == 'http://localhost:11434'
            assert settings.llm_model == 'llama3.3:70b'
    
    def test_vllm_configuration(self):
        """Test vLLM provider configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'vllm',
            'SENTINEL_APP_VLLM_BASE_URL': 'http://vllm-server:8000',
            'SENTINEL_APP_LLM_MODEL': 'meta-llama/Llama-3.1-70B'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_provider == 'vllm'
            assert settings.vllm_base_url == 'http://vllm-server:8000'
            assert settings.llm_model == 'meta-llama/Llama-3.1-70B'
    
    def test_missing_api_key_validation(self):
        """Test validation when API key is missing."""
        validator = ConfigurationValidator()
        
        providers_requiring_keys = [
            ('openai', 'SENTINEL_APP_OPENAI_API_KEY'),
            ('anthropic', 'SENTINEL_APP_ANTHROPIC_API_KEY'),
            ('google', 'SENTINEL_APP_GOOGLE_API_KEY'),
            ('mistral', 'SENTINEL_APP_MISTRAL_API_KEY')
        ]
        
        for provider, key_var in providers_requiring_keys:
            with patch.dict(os.environ, {
                'SENTINEL_APP_LLM_PROVIDER': provider,
                key_var: ''
            }, clear=True):
                validator.errors = []
                validator._validate_application_settings()
                
                assert len(validator.errors) > 0
                assert any("api key" in error.lower() for error in validator.errors)
    
    def test_llm_fallback_configuration(self):
        """Test LLM provider fallback configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_FALLBACK_ENABLED': 'true',
            'SENTINEL_APP_LLM_FALLBACK_PROVIDERS': '["anthropic", "openai", "google"]'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_fallback_enabled is True
            assert settings.llm_fallback_providers == ["anthropic", "openai", "google"]
    
    def test_llm_retry_configuration(self):
        """Test LLM retry configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_RETRY_ATTEMPTS': '3',
            'SENTINEL_APP_LLM_RETRY_DELAY': '2',
            'SENTINEL_APP_LLM_RETRY_MAX_DELAY': '30'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_retry_attempts == 3
            assert settings.llm_retry_delay == 2
            assert settings.llm_retry_max_delay == 30
    
    def test_llm_timeout_configuration(self):
        """Test LLM timeout configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_REQUEST_TIMEOUT': '60',
            'SENTINEL_APP_LLM_CONNECT_TIMEOUT': '10'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_request_timeout == 60
            assert settings.llm_connect_timeout == 10
    
    def test_llm_caching_configuration(self):
        """Test LLM response caching configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_CACHE_ENABLED': 'true',
            'SENTINEL_APP_LLM_CACHE_TTL': '3600',
            'SENTINEL_APP_LLM_CACHE_MAX_SIZE': '1000'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_cache_enabled is True
            assert settings.llm_cache_ttl == 3600
            assert settings.llm_cache_max_size == 1000
    
    def test_llm_rate_limiting_configuration(self):
        """Test LLM rate limiting configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_RATE_LIMIT_ENABLED': 'true',
            'SENTINEL_APP_LLM_RATE_LIMIT_REQUESTS': '100',
            'SENTINEL_APP_LLM_RATE_LIMIT_WINDOW': '60'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_rate_limit_enabled is True
            assert settings.llm_rate_limit_requests == 100
            assert settings.llm_rate_limit_window == 60
    
    def test_llm_cost_tracking_configuration(self):
        """Test LLM cost tracking configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_COST_TRACKING_ENABLED': 'true',
            'SENTINEL_APP_LLM_COST_PER_1K_TOKENS': '0.03',
            'SENTINEL_APP_LLM_COST_BUDGET_MONTHLY': '1000'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_cost_tracking_enabled is True
            assert settings.llm_cost_per_1k_tokens == 0.03
            assert settings.llm_cost_budget_monthly == 1000
    
    def test_llm_streaming_configuration(self):
        """Test LLM streaming configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_STREAMING_ENABLED': 'true',
            'SENTINEL_APP_LLM_STREAM_CHUNK_SIZE': '512'
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert settings.llm_streaming_enabled is True
            assert settings.llm_stream_chunk_size == 512
    
    def test_model_specific_configuration(self):
        """Test model-specific configuration overrides."""
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_MODEL_CONFIGS': json.dumps({
                "gpt-4-turbo": {
                    "temperature": 0.7,
                    "max_tokens": 4000
                },
                "claude-sonnet-4": {
                    "temperature": 0.5,
                    "max_tokens": 8000
                }
            })
        }):
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            assert "gpt-4-turbo" in settings.llm_model_configs
            assert settings.llm_model_configs["gpt-4-turbo"]["temperature"] == 0.7
            assert settings.llm_model_configs["claude-sonnet-4"]["max_tokens"] == 8000


class TestLLMProviderValidation:
    """Test LLM provider validation rules."""
    
    def test_invalid_provider_validation(self):
        """Test validation of invalid LLM provider."""
        validator = ConfigurationValidator()
        
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'invalid_provider'
        }):
            validator.errors = []
            validator._validate_application_settings()
            
            assert len(validator.errors) > 0
            assert any("provider" in error.lower() for error in validator.errors)
    
    def test_temperature_range_validation(self):
        """Test validation of temperature parameter range."""
        validator = ConfigurationValidator()
        
        # Test invalid temperature (out of range)
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_TEMPERATURE': '2.0'  # Should be 0-1
        }):
            validator.errors = []
            validator._validate_application_settings()
            
            assert len(validator.errors) > 0
            assert any("temperature" in error.lower() for error in validator.errors)
    
    def test_max_tokens_validation(self):
        """Test validation of max tokens parameter."""
        validator = ConfigurationValidator()
        
        # Test invalid max tokens (negative value)
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_MAX_TOKENS': '-1'
        }):
            validator.errors = []
            validator._validate_application_settings()
            
            assert len(validator.errors) > 0
            assert any("tokens" in error.lower() for error in validator.errors)
    
    def test_local_provider_url_validation(self):
        """Test validation of local provider URLs."""
        validator = ConfigurationValidator()
        
        # Test missing URL for local providers
        for provider in ['ollama', 'vllm']:
            with patch.dict(os.environ, {
                'SENTINEL_APP_LLM_PROVIDER': provider,
                f'SENTINEL_APP_{provider.upper()}_BASE_URL': ''
            }):
                validator.errors = []
                validator._validate_application_settings()
                
                assert len(validator.errors) > 0
                assert any("url" in error.lower() for error in validator.errors)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])