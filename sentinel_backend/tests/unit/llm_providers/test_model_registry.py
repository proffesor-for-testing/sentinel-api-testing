"""
Comprehensive Unit Tests for Model Registry

This module provides extensive test coverage for the model registry,
including model specifications, capability detection, and pricing information.
"""

import pytest
from typing import Dict, Any, List

from sentinel_backend.llm_providers.model_registry import (
    ModelSpec, MODEL_REGISTRY, get_model_spec, 
    get_models_by_provider, get_models_by_capability
)
from sentinel_backend.llm_providers.base_provider import LLMProvider, ModelCapability


class TestModelSpec:
    """Test suite for ModelSpec dataclass"""
    
    def test_model_spec_creation(self):
        """Test creating a ModelSpec instance"""
        spec = ModelSpec(
            provider=LLMProvider.OPENAI,
            model_id="gpt-4-turbo",
            display_name="GPT-4 Turbo",
            context_window=128000,
            max_output_tokens=4096,
            capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION],
            input_cost_per_1k=0.01,
            output_cost_per_1k=0.03,
            supports_functions=True,
            supports_vision=True,
            supports_streaming=True,
            notes="Test model"
        )
        
        assert spec.provider == LLMProvider.OPENAI
        assert spec.model_id == "gpt-4-turbo"
        assert spec.display_name == "GPT-4 Turbo"
        assert spec.context_window == 128000
        assert spec.max_output_tokens == 4096
        assert ModelCapability.TEXT_GENERATION in spec.capabilities
        assert spec.input_cost_per_1k == 0.01
        assert spec.output_cost_per_1k == 0.03
        assert spec.supports_functions is True
        assert spec.supports_vision is True
        assert spec.supports_streaming is True
        assert spec.notes == "Test model"
    
    def test_model_spec_defaults(self):
        """Test ModelSpec default values"""
        spec = ModelSpec(
            provider=LLMProvider.OPENAI,
            model_id="test-model",
            display_name="Test Model",
            context_window=4096,
            max_output_tokens=None,
            capabilities=[],
            input_cost_per_1k=0.001,
            output_cost_per_1k=0.002
        )
        
        assert spec.supports_functions is False
        assert spec.supports_vision is False
        assert spec.supports_streaming is True
        assert spec.notes == ""


class TestModelRegistry:
    """Test suite for MODEL_REGISTRY"""
    
    def test_registry_structure(self):
        """Test that MODEL_REGISTRY has expected structure"""
        assert isinstance(MODEL_REGISTRY, dict)
        assert len(MODEL_REGISTRY) > 0
        
        # Check a few known models
        assert "gpt-4-turbo" in MODEL_REGISTRY
        assert "claude-opus-4.1" in MODEL_REGISTRY
        assert "gemini-2.5-pro" in MODEL_REGISTRY
    
    def test_openai_models(self):
        """Test OpenAI model specifications"""
        gpt4_turbo = MODEL_REGISTRY.get("gpt-4-turbo")
        assert gpt4_turbo is not None
        assert gpt4_turbo.provider == LLMProvider.OPENAI
        assert gpt4_turbo.model_id == "gpt-4-turbo-preview"
        assert gpt4_turbo.context_window == 128000
        assert gpt4_turbo.supports_functions is True
        assert gpt4_turbo.supports_vision is True
        assert ModelCapability.LONG_CONTEXT in gpt4_turbo.capabilities
        
        gpt35 = MODEL_REGISTRY.get("gpt-3.5-turbo")
        assert gpt35 is not None
        assert gpt35.context_window == 16385
        assert gpt35.input_cost_per_1k == 0.0005
        assert gpt35.output_cost_per_1k == 0.0015
    
    def test_anthropic_models(self):
        """Test Anthropic Claude model specifications"""
        opus = MODEL_REGISTRY.get("claude-opus-4.1")
        assert opus is not None
        assert opus.provider == LLMProvider.ANTHROPIC
        assert opus.context_window == 200000
        assert ModelCapability.REASONING in opus.capabilities
        assert opus.supports_vision is True
        assert opus.notes == "Most advanced Claude model, 74.5% on SWE-bench"
        
        sonnet = MODEL_REGISTRY.get("claude-sonnet-4")
        assert sonnet is not None
        assert sonnet.context_window == 1000000  # 1M tokens
        assert sonnet.max_output_tokens == 8192
        assert "hybrid modes" in sonnet.notes.lower()
        
        haiku = MODEL_REGISTRY.get("claude-3.5-haiku")
        assert haiku is not None
        assert haiku.input_cost_per_1k == 0.001
        assert haiku.output_cost_per_1k == 0.005
        assert haiku.supports_vision is False
    
    def test_google_models(self):
        """Test Google Gemini model specifications"""
        gemini_25_pro = MODEL_REGISTRY.get("gemini-2.5-pro")
        assert gemini_25_pro is not None
        assert gemini_25_pro.provider == LLMProvider.GOOGLE
        assert gemini_25_pro.context_window == 2097152  # 2M context
        assert ModelCapability.REASONING in gemini_25_pro.capabilities
        assert gemini_25_pro.supports_vision is True
        
        gemini_25_flash = MODEL_REGISTRY.get("gemini-2.5-flash")
        assert gemini_25_flash is not None
        assert gemini_25_flash.context_window == 1048576  # 1M context
        assert gemini_25_flash.input_cost_per_1k == 0.00025
        
        # Check legacy models
        gemini_15_pro = MODEL_REGISTRY.get("gemini-1.5-pro")
        assert gemini_15_pro is not None
        assert "legacy" in gemini_15_pro.notes.lower()
        assert "april 2025" in gemini_15_pro.notes.lower()
    
    def test_mistral_models(self):
        """Test Mistral model specifications"""
        mistral_large = MODEL_REGISTRY.get("mistral-large")
        assert mistral_large is not None
        assert mistral_large.provider == LLMProvider.MISTRAL
        assert mistral_large.context_window == 128000
        assert ModelCapability.FUNCTION_CALLING in mistral_large.capabilities
        assert mistral_large.supports_functions is True
        
        mistral_small = MODEL_REGISTRY.get("mistral-small-3")
        assert mistral_small is not None
        assert mistral_small.supports_vision is True
        assert "24B parameters" in mistral_small.notes
        
        codestral = MODEL_REGISTRY.get("codestral")
        assert codestral is not None
        assert ModelCapability.CODE_GENERATION in codestral.capabilities
        assert "Specialized for code" in codestral.notes
    
    def test_ollama_models(self):
        """Test Ollama (local) model specifications"""
        deepseek_r1 = MODEL_REGISTRY.get("deepseek-r1:671b")
        assert deepseek_r1 is not None
        assert deepseek_r1.provider == LLMProvider.OLLAMA
        assert ModelCapability.REASONING in deepseek_r1.capabilities
        assert deepseek_r1.input_cost_per_1k == 0.0  # Local inference
        assert deepseek_r1.output_cost_per_1k == 0.0
        assert "rivals GPT-4" in deepseek_r1.notes
        
        llama33 = MODEL_REGISTRY.get("llama3.3:70b")
        assert llama33 is not None
        assert llama33.context_window == 128000
        assert ModelCapability.LONG_CONTEXT in llama33.capabilities
        
        qwen_coder = MODEL_REGISTRY.get("qwen2.5-coder:32b")
        assert qwen_coder is not None
        assert ModelCapability.CODE_GENERATION in qwen_coder.capabilities
    
    def test_model_capabilities(self):
        """Test model capability flags"""
        # Vision models
        vision_models = ["gpt-4-turbo", "claude-opus-4.1", "gemini-2.5-pro"]
        for model_key in vision_models:
            spec = MODEL_REGISTRY.get(model_key)
            assert spec is not None
            assert spec.supports_vision is True
            assert ModelCapability.VISION in spec.capabilities or spec.supports_vision
        
        # Function calling models
        function_models = ["gpt-4", "mistral-large", "claude-sonnet-4"]
        for model_key in function_models:
            spec = MODEL_REGISTRY.get(model_key)
            assert spec is not None
            assert spec.supports_functions is True
        
        # Reasoning models
        reasoning_models = ["claude-opus-4.1", "deepseek-r1:671b", "gemini-2.5-pro"]
        for model_key in reasoning_models:
            spec = MODEL_REGISTRY.get(model_key)
            assert spec is not None
            assert ModelCapability.REASONING in spec.capabilities
        
        # Long context models
        long_context_models = ["claude-sonnet-4", "gemini-2.5-pro", "llama3.3:70b"]
        for model_key in long_context_models:
            spec = MODEL_REGISTRY.get(model_key)
            assert spec is not None
            assert ModelCapability.LONG_CONTEXT in spec.capabilities
    
    def test_pricing_information(self):
        """Test model pricing information"""
        # Free local models
        local_models = ["deepseek-r1:671b", "llama3.3:70b", "qwen2.5:72b"]
        for model_key in local_models:
            spec = MODEL_REGISTRY.get(model_key)
            assert spec is not None
            assert spec.input_cost_per_1k == 0.0
            assert spec.output_cost_per_1k == 0.0
        
        # Premium models
        assert MODEL_REGISTRY["claude-opus-4.1"].input_cost_per_1k == 0.015
        assert MODEL_REGISTRY["claude-opus-4.1"].output_cost_per_1k == 0.075
        
        assert MODEL_REGISTRY["gpt-4"].input_cost_per_1k == 0.03
        assert MODEL_REGISTRY["gpt-4"].output_cost_per_1k == 0.06
        
        # Budget models
        assert MODEL_REGISTRY["gpt-3.5-turbo"].input_cost_per_1k == 0.0005
        assert MODEL_REGISTRY["gemini-2.5-flash"].input_cost_per_1k == 0.00025


class TestRegistryFunctions:
    """Test suite for registry utility functions"""
    
    def test_get_model_spec(self):
        """Test getting model specification by key"""
        # Valid model
        spec = get_model_spec("gpt-4-turbo")
        assert spec is not None
        assert spec.model_id == "gpt-4-turbo-preview"
        
        # Invalid model
        spec = get_model_spec("non-existent-model")
        assert spec is None
    
    def test_get_models_by_provider(self):
        """Test filtering models by provider"""
        # OpenAI models
        openai_models = get_models_by_provider(LLMProvider.OPENAI)
        assert len(openai_models) > 0
        assert "gpt-4-turbo" in openai_models
        assert "gpt-3.5-turbo" in openai_models
        for spec in openai_models.values():
            assert spec.provider == LLMProvider.OPENAI
        
        # Anthropic models
        anthropic_models = get_models_by_provider(LLMProvider.ANTHROPIC)
        assert len(anthropic_models) > 0
        assert "claude-opus-4.1" in anthropic_models
        for spec in anthropic_models.values():
            assert spec.provider == LLMProvider.ANTHROPIC
        
        # Google models
        google_models = get_models_by_provider(LLMProvider.GOOGLE)
        assert len(google_models) > 0
        assert "gemini-2.5-pro" in google_models
        for spec in google_models.values():
            assert spec.provider == LLMProvider.GOOGLE
        
        # Ollama models
        ollama_models = get_models_by_provider(LLMProvider.OLLAMA)
        assert len(ollama_models) > 0
        assert "deepseek-r1:671b" in ollama_models
        for spec in ollama_models.values():
            assert spec.provider == LLMProvider.OLLAMA
    
    def test_get_models_by_capability(self):
        """Test filtering models by capability"""
        # Text generation (should include all)
        text_models = get_models_by_capability(ModelCapability.TEXT_GENERATION)
        assert len(text_models) > 20
        
        # Code generation
        code_models = get_models_by_capability(ModelCapability.CODE_GENERATION)
        assert len(code_models) > 10
        assert "codestral" in code_models
        assert "qwen2.5-coder:32b" in code_models
        for spec in code_models.values():
            assert ModelCapability.CODE_GENERATION in spec.capabilities
        
        # Vision capability
        vision_models = get_models_by_capability(ModelCapability.VISION)
        assert len(vision_models) > 5
        assert "gpt-4-turbo" in vision_models
        assert "claude-opus-4.1" in vision_models
        for spec in vision_models.values():
            assert ModelCapability.VISION in spec.capabilities
        
        # Function calling
        function_models = get_models_by_capability(ModelCapability.FUNCTION_CALLING)
        assert len(function_models) > 3
        assert "gpt-4" in function_models
        assert "mistral-large" in function_models
        for spec in function_models.values():
            assert ModelCapability.FUNCTION_CALLING in spec.capabilities
        
        # Reasoning capability
        reasoning_models = get_models_by_capability(ModelCapability.REASONING)
        assert len(reasoning_models) > 3
        assert "claude-opus-4.1" in reasoning_models
        assert "deepseek-r1:671b" in reasoning_models
        for spec in reasoning_models.values():
            assert ModelCapability.REASONING in spec.capabilities
        
        # Long context
        long_context_models = get_models_by_capability(ModelCapability.LONG_CONTEXT)
        assert len(long_context_models) > 10
        for spec in long_context_models.values():
            assert ModelCapability.LONG_CONTEXT in spec.capabilities
    
    def test_context_window_sizes(self):
        """Test various context window sizes"""
        # Ultra-long context (>1M tokens)
        assert MODEL_REGISTRY["gemini-2.5-pro"].context_window == 2097152  # 2M
        assert MODEL_REGISTRY["claude-sonnet-4"].context_window == 1000000  # 1M
        assert MODEL_REGISTRY["gemini-2.5-flash"].context_window == 1048576  # 1M
        
        # Long context (100k-200k tokens)
        assert MODEL_REGISTRY["claude-opus-4.1"].context_window == 200000
        assert MODEL_REGISTRY["yi:200k"].context_window == 200000 if "yi:200k" in MODEL_REGISTRY else True
        assert MODEL_REGISTRY["gpt-4-turbo"].context_window == 128000
        
        # Medium context (32k-64k tokens)
        assert MODEL_REGISTRY["mistral-large"].context_window == 128000
        assert MODEL_REGISTRY["codestral"].context_window == 32768
        
        # Standard context (<32k tokens)
        assert MODEL_REGISTRY["gpt-4"].context_window == 8192
    
    def test_model_notes(self):
        """Test that important models have descriptive notes"""
        important_models = [
            "claude-opus-4.1",
            "claude-sonnet-4",
            "deepseek-r1:671b",
            "gemini-1.5-pro",
            "mistral-small-3"
        ]
        
        for model_key in important_models:
            spec = MODEL_REGISTRY.get(model_key)
            if spec:
                assert spec.notes != ""
                assert len(spec.notes) > 10  # Should have meaningful notes
    
    def test_model_output_limits(self):
        """Test max output token specifications"""
        # Models with defined output limits
        assert MODEL_REGISTRY["gpt-4-turbo"].max_output_tokens == 4096
        assert MODEL_REGISTRY["gpt-4"].max_output_tokens == 4096
        assert MODEL_REGISTRY["claude-sonnet-4"].max_output_tokens == 8192
        assert MODEL_REGISTRY["gemini-2.5-pro"].max_output_tokens == 8192
        
        # Models with no defined limit (None)
        assert MODEL_REGISTRY["mistral-large"].max_output_tokens is None
        assert MODEL_REGISTRY["deepseek-r1:671b"].max_output_tokens is None
    
    def test_streaming_support(self):
        """Test streaming support flags"""
        # Most models should support streaming by default
        streaming_count = sum(
            1 for spec in MODEL_REGISTRY.values() 
            if spec.supports_streaming
        )
        
        assert streaming_count > len(MODEL_REGISTRY) * 0.9  # >90% should support streaming
        
        # Verify specific models
        assert MODEL_REGISTRY["gpt-4-turbo"].supports_streaming is True
        assert MODEL_REGISTRY["claude-sonnet-4"].supports_streaming is True
        assert MODEL_REGISTRY["deepseek-r1:671b"].supports_streaming is True