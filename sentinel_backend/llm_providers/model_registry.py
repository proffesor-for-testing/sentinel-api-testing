"""
Model Registry

Central registry of all supported models with their specifications and pricing.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
from .base_provider import LLMProvider, ModelCapability


@dataclass
class ModelSpec:
    """Specification for a model"""
    provider: LLMProvider
    model_id: str
    display_name: str
    context_window: int
    max_output_tokens: Optional[int]
    capabilities: list[ModelCapability]
    input_cost_per_1k: float  # USD per 1000 tokens
    output_cost_per_1k: float  # USD per 1000 tokens
    supports_functions: bool = False
    supports_vision: bool = False
    supports_streaming: bool = True
    notes: str = ""


# Model Registry
MODEL_REGISTRY: Dict[str, ModelSpec] = {
    # OpenAI Models
    "gpt-4-turbo": ModelSpec(
        provider=LLMProvider.OPENAI,
        model_id="gpt-4-turbo-preview",
        display_name="GPT-4 Turbo",
        context_window=128000,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION, 
                     ModelCapability.FUNCTION_CALLING, ModelCapability.VISION, 
                     ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.01,
        output_cost_per_1k=0.03,
        supports_functions=True,
        supports_vision=True
    ),
    "gpt-4": ModelSpec(
        provider=LLMProvider.OPENAI,
        model_id="gpt-4",
        display_name="GPT-4",
        context_window=8192,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.FUNCTION_CALLING],
        input_cost_per_1k=0.03,
        output_cost_per_1k=0.06,
        supports_functions=True
    ),
    "gpt-3.5-turbo": ModelSpec(
        provider=LLMProvider.OPENAI,
        model_id="gpt-3.5-turbo",
        display_name="GPT-3.5 Turbo",
        context_window=16385,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.FUNCTION_CALLING],
        input_cost_per_1k=0.0005,
        output_cost_per_1k=0.0015,
        supports_functions=True
    ),
    
    # Anthropic Models (Claude)
    "claude-opus-4.1": ModelSpec(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-opus-4-1-20250805",
        display_name="Claude Opus 4.1",
        context_window=200000,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT,
                     ModelCapability.REASONING],
        input_cost_per_1k=0.015,
        output_cost_per_1k=0.075,
        supports_vision=True,
        supports_functions=True,
        notes="Most advanced Claude model, 74.5% on SWE-bench"
    ),
    "claude-opus-4": ModelSpec(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-opus-4-20250514",
        display_name="Claude Opus 4",
        context_window=200000,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT,
                     ModelCapability.REASONING],
        input_cost_per_1k=0.015,
        output_cost_per_1k=0.075,
        supports_vision=True,
        supports_functions=True,
        notes="World's best coding model"
    ),
    "claude-sonnet-4": ModelSpec(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-sonnet-4-20250514",
        display_name="Claude Sonnet 4",
        context_window=200000,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.003,
        output_cost_per_1k=0.015,
        supports_vision=True,
        supports_functions=True,
        notes="72.7% on SWE-bench, balanced performance"
    ),
    "claude-3.5-sonnet": ModelSpec(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-3-5-sonnet-20241022",
        display_name="Claude 3.5 Sonnet",
        context_window=200000,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.003,
        output_cost_per_1k=0.015,
        supports_vision=True,
        notes="Previous generation balanced model"
    ),
    "claude-3.5-haiku": ModelSpec(
        provider=LLMProvider.ANTHROPIC,
        model_id="claude-3-5-haiku-20241022",
        display_name="Claude 3.5 Haiku",
        context_window=200000,
        max_output_tokens=4096,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.001,
        output_cost_per_1k=0.005,
        notes="Fast and affordable"
    ),
    
    # Google Models (Gemini)
    "gemini-2.5-pro": ModelSpec(
        provider=LLMProvider.GOOGLE,
        model_id="gemini-2.5-pro",
        display_name="Gemini 2.5 Pro",
        context_window=2097152,  # 2M context
        max_output_tokens=8192,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT, ModelCapability.REASONING],
        input_cost_per_1k=0.00125,
        output_cost_per_1k=0.005,
        supports_vision=True,
        notes="Latest thinking model with enhanced reasoning"
    ),
    "gemini-2.5-flash": ModelSpec(
        provider=LLMProvider.GOOGLE,
        model_id="gemini-2.5-flash",
        display_name="Gemini 2.5 Flash",
        context_window=1048576,  # 1M context
        max_output_tokens=8192,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.00025,
        output_cost_per_1k=0.001,
        supports_vision=True,
        notes="Fast and efficient workhorse model"
    ),
    "gemini-2.0-flash": ModelSpec(
        provider=LLMProvider.GOOGLE,
        model_id="gemini-2.0-flash",
        display_name="Gemini 2.0 Flash",
        context_window=1048576,  # 1M context
        max_output_tokens=8192,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.00025,
        output_cost_per_1k=0.001,
        supports_vision=True,
        notes="Multimodal with native image generation"
    ),
    # Legacy models (limited availability from April 2025)
    "gemini-1.5-pro": ModelSpec(
        provider=LLMProvider.GOOGLE,
        model_id="gemini-1.5-pro",
        display_name="Gemini 1.5 Pro (Legacy)",
        context_window=2097152,  # 2M context
        max_output_tokens=8192,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.00125,
        output_cost_per_1k=0.005,
        supports_vision=True,
        notes="Legacy model, limited availability from April 2025"
    ),
    "gemini-1.5-flash": ModelSpec(
        provider=LLMProvider.GOOGLE,
        model_id="gemini-1.5-flash",
        display_name="Gemini 1.5 Flash (Legacy)",
        context_window=1048576,  # 1M context
        max_output_tokens=8192,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.00025,
        output_cost_per_1k=0.001,
        supports_vision=True,
        notes="Legacy model, limited availability from April 2025"
    ),
    
    # Mistral Models
    "mistral-large": ModelSpec(
        provider=LLMProvider.MISTRAL,
        model_id="mistral-large-latest",
        display_name="Mistral Large",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.FUNCTION_CALLING, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.002,
        output_cost_per_1k=0.006,
        supports_functions=True
    ),
    "mistral-small-3": ModelSpec(
        provider=LLMProvider.MISTRAL,
        model_id="mistral-small-latest",
        display_name="Mistral Small 3",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.VISION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.001,
        output_cost_per_1k=0.003,
        supports_vision=True,
        notes="24B parameters, January 2025 release"
    ),
    "codestral": ModelSpec(
        provider=LLMProvider.MISTRAL,
        model_id="codestral-latest",
        display_name="Codestral",
        context_window=32768,
        max_output_tokens=None,
        capabilities=[ModelCapability.CODE_GENERATION, ModelCapability.TEXT_GENERATION],
        input_cost_per_1k=0.001,
        output_cost_per_1k=0.003,
        notes="Specialized for code"
    ),
    
    # Open Source Models (via Ollama)
    "deepseek-r1:671b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="deepseek-r1:671b",
        display_name="DeepSeek-R1 671B",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.REASONING, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.0,  # Local inference
        output_cost_per_1k=0.0,
        notes="State-of-the-art reasoning, rivals GPT-4"
    ),
    "deepseek-r1:70b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="deepseek-r1:70b",
        display_name="DeepSeek-R1 70B",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.REASONING, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Distilled version with excellent performance"
    ),
    "llama3.3:70b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="llama3.3:70b",
        display_name="Llama 3.3 70B",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Latest Meta model, rivals 405B performance"
    ),
    "qwen2.5:72b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="qwen2.5:72b",
        display_name="Qwen 2.5 72B",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Excellent multilingual support (29+ languages)"
    ),
    "qwen2.5-coder:32b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="qwen2.5-coder:32b",
        display_name="Qwen 2.5 Coder 32B",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.CODE_GENERATION, ModelCapability.TEXT_GENERATION,
                     ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Specialized for code generation"
    ),
    "mistral:7b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="mistral:7b",
        display_name="Mistral 7B",
        context_window=32768,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Efficient small model"
    ),
    "phi3:14b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="phi3:14b",
        display_name="Phi-3 14B",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION,
                     ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Microsoft's efficient model"
    ),
    "gemma2:27b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="gemma2:27b",
        display_name="Gemma 2 27B",
        context_window=8192,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CODE_GENERATION],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Google's open model"
    ),
    "command-r:35b": ModelSpec(
        provider=LLMProvider.OLLAMA,
        model_id="command-r:35b",
        display_name="Command R 35B",
        context_window=128000,
        max_output_tokens=None,
        capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.LONG_CONTEXT],
        input_cost_per_1k=0.0,
        output_cost_per_1k=0.0,
        notes="Optimized for RAG/retrieval"
    ),
}


def get_model_spec(model_key: str) -> Optional[ModelSpec]:
    """Get model specification by key"""
    return MODEL_REGISTRY.get(model_key)


def get_models_by_provider(provider: LLMProvider) -> Dict[str, ModelSpec]:
    """Get all models for a specific provider"""
    return {
        key: spec for key, spec in MODEL_REGISTRY.items()
        if spec.provider == provider
    }


def get_models_by_capability(capability: ModelCapability) -> Dict[str, ModelSpec]:
    """Get all models with a specific capability"""
    return {
        key: spec for key, spec in MODEL_REGISTRY.items()
        if capability in spec.capabilities
    }