"""
Prompt Templates Module

Provides model-specific prompt optimization and template management.
"""

from .base_template import BasePromptTemplate, PromptTemplate
from .model_templates import (
    get_template_for_model,
    OpenAITemplate,
    AnthropicTemplate,
    GoogleTemplate,
    MistralTemplate,
    OllamaTemplate
)

__all__ = [
    "BasePromptTemplate",
    "PromptTemplate",
    "get_template_for_model",
    "OpenAITemplate",
    "AnthropicTemplate",
    "GoogleTemplate",
    "MistralTemplate",
    "OllamaTemplate"
]