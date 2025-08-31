"""
Ollama Model Configuration

Defines available Ollama models and their specific configurations.
"""

from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class OllamaModelConfig:
    """Configuration for an Ollama model"""
    name: str
    display_name: str
    description: str
    context_length: int
    default_temperature: float
    capabilities: List[str]
    recommended_for: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "context_length": self.context_length,
            "default_temperature": self.default_temperature,
            "capabilities": self.capabilities,
            "recommended_for": self.recommended_for
        }


# Available Ollama models with their configurations
OLLAMA_MODELS = {
    "mistral:7b": OllamaModelConfig(
        name="mistral:7b",
        display_name="Mistral 7B",
        description="Fast, general-purpose model with good balance of speed and quality",
        context_length=8192,
        default_temperature=0.7,
        capabilities=["text_generation", "reasoning", "analysis"],
        recommended_for=["functional_testing", "general_agents", "quick_generation"]
    ),
    
    "codellama:7b": OllamaModelConfig(
        name="codellama:7b",
        display_name="Code Llama 7B",
        description="Specialized for code generation and technical tasks",
        context_length=16384,
        default_temperature=0.5,
        capabilities=["code_generation", "api_analysis", "technical_writing"],
        recommended_for=["api_testing", "test_generation", "code_analysis"]
    ),
    
    "deepseek-coder:6.7b": OllamaModelConfig(
        name="deepseek-coder:6.7b",
        display_name="DeepSeek Coder 6.7B",
        description="Advanced code model with strong reasoning capabilities",
        context_length=16384,
        default_temperature=0.5,
        capabilities=["code_generation", "reasoning", "debugging", "optimization"],
        recommended_for=["complex_testing", "security_analysis", "performance_optimization"]
    )
}


def get_available_models() -> List[str]:
    """Get list of available model names"""
    return list(OLLAMA_MODELS.keys())


def get_model_config(model_name: str) -> OllamaModelConfig:
    """
    Get configuration for a specific model.
    
    Args:
        model_name: Name of the model
        
    Returns:
        Model configuration
        
    Raises:
        KeyError: If model not found
    """
    if model_name not in OLLAMA_MODELS:
        raise KeyError(f"Model {model_name} not found. Available models: {get_available_models()}")
    return OLLAMA_MODELS[model_name]


def get_recommended_model(task_type: str) -> str:
    """
    Get recommended model for a specific task type.
    
    Args:
        task_type: Type of task (e.g., "api_testing", "security_analysis")
        
    Returns:
        Recommended model name
    """
    # Default recommendations based on task type
    recommendations = {
        "api_testing": "codellama:7b",
        "functional_testing": "mistral:7b",
        "security_analysis": "deepseek-coder:6.7b",
        "performance_optimization": "deepseek-coder:6.7b",
        "general": "mistral:7b",
        "code_generation": "codellama:7b",
        "complex_reasoning": "deepseek-coder:6.7b"
    }
    
    return recommendations.get(task_type, "mistral:7b")


def get_model_for_agent(agent_type: str) -> str:
    """
    Get recommended model for a specific agent type.
    
    Args:
        agent_type: Type of agent
        
    Returns:
        Recommended model name
    """
    # Agent-specific recommendations
    agent_models = {
        "Functional-Positive-Agent": "mistral:7b",
        "Functional-Negative-Agent": "codellama:7b",
        "Functional-Stateful-Agent": "deepseek-coder:6.7b",
        "Security-Auth-Agent": "deepseek-coder:6.7b",
        "Security-Injection-Agent": "deepseek-coder:6.7b",
        "Performance-Planner-Agent": "codellama:7b",
        "Data-Mocking-Agent": "mistral:7b"
    }
    
    return agent_models.get(agent_type, "mistral:7b")