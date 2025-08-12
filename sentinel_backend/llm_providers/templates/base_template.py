"""Base template class for prompt optimization."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json


@dataclass
class PromptTemplate:
    """Container for prompt template data."""
    system_prompt: Optional[str] = None
    user_prompt: str = ""
    assistant_prompt: Optional[str] = None
    variables: Dict[str, Any] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    
    def format(self, **kwargs) -> 'PromptTemplate':
        """Format the template with provided variables."""
        formatted = PromptTemplate(
            system_prompt=self._format_str(self.system_prompt, kwargs) if self.system_prompt else None,
            user_prompt=self._format_str(self.user_prompt, kwargs),
            assistant_prompt=self._format_str(self.assistant_prompt, kwargs) if self.assistant_prompt else None,
            variables=kwargs,
            max_tokens=self.max_tokens,
            temperature=self.temperature
        )
        return formatted
    
    def _format_str(self, template: str, variables: Dict[str, Any]) -> str:
        """Format a string template with variables."""
        if not template:
            return template
        
        # Handle both {var} and {{var}} formats
        result = template
        for key, value in variables.items():
            result = result.replace(f"{{{key}}}", str(value))
            result = result.replace(f"{{{{{key}}}}}", str(value))
        return result


class BasePromptTemplate(ABC):
    """Base class for model-specific prompt templates."""
    
    def __init__(self):
        """Initialize the template."""
        self.templates = self._load_templates()
    
    @abstractmethod
    def _load_templates(self) -> Dict[str, PromptTemplate]:
        """Load model-specific templates."""
        pass
    
    @abstractmethod
    def optimize_for_task(self, task: str, context: Dict[str, Any]) -> PromptTemplate:
        """Optimize prompt for a specific task."""
        pass
    
    def get_template(self, name: str) -> Optional[PromptTemplate]:
        """Get a template by name."""
        return self.templates.get(name)
    
    def format_for_api_testing(self, task: str, api_spec: Dict[str, Any]) -> PromptTemplate:
        """Format prompt specifically for API testing tasks."""
        base_template = self.get_template(task) or self.get_default_template(task)
        
        # Extract relevant API information
        api_info = self._extract_api_info(api_spec)
        
        # Format the template
        return base_template.format(
            endpoint=api_info.get("endpoint", ""),
            method=api_info.get("method", ""),
            parameters=json.dumps(api_info.get("parameters", {}), indent=2),
            schema=json.dumps(api_info.get("schema", {}), indent=2),
            description=api_info.get("description", "")
        )
    
    def _extract_api_info(self, api_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant information from API specification."""
        return {
            "endpoint": api_spec.get("path", ""),
            "method": api_spec.get("method", "GET").upper(),
            "parameters": api_spec.get("parameters", {}),
            "schema": api_spec.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {}),
            "description": api_spec.get("description", api_spec.get("summary", ""))
        }
    
    def get_default_template(self, task: str) -> PromptTemplate:
        """Get a default template for common tasks."""
        defaults = {
            "test_generation": PromptTemplate(
                system_prompt="You are an expert API tester. Generate comprehensive test cases.",
                user_prompt="Generate test cases for the following API endpoint:\n{endpoint}\nMethod: {method}\nParameters: {parameters}",
                temperature=0.7
            ),
            "data_mocking": PromptTemplate(
                system_prompt="You are a data generation expert. Create realistic test data.",
                user_prompt="Generate mock data for the following schema:\n{schema}",
                temperature=0.8
            ),
            "security_testing": PromptTemplate(
                system_prompt="You are a security testing expert. Identify potential vulnerabilities.",
                user_prompt="Analyze this API endpoint for security vulnerabilities:\n{endpoint}\nMethod: {method}",
                temperature=0.6
            ),
            "performance_testing": PromptTemplate(
                system_prompt="You are a performance testing expert. Design load testing scenarios.",
                user_prompt="Create a performance test plan for:\n{endpoint}\nExpected load: {load}",
                temperature=0.5
            )
        }
        return defaults.get(task, PromptTemplate(user_prompt="Complete the following task: {task}"))