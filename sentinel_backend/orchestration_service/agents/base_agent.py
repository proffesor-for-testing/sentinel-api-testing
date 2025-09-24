"""
Base Agent class for all Sentinel testing agents.

This module provides the foundational structure that all specialized agents inherit from.
It defines the common interface and shared functionality for the agent ecosystem.

Now enhanced with optional LLM capabilities that can be enabled via configuration.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
import json
import logging

logger = logging.getLogger(__name__)


class AgentTask(BaseModel):
    """Represents a task that can be executed by an agent."""
    task_id: str
    spec_id: int
    agent_type: str
    parameters: Dict[str, Any] = {}
    target_environment: Optional[str] = None


class AgentResult(BaseModel):
    """Represents the result of an agent's execution."""
    task_id: str
    agent_type: str
    status: str  # "success", "failed", "partial"
    test_cases: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}
    error_message: Optional[str] = None


class BaseAgent(ABC):
    """
    Abstract base class for all Sentinel testing agents.
    
    Each agent is responsible for a specific type of test generation or analysis.
    Agents follow the "ephemeral" pattern - they are spawned for a specific task,
    execute it, and then dissolve.
    
    Now supports optional LLM enhancement based on configuration.
    """
    
    def __init__(self, agent_type: str):
        self.agent_type = agent_type
        self.logger = logging.getLogger(f"agent.{agent_type}")
        self.llm_provider = None
        self.llm_enabled = False
        self._initialize_llm_if_configured()
    
    @abstractmethod
    async def execute(self, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
        """
        Execute the agent's primary function.
        
        Args:
            task: The specific task to execute
            api_spec: The parsed API specification
            
        Returns:
            AgentResult containing generated test cases and metadata
        """
        pass
    
    def _create_test_case(
        self, 
        endpoint: str, 
        method: str, 
        description: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        expected_status: int = 200,
        assertions: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Helper method to create a standardized test case structure.
        
        Returns:
            A dictionary representing a test case that can be executed by the test runner
        """
        test_case = {
            "endpoint": endpoint,
            "method": method.upper(),
            "description": description,
            "headers": headers or {},
            "query_params": query_params or {},
            "expected_status": expected_status,
            "assertions": assertions or []
        }
        
        if body is not None:
            test_case["body"] = body
            
        return test_case
    
    def _extract_endpoints(self, api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract all endpoints from the API specification.
        
        Returns:
            List of endpoint definitions with path, method, and operation details
        """
        endpoints = []
        paths = api_spec.get("paths", {})
        
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() in ["get", "post", "put", "patch", "delete", "head", "options"]:
                    endpoints.append({
                        "path": path,
                        "method": method.upper(),
                        "operation": operation,
                        "summary": operation.get("summary", ""),
                        "description": operation.get("description", ""),
                        "parameters": operation.get("parameters", []),
                        "requestBody": operation.get("requestBody", {}),
                        "responses": operation.get("responses", {})
                    })
        
        return endpoints
    
    def _get_schema_example(self, schema: Dict[str, Any]) -> Any:
        """
        Generate an example value based on a JSON schema.

        This is a basic implementation that can be enhanced with more sophisticated
        data generation techniques.
        """
        if "example" in schema:
            return schema["example"]

        # Handle anyOf/oneOf - take the first non-null option
        if "anyOf" in schema:
            for option in schema["anyOf"]:
                if option.get("type") != "null":
                    # If it's a $ref, we'll return the option as-is for now
                    # The caller should resolve refs if needed
                    return self._get_schema_example(option)

        if "oneOf" in schema:
            for option in schema["oneOf"]:
                if option.get("type") != "null":
                    return self._get_schema_example(option)

        # Check for enum values first (they can override the type)
        if "enum" in schema and schema["enum"]:
            import random
            return random.choice(schema["enum"])

        schema_type = schema.get("type", "string")

        if schema_type == "string":
            # Generate more realistic string values based on format or property name
            format_hint = schema.get("format", "")
            if format_hint == "email":
                return "test@example.com"
            elif format_hint == "uri" or format_hint == "url":
                return "https://example.com"
            elif format_hint == "date":
                return "2024-01-01"
            elif format_hint == "date-time":
                return "2024-01-01T00:00:00Z"
            # Default realistic values for common properties
            return "Test Value"
        elif schema_type == "integer":
            return schema.get("minimum", 1)
        elif schema_type == "number":
            return schema.get("minimum", 1.0)
        elif schema_type == "boolean":
            return True
        elif schema_type == "array":
            items_schema = schema.get("items", {})
            return [self._get_schema_example(items_schema)]
        elif schema_type == "object":
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            
            example_obj = {}
            for prop_name, prop_schema in properties.items():
                if prop_name in required or len(properties) <= 3:  # Include all if few properties
                    example_obj[prop_name] = self._get_schema_example(prop_schema)
            
            return example_obj
        
        return None
    
    def _initialize_llm_if_configured(self):
        """Initialize LLM provider if configured in settings."""
        try:
            from sentinel_backend.config.settings import get_application_settings
            from sentinel_backend.llm_providers import LLMProviderFactory, LLMConfig
            from sentinel_backend.llm_providers.base_provider import LLMProvider
            
            app_settings = get_application_settings()
            
            # Check if LLM is configured and should be enabled
            if not app_settings.llm_provider or app_settings.llm_provider == "none":
                self.logger.debug("LLM provider not configured or disabled")
                return
            
            # Get API key for the provider
            api_key = self._get_api_key_for_provider(app_settings)
            if not api_key and app_settings.llm_provider not in ["ollama", "vllm"]:
                self.logger.warning(f"No API key found for provider {app_settings.llm_provider}")
                return
            
            # Create LLM configuration
            config = LLMConfig(
                provider=LLMProvider(app_settings.llm_provider),
                model=app_settings.llm_model,
                api_key=api_key,
                api_base=self._get_api_base_for_provider(app_settings),
                temperature=app_settings.llm_temperature,
                max_tokens=app_settings.llm_max_tokens,
                top_p=app_settings.llm_top_p,
                timeout=app_settings.llm_timeout,
                max_retries=app_settings.llm_max_retries,
                cache_enabled=app_settings.llm_cache_enabled,
                cache_ttl=app_settings.llm_cache_ttl
            )
            
            # Create provider with fallback if enabled
            if app_settings.llm_fallback_enabled:
                self.llm_provider = LLMProviderFactory.create_with_fallback(
                    primary_config=config,
                    app_settings=app_settings
                )
            else:
                self.llm_provider = LLMProviderFactory.create_provider(config)
            
            self.llm_enabled = True
            self.logger.info(f"LLM provider initialized: {config.provider.value} with model {config.model}")
            
        except Exception as e:
            self.logger.debug(f"LLM initialization skipped or failed: {e}")
            self.llm_enabled = False
    
    def _get_api_key_for_provider(self, app_settings) -> Optional[str]:
        """Get API key for the configured provider."""
        provider_key_map = {
            "openai": "openai_api_key",
            "anthropic": "anthropic_api_key",
            "google": "google_api_key",
            "mistral": "mistral_api_key"
        }
        
        key_attr = provider_key_map.get(app_settings.llm_provider)
        if key_attr:
            return getattr(app_settings, key_attr, None)
        return None
    
    def _get_api_base_for_provider(self, app_settings) -> Optional[str]:
        """Get API base URL for the configured provider."""
        if app_settings.llm_provider == "ollama":
            return app_settings.ollama_base_url
        elif app_settings.llm_provider == "vllm":
            return app_settings.vllm_base_url
        return None
    
    async def enhance_with_llm(
        self,
        data: Any,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None
    ) -> Optional[Any]:
        """
        Enhance data using LLM if available.
        
        Args:
            data: Data to enhance (will be JSON serialized if dict/list)
            prompt: Enhancement prompt
            system_prompt: Optional system prompt
            temperature: Optional temperature override
            
        Returns:
            Enhanced data or original data if LLM not available
        """
        if not self.llm_enabled or not self.llm_provider:
            return data
        
        try:
            from sentinel_backend.llm_providers.base_provider import Message
            
            # Build messages
            messages = []
            if system_prompt:
                messages.append(Message(role="system", content=system_prompt))
            
            # Include data in prompt if it's structured
            if isinstance(data, (dict, list)):
                full_prompt = f"{prompt}\n\nData:\n{json.dumps(data, indent=2)}"
            else:
                full_prompt = f"{prompt}\n\nData: {data}"
            
            messages.append(Message(role="user", content=full_prompt))
            
            # Generate enhancement
            kwargs = {}
            if temperature is not None:
                kwargs["temperature"] = temperature
            
            response = await self.llm_provider.generate(messages, **kwargs)
            
            # Try to parse as JSON if the original data was structured
            if isinstance(data, (dict, list)):
                try:
                    return json.loads(response.content)
                except json.JSONDecodeError:
                    self.logger.debug("LLM response not valid JSON, returning as text")
                    return response.content
            
            return response.content
            
        except Exception as e:
            self.logger.debug(f"LLM enhancement failed: {e}")
            return data
    
    async def generate_creative_variant(
        self,
        test_case: Dict[str, Any],
        variation_type: str = "realistic"
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a creative variant of a test case using LLM.
        
        Args:
            test_case: Original test case
            variation_type: Type of variation (realistic, edge_case, unusual)
            
        Returns:
            Variant test case or None if LLM not available
        """
        if not self.llm_enabled:
            return None
        
        prompts = {
            "realistic": "Create a realistic variant of this test case with different but valid data",
            "edge_case": "Create an edge case variant that tests boundaries",
            "unusual": "Create an unusual but valid variant that might expose hidden issues"
        }
        
        prompt = prompts.get(variation_type, prompts["realistic"])
        system_prompt = "You are an expert API tester. Generate test case variants that maintain the same structure but use different test data and scenarios."
        
        variant = await self.enhance_with_llm(
            test_case,
            prompt,
            system_prompt=system_prompt,
            temperature=0.7
        )
        
        if isinstance(variant, dict):
            # Ensure the variant maintains required fields
            variant["endpoint"] = test_case.get("endpoint", variant.get("endpoint"))
            variant["method"] = test_case.get("method", variant.get("method"))
            return variant
        
        return None
