"""
Base Agent class for all Sentinel testing agents.

This module provides the foundational structure that all specialized agents inherit from.
It defines the common interface and shared functionality for the agent ecosystem.
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
    """
    
    def __init__(self, agent_type: str):
        self.agent_type = agent_type
        self.logger = logging.getLogger(f"agent.{agent_type}")
    
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
        
        schema_type = schema.get("type", "string")
        
        if schema_type == "string":
            if "enum" in schema:
                return schema["enum"][0]
            return "example_string"
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
