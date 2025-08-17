"""
Comprehensive Unit Tests for BaseAgent Class

This module provides extensive test coverage for the BaseAgent class,
including core functionality, LLM integration, error handling, and edge cases.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call
from typing import Dict, Any, List, Optional
import logging

from sentinel_backend.orchestration_service.agents.base_agent import (
    BaseAgent, AgentTask, AgentResult
)


class ConcreteAgent(BaseAgent):
    """Concrete implementation of BaseAgent for testing"""
    
    async def execute(self, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
        """Concrete implementation of abstract execute method"""
        return AgentResult(
            task_id=task.task_id,
            agent_type=self.agent_type,
            status="success",
            test_cases=[],
            metadata={}
        )


class TestBaseAgent:
    """Comprehensive test suite for BaseAgent class"""
    
    @pytest.fixture
    def mock_settings(self):
        """Mock application settings"""
        mock = MagicMock()
        mock.llm_provider = "openai"
        mock.llm_model = "gpt-4"
        mock.openai_api_key = "test-key"
        mock.llm_temperature = 0.7
        mock.llm_max_tokens = 2000
        mock.llm_top_p = 0.9
        mock.llm_timeout = 30
        mock.llm_max_retries = 3
        mock.llm_cache_enabled = True
        mock.llm_cache_ttl = 3600
        mock.llm_fallback_enabled = False
        return mock
    
    @pytest.fixture
    def mock_llm_provider(self):
        """Mock LLM provider"""
        mock = MagicMock()
        mock.config = MagicMock()
        mock.config.provider = "openai"
        mock.config.model = "gpt-4"
        mock.generate = AsyncMock()
        return mock
    
    @pytest.fixture
    def agent_task(self):
        """Sample agent task for testing"""
        return AgentTask(
            task_id="test-task-123",
            spec_id=1,
            agent_type="test-agent",
            parameters={"test_param": "value"}
        )
    
    @pytest.fixture
    def api_spec(self):
        """Sample OpenAPI specification"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {
                            "200": {"description": "Success"}
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "email": {"type": "string", "format": "email"}
                                        },
                                        "required": ["name", "email"]
                                    }
                                }
                            }
                        }
                    }
                },
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ]
                    },
                    "delete": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ]
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer", "minimum": 1},
                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                            "email": {"type": "string", "format": "email"},
                            "role": {"type": "string", "enum": ["admin", "user", "guest"]},
                            "active": {"type": "boolean"},
                            "tags": {"type": "array", "items": {"type": "string"}},
                            "metadata": {
                                "type": "object",
                                "properties": {
                                    "created": {"type": "string", "format": "date-time"}
                                }
                            }
                        }
                    }
                }
            }
        }
    
    # Core Functionality Tests
    
    def test_agent_initialization(self):
        """Test agent initialization with different configurations"""
        agent = ConcreteAgent("test-agent")
        assert agent.agent_type == "test-agent"
        assert agent.logger is not None
        assert agent.llm_provider is None
        assert agent.llm_enabled is False
    
    @patch('sentinel_backend.config.settings.get_application_settings')
    def test_agent_initialization_with_llm(self, mock_get_settings, mock_settings, mock_llm_provider):
        """Test agent initialization with LLM enabled"""
        mock_get_settings.return_value = mock_settings
        
        with patch('sentinel_backend.llm_providers.LLMProviderFactory.create_provider') as mock_create:
            mock_create.return_value = mock_llm_provider
            agent = ConcreteAgent("test-agent")
            
            assert agent.llm_enabled is True
            assert agent.llm_provider is not None
    
    def test_create_test_case(self):
        """Test creating standardized test cases"""
        agent = ConcreteAgent("test-agent")
        
        test_case = agent._create_test_case(
            endpoint="/users",
            method="GET",
            description="Test getting users",
            headers={"Authorization": "Bearer token"},
            query_params={"limit": 10},
            body=None,
            expected_status=200,
            assertions=[{"type": "status_code", "expected": 200}]
        )
        
        assert test_case["endpoint"] == "/users"
        assert test_case["method"] == "GET"
        assert test_case["description"] == "Test getting users"
        assert test_case["headers"]["Authorization"] == "Bearer token"
        assert test_case["query_params"]["limit"] == 10
        assert test_case["expected_status"] == 200
        assert len(test_case["assertions"]) == 1
    
    def test_extract_endpoints(self, api_spec):
        """Test extracting endpoints from API specification"""
        agent = ConcreteAgent("test-agent")
        endpoints = agent._extract_endpoints(api_spec)
        
        assert len(endpoints) == 4  # GET /users, POST /users, GET /users/{id}, DELETE /users/{id}
        
        # Check first endpoint
        assert endpoints[0]["path"] == "/users"
        assert endpoints[0]["method"] == "GET"
        assert "summary" in endpoints[0]
        
        # Check path parameters are extracted
        user_id_endpoints = [e for e in endpoints if "{id}" in e["path"]]
        assert len(user_id_endpoints) == 2
    
    def test_get_schema_example_string(self):
        """Test generating example for string schema"""
        agent = ConcreteAgent("test-agent")
        
        # Basic string
        example = agent._get_schema_example({"type": "string"})
        assert example == "example_string"
        
        # String with enum
        example = agent._get_schema_example({"type": "string", "enum": ["red", "green", "blue"]})
        assert example == "red"
        
        # String with example
        example = agent._get_schema_example({"type": "string", "example": "test@example.com"})
        assert example == "test@example.com"
    
    def test_get_schema_example_number(self):
        """Test generating example for numeric schemas"""
        agent = ConcreteAgent("test-agent")
        
        # Integer
        example = agent._get_schema_example({"type": "integer"})
        assert example == 1
        
        # Integer with minimum
        example = agent._get_schema_example({"type": "integer", "minimum": 10})
        assert example == 10
        
        # Number
        example = agent._get_schema_example({"type": "number"})
        assert example == 1.0
        
        # Boolean
        example = agent._get_schema_example({"type": "boolean"})
        assert example is True
    
    def test_get_schema_example_array(self):
        """Test generating example for array schema"""
        agent = ConcreteAgent("test-agent")
        
        # Simple array
        example = agent._get_schema_example({
            "type": "array",
            "items": {"type": "string"}
        })
        assert isinstance(example, list)
        assert len(example) == 1
        assert example[0] == "example_string"
        
        # Array with complex items
        example = agent._get_schema_example({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"}
                }
            }
        })
        assert isinstance(example, list)
        assert isinstance(example[0], dict)
        assert "id" in example[0]
    
    def test_get_schema_example_object(self):
        """Test generating example for object schema"""
        agent = ConcreteAgent("test-agent")
        
        schema = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "active": {"type": "boolean"}
            },
            "required": ["id", "name"]
        }
        
        example = agent._get_schema_example(schema)
        assert isinstance(example, dict)
        assert "id" in example
        assert "name" in example
        assert example["id"] == 1
        assert example["name"] == "example_string"
    
    # LLM Integration Tests
    
    @pytest.mark.asyncio
    @patch('sentinel_backend.config.settings.get_application_settings')
    async def test_enhance_with_llm_success(self, mock_get_settings, mock_settings, mock_llm_provider):
        """Test successful LLM enhancement"""
        mock_get_settings.return_value = mock_settings
        
        with patch('sentinel_backend.llm_providers.LLMProviderFactory.create_provider') as mock_create:
            mock_create.return_value = mock_llm_provider
            
            # Setup mock response
            mock_response = MagicMock()
            mock_response.content = '{"enhanced": "data"}'
            mock_llm_provider.generate.return_value = mock_response
            
            agent = ConcreteAgent("test-agent")
            agent.llm_enabled = True
            agent.llm_provider = mock_llm_provider
            
            result = await agent.enhance_with_llm(
                {"original": "data"},
                "Enhance this data",
                system_prompt="You are a helpful assistant"
            )
            
            assert result == {"enhanced": "data"}
            mock_llm_provider.generate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_enhance_with_llm_disabled(self):
        """Test enhancement when LLM is disabled"""
        agent = ConcreteAgent("test-agent")
        agent.llm_enabled = False
        
        original_data = {"original": "data"}
        result = await agent.enhance_with_llm(
            original_data,
            "Enhance this data"
        )
        
        assert result == original_data
    
    @pytest.mark.asyncio
    @patch('sentinel_backend.config.settings.get_application_settings')
    async def test_enhance_with_llm_error_handling(self, mock_get_settings, mock_settings, mock_llm_provider):
        """Test LLM enhancement error handling"""
        mock_get_settings.return_value = mock_settings
        
        agent = ConcreteAgent("test-agent")
        agent.llm_enabled = True
        agent.llm_provider = mock_llm_provider
        
        # Setup mock to raise exception
        mock_llm_provider.generate.side_effect = Exception("LLM error")
        
        original_data = {"original": "data"}
        result = await agent.enhance_with_llm(original_data, "Enhance this")
        
        # Should return original data on error
        assert result == original_data
    
    @pytest.mark.asyncio
    async def test_generate_creative_variant(self, mock_llm_provider):
        """Test generating creative test case variants"""
        agent = ConcreteAgent("test-agent")
        agent.llm_enabled = True
        agent.llm_provider = mock_llm_provider
        
        # Setup mock response
        mock_response = MagicMock()
        mock_response.content = json.dumps({
            "endpoint": "/users",
            "method": "POST",
            "body": {"name": "Creative User", "email": "creative@test.com"}
        })
        mock_llm_provider.generate.return_value = mock_response
        
        test_case = {
            "endpoint": "/users",
            "method": "POST",
            "body": {"name": "Test User", "email": "test@test.com"}
        }
        
        variant = await agent.generate_creative_variant(test_case, "realistic")
        
        assert variant is not None
        assert variant["endpoint"] == "/users"
        assert variant["method"] == "POST"
        assert "Creative" in variant["body"]["name"]
    
    # Edge Cases and Error Handling
    
    def test_extract_endpoints_empty_spec(self):
        """Test endpoint extraction with empty specification"""
        agent = ConcreteAgent("test-agent")
        endpoints = agent._extract_endpoints({})
        assert endpoints == []
        
        endpoints = agent._extract_endpoints({"paths": {}})
        assert endpoints == []
    
    def test_get_schema_example_unknown_type(self):
        """Test schema example generation with unknown type"""
        agent = ConcreteAgent("test-agent")
        
        example = agent._get_schema_example({"type": "unknown"})
        assert example is None
        
        example = agent._get_schema_example({})
        assert example is None
    
    def test_create_test_case_with_none_values(self):
        """Test creating test case with None values"""
        agent = ConcreteAgent("test-agent")
        
        test_case = agent._create_test_case(
            endpoint="/test",
            method="GET",
            description="Test",
            headers=None,
            query_params=None,
            body=None,
            expected_status=200,
            assertions=None
        )
        
        assert test_case["headers"] == {}
        assert test_case["query_params"] == {}
        assert test_case["body"] is None
        assert test_case["assertions"] == []
    
    @patch('sentinel_backend.config.settings.get_application_settings')
    def test_initialize_llm_no_api_key(self, mock_get_settings, mock_settings):
        """Test LLM initialization without API key"""
        mock_settings.llm_provider = "openai"
        mock_settings.openai_api_key = None
        mock_get_settings.return_value = mock_settings
        
        agent = ConcreteAgent("test-agent")
        assert agent.llm_enabled is False
        assert agent.llm_provider is None
    
    @patch('sentinel_backend.config.settings.get_application_settings')
    def test_initialize_llm_with_ollama(self, mock_get_settings, mock_settings):
        """Test LLM initialization with Ollama (no API key required)"""
        mock_settings.llm_provider = "ollama"
        mock_settings.ollama_base_url = "http://localhost:11434"
        mock_get_settings.return_value = mock_settings
        
        with patch('sentinel_backend.llm_providers.LLMProviderFactory.create_provider') as mock_create:
            mock_create.return_value = MagicMock()
            agent = ConcreteAgent("test-agent")
            
            # Ollama should initialize without API key
            assert mock_create.called
    
    def test_get_api_key_for_provider(self, mock_settings):
        """Test getting API key for different providers"""
        agent = ConcreteAgent("test-agent")
        
        # OpenAI
        mock_settings.llm_provider = "openai"
        mock_settings.openai_api_key = "openai-key"
        key = agent._get_api_key_for_provider(mock_settings)
        assert key == "openai-key"
        
        # Anthropic
        mock_settings.llm_provider = "anthropic"
        mock_settings.anthropic_api_key = "anthropic-key"
        key = agent._get_api_key_for_provider(mock_settings)
        assert key == "anthropic-key"
        
        # Unknown provider
        mock_settings.llm_provider = "unknown"
        key = agent._get_api_key_for_provider(mock_settings)
        assert key is None
    
    def test_get_api_base_for_provider(self, mock_settings):
        """Test getting API base URL for providers"""
        agent = ConcreteAgent("test-agent")
        
        # Ollama
        mock_settings.llm_provider = "ollama"
        mock_settings.ollama_base_url = "http://localhost:11434"
        base = agent._get_api_base_for_provider(mock_settings)
        assert base == "http://localhost:11434"
        
        # vLLM
        mock_settings.llm_provider = "vllm"
        mock_settings.vllm_base_url = "http://localhost:8000"
        base = agent._get_api_base_for_provider(mock_settings)
        assert base == "http://localhost:8000"
        
        # Other providers
        mock_settings.llm_provider = "openai"
        base = agent._get_api_base_for_provider(mock_settings)
        assert base is None
    
    @pytest.mark.asyncio
    async def test_execute_abstract_method(self, agent_task, api_spec):
        """Test that execute method is properly implemented in concrete class"""
        agent = ConcreteAgent("test-agent")
        result = await agent.execute(agent_task, api_spec)
        
        assert isinstance(result, AgentResult)
        assert result.task_id == agent_task.task_id
        assert result.agent_type == "test-agent"
        assert result.status == "success"
    
    def test_extract_endpoints_with_multiple_methods(self, api_spec):
        """Test extraction of endpoints with multiple HTTP methods"""
        agent = ConcreteAgent("test-agent")
        
        # Add more methods to test
        api_spec["paths"]["/users"]["put"] = {"summary": "Update all users"}
        api_spec["paths"]["/users"]["patch"] = {"summary": "Partial update"}
        api_spec["paths"]["/users"]["head"] = {"summary": "Check users"}
        api_spec["paths"]["/users"]["options"] = {"summary": "Options"}
        
        endpoints = agent._extract_endpoints(api_spec)
        
        # Should include all standard HTTP methods
        methods = [e["method"] for e in endpoints if e["path"] == "/users"]
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods
        assert "PATCH" in methods
        assert "HEAD" in methods
        assert "OPTIONS" in methods
    
    def test_complex_schema_example_generation(self):
        """Test generating examples for complex nested schemas"""
        agent = ConcreteAgent("test-agent")
        
        complex_schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "profile": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "age": {"type": "integer", "minimum": 18}
                            }
                        },
                        "settings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "key": {"type": "string"},
                                    "value": {"type": "boolean"}
                                }
                            }
                        }
                    }
                }
            }
        }
        
        example = agent._get_schema_example(complex_schema)
        
        assert isinstance(example, dict)
        assert "user" in example
        assert "profile" in example["user"]
        assert "settings" in example["user"]
        assert isinstance(example["user"]["settings"], list)