"""
Comprehensive Unit Tests for FunctionalPositiveAgent

This module provides extensive test coverage for the FunctionalPositiveAgent class,
including positive test generation, happy path scenarios, and success testing.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List

from sentinel_backend.orchestration_service.agents.functional_positive_agent import (
    FunctionalPositiveAgent
)
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


class TestFunctionalPositiveAgent:
    """Comprehensive test suite for FunctionalPositiveAgent"""
    
    @pytest.fixture
    def agent(self):
        """Create FunctionalPositiveAgent instance for testing"""
        return FunctionalPositiveAgent()
    
    @pytest.fixture
    def agent_task(self):
        """Sample agent task for testing"""
        return AgentTask(
            task_id="test-positive-456",
            spec_id=1,
            agent_type="Functional-Positive-Agent",
            parameters={}
        )
    
    @pytest.fixture
    def api_spec(self):
        """Sample OpenAPI specification for testing"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [
                {"url": "https://api.example.com", "description": "Production"},
                {"url": "https://staging.example.com", "description": "Staging"}
            ],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {
                                "name": "page",
                                "in": "query",
                                "schema": {"type": "integer", "default": 1, "minimum": 1}
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100}
                            },
                            {
                                "name": "sort",
                                "in": "query",
                                "schema": {"type": "string", "enum": ["name", "created", "updated"]}
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/User"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/UserInput"},
                                    "examples": {
                                        "basic": {
                                            "value": {
                                                "name": "John Doe",
                                                "email": "john@example.com"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Created"},
                            "400": {"description": "Bad Request"}
                        }
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer", "example": 123}
                            }
                        ],
                        "responses": {
                            "200": {"description": "Success"},
                            "404": {"description": "Not Found"}
                        }
                    },
                    "put": {
                        "summary": "Update user",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}
                            }
                        ],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/UserInput"}
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Success"},
                            "404": {"description": "Not Found"}
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "email": {"type": "string", "format": "email"},
                            "created_at": {"type": "string", "format": "date-time"}
                        }
                    },
                    "UserInput": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                            "email": {"type": "string", "format": "email"},
                            "bio": {"type": "string", "maxLength": 500}
                        },
                        "required": ["name", "email"]
                    }
                }
            }
        }
    
    # Core Functionality Tests
    
    def test_agent_initialization(self, agent):
        """Test agent initialization and configuration"""
        assert agent.agent_type == "Functional-Positive-Agent"
        assert agent.max_test_variations == 12
        assert agent.include_optional_fields_probability == 0.7
        assert agent.use_example_values_probability == 0.8
        assert agent.realistic_data_probability == 0.9
    
    @pytest.mark.asyncio
    async def test_execute_success(self, agent, agent_task, api_spec):
        """Test successful execution of positive test generation"""
        result = await agent.execute(agent_task, api_spec)
        
        assert isinstance(result, AgentResult)
        assert result.task_id == agent_task.task_id
        assert result.agent_type == "Functional-Positive-Agent"
        assert result.status == "success"
        assert len(result.test_cases) > 0
        assert result.metadata is not None
        assert "total_test_cases" in result.metadata
        assert "test_categories" in result.metadata
    
    @pytest.mark.asyncio
    async def test_execute_with_empty_spec(self, agent, agent_task):
        """Test execution with empty specification"""
        empty_spec = {"paths": {}}
        
        result = await agent.execute(agent_task, empty_spec)
        
        assert result.status == "success"
        assert len(result.test_cases) == 0
    
    # Valid Data Generation Tests
    
    def test_generate_valid_data_string(self, agent):
        """Test generating valid string data"""
        schema = {
            "type": "string",
            "minLength": 5,
            "maxLength": 20,
            "pattern": "^[A-Za-z]+$"
        }
        
        for _ in range(10):
            data = agent._generate_valid_data(schema)
            assert isinstance(data, str)
            assert 5 <= len(data) <= 20
            assert all(c.isalpha() for c in data)
    
    def test_generate_valid_data_with_example(self, agent):
        """Test generating data using example values"""
        schema = {
            "type": "string",
            "example": "test@example.com"
        }
        
        # Should sometimes use the example
        examples_used = 0
        for _ in range(10):
            data = agent._generate_valid_data(schema)
            if data == "test@example.com":
                examples_used += 1
        
        assert examples_used > 0
    
    def test_generate_valid_data_integer(self, agent):
        """Test generating valid integer data"""
        schema = {
            "type": "integer",
            "minimum": 10,
            "maximum": 100,
            "multipleOf": 5
        }
        
        for _ in range(10):
            data = agent._generate_valid_data(schema)
            assert isinstance(data, int)
            assert 10 <= data <= 100
            assert data % 5 == 0
    
    def test_generate_valid_data_array(self, agent):
        """Test generating valid array data"""
        schema = {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
            "maxItems": 5,
            "uniqueItems": True
        }
        
        data = agent._generate_valid_data(schema)
        assert isinstance(data, list)
        assert 2 <= len(data) <= 5
        assert len(data) == len(set(data))  # Check uniqueness
    
    def test_generate_valid_data_object(self, agent):
        """Test generating valid object data"""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer", "minimum": 0},
                "email": {"type": "string", "format": "email"}
            },
            "required": ["name", "email"]
        }
        
        data = agent._generate_valid_data(schema)
        assert isinstance(data, dict)
        assert "name" in data
        assert "email" in data
        assert isinstance(data["name"], str)
        assert "@" in data["email"]
        
        # Optional field should sometimes be included
        optional_included = 0
        for _ in range(10):
            data = agent._generate_valid_data(schema)
            if "age" in data:
                optional_included += 1
        assert optional_included > 0
    
    # Test Case Generation Tests
    
    @pytest.mark.asyncio
    async def test_generate_test_cases(self, agent, api_spec):
        """Test comprehensive test case generation"""
        test_cases = await agent.generate_test_cases(api_spec)
        
        assert len(test_cases) > 0
        
        # Check test case structure
        for test_case in test_cases:
            assert "test_name" in test_case
            assert "test_type" in test_case
            assert test_case["test_type"] == "functional-positive"
            assert "method" in test_case
            assert "path" in test_case
            assert "expected_status_codes" in test_case
            
            # Should expect success status codes
            for status in test_case["expected_status_codes"]:
                assert 200 <= status < 300
    
    def test_generate_minimal_valid_request(self, agent, api_spec):
        """Test generating minimal valid requests"""
        path = "/users"
        method = "post"
        operation = api_spec["paths"]["/users"]["post"]
        
        test_cases = agent._generate_minimal_valid_request(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "minimal"
            assert "body" in test_case
            
            body = test_case["body"]
            if isinstance(body, dict):
                # Should have only required fields
                assert "name" in body
                assert "email" in body
                # Optional field should not be present in minimal request
                assert "bio" not in body
    
    def test_generate_complete_valid_request(self, agent, api_spec):
        """Test generating complete valid requests"""
        path = "/users"
        method = "post"
        operation = api_spec["paths"]["/users"]["post"]
        
        test_cases = agent._generate_complete_valid_request(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "complete"
            assert "body" in test_case
            
            body = test_case["body"]
            if isinstance(body, dict):
                # Should have all fields including optional
                assert "name" in body
                assert "email" in body
                # Complete request should include optional fields
                assert "bio" in body
    
    def test_generate_example_based_request(self, agent, api_spec):
        """Test generating requests based on examples"""
        path = "/users"
        method = "post"
        operation = api_spec["paths"]["/users"]["post"]
        
        test_cases = agent._generate_example_based_request(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "example-based"
            assert "body" in test_case
            
            body = test_case["body"]
            if isinstance(body, dict):
                # Should use example values
                assert body.get("name") == "John Doe" or "name" in body
                assert body.get("email") == "john@example.com" or "email" in body
    
    def test_generate_valid_query_combinations(self, agent, api_spec):
        """Test generating valid query parameter combinations"""
        path = "/users"
        method = "get"
        operation = api_spec["paths"]["/users"]["get"]
        
        test_cases = agent._generate_valid_query_combinations(path, method, operation)
        
        assert len(test_cases) > 0
        
        # Should have different combinations
        param_combinations = []
        for test_case in test_cases:
            params = frozenset(test_case.get("query_params", {}).keys())
            param_combinations.append(params)
        
        # Should have variety in combinations
        assert len(set(param_combinations)) > 1
    
    def test_generate_valid_path_params(self, agent, api_spec):
        """Test generating valid path parameters"""
        path = "/users/{id}"
        method = "get"
        operation = api_spec["paths"]["/users/{id}"]["get"]
        
        test_cases = agent._generate_valid_path_params(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert "path_params" in test_case
            assert "id" in test_case["path_params"]
            
            # Should use valid integer IDs
            id_value = test_case["path_params"]["id"]
            assert isinstance(id_value, int)
            assert id_value > 0
    
    # Realistic Data Generation Tests
    
    def test_generate_realistic_string(self, agent):
        """Test generating realistic string values"""
        # Name field
        data = agent._generate_realistic_string("name", {})
        assert isinstance(data, str)
        assert len(data) > 0
        
        # Email field
        data = agent._generate_realistic_string("email", {"format": "email"})
        assert "@" in data
        assert "." in data.split("@")[1]
        
        # Phone field
        data = agent._generate_realistic_string("phone", {})
        assert any(c.isdigit() for c in data)
        
        # URL field
        data = agent._generate_realistic_string("url", {"format": "uri"})
        assert data.startswith("http")
    
    def test_generate_realistic_integer(self, agent):
        """Test generating realistic integer values"""
        # Age field
        data = agent._generate_realistic_integer("age", {"minimum": 0, "maximum": 120})
        assert 18 <= data <= 65  # Realistic age range
        
        # ID field
        data = agent._generate_realistic_integer("id", {})
        assert data > 0
        
        # Count field
        data = agent._generate_realistic_integer("count", {"minimum": 0})
        assert data >= 0
    
    # LLM Enhancement Tests
    
    @pytest.mark.asyncio
    async def test_generate_llm_positive_tests(self, agent, api_spec):
        """Test LLM-enhanced positive test generation"""
        with patch.object(agent, 'llm_enabled', True):
            with patch.object(agent, 'enhance_with_llm', new_callable=AsyncMock) as mock_llm:
                # Setup mock response
                mock_llm.return_value = [
                    {
                        "description": "Create premium user",
                        "body": {
                            "name": "Premium User",
                            "email": "premium@example.com",
                            "bio": "VIP customer account"
                        },
                        "expected_status": 201
                    }
                ]
                
                endpoint = {
                    "path": "/users",
                    "method": "POST",
                    "operation": api_spec["paths"]["/users"]["post"]
                }
                
                test_cases = await agent._generate_llm_positive_tests([endpoint], api_spec)
                
                assert len(test_cases) > 0
                assert mock_llm.called
    
    # Edge Cases and Error Handling
    
    def test_handle_allof_schema(self, agent):
        """Test handling of allOf schema composition"""
        schema = {
            "allOf": [
                {"type": "object", "properties": {"id": {"type": "integer"}}},
                {"type": "object", "properties": {"name": {"type": "string"}}}
            ]
        }
        
        data = agent._generate_valid_data(schema)
        assert isinstance(data, dict)
        # Should merge properties from all schemas
        assert "id" in data or "name" in data
    
    def test_handle_oneof_schema(self, agent):
        """Test handling of oneOf schema composition"""
        schema = {
            "oneOf": [
                {"type": "string"},
                {"type": "integer"}
            ]
        }
        
        data = agent._generate_valid_data(schema)
        assert isinstance(data, (str, int))
    
    def test_handle_anyof_schema(self, agent):
        """Test handling of anyOf schema composition"""
        schema = {
            "anyOf": [
                {"type": "string", "minLength": 5},
                {"type": "integer", "minimum": 10}
            ]
        }
        
        data = agent._generate_valid_data(schema)
        if isinstance(data, str):
            assert len(data) >= 5
        elif isinstance(data, int):
            assert data >= 10
    
    def test_handle_recursive_schema(self, agent):
        """Test handling of recursive schema references"""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "children": {
                    "type": "array",
                    "items": {"$ref": "#"}  # Recursive reference
                }
            }
        }
        
        # Should handle without infinite recursion
        data = agent._generate_valid_data(schema)
        assert isinstance(data, dict)
    
    @pytest.mark.asyncio
    async def test_concurrent_endpoint_processing(self, agent, api_spec):
        """Test concurrent processing of multiple endpoints"""
        # Add more endpoints
        api_spec["paths"]["/products"] = {
            "get": {"responses": {"200": {}}},
            "post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}
        }
        api_spec["paths"]["/orders"] = {
            "get": {"responses": {"200": {}}},
            "post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}
        }
        
        test_cases = await agent.generate_test_cases(api_spec)
        
        # Should generate tests for all endpoints
        paths_tested = set(tc["path"] for tc in test_cases)
        assert "/users" in paths_tested
        assert "/products" in paths_tested
        assert "/orders" in paths_tested
    
    def test_server_url_handling(self, agent, api_spec):
        """Test handling of server URLs from specification"""
        servers = agent._extract_server_urls(api_spec)
        
        assert len(servers) == 2
        assert "https://api.example.com" in servers
        assert "https://staging.example.com" in servers