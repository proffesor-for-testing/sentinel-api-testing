"""
Comprehensive Unit Tests for FunctionalNegativeAgent

This module provides extensive test coverage for the FunctionalNegativeAgent class,
including negative test generation, error scenarios, and validation testing.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List

from sentinel_backend.orchestration_service.agents.functional_negative_agent import (
    FunctionalNegativeAgent
)
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


class TestFunctionalNegativeAgent:
    """Comprehensive test suite for FunctionalNegativeAgent"""
    
    @pytest.fixture
    def agent(self):
        """Create FunctionalNegativeAgent instance for testing"""
        return FunctionalNegativeAgent()
    
    @pytest.fixture
    def agent_task(self):
        """Sample agent task for testing"""
        return AgentTask(
            task_id="test-negative-123",
            spec_id=1,
            agent_type="Functional-Negative-Agent",
            parameters={}
        )
    
    @pytest.fixture
    def api_spec(self):
        """Sample OpenAPI specification for testing"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                            },
                            {
                                "name": "offset",
                                "in": "query",
                                "schema": {"type": "integer", "minimum": 0}
                            }
                        ],
                        "responses": {
                            "200": {"description": "Success"},
                            "400": {"description": "Bad Request"},
                            "401": {"description": "Unauthorized"}
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                                            "email": {"type": "string", "format": "email"},
                                            "age": {"type": "integer", "minimum": 18, "maximum": 120},
                                            "role": {"type": "string", "enum": ["admin", "user", "guest"]}
                                        },
                                        "required": ["name", "email"]
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Created"},
                            "400": {"description": "Bad Request"},
                            "422": {"description": "Unprocessable Entity"}
                        }
                    }
                },
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}
                            }
                        ],
                        "responses": {
                            "200": {"description": "Success"},
                            "404": {"description": "Not Found"}
                        }
                    },
                    "delete": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}
                            }
                        ],
                        "responses": {
                            "204": {"description": "No Content"},
                            "404": {"description": "Not Found"}
                        }
                    }
                }
            }
        }
    
    # Core Functionality Tests
    
    def test_agent_initialization(self, agent):
        """Test agent initialization and configuration"""
        assert agent.agent_type == "Functional-Negative-Agent"
        assert agent.max_test_variations == 12
        assert agent.boundary_test_multiplier == 3
        assert agent.constraint_strictness == 'strict'
        assert agent.test_timeout == 30
    
    @pytest.mark.asyncio
    async def test_execute_success(self, agent, agent_task, api_spec):
        """Test successful execution of negative test generation"""
        result = await agent.execute(agent_task, api_spec)
        
        assert isinstance(result, AgentResult)
        assert result.task_id == agent_task.task_id
        assert result.agent_type == "Functional-Negative-Agent"
        assert result.status == "success"
        assert len(result.test_cases) > 0
        assert result.metadata is not None
        assert "total_test_cases" in result.metadata
    
    @pytest.mark.asyncio
    async def test_execute_error_handling(self, agent, agent_task):
        """Test error handling during execution"""
        invalid_spec = {"invalid": "spec"}
        
        result = await agent.execute(agent_task, invalid_spec)
        
        assert result.status == "failed"
        assert result.error_message is not None
        assert len(result.test_cases) == 0
    
    # Invalid Data Generation Tests
    
    def test_generate_invalid_type_integer(self, agent):
        """Test generating invalid data for integer type"""
        schema = {"type": "integer"}
        invalid_data = agent._generate_invalid_type(schema)
        
        # Should return non-integer values
        valid_types = [str, float, bool, list, dict, type(None)]
        assert any(isinstance(invalid_data, t) for t in valid_types)
        assert not isinstance(invalid_data, int)
    
    def test_generate_invalid_type_string(self, agent):
        """Test generating invalid data for string type"""
        schema = {"type": "string"}
        invalid_data = agent._generate_invalid_type(schema)
        
        # Should return non-string values
        assert not isinstance(invalid_data, str)
    
    def test_generate_invalid_type_with_format(self, agent):
        """Test generating invalid data for formatted strings"""
        # Email format
        schema = {"type": "string", "format": "email"}
        invalid_data = agent._generate_invalid_type(schema)
        
        if isinstance(invalid_data, str):
            # If it returns a string, it should be malformed
            assert "@" not in invalid_data or "." not in invalid_data.split("@")[-1]
        
        # Date format
        schema = {"type": "string", "format": "date"}
        invalid_data = agent._generate_invalid_type(schema)
        
        if isinstance(invalid_data, str):
            # Should be malformed date
            assert not all(c in "0123456789-" for c in invalid_data)
    
    def test_generate_constraint_violations_integer(self, agent):
        """Test generating constraint violations for integers"""
        schema = {"type": "integer", "minimum": 10, "maximum": 20}
        violations = agent._generate_constraint_violations(schema)
        
        assert len(violations) > 0
        
        # Should include values outside the range
        has_below_min = any(v < 10 for v in violations if isinstance(v, (int, float)))
        has_above_max = any(v > 20 for v in violations if isinstance(v, (int, float)))
        
        assert has_below_min or has_above_max
    
    def test_generate_constraint_violations_string(self, agent):
        """Test generating constraint violations for strings"""
        schema = {
            "type": "string",
            "minLength": 5,
            "maxLength": 10,
            "pattern": "^[A-Z]+$"
        }
        violations = agent._generate_constraint_violations(schema)
        
        assert len(violations) > 0
        
        for violation in violations:
            if isinstance(violation, str):
                # Should violate at least one constraint
                length_violation = len(violation) < 5 or len(violation) > 10
                pattern_violation = not all(c.isupper() for c in violation if c.isalpha())
                assert length_violation or pattern_violation
    
    def test_generate_constraint_violations_enum(self, agent):
        """Test generating constraint violations for enums"""
        schema = {"type": "string", "enum": ["red", "green", "blue"]}
        violations = agent._generate_constraint_violations(schema)
        
        assert len(violations) > 0
        
        # Should include values not in enum
        for violation in violations:
            if isinstance(violation, str):
                assert violation not in ["red", "green", "blue"]
    
    # Missing Required Fields Tests
    
    def test_generate_missing_required_variations(self, agent):
        """Test generating variations with missing required fields"""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "email": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name", "email"]
        }
        
        variations = agent._generate_missing_required_variations(schema)
        
        assert len(variations) > 0
        
        # Should have variations missing required fields
        has_missing_name = any("name" not in v for v in variations if isinstance(v, dict))
        has_missing_email = any("email" not in v for v in variations if isinstance(v, dict))
        
        assert has_missing_name or has_missing_email
    
    def test_generate_additional_properties(self, agent):
        """Test generating objects with additional properties"""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": False
        }
        
        result = agent._generate_additional_properties(schema)
        
        assert isinstance(result, dict)
        assert "name" in result
        # Should have extra properties despite additionalProperties: false
        assert len(result) > 1
    
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
            assert test_case["test_type"] == "functional-negative"
            assert "method" in test_case
            assert "path" in test_case
            assert "expected_status_codes" in test_case
            
            # Should expect error status codes
            for status in test_case["expected_status_codes"]:
                assert status >= 400
    
    def test_generate_invalid_path_params(self, agent, api_spec):
        """Test generating invalid path parameters"""
        path = "/users/{id}"
        method = "get"
        operation = api_spec["paths"]["/users/{id}"]["get"]
        
        test_cases = agent._generate_invalid_path_params(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["path"] == path
            assert test_case["method"] == "GET"
            assert "path_params" in test_case
            
            # Should have invalid path parameter values
            if "id" in test_case["path_params"]:
                id_value = test_case["path_params"]["id"]
                # Could be wrong type, negative, etc.
                assert not isinstance(id_value, int) or id_value < 0
    
    def test_generate_invalid_query_params(self, agent, api_spec):
        """Test generating invalid query parameters"""
        path = "/users"
        method = "get"
        operation = api_spec["paths"]["/users"]["get"]
        
        test_cases = agent._generate_invalid_query_params(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert "query_params" in test_case
            
            # Should have invalid query parameter values
            params = test_case["query_params"]
            if "limit" in params:
                # Should violate constraints
                assert params["limit"] < 1 or params["limit"] > 100 or not isinstance(params["limit"], int)
    
    def test_generate_invalid_request_body(self, agent, api_spec):
        """Test generating invalid request bodies"""
        path = "/users"
        method = "post"
        operation = api_spec["paths"]["/users"]["post"]
        
        test_cases = agent._generate_invalid_request_body(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert "body" in test_case
            body = test_case["body"]
            
            if body is not None:
                # Should have some form of invalid data
                # Could be missing required fields, wrong types, etc.
                if isinstance(body, dict):
                    # Check for various types of invalidity
                    has_missing = "name" not in body or "email" not in body
                    has_invalid_type = (
                        ("name" in body and not isinstance(body["name"], str)) or
                        ("email" in body and not isinstance(body["email"], str))
                    )
                    has_constraint_violation = (
                        ("age" in body and isinstance(body["age"], int) and 
                         (body["age"] < 18 or body["age"] > 120))
                    )
                    
                    assert has_missing or has_invalid_type or has_constraint_violation
    
    def test_generate_malformed_json(self, agent):
        """Test generating malformed JSON test cases"""
        path = "/users"
        method = "post"
        operation = {
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {"type": "object"}
                    }
                }
            }
        }
        
        test_cases = agent._generate_malformed_json(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert "body" in test_case
            body = test_case["body"]
            
            # Should be malformed JSON strings
            if isinstance(body, str):
                # Should not be valid JSON
                try:
                    json.loads(body)
                    # If it parses, it might be a special case like null
                    assert body in ["null", "undefined"]
                except:
                    # Expected - malformed JSON
                    pass
    
    # LLM Enhancement Tests
    
    @pytest.mark.asyncio
    async def test_generate_llm_negative_tests(self, agent, api_spec):
        """Test LLM-enhanced negative test generation"""
        with patch.object(agent, 'llm_enabled', True):
            with patch.object(agent, 'enhance_with_llm', new_callable=AsyncMock) as mock_llm:
                # Setup mock response
                mock_llm.return_value = [
                    {
                        "description": "SQL injection attempt",
                        "body": {"name": "'; DROP TABLE users; --"},
                        "expected_status": [400, 422]
                    }
                ]
                
                # Extract sample endpoint
                endpoint = {
                    "path": "/users",
                    "method": "POST",
                    "operation": api_spec["paths"]["/users"]["post"]
                }
                
                test_cases = await agent._generate_llm_negative_tests([endpoint], api_spec)
                
                assert len(test_cases) > 0
                assert mock_llm.called
    
    # Edge Cases and Error Handling
    
    def test_handle_empty_schema(self, agent):
        """Test handling of empty schemas"""
        empty_schema = {}
        
        # Should handle gracefully
        invalid_type = agent._generate_invalid_type(empty_schema)
        assert invalid_type is not None
        
        violations = agent._generate_constraint_violations(empty_schema)
        assert isinstance(violations, list)
    
    def test_handle_complex_nested_schema(self, agent):
        """Test handling of complex nested schemas"""
        complex_schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "profile": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "minLength": 1}
                            },
                            "required": ["name"]
                        }
                    },
                    "required": ["profile"]
                }
            },
            "required": ["user"]
        }
        
        variations = agent._generate_missing_required_variations(complex_schema)
        
        assert len(variations) > 0
        # Should handle nested required fields
    
    @pytest.mark.asyncio
    async def test_concurrent_test_generation(self, agent, api_spec):
        """Test concurrent generation of multiple test types"""
        # Add more endpoints to test concurrent processing
        api_spec["paths"]["/products"] = {
            "get": {"responses": {"200": {}}},
            "post": {"requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}
        }
        
        test_cases = await agent.generate_test_cases(api_spec)
        
        # Should generate tests for all endpoints
        paths_tested = set(tc["path"] for tc in test_cases)
        assert "/users" in paths_tested
        assert "/users/{id}" in paths_tested
        assert "/products" in paths_tested
    
    def test_boundary_value_generation(self, agent):
        """Test boundary value test generation"""
        schema = {"type": "integer", "minimum": 0, "maximum": 100}
        
        # Generate multiple times to check boundary coverage
        boundaries_seen = set()
        for _ in range(10):
            violations = agent._generate_constraint_violations(schema)
            for v in violations:
                if isinstance(v, int):
                    boundaries_seen.add(v)
        
        # Should include boundary values
        assert -1 in boundaries_seen or 101 in boundaries_seen