"""
Comprehensive Unit Tests for SecurityAuthAgent

This module provides extensive test coverage for the SecurityAuthAgent class,
including BOLA testing, authentication bypass, and authorization vulnerability testing.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List

from sentinel_backend.orchestration_service.agents.security_auth_agent import (
    SecurityAuthAgent
)
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


class TestSecurityAuthAgent:
    """Comprehensive test suite for SecurityAuthAgent"""
    
    @pytest.fixture
    def agent(self):
        """Create SecurityAuthAgent instance for testing"""
        return SecurityAuthAgent()
    
    @pytest.fixture
    def agent_task(self):
        """Sample agent task for testing"""
        return AgentTask(
            task_id="test-security-auth-202",
            spec_id=1,
            agent_type="Security-Auth-Agent",
            parameters={}
        )
    
    @pytest.fixture
    def api_spec_with_auth(self):
        """API specification with authentication endpoints"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Secure API", "version": "1.0.0"},
            "paths": {
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}
                            }
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "Success"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"},
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
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Success"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"}
                        }
                    },
                    "delete": {
                        "summary": "Delete user",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"}
                            }
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "204": {"description": "No Content"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"}
                        }
                    }
                },
                "/admin/users": {
                    "get": {
                        "summary": "Admin endpoint to list users",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "Success"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"}
                        }
                    },
                    "delete": {
                        "summary": "Admin endpoint to delete all users",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "204": {"description": "No Content"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"}
                        }
                    }
                },
                "/public/info": {
                    "get": {
                        "summary": "Public endpoint",
                        "responses": {
                            "200": {"description": "Success"}
                        }
                    }
                },
                "/search": {
                    "get": {
                        "summary": "Search endpoint",
                        "parameters": [
                            {
                                "name": "userId",
                                "in": "query",
                                "schema": {"type": "integer"}
                            }
                        ],
                        "responses": {"200": {}}
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            }
        }
    
    # Core Functionality Tests
    
    def test_agent_initialization(self, agent):
        """Test agent initialization and configuration"""
        assert agent.agent_type == "Security-Auth-Agent"
        assert agent.max_bola_vectors == 12
        assert agent.max_auth_scenarios == 4
        assert agent.default_test_timeout == 30
        assert agent.enable_aggressive_testing is False
    
    @pytest.mark.asyncio
    async def test_execute_success(self, agent, agent_task, api_spec_with_auth):
        """Test successful execution of security auth test generation"""
        result = await agent.execute(agent_task, api_spec_with_auth)
        
        assert isinstance(result, AgentResult)
        assert result.task_id == agent_task.task_id
        assert result.agent_type == "Security-Auth-Agent"
        assert result.status == "success"
        assert len(result.test_cases) > 0
        assert result.metadata is not None
        assert "focus_areas" in result.metadata
        assert "BOLA" in result.metadata["focus_areas"]
    
    @pytest.mark.asyncio
    async def test_execute_error_handling(self, agent, agent_task):
        """Test error handling during execution"""
        invalid_spec = {"invalid": "spec"}
        
        result = await agent.execute(agent_task, invalid_spec)
        
        assert result.status == "failed"
        assert result.error_message is not None
        assert len(result.test_cases) == 0
    
    # BOLA Testing
    
    def test_generate_bola_tests(self, agent, api_spec_with_auth):
        """Test BOLA (Broken Object Level Authorization) test generation"""
        path = "/users/{id}"
        method = "get"
        operation = api_spec_with_auth["paths"]["/users/{id}"]["get"]
        
        test_cases = agent._generate_bola_tests(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_type"] == "security-auth"
            assert test_case["test_subtype"] == "bola"
            assert "security_check" in test_case
            assert test_case["security_check"]["type"] == "bola"
            assert "path_params" in test_case
            assert "id" in test_case["path_params"]
            
            # Should expect auth failure status codes
            for status in test_case["expected_status_codes"]:
                assert status in [401, 403, 404]
    
    def test_extract_path_parameters(self, agent, api_spec_with_auth):
        """Test extraction of path parameters for BOLA testing"""
        path = "/users/{id}"
        operation = api_spec_with_auth["paths"]["/users/{id}"]["get"]
        
        params = agent._extract_path_parameters(path, operation)
        
        assert len(params) > 0
        assert params[0]["name"] == "id"
        assert params[0]["in"] == "path"
        assert params[0]["required"] is True
    
    def test_is_likely_object_id(self, agent):
        """Test identification of object ID parameters"""
        assert agent._is_likely_object_id("id")
        assert agent._is_likely_object_id("userId")
        assert agent._is_likely_object_id("user_id")
        assert agent._is_likely_object_id("uuid")
        assert agent._is_likely_object_id("resourceKey")
        assert not agent._is_likely_object_id("name")
        assert not agent._is_likely_object_id("type")
    
    def test_generate_bola_vectors(self, agent):
        """Test BOLA attack vector generation"""
        param_spec = {
            "name": "id",
            "schema": {"type": "integer"}
        }
        
        vectors = agent._generate_bola_vectors("id", param_spec)
        
        assert len(vectors) > 0
        
        # Check for different auth scenarios
        auth_scenarios = set(v["auth_scenario"] for v in vectors)
        assert "no_auth" in auth_scenarios
        assert "different_user" in auth_scenarios
        assert "invalid_token" in auth_scenarios
        
        # Check for different ID values
        id_values = set(v["value"] for v in vectors)
        assert 1 in id_values  # First resource
        assert 999999 in id_values  # High-numbered resource
        assert -1 in id_values  # Negative ID
        assert 0 in id_values  # Zero ID
    
    def test_get_integer_bola_vectors(self, agent):
        """Test integer-based BOLA vectors"""
        vectors = agent._get_integer_bola_vectors()
        
        assert len(vectors) == 4
        values = [v["value"] for v in vectors]
        assert 1 in values
        assert 999999 in values
        assert -1 in values
        assert 0 in values
    
    def test_get_string_bola_vectors(self, agent):
        """Test string-based BOLA vectors"""
        vectors = agent._get_string_bola_vectors()
        
        assert len(vectors) == 6
        values = [v["value"] for v in vectors]
        assert "admin" in values
        assert "test" in values
        assert "../admin" in values  # Path traversal
        assert "null" in values
    
    # Function-Level Authorization Tests
    
    def test_generate_function_auth_tests(self, agent, api_spec_with_auth):
        """Test function-level authorization test generation"""
        path = "/admin/users"
        method = "delete"
        operation = api_spec_with_auth["paths"]["/admin/users"]["delete"]
        
        test_cases = agent._generate_function_auth_tests(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "function-level-auth"
            assert "security_check" in test_case
            assert test_case["security_check"]["type"] == "function-level-authorization"
            
            # Should test different auth levels
            headers = test_case["headers"]
            if "Authorization" not in headers:
                # No auth scenario
                assert 401 in test_case["expected_status_codes"] or 403 in test_case["expected_status_codes"]
    
    def test_identify_sensitive_operations(self, agent, api_spec_with_auth):
        """Test identification of sensitive operations"""
        # Admin endpoint should be sensitive
        sensitive_ops = agent._identify_sensitive_operations(
            "/admin/users", "DELETE",
            api_spec_with_auth["paths"]["/admin/users"]["delete"]
        )
        
        assert len(sensitive_ops) > 0
        assert any("admin" in op for op in sensitive_ops)
        assert any("delete" in op for op in sensitive_ops)
        
        # Regular GET might not be sensitive
        public_ops = agent._identify_sensitive_operations(
            "/public/info", "GET",
            api_spec_with_auth["paths"]["/public/info"]["get"]
        )
        
        assert len(public_ops) == 0
    
    # Authentication Bypass Tests
    
    def test_generate_auth_bypass_tests(self, agent, api_spec_with_auth):
        """Test authentication bypass test generation"""
        path = "/users/{id}"
        method = "put"
        operation = api_spec_with_auth["paths"]["/users/{id}"]["put"]
        
        test_cases = agent._generate_auth_bypass_tests(path, method, operation)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "auth-bypass"
            assert "security_check" in test_case
            assert test_case["security_check"]["type"] == "authentication-bypass"
            assert "technique" in test_case["security_check"]
            
            # Should expect auth failure
            assert 401 in test_case["expected_status_codes"] or 403 in test_case["expected_status_codes"]
    
    def test_get_bypass_techniques(self, agent):
        """Test authentication bypass technique generation"""
        techniques = agent._get_bypass_techniques()
        
        assert len(techniques) > 0
        
        technique_names = [t["name"] for t in techniques]
        assert "header_manipulation" in technique_names
        assert "user_agent_bypass" in technique_names
        assert "referer_bypass" in technique_names
        assert "method_override" in technique_names
        assert "content_type_bypass" in technique_names
        
        # Check header manipulation
        header_manip = next(t for t in techniques if t["name"] == "header_manipulation")
        assert "X-Forwarded-For" in header_manip["headers"]
        assert header_manip["headers"]["X-Forwarded-For"] == "127.0.0.1"
    
    def test_get_bypass_techniques_aggressive(self, agent):
        """Test aggressive authentication bypass techniques"""
        agent.enable_aggressive_testing = True
        techniques = agent._get_bypass_techniques()
        
        technique_names = [t["name"] for t in techniques]
        
        # Should include additional aggressive techniques
        assert "host_header_injection" in technique_names
        assert "origin_bypass" in technique_names
    
    # Authentication Detection Tests
    
    def test_requires_authentication(self, agent, api_spec_with_auth):
        """Test authentication requirement detection"""
        # Endpoint with security requirement
        secure_op = api_spec_with_auth["paths"]["/users/{id}"]["get"]
        assert agent._requires_authentication(secure_op)
        
        # Public endpoint without security
        public_op = api_spec_with_auth["paths"]["/public/info"]["get"]
        assert not agent._requires_authentication(public_op)
        
        # Endpoint with 401 response
        op_with_401 = {"responses": {"401": {}}}
        assert agent._requires_authentication(op_with_401)
        
        # Endpoint with 403 response
        op_with_403 = {"responses": {"403": {}}}
        assert agent._requires_authentication(op_with_403)
    
    def test_get_auth_headers_variants(self, agent):
        """Test authentication header generation for different scenarios"""
        # No auth
        headers = agent._get_auth_headers_variants("no_auth")
        assert len(headers) == 0
        
        # Different user
        headers = agent._get_auth_headers_variants("different_user")
        assert "Authorization" in headers
        assert "different_user" in headers["Authorization"]
        
        # Invalid token
        headers = agent._get_auth_headers_variants("invalid_token")
        assert "Authorization" in headers
        assert "invalid" in headers["Authorization"]
    
    # Helper Method Tests
    
    def test_generate_valid_path_params(self, agent, api_spec_with_auth):
        """Test valid path parameter generation"""
        path = "/users/{id}"
        operation = api_spec_with_auth["paths"]["/users/{id}"]["get"]
        
        params = agent._generate_valid_path_params(path, operation)
        
        assert "id" in params
        assert params["id"] == 123  # Default integer value
    
    def test_generate_request_body(self, agent, api_spec_with_auth):
        """Test request body generation for auth tests"""
        operation = api_spec_with_auth["paths"]["/users/{id}"]["put"]
        
        body = agent._generate_request_body(operation)
        
        assert body is not None
        assert isinstance(body, dict)
        assert "test" in str(body).lower()  # Should have test data
    
    # LLM Enhancement Tests
    
    @pytest.mark.asyncio
    async def test_generate_llm_auth_tests(self, agent, api_spec_with_auth):
        """Test LLM-enhanced auth test generation"""
        with patch.object(agent, 'llm_enabled', True):
            with patch.object(agent, 'enhance_with_llm', new_callable=AsyncMock) as mock_llm:
                # Setup mock response
                mock_llm.return_value = [
                    {
                        "name": "JWT token manipulation",
                        "subtype": "jwt-attack",
                        "method": "GET",
                        "headers": {"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},
                        "expected_status": [401, 403],
                        "attack_type": "jwt",
                        "description": "JWT with 'none' algorithm"
                    }
                ]
                
                paths = list(api_spec_with_auth["paths"].items())[:1]
                test_cases = await agent._generate_llm_auth_tests(paths, api_spec_with_auth)
                
                assert len(test_cases) > 0
                assert mock_llm.called
                
                # Check generated test case
                test_case = test_cases[0]
                assert "[LLM]" in test_case["test_name"]
                assert test_case["test_type"] == "security-auth"
    
    # Edge Cases and Complex Scenarios
    
    @pytest.mark.asyncio
    async def test_generate_test_cases_comprehensive(self, agent, api_spec_with_auth):
        """Test comprehensive test case generation"""
        test_cases = await agent.generate_test_cases(api_spec_with_auth)
        
        assert len(test_cases) > 0
        
        # Should have different test subtypes
        subtypes = set(tc["test_subtype"] for tc in test_cases)
        assert "bola" in subtypes
        assert "function-level-auth" in subtypes
        assert "auth-bypass" in subtypes
        
        # Should test different endpoints
        paths = set(tc["path"] for tc in test_cases)
        assert "/users/{id}" in paths
        assert "/admin/users" in paths
    
    def test_handle_missing_parameters(self, agent):
        """Test handling of operations without parameters"""
        path = "/users"
        operation = {"responses": {"200": {}}}
        
        params = agent._extract_path_parameters(path, operation)
        assert len(params) == 0
        
        # Should not generate BOLA tests without parameters
        test_cases = agent._generate_bola_tests(path, "GET", operation)
        assert len(test_cases) == 0
    
    def test_handle_complex_auth_schemes(self, agent):
        """Test handling of complex authentication schemes"""
        operation = {
            "security": [
                {"bearerAuth": []},
                {"apiKey": []},
                {"oauth2": ["read", "write"]}
            ],
            "responses": {"401": {}}
        }
        
        assert agent._requires_authentication(operation)
    
    def test_filter_reference_pattern_detection(self, agent):
        """Test detection of filter reference patterns"""
        from_node = MagicMock()
        from_node.path = "/users"
        from_node.method = "POST"
        
        to_node = MagicMock()
        to_node.operation_spec = {
            "parameters": [
                {"name": "userId", "in": "query", "schema": {"type": "integer"}}
            ]
        }
        
        assert agent._is_filter_reference_pattern(from_node, to_node)
        
        # Without matching parameter
        to_node.operation_spec = {
            "parameters": [
                {"name": "unrelated", "in": "query", "schema": {"type": "string"}}
            ]
        }
        
        assert not agent._is_filter_reference_pattern(from_node, to_node)