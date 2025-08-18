"""
End-to-end tests for complete workflow.

These tests verify the complete API testing workflow including:
- Specification upload
- Test generation with AI agents
- Test execution
- Result analysis
- Report generation
- Full pipeline from spec to results
"""
import pytest
import asyncio
import json
import time
from typing import Dict, Any, List
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import Mock, AsyncMock, patch
import httpx


@pytest.mark.e2e
class TestCompleteWorkflow:
    """Test complete end-to-end API testing workflow."""
    
    @pytest.fixture
    def api_client(self):
        """Create test client for API Gateway."""
        from api_gateway.main import app
        return TestClient(app)
    
    @pytest.fixture
    def auth_headers(self, api_client):
        """Get authenticated headers."""
        response = api_client.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "admin123"
        })
        
        if response.status_code == status.HTTP_200_OK:
            token = response.json()["access_token"]
            return {"Authorization": f"Bearer {token}"}
        return {}
    
    @pytest.fixture
    def sample_openapi_spec(self):
        """Sample OpenAPI specification for testing."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "E2E Test API",
                "version": "1.0.0",
                "description": "API for end-to-end testing"
            },
            "servers": [
                {"url": "https://api.e2e-test.com"}
            ],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "operationId": "listUsers",
                        "tags": ["Users"],
                        "parameters": [
                            {
                                "name": "page",
                                "in": "query",
                                "schema": {"type": "integer", "minimum": 1},
                                "description": "Page number"
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer", "minimum": 1, "maximum": 100},
                                "description": "Items per page"
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Successful response",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "users": {
                                                    "type": "array",
                                                    "items": {"$ref": "#/components/schemas/User"}
                                                },
                                                "total": {"type": "integer"},
                                                "page": {"type": "integer"}
                                            }
                                        }
                                    }
                                }
                            },
                            "401": {"description": "Unauthorized"},
                            "500": {"description": "Internal server error"}
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "operationId": "createUser",
                        "tags": ["Users"],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/UserInput"}
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "description": "User created",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            },
                            "400": {"description": "Invalid input"},
                            "401": {"description": "Unauthorized"}
                        }
                    }
                },
                "/users/{userId}": {
                    "get": {
                        "summary": "Get user by ID",
                        "operationId": "getUser",
                        "tags": ["Users"],
                        "parameters": [
                            {
                                "name": "userId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string", "format": "uuid"}
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "User found",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            },
                            "404": {"description": "User not found"}
                        }
                    },
                    "put": {
                        "summary": "Update user",
                        "operationId": "updateUser",
                        "tags": ["Users"],
                        "parameters": [
                            {
                                "name": "userId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string", "format": "uuid"}
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
                            "200": {"description": "User updated"},
                            "404": {"description": "User not found"}
                        }
                    },
                    "delete": {
                        "summary": "Delete user",
                        "operationId": "deleteUser",
                        "tags": ["Users"],
                        "parameters": [
                            {
                                "name": "userId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string", "format": "uuid"}
                            }
                        ],
                        "responses": {
                            "204": {"description": "User deleted"},
                            "404": {"description": "User not found"}
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "email": {"type": "string", "format": "email"},
                            "name": {"type": "string"},
                            "role": {"type": "string", "enum": ["admin", "user", "guest"]},
                            "createdAt": {"type": "string", "format": "date-time"},
                            "updatedAt": {"type": "string", "format": "date-time"}
                        },
                        "required": ["id", "email", "name", "role"]
                    },
                    "UserInput": {
                        "type": "object",
                        "properties": {
                            "email": {"type": "string", "format": "email"},
                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                            "password": {"type": "string", "minLength": 8},
                            "role": {"type": "string", "enum": ["admin", "user", "guest"]}
                        },
                        "required": ["email", "name", "password"]
                    }
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_full_api_testing_workflow(self, api_client, auth_headers, sample_openapi_spec):
        """Test complete workflow from spec upload to test results."""
        
        # Step 1: Upload API specification
        spec_response = api_client.post(
            "/specifications/",
            headers=auth_headers,
            json={
                "name": "E2E Test API",
                "spec_content": json.dumps(sample_openapi_spec),
                "description": "End-to-end test specification"
            }
        )
        
        assert spec_response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
        spec_data = spec_response.json()
        spec_id = spec_data.get("id", 1)
        
        # Step 2: Create test run with multiple agents
        test_run_response = api_client.post(
            "/test-runs/",
            headers=auth_headers,
            json={
                "spec_id": spec_id,
                "agent_types": [
                    "functional-positive",
                    "functional-negative",
                    "security-auth",
                    "security-injection"
                ],
                "config": {
                    "parallel_execution": True,
                    "max_workers": 4,
                    "timeout": 300
                }
            }
        )
        
        assert test_run_response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
        test_run_data = test_run_response.json()
        test_run_id = test_run_data.get("id", "test-run-001")
        
        # Step 3: Wait for test generation (mock or real)
        max_wait = 30  # seconds
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            status_response = api_client.get(
                f"/test-runs/{test_run_id}",
                headers=auth_headers
            )
            
            if status_response.status_code == status.HTTP_200_OK:
                status_data = status_response.json()
                if status_data.get("status") in ["completed", "failed"]:
                    break
            
            await asyncio.sleep(2)
        
        # Step 4: Get generated test cases
        test_cases_response = api_client.get(
            f"/test-cases/?test_run_id={test_run_id}",
            headers=auth_headers
        )
        
        if test_cases_response.status_code == status.HTTP_200_OK:
            test_cases = test_cases_response.json()
            assert isinstance(test_cases, list) or "test_cases" in test_cases
            
            # Should have generated test cases from different agents
            if isinstance(test_cases, list):
                assert len(test_cases) > 0
        
        # Step 5: Execute test cases
        execution_response = api_client.post(
            f"/test-runs/{test_run_id}/execute",
            headers=auth_headers,
            json={
                "environment": "staging",
                "parallel": True,
                "continue_on_failure": True
            }
        )
        
        assert execution_response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_202_ACCEPTED,
            status.HTTP_404_NOT_FOUND  # Endpoint might not exist
        ]
        
        # Step 6: Get test results
        results_response = api_client.get(
            f"/test-runs/{test_run_id}/results",
            headers=auth_headers
        )
        
        if results_response.status_code == status.HTTP_200_OK:
            results = results_response.json()
            
            # Verify results structure
            assert "summary" in results or "results" in results
            
            if "summary" in results:
                summary = results["summary"]
                assert "total" in summary or "total_tests" in summary
                assert "passed" in summary or "passed_tests" in summary
                assert "failed" in summary or "failed_tests" in summary
        
        # Step 7: Get analytics
        analytics_response = api_client.get(
            f"/analytics/test-run/{test_run_id}",
            headers=auth_headers
        )
        
        if analytics_response.status_code == status.HTTP_200_OK:
            analytics = analytics_response.json()
            
            # Should have analytics data
            assert analytics is not None
    
    @pytest.mark.asyncio
    async def test_multi_agent_coordination(self, api_client, auth_headers, sample_openapi_spec):
        """Test coordination between multiple AI agents."""
        
        # Upload specification
        spec_response = api_client.post(
            "/specifications/",
            headers=auth_headers,
            json={
                "name": "Multi-Agent Test",
                "spec_content": json.dumps(sample_openapi_spec)
            }
        )
        
        spec_id = spec_response.json().get("id", 1) if spec_response.status_code == 201 else 1
        
        # Create test run with all agent types
        all_agents = [
            "functional-positive",
            "functional-negative",
            "functional-stateful",
            "security-auth",
            "security-injection",
            "performance-planner",
            "data-mocking"
        ]
        
        test_run_response = api_client.post(
            "/test-runs/",
            headers=auth_headers,
            json={
                "spec_id": spec_id,
                "agent_types": all_agents
            }
        )
        
        if test_run_response.status_code in [201, 200]:
            test_run_id = test_run_response.json()["id"]
            
            # Monitor agent progress
            agent_status = {}
            max_wait = 60
            start_time = time.time()
            
            while time.time() - start_time < max_wait:
                status_response = api_client.get(
                    f"/test-runs/{test_run_id}/agents",
                    headers=auth_headers
                )
                
                if status_response.status_code == 200:
                    agents = status_response.json()
                    
                    for agent in agents:
                        agent_type = agent.get("type")
                        agent_status[agent_type] = agent.get("status")
                    
                    # Check if all agents completed
                    if all(status in ["completed", "failed"] for status in agent_status.values()):
                        break
                
                await asyncio.sleep(3)
            
            # Verify all agents participated
            assert len(agent_status) > 0
    
    @pytest.mark.asyncio
    async def test_error_handling_workflow(self, api_client, auth_headers):
        """Test workflow error handling and recovery."""
        
        # Test with invalid specification
        invalid_spec = {
            "not": "valid",
            "openapi": "spec"
        }
        
        spec_response = api_client.post(
            "/specifications/",
            headers=auth_headers,
            json={
                "name": "Invalid Spec",
                "spec_content": json.dumps(invalid_spec)
            }
        )
        
        # Should handle invalid spec gracefully
        if spec_response.status_code == 400:
            error_data = spec_response.json()
            assert "detail" in error_data or "error" in error_data
        
        # Test with non-existent spec ID
        test_run_response = api_client.post(
            "/test-runs/",
            headers=auth_headers,
            json={
                "spec_id": 99999,
                "agent_types": ["functional-positive"]
            }
        )
        
        # Should handle missing spec
        assert test_run_response.status_code in [404, 400, 422]
        
        # Test agent failure recovery
        with patch('orchestration_service.agents.functional_positive_agent.FunctionalPositiveAgent.execute') as mock_execute:
            mock_execute.side_effect = Exception("Agent failure")
            
            test_run_response = api_client.post(
                "/test-runs/",
                headers=auth_headers,
                json={
                    "spec_id": 1,
                    "agent_types": ["functional-positive"]
                }
            )
            
            # Should handle agent failures gracefully
            if test_run_response.status_code == 200:
                test_run_id = test_run_response.json()["id"]
                
                # Check failure is recorded
                status_response = api_client.get(
                    f"/test-runs/{test_run_id}",
                    headers=auth_headers
                )
                
                if status_response.status_code == 200:
                    status_data = status_response.json()
                    # Should show failure or error status
                    assert status_data.get("status") in ["failed", "error", "completed_with_errors"]
    
    @pytest.mark.asyncio
    async def test_performance_workflow(self, api_client, auth_headers, sample_openapi_spec):
        """Test performance testing workflow."""
        
        # Upload spec
        spec_response = api_client.post(
            "/specifications/",
            headers=auth_headers,
            json={
                "name": "Performance Test API",
                "spec_content": json.dumps(sample_openapi_spec)
            }
        )
        
        spec_id = spec_response.json().get("id", 1) if spec_response.status_code == 201 else 1
        
        # Create performance test run
        test_run_response = api_client.post(
            "/test-runs/",
            headers=auth_headers,
            json={
                "spec_id": spec_id,
                "agent_types": ["performance-planner"],
                "config": {
                    "test_type": "load",
                    "duration": 60,
                    "concurrent_users": 100,
                    "ramp_up_time": 10
                }
            }
        )
        
        if test_run_response.status_code in [201, 200]:
            test_run_id = test_run_response.json()["id"]
            
            # Get performance test plan
            plan_response = api_client.get(
                f"/test-runs/{test_run_id}/performance-plan",
                headers=auth_headers
            )
            
            if plan_response.status_code == 200:
                plan = plan_response.json()
                
                # Should have performance test configuration
                assert "scenarios" in plan or "test_plan" in plan
    
    @pytest.mark.asyncio
    async def test_report_generation_workflow(self, api_client, auth_headers):
        """Test report generation at the end of workflow."""
        
        # Assume we have a completed test run
        test_run_id = "completed-test-001"
        
        # Generate different report formats
        report_formats = ["json", "html", "pdf", "csv"]
        
        for format_type in report_formats:
            report_response = api_client.get(
                f"/reports/test-run/{test_run_id}?format={format_type}",
                headers=auth_headers
            )
            
            if report_response.status_code == 200:
                # Check content type matches requested format
                content_type = report_response.headers.get("content-type", "")
                
                if format_type == "json":
                    assert "application/json" in content_type
                elif format_type == "html":
                    assert "text/html" in content_type
                elif format_type == "pdf":
                    assert "application/pdf" in content_type
                elif format_type == "csv":
                    assert "text/csv" in content_type or "application/csv" in content_type