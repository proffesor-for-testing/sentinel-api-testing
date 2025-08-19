"""
End-to-End test for complete API workflow from specification to execution results.
Tests the full pipeline of uploading specs, generating tests, and executing them.
"""

import pytest
import asyncio
import json
from typing import Dict, Any, List
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
from datetime import datetime

# Test configuration
API_GATEWAY_URL = "http://localhost:8000"
AUTH_SERVICE_URL = "http://localhost:8005"
SPEC_SERVICE_URL = "http://localhost:8001"
ORCHESTRATION_URL = "http://localhost:8002"
EXECUTION_URL = "http://localhost:8003"
DATA_SERVICE_URL = "http://localhost:8004"


class TestSpecToExecution:
    """Complete E2E workflow tests from specification upload to test execution."""
    
    @pytest.fixture
    async def auth_headers(self):
        """Get authentication headers for API calls."""
        async with aiohttp.ClientSession() as session:
            # Login to get token
            login_data = {
                "email": "admin@sentinel.com",
                "password": "admin123"
            }
            
            async with session.post(
                f"{AUTH_SERVICE_URL}/api/auth/login",
                json=login_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {"Authorization": f"Bearer {data['access_token']}"}
                else:
                    # Mock auth for testing
                    return {"Authorization": "Bearer mock-token-for-testing"}
    
    @pytest.fixture
    def sample_openapi_spec(self) -> Dict[str, Any]:
        """Sample OpenAPI specification for testing."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "E2E Test API",
                "version": "1.0.0",
                "description": "API for E2E testing"
            },
            "servers": [
                {"url": "https://api.example.com/v1"}
            ],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "operationId": "listUsers",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer", "default": 10}
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Successful response",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/User"}
                                        }
                                    }
                                }
                            },
                            "401": {"description": "Unauthorized"}
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "operationId": "createUser",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "User created"},
                            "400": {"description": "Invalid input"}
                        }
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "operationId": "getUser",
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"}
                            }
                        ],
                        "responses": {
                            "200": {"description": "User found"},
                            "404": {"description": "User not found"}
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "required": ["name", "email"],
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "email": {"type": "string", "format": "email"},
                            "age": {"type": "integer", "minimum": 0}
                        }
                    }
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_complete_workflow(self, auth_headers, sample_openapi_spec):
        """Test the complete workflow from spec upload to test execution."""
        async with aiohttp.ClientSession() as session:
            # Step 1: Upload API Specification
            spec_data = {
                "name": "E2E Test API Spec",
                "description": "Specification for E2E testing",
                "content": json.dumps(sample_openapi_spec),
                "version": "1.0.0"
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                spec_response = await response.json()
                spec_id = spec_response.get("id", "mock-spec-id")
            
            # Step 2: Create Test Run with AI Agents
            test_run_data = {
                "name": "E2E Test Run",
                "spec_id": spec_id,
                "agents": [
                    "functional-positive",
                    "functional-negative",
                    "security-auth",
                    "data-mocking"
                ],
                "configuration": {
                    "parallel_execution": True,
                    "max_concurrent": 3,
                    "timeout": 300
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id", "mock-run-id")
            
            # Step 3: Monitor Test Generation Progress
            max_retries = 30
            generation_complete = False
            
            for _ in range(max_retries):
                async with session.get(
                    f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/status",
                    headers=auth_headers
                ) as response:
                    if response.status == 200:
                        status_data = await response.json()
                        
                        if status_data.get("generation_status") == "completed":
                            generation_complete = True
                            break
                        elif status_data.get("generation_status") == "failed":
                            pytest.fail("Test generation failed")
                
                await asyncio.sleep(2)  # Wait before checking again
            
            assert generation_complete, "Test generation did not complete in time"
            
            # Step 4: Retrieve Generated Test Cases
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/test-cases",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                test_cases = await response.json()
                assert len(test_cases) > 0, "No test cases were generated"
                
                # Verify test cases from different agents
                agent_types = {tc.get("agent_type") for tc in test_cases}
                assert "functional-positive" in agent_types
                assert "functional-negative" in agent_types
            
            # Step 5: Execute Test Cases
            execution_data = {
                "test_run_id": test_run_id,
                "test_case_ids": [tc.get("id") for tc in test_cases[:10]],  # Execute first 10
                "execution_config": {
                    "base_url": "https://api.example.com/v1",
                    "timeout": 30,
                    "retry_failed": True
                }
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/executions",
                json=execution_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                execution_response = await response.json()
                execution_id = execution_response.get("id", "mock-exec-id")
            
            # Step 6: Monitor Execution Progress
            execution_complete = False
            
            for _ in range(max_retries):
                async with session.get(
                    f"{EXECUTION_URL}/api/executions/{execution_id}/status",
                    headers=auth_headers
                ) as response:
                    if response.status == 200:
                        exec_status = await response.json()
                        
                        if exec_status.get("status") in ["completed", "finished"]:
                            execution_complete = True
                            break
                        elif exec_status.get("status") == "failed":
                            # Partial failure is acceptable
                            execution_complete = True
                            break
                
                await asyncio.sleep(2)
            
            assert execution_complete, "Test execution did not complete"
            
            # Step 7: Retrieve Execution Results
            async with session.get(
                f"{EXECUTION_URL}/api/executions/{execution_id}/results",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                results = await response.json()
                
                # Verify results structure
                assert "summary" in results
                assert "test_results" in results
                assert results["summary"].get("total_tests", 0) > 0
                
                # Check individual test results
                for test_result in results["test_results"]:
                    assert "test_case_id" in test_result
                    assert "status" in test_result
                    assert test_result["status"] in ["passed", "failed", "skipped", "error"]
                    
                    if test_result["status"] == "failed":
                        assert "error_message" in test_result
            
            # Step 8: Save Results to Data Service
            analytics_data = {
                "test_run_id": test_run_id,
                "execution_id": execution_id,
                "results": results,
                "metadata": {
                    "spec_name": "E2E Test API Spec",
                    "agents_used": list(agent_types),
                    "execution_time": datetime.utcnow().isoformat()
                }
            }
            
            async with session.post(
                f"{DATA_SERVICE_URL}/api/analytics",
                json=analytics_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
    
    @pytest.mark.asyncio
    async def test_spec_validation_workflow(self, auth_headers):
        """Test specification validation during upload."""
        async with aiohttp.ClientSession() as session:
            # Upload invalid specification
            invalid_spec = {
                "openapi": "3.0.0",
                "info": {
                    "title": "Invalid Spec"
                    # Missing required 'version' field
                },
                "paths": {}  # Empty paths
            }
            
            spec_data = {
                "name": "Invalid Test Spec",
                "description": "Testing validation",
                "content": json.dumps(invalid_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                # Should fail validation
                assert response.status in [400, 422]
                error_response = await response.json()
                assert "error" in error_response or "message" in error_response
                
                # Should indicate validation error
                error_msg = str(error_response)
                assert "version" in error_msg.lower() or "validation" in error_msg.lower()
    
    @pytest.mark.asyncio
    async def test_agent_failure_handling(self, auth_headers, sample_openapi_spec):
        """Test handling of agent failures during test generation."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Agent Failure Test Spec",
                "description": "Testing agent failure handling",
                "content": json.dumps(sample_openapi_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id", "mock-spec-id")
            
            # Create test run with potentially failing agent
            test_run_data = {
                "name": "Agent Failure Test",
                "spec_id": spec_id,
                "agents": [
                    "functional-positive",
                    "invalid-agent-type",  # This should fail
                    "security-auth"
                ]
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                # Should either reject invalid agent or handle gracefully
                if response.status in [200, 201]:
                    test_run_response = await response.json()
                    test_run_id = test_run_response.get("id")
                    
                    # Check status to see if partial success
                    async with session.get(
                        f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/status",
                        headers=auth_headers
                    ) as status_response:
                        status_data = await status_response.json()
                        
                        # Should indicate agent failure
                        agent_statuses = status_data.get("agent_statuses", {})
                        if "invalid-agent-type" in agent_statuses:
                            assert agent_statuses["invalid-agent-type"] in ["failed", "error", "invalid"]
                else:
                    # Should return error for invalid agent
                    assert response.status in [400, 422]
    
    @pytest.mark.asyncio
    async def test_concurrent_test_execution(self, auth_headers, sample_openapi_spec):
        """Test concurrent execution of multiple test runs."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Concurrent Test Spec",
                "description": "Testing concurrent execution",
                "content": json.dumps(sample_openapi_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id", "mock-spec-id")
            
            # Create multiple test runs concurrently
            test_runs = []
            for i in range(3):
                test_run_data = {
                    "name": f"Concurrent Test Run {i+1}",
                    "spec_id": spec_id,
                    "agents": ["functional-positive", "functional-negative"]
                }
                test_runs.append(test_run_data)
            
            # Submit all test runs concurrently
            tasks = []
            for test_run in test_runs:
                task = session.post(
                    f"{ORCHESTRATION_URL}/api/test-runs",
                    json=test_run,
                    headers=auth_headers
                )
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Verify all test runs were created
            test_run_ids = []
            for response in responses:
                if not isinstance(response, Exception):
                    async with response:
                        if response.status in [200, 201]:
                            data = await response.json()
                            test_run_ids.append(data.get("id"))
            
            assert len(test_run_ids) >= 2, "Not enough concurrent test runs created"
            
            # Monitor all test runs
            status_tasks = []
            for run_id in test_run_ids:
                task = session.get(
                    f"{ORCHESTRATION_URL}/api/test-runs/{run_id}/status",
                    headers=auth_headers
                )
                status_tasks.append(task)
            
            status_responses = await asyncio.gather(*status_tasks, return_exceptions=True)
            
            # Verify all are processing
            for response in status_responses:
                if not isinstance(response, Exception):
                    async with response:
                        if response.status == 200:
                            status_data = await response.json()
                            assert status_data.get("status") in [
                                "pending", "running", "generating", "completed"
                            ]
    
    @pytest.mark.asyncio
    async def test_test_data_persistence(self, auth_headers, sample_openapi_spec):
        """Test that test results are properly persisted and retrievable."""
        async with aiohttp.ClientSession() as session:
            # Create and execute a test run
            spec_data = {
                "name": "Persistence Test Spec",
                "description": "Testing data persistence",
                "content": json.dumps(sample_openapi_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id", "mock-spec-id")
            
            # Create test run
            test_run_data = {
                "name": "Persistence Test Run",
                "spec_id": spec_id,
                "agents": ["functional-positive"]
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Wait a moment for processing
            await asyncio.sleep(5)
            
            # Retrieve test run history
            async with session.get(
                f"{DATA_SERVICE_URL}/api/test-runs",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                test_runs = await response.json()
                
                # Find our test run
                our_run = None
                for run in test_runs:
                    if run.get("id") == test_run_id:
                        our_run = run
                        break
                
                assert our_run is not None, "Test run not found in history"
                assert our_run.get("name") == "Persistence Test Run"
            
            # Retrieve analytics data
            async with session.get(
                f"{DATA_SERVICE_URL}/api/analytics/summary",
                headers=auth_headers
            ) as response:
                if response.status == 200:
                    analytics = await response.json()
                    
                    # Should have some aggregate data
                    assert "total_test_runs" in analytics
                    assert analytics["total_test_runs"] > 0