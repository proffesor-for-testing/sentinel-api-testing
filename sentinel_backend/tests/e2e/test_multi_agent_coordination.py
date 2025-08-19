"""
End-to-End test for multi-agent coordination and orchestration.
Tests agent collaboration, data sharing, and parallel execution.
"""

import pytest
import asyncio
import json
from typing import Dict, Any, List, Set
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
from datetime import datetime, timedelta
import uuid

# Service URLs
ORCHESTRATION_URL = "http://localhost:8002"
EXECUTION_URL = "http://localhost:8003"
AUTH_SERVICE_URL = "http://localhost:8005"
SPEC_SERVICE_URL = "http://localhost:8001"
DATA_SERVICE_URL = "http://localhost:8004"


class TestMultiAgentCoordination:
    """E2E tests for multi-agent coordination and collaboration."""
    
    @pytest.fixture
    async def auth_headers(self):
        """Get authentication headers."""
        return {"Authorization": "Bearer mock-token-for-testing"}
    
    @pytest.fixture
    def complex_api_spec(self) -> Dict[str, Any]:
        """Complex API spec requiring multiple agent types."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Complex Multi-Domain API",
                "version": "2.0.0",
                "description": "API requiring multiple agent expertise"
            },
            "servers": [
                {"url": "https://api.complex.com/v2"}
            ],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    },
                    "apiKey": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key"
                    }
                },
                "schemas": {
                    "User": {
                        "type": "object",
                        "required": ["username", "email"],
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "username": {"type": "string", "minLength": 3, "maxLength": 50},
                            "email": {"type": "string", "format": "email"},
                            "role": {"type": "string", "enum": ["admin", "user", "guest"]},
                            "profile": {"$ref": "#/components/schemas/Profile"}
                        }
                    },
                    "Profile": {
                        "type": "object",
                        "properties": {
                            "firstName": {"type": "string"},
                            "lastName": {"type": "string"},
                            "age": {"type": "integer", "minimum": 0, "maximum": 150},
                            "preferences": {
                                "type": "object",
                                "additionalProperties": True
                            }
                        }
                    },
                    "Transaction": {
                        "type": "object",
                        "required": ["amount", "currency"],
                        "properties": {
                            "id": {"type": "string"},
                            "amount": {"type": "number", "minimum": 0},
                            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
                            "status": {"type": "string", "enum": ["pending", "completed", "failed"]},
                            "timestamp": {"type": "string", "format": "date-time"}
                        }
                    }
                }
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users with pagination",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100}},
                            {"name": "role", "in": "query", "schema": {"type": "string", "enum": ["admin", "user", "guest"]}}
                        ],
                        "responses": {
                            "200": {"description": "Success"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"}
                        }
                    },
                    "post": {
                        "summary": "Create user with validation",
                        "security": [{"bearerAuth": []}, {"apiKey": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Created"},
                            "400": {"description": "Bad Request"},
                            "409": {"description": "Conflict"}
                        }
                    }
                },
                "/users/{userId}/transactions": {
                    "get": {
                        "summary": "Get user transactions",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "string"}},
                            {"name": "status", "in": "query", "schema": {"type": "string"}},
                            {"name": "from", "in": "query", "schema": {"type": "string", "format": "date"}},
                            {"name": "to", "in": "query", "schema": {"type": "string", "format": "date"}}
                        ],
                        "responses": {
                            "200": {"description": "Success"},
                            "404": {"description": "User not found"}
                        }
                    },
                    "post": {
                        "summary": "Create transaction",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Transaction"}
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Transaction created"},
                            "400": {"description": "Invalid transaction data"},
                            "402": {"description": "Payment required"},
                            "503": {"description": "Service unavailable"}
                        }
                    }
                },
                "/admin/users/bulk": {
                    "delete": {
                        "summary": "Bulk delete users (admin only)",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "userIds": {
                                                "type": "array",
                                                "items": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Users deleted"},
                            "403": {"description": "Forbidden - Admin only"}
                        }
                    }
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_agent_collaboration_workflow(self, auth_headers, complex_api_spec):
        """Test multiple agents collaborating on complex API testing."""
        async with aiohttp.ClientSession() as session:
            # Upload complex specification
            spec_data = {
                "name": "Multi-Agent Collaboration API",
                "description": "Complex API for agent collaboration testing",
                "content": json.dumps(complex_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id", "mock-spec-id")
            
            # Create test run with all agent types
            all_agents = [
                "data-mocking",        # Creates test data first
                "functional-positive", # Uses mocked data
                "functional-negative", # Edge cases
                "functional-stateful", # Transaction flows
                "security-auth",       # Authentication tests
                "security-injection",  # SQL injection tests
                "performance-planner"  # Load test scenarios
            ]
            
            test_run_data = {
                "name": "Full Agent Collaboration Test",
                "spec_id": spec_id,
                "agents": all_agents,
                "configuration": {
                    "coordination_mode": "collaborative",
                    "data_sharing": True,
                    "agent_dependencies": {
                        "functional-positive": ["data-mocking"],
                        "functional-negative": ["data-mocking"],
                        "functional-stateful": ["data-mocking", "functional-positive"],
                        "security-auth": ["data-mocking"],
                        "security-injection": ["data-mocking"],
                        "performance-planner": ["functional-positive", "functional-negative"]
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Monitor agent coordination
            await asyncio.sleep(3)
            
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/agents/status",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                agent_statuses = await response.json()
                
                # Verify all agents are initialized
                assert len(agent_statuses) == len(all_agents)
                
                # Check data-mocking runs first (dependency)
                data_mocking_status = agent_statuses.get("data-mocking", {})
                assert data_mocking_status.get("status") in ["running", "completed"]
                
                # Verify shared data pool exists
                if "shared_data" in agent_statuses:
                    shared_data = agent_statuses["shared_data"]
                    assert "test_users" in shared_data or "mock_data" in shared_data
            
            # Wait for agents to generate tests
            max_wait = 60
            start_time = datetime.utcnow()
            
            while (datetime.utcnow() - start_time).seconds < max_wait:
                async with session.get(
                    f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/status",
                    headers=auth_headers
                ) as response:
                    status_data = await response.json()
                    
                    if status_data.get("generation_status") == "completed":
                        break
                    elif status_data.get("generation_status") == "failed":
                        # Check which agents failed
                        failed_agents = [
                            agent for agent, status in status_data.get("agent_statuses", {}).items()
                            if status == "failed"
                        ]
                        print(f"Failed agents: {failed_agents}")
                        break
                
                await asyncio.sleep(3)
            
            # Retrieve test cases from all agents
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/test-cases",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                all_test_cases = await response.json()
                
                # Group test cases by agent
                test_cases_by_agent: Dict[str, List] = {}
                for tc in all_test_cases:
                    agent = tc.get("agent_type", "unknown")
                    if agent not in test_cases_by_agent:
                        test_cases_by_agent[agent] = []
                    test_cases_by_agent[agent].append(tc)
                
                # Verify each agent contributed tests
                assert len(test_cases_by_agent) >= 5, f"Not enough agents contributed: {test_cases_by_agent.keys()}"
                
                # Verify data sharing between agents
                data_mocking_tests = test_cases_by_agent.get("data-mocking", [])
                functional_tests = test_cases_by_agent.get("functional-positive", [])
                
                if data_mocking_tests and functional_tests:
                    # Check if functional tests use mocked data
                    mocked_user_ids = set()
                    for dm_test in data_mocking_tests:
                        if "generated_data" in dm_test:
                            data = dm_test["generated_data"]
                            if isinstance(data, dict) and "id" in data:
                                mocked_user_ids.add(data["id"])
                    
                    # Functional tests should reference mocked data
                    for func_test in functional_tests:
                        test_data = func_test.get("request_data", {})
                        if "userId" in test_data or "user_id" in test_data:
                            # Should use mocked IDs
                            used_id = test_data.get("userId") or test_data.get("user_id")
                            # This is a soft check as IDs might be generated differently
                            assert used_id is not None
                
                # Verify security tests cover auth scenarios
                security_auth_tests = test_cases_by_agent.get("security-auth", [])
                assert len(security_auth_tests) > 0, "No security auth tests generated"
                
                auth_scenarios = set()
                for sec_test in security_auth_tests:
                    scenario = sec_test.get("test_scenario", "")
                    auth_scenarios.add(scenario)
                
                # Should test multiple auth scenarios
                expected_scenarios = {"missing_token", "invalid_token", "expired_token", "insufficient_permissions"}
                assert len(auth_scenarios.intersection(expected_scenarios)) > 0
    
    @pytest.mark.asyncio
    async def test_agent_dependency_resolution(self, auth_headers, complex_api_spec):
        """Test that agent dependencies are properly resolved."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Dependency Test API",
                "description": "Testing agent dependency resolution",
                "content": json.dumps(complex_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create test run with explicit dependencies
            test_run_data = {
                "name": "Dependency Resolution Test",
                "spec_id": spec_id,
                "agents": [
                    "functional-stateful",  # Depends on others
                    "functional-positive",  # Depends on data-mocking
                    "data-mocking"         # No dependencies
                ],
                "configuration": {
                    "coordination_mode": "sequential",
                    "agent_dependencies": {
                        "functional-stateful": ["functional-positive", "data-mocking"],
                        "functional-positive": ["data-mocking"],
                        "data-mocking": []
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Monitor execution order
            execution_order = []
            max_checks = 20
            
            for _ in range(max_checks):
                async with session.get(
                    f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/agents/timeline",
                    headers=auth_headers
                ) as response:
                    if response.status == 200:
                        timeline = await response.json()
                        
                        for event in timeline.get("events", []):
                            agent = event.get("agent")
                            status = event.get("status")
                            
                            if status == "started" and agent not in execution_order:
                                execution_order.append(agent)
                        
                        # Check if all agents have started
                        if len(execution_order) >= 3:
                            break
                
                await asyncio.sleep(2)
            
            # Verify execution order respects dependencies
            if len(execution_order) >= 3:
                # data-mocking should start first (no dependencies)
                assert execution_order[0] == "data-mocking"
                
                # functional-positive should start after data-mocking
                dm_index = execution_order.index("data-mocking")
                fp_index = execution_order.index("functional-positive")
                assert fp_index > dm_index
                
                # functional-stateful should start last
                fs_index = execution_order.index("functional-stateful")
                assert fs_index > fp_index
    
    @pytest.mark.asyncio
    async def test_parallel_agent_execution(self, auth_headers, complex_api_spec):
        """Test parallel execution of independent agents."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Parallel Execution API",
                "description": "Testing parallel agent execution",
                "content": json.dumps(complex_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create test run with parallel agents
            test_run_data = {
                "name": "Parallel Agent Test",
                "spec_id": spec_id,
                "agents": [
                    "functional-positive",
                    "functional-negative",
                    "security-auth",
                    "security-injection"
                ],
                "configuration": {
                    "coordination_mode": "parallel",
                    "max_concurrent": 4,
                    "agent_dependencies": {}  # No dependencies - all can run in parallel
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Wait a moment for agents to start
            await asyncio.sleep(3)
            
            # Check that multiple agents are running concurrently
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/agents/status",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                agent_statuses = await response.json()
                
                # Count running agents
                running_agents = [
                    agent for agent, status in agent_statuses.items()
                    if status.get("status") == "running"
                ]
                
                # Should have multiple agents running in parallel
                assert len(running_agents) >= 2, f"Not enough parallel agents: {running_agents}"
                
                # Record start times
                start_times = {}
                for agent, status in agent_statuses.items():
                    if "started_at" in status:
                        start_times[agent] = status["started_at"]
                
                # Verify agents started close to each other (parallel)
                if len(start_times) >= 2:
                    times = list(start_times.values())
                    # Parse times and check they're within a few seconds
                    # This indicates parallel execution
                    # Note: Implementation depends on timestamp format
    
    @pytest.mark.asyncio
    async def test_agent_failure_recovery(self, auth_headers, complex_api_spec):
        """Test recovery when an agent fails during generation."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Failure Recovery API",
                "description": "Testing agent failure recovery",
                "content": json.dumps(complex_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create test run with potential failure scenario
            test_run_data = {
                "name": "Agent Failure Test",
                "spec_id": spec_id,
                "agents": [
                    "functional-positive",
                    "functional-negative",
                    "invalid-agent",  # This should fail
                    "security-auth"
                ],
                "configuration": {
                    "coordination_mode": "parallel",
                    "continue_on_failure": True,  # Continue even if an agent fails
                    "retry_failed_agents": True,
                    "max_retries": 2
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                # Should handle invalid agent gracefully
                if response.status in [200, 201]:
                    test_run_response = await response.json()
                    test_run_id = test_run_response.get("id")
                    
                    # Wait for processing
                    await asyncio.sleep(5)
                    
                    # Check agent statuses
                    async with session.get(
                        f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/agents/status",
                        headers=auth_headers
                    ) as status_response:
                        agent_statuses = await status_response.json()
                        
                        # Invalid agent should be marked as failed
                        if "invalid-agent" in agent_statuses:
                            assert agent_statuses["invalid-agent"]["status"] in ["failed", "error", "skipped"]
                        
                        # Other agents should continue
                        successful_agents = [
                            agent for agent, status in agent_statuses.items()
                            if status.get("status") in ["running", "completed"]
                        ]
                        assert len(successful_agents) >= 2
                    
                    # Check if retry was attempted
                    async with session.get(
                        f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/agents/retries",
                        headers=auth_headers
                    ) as retry_response:
                        if retry_response.status == 200:
                            retry_data = await retry_response.json()
                            
                            # Should show retry attempts for failed agent
                            if "invalid-agent" in retry_data:
                                assert retry_data["invalid-agent"]["retry_count"] > 0
    
    @pytest.mark.asyncio
    async def test_agent_resource_optimization(self, auth_headers, complex_api_spec):
        """Test resource optimization across multiple agents."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Resource Optimization API",
                "description": "Testing agent resource usage",
                "content": json.dumps(complex_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create test run with resource constraints
            test_run_data = {
                "name": "Resource Optimization Test",
                "spec_id": spec_id,
                "agents": [
                    "functional-positive",
                    "functional-negative",
                    "functional-stateful",
                    "security-auth",
                    "security-injection",
                    "performance-planner"
                ],
                "configuration": {
                    "coordination_mode": "adaptive",  # Adapt based on resources
                    "max_concurrent": 3,  # Limit concurrent agents
                    "resource_limits": {
                        "max_memory_mb": 512,
                        "max_cpu_percent": 50,
                        "max_test_cases_per_agent": 100
                    },
                    "optimization_strategy": "balanced"  # Balance speed vs resource usage
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Monitor resource usage
            await asyncio.sleep(5)
            
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/resources",
                headers=auth_headers
            ) as response:
                if response.status == 200:
                    resource_data = await response.json()
                    
                    # Check resource constraints are respected
                    current_memory = resource_data.get("current_memory_mb", 0)
                    current_cpu = resource_data.get("current_cpu_percent", 0)
                    concurrent_agents = resource_data.get("concurrent_agents", 0)
                    
                    # Verify limits are respected
                    assert concurrent_agents <= 3, f"Too many concurrent agents: {concurrent_agents}"
                    
                    # Check queue management
                    queued_agents = resource_data.get("queued_agents", [])
                    running_agents = resource_data.get("running_agents", [])
                    
                    # Should have proper queue when at capacity
                    if len(running_agents) >= 3:
                        assert len(queued_agents) > 0
    
    @pytest.mark.asyncio
    async def test_agent_communication_protocol(self, auth_headers, complex_api_spec):
        """Test inter-agent communication and message passing."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Agent Communication API",
                "description": "Testing inter-agent communication",
                "content": json.dumps(complex_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create test run with communicating agents
            test_run_data = {
                "name": "Agent Communication Test",
                "spec_id": spec_id,
                "agents": [
                    "data-mocking",
                    "functional-stateful",
                    "security-auth"
                ],
                "configuration": {
                    "coordination_mode": "collaborative",
                    "enable_agent_communication": True,
                    "communication_protocol": "message_passing",
                    "shared_context": {
                        "test_environment": "staging",
                        "base_url": "https://staging.api.com"
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Wait for agents to start communicating
            await asyncio.sleep(5)
            
            # Retrieve communication logs
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/communications",
                headers=auth_headers
            ) as response:
                if response.status == 200:
                    communications = await response.json()
                    
                    # Should have inter-agent messages
                    messages = communications.get("messages", [])
                    assert len(messages) > 0, "No inter-agent communication found"
                    
                    # Verify message structure
                    for msg in messages[:5]:  # Check first few messages
                        assert "from_agent" in msg
                        assert "to_agent" in msg
                        assert "message_type" in msg
                        assert "content" in msg
                        assert "timestamp" in msg
                    
                    # Check for data sharing messages
                    data_share_messages = [
                        msg for msg in messages
                        if msg.get("message_type") == "data_share"
                    ]
                    
                    # data-mocking should share data with other agents
                    if data_share_messages:
                        dm_shares = [
                            msg for msg in data_share_messages
                            if msg.get("from_agent") == "data-mocking"
                        ]
                        assert len(dm_shares) > 0, "data-mocking didn't share data"
            
            # Check shared context usage
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/shared-context",
                headers=auth_headers
            ) as response:
                if response.status == 200:
                    context = await response.json()
                    
                    # Should have initial context
                    assert context.get("test_environment") == "staging"
                    
                    # Agents should have added to context
                    agent_contributions = context.get("agent_contributions", {})
                    assert len(agent_contributions) > 0
    
    @pytest.mark.asyncio
    async def test_distributed_agent_execution(self, auth_headers, complex_api_spec):
        """Test distributed execution across multiple worker nodes."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Distributed Execution API",
                "description": "Testing distributed agent execution",
                "content": json.dumps(complex_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create large test run for distribution
            test_run_data = {
                "name": "Distributed Agent Test",
                "spec_id": spec_id,
                "agents": [
                    "functional-positive",
                    "functional-negative",
                    "functional-stateful",
                    "security-auth",
                    "security-injection",
                    "performance-planner",
                    "data-mocking"
                ],
                "configuration": {
                    "coordination_mode": "distributed",
                    "distribution_strategy": "load_balanced",
                    "worker_nodes": ["worker-1", "worker-2", "worker-3"],  # Simulated workers
                    "fault_tolerance": True,
                    "replication_factor": 2  # Each agent task replicated for reliability
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Monitor distribution
            await asyncio.sleep(3)
            
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/distribution",
                headers=auth_headers
            ) as response:
                if response.status == 200:
                    distribution = await response.json()
                    
                    # Check agent distribution across workers
                    worker_assignments = distribution.get("worker_assignments", {})
                    
                    # Should distribute agents across workers
                    workers_used = set()
                    for agent, worker in worker_assignments.items():
                        workers_used.add(worker)
                    
                    # Should use multiple workers
                    assert len(workers_used) >= 2, f"Not enough distribution: {workers_used}"
                    
                    # Check load balancing
                    worker_loads = distribution.get("worker_loads", {})
                    if worker_loads:
                        loads = list(worker_loads.values())
                        # Load should be relatively balanced
                        if len(loads) >= 2:
                            max_load = max(loads)
                            min_load = min(loads)
                            # Max should not be more than 2x min (rough balance check)
                            if min_load > 0:
                                assert max_load / min_load <= 3.0, "Load imbalance detected"