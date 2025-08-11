"""
Unit tests for Orchestration Service.

Tests AI agent orchestration, test generation, and task management functionality.
"""
import pytest
from fastapi.testclient import TestClient
from fastapi import status
import json
from unittest.mock import AsyncMock, patch
import asyncio

from orchestration_service.app_factory import (
    create_orchestration_app,
    create_test_orchestration_app,
    OrchestrationConfig,
    AgentType,
    TaskStatus,
    TestGenerationRequest,
    MockAgent
)


class TestMockAgent:
    """Test MockAgent functionality."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_mock_agent_positive(self):
        """Test mock agent generates positive test cases."""
        agent = MockAgent(AgentType.FUNCTIONAL_POSITIVE)
        spec = {"paths": {"/test": {"get": {}}}}
        
        test_cases = await agent.generate_tests(spec, {})
        
        assert len(test_cases) == 1
        assert test_cases[0]["type"] == "positive"
        assert test_cases[0]["expected_status"] == 200
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_mock_agent_negative(self):
        """Test mock agent generates negative test cases."""
        agent = MockAgent(AgentType.FUNCTIONAL_NEGATIVE)
        spec = {"paths": {"/test": {"get": {}}}}
        
        test_cases = await agent.generate_tests(spec, {})
        
        assert len(test_cases) == 1
        assert test_cases[0]["type"] == "negative"
        assert test_cases[0]["expected_status"] == 400
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_mock_agent_security(self):
        """Test mock agent generates security test cases."""
        agent = MockAgent(AgentType.SECURITY_INJECTION)
        spec = {"paths": {"/test": {"post": {}}}}
        
        test_cases = await agent.generate_tests(spec, {})
        
        assert len(test_cases) == 1
        assert test_cases[0]["type"] == "security"
        assert "DROP TABLE" in test_cases[0]["payload"]


class TestOrchestrationService:
    """Test Orchestration Service endpoints."""
    
    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return OrchestrationConfig(
            enable_background_tasks=False,  # Run synchronously for testing
            mock_agents=True,
            mock_spec_service=True,
            mock_data_service=True
        )
    
    @pytest.fixture
    def app(self, config):
        """Create test app."""
        return create_orchestration_app(config)
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)
    
    @pytest.mark.unit
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["service"] == "Sentinel Orchestration Service"
        assert "available_agents" in data
        assert len(data["available_agents"]) == 7  # All AgentType values
    
    @pytest.mark.unit
    def test_health_endpoint(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
    
    @pytest.mark.unit
    def test_list_agents(self, client):
        """Test listing available agents."""
        response = client.get("/agents")
        assert response.status_code == status.HTTP_200_OK
        agents = response.json()
        
        assert len(agents) == 7
        
        # Check functional positive agent
        positive_agent = next(a for a in agents if "Positive" in a["type"])
        assert "happy_path" in positive_agent["capabilities"]
        assert "valid_inputs" in positive_agent["capabilities"]
        
        # Check security auth agent
        auth_agent = next(a for a in agents if "Security-Auth" in a["type"])
        assert "authentication" in auth_agent["capabilities"]
        assert "authorization" in auth_agent["capabilities"]
    
    @pytest.mark.unit
    def test_generate_tests_single_agent(self, client):
        """Test generating tests with a single agent."""
        request_data = {
            "spec_id": 1,
            "agent_types": ["Functional-Positive-Agent"]
        }
        
        response = client.post("/generate-tests", json=request_data)
        assert response.status_code == status.HTTP_200_OK
        
        data = response.json()
        assert data["spec_id"] == 1
        assert data["agent_types"] == ["Functional-Positive-Agent"]
        assert data["status"] in ["pending", "completed"]  # Sync mode completes immediately
        assert "task_id" in data
        assert "created_at" in data
    
    @pytest.mark.unit
    def test_generate_tests_multiple_agents(self, client):
        """Test generating tests with multiple agents."""
        request_data = {
            "spec_id": 1,
            "agent_types": [
                "Functional-Positive-Agent",
                "Functional-Negative-Agent",
                "Security-Auth-Agent"
            ]
        }
        
        response = client.post("/generate-tests", json=request_data)
        assert response.status_code == status.HTTP_200_OK
        
        data = response.json()
        assert len(data["agent_types"]) == 3
        assert data["spec_id"] == 1
    
    @pytest.mark.unit
    def test_generate_tests_with_options(self, client):
        """Test generating tests with custom options."""
        request_data = {
            "spec_id": 1,
            "agent_types": ["Functional-Positive-Agent"],
            "target_environment": "staging",
            "options": {
                "max_test_cases": 10,
                "include_edge_cases": True
            }
        }
        
        response = client.post("/generate-tests", json=request_data)
        assert response.status_code == status.HTTP_200_OK
        
        data = response.json()
        assert data["spec_id"] == 1
    
    @pytest.mark.unit
    def test_get_task_status(self, client):
        """Test getting task status."""
        # Generate a task first
        response = client.post("/generate-tests", json={
            "spec_id": 1,
            "agent_types": ["Functional-Positive-Agent"]
        })
        task_id = response.json()["task_id"]
        
        # Get task status
        response = client.get(f"/tasks/{task_id}")
        assert response.status_code == status.HTTP_200_OK
        
        task_data = response.json()
        assert task_data["task_id"] == task_id
        assert task_data["spec_id"] == 1
        assert "status" in task_data
        assert "created_at" in task_data
    
    @pytest.mark.unit
    def test_get_nonexistent_task(self, client):
        """Test getting non-existent task."""
        response = client.get("/tasks/non-existent-task")
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"]
    
    @pytest.mark.unit
    def test_list_tasks(self, client):
        """Test listing all tasks."""
        # Create multiple tasks
        for i in range(3):
            client.post("/generate-tests", json={
                "spec_id": i + 1,
                "agent_types": ["Functional-Positive-Agent"]
            })
        
        response = client.get("/tasks")
        assert response.status_code == status.HTTP_200_OK
        
        tasks = response.json()
        assert len(tasks) == 3
        assert all("task_id" in task for task in tasks)
        assert all("spec_id" in task for task in tasks)
    
    @pytest.mark.unit
    def test_list_tasks_with_pagination(self, client):
        """Test listing tasks with pagination."""
        # Create 5 tasks
        for i in range(5):
            client.post("/generate-tests", json={
                "spec_id": i + 1,
                "agent_types": ["Functional-Positive-Agent"]
            })
        
        # Get first 2 tasks
        response = client.get("/tasks?skip=0&limit=2")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()) == 2
        
        # Get next 2 tasks
        response = client.get("/tasks?skip=2&limit=2")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()) == 2
    
    @pytest.mark.unit
    def test_list_tasks_by_status(self, client):
        """Test filtering tasks by status."""
        # Create tasks
        for i in range(3):
            client.post("/generate-tests", json={
                "spec_id": i + 1,
                "agent_types": ["Functional-Positive-Agent"]
            })
        
        # Filter by completed status (sync mode completes immediately)
        response = client.get("/tasks?status=completed")
        assert response.status_code == status.HTTP_200_OK
        
        tasks = response.json()
        assert all(task["status"] == "completed" for task in tasks)
    
    @pytest.mark.unit
    def test_get_test_cases_for_spec(self, client):
        """Test getting test cases for a specification."""
        # Generate tests first
        response = client.post("/generate-tests", json={
            "spec_id": 1,
            "agent_types": ["Functional-Positive-Agent", "Functional-Negative-Agent"]
        })
        
        # Get test cases
        response = client.get("/test-cases/1")
        assert response.status_code == status.HTTP_200_OK
        
        test_cases = response.json()
        assert len(test_cases) == 2  # One from each agent
        assert any(tc["type"] == "positive" for tc in test_cases)
        assert any(tc["type"] == "negative" for tc in test_cases)
    
    @pytest.mark.unit
    def test_get_test_cases_empty_spec(self, client):
        """Test getting test cases for spec with no tests."""
        response = client.get("/test-cases/999")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []
    
    @pytest.mark.unit
    def test_test_agent(self, client):
        """Test testing a specific agent."""
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {"summary": "Get users"}
                }
            }
        }
        
        response = client.post("/agents/Functional-Positive-Agent/test", json=spec)
        assert response.status_code == status.HTTP_200_OK
        
        data = response.json()
        assert data["agent_type"] == "Functional-Positive-Agent"
        assert "test_cases" in data
        assert data["count"] > 0
    
    @pytest.mark.unit
    def test_test_invalid_agent(self, client):
        """Test testing with invalid agent type."""
        spec = {"openapi": "3.0.0", "paths": {}}
        
        response = client.post("/agents/Invalid-Agent/test", json=spec)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid agent type" in response.json()["detail"]


class TestOrchestrationServiceBackground:
    """Test background task functionality."""
    
    @pytest.fixture
    def config(self):
        """Create config with background tasks enabled."""
        return OrchestrationConfig(
            enable_background_tasks=True,
            mock_agents=True,
            mock_spec_service=True,
            mock_data_service=True
        )
    
    @pytest.fixture
    def app(self, config):
        """Create test app."""
        return create_orchestration_app(config)
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)
    
    @pytest.mark.unit
    def test_background_task_creation(self, client):
        """Test that background tasks are created properly."""
        response = client.post("/generate-tests", json={
            "spec_id": 1,
            "agent_types": ["Functional-Positive-Agent"]
        })
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Task should be pending since it's running in background
        assert data["status"] == "pending"
        assert "task_id" in data


class TestOrchestrationServiceWithPredefinedData:
    """Test with predefined test data."""
    
    @pytest.fixture
    def test_tasks(self):
        """Predefined test tasks."""
        return {
            "task-1": {
                "task_id": "task-1",
                "spec_id": 1,
                "agent_types": ["Functional-Positive-Agent"],
                "status": "completed",
                "total_test_cases": 5,
                "created_at": "2024-01-01T00:00:00",
                "completed_at": "2024-01-01T00:01:00"
            },
            "task-2": {
                "task_id": "task-2",
                "spec_id": 2,
                "agent_types": ["Security-Auth-Agent"],
                "status": "running",
                "total_test_cases": 0,
                "created_at": "2024-01-01T00:02:00"
            },
            "task-3": {
                "task_id": "task-3",
                "spec_id": 3,
                "agent_types": ["Functional-Negative-Agent"],
                "status": "failed",
                "total_test_cases": 0,
                "created_at": "2024-01-01T00:03:00",
                "error": "Failed to retrieve specification"
            }
        }
    
    @pytest.fixture
    def test_cases(self):
        """Predefined test cases."""
        return {
            1: [
                {"id": 1, "name": "Test 1", "type": "positive"},
                {"id": 2, "name": "Test 2", "type": "positive"}
            ],
            2: [
                {"id": 3, "name": "Test 3", "type": "security"}
            ]
        }
    
    @pytest.fixture
    def app(self, test_tasks, test_cases):
        """Create app with test data."""
        return create_test_orchestration_app(test_tasks, test_cases)
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)
    
    @pytest.mark.unit
    def test_list_predefined_tasks(self, client):
        """Test listing predefined tasks."""
        response = client.get("/tasks")
        assert response.status_code == status.HTTP_200_OK
        
        tasks = response.json()
        assert len(tasks) == 3
        
        # Check task statuses
        statuses = [task["status"] for task in tasks]
        assert "completed" in statuses
        assert "running" in statuses
        assert "failed" in statuses
    
    @pytest.mark.unit
    def test_get_predefined_task(self, client):
        """Test getting predefined task."""
        response = client.get("/tasks/task-1")
        assert response.status_code == status.HTTP_200_OK
        
        task = response.json()
        assert task["task_id"] == "task-1"
        assert task["status"] == "completed"
        assert task["total_test_cases"] == 5
    
    @pytest.mark.unit
    def test_get_predefined_test_cases(self, client):
        """Test getting predefined test cases."""
        response = client.get("/test-cases/1")
        assert response.status_code == status.HTTP_200_OK
        
        test_cases = response.json()
        assert len(test_cases) == 2
        assert all(tc["type"] == "positive" for tc in test_cases)


class TestOrchestrationIntegration:
    """Integration tests for complete workflows."""
    
    @pytest.fixture
    def app(self):
        """Create app with minimal mocking."""
        config = OrchestrationConfig(
            enable_background_tasks=False,
            mock_agents=True,
            mock_spec_service=True,
            mock_data_service=True
        )
        return create_orchestration_app(config)
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)
    
    @pytest.mark.unit
    def test_complete_test_generation_workflow(self, client):
        """Test complete workflow from test generation to retrieval."""
        # Step 1: Generate tests
        response = client.post("/generate-tests", json={
            "spec_id": 1,
            "agent_types": [
                "Functional-Positive-Agent",
                "Functional-Negative-Agent",
                "Security-Injection-Agent"
            ],
            "options": {"max_tests": 10}
        })
        
        assert response.status_code == status.HTTP_200_OK
        task_data = response.json()
        task_id = task_data["task_id"]
        
        # Step 2: Check task status
        response = client.get(f"/tasks/{task_id}")
        assert response.status_code == status.HTTP_200_OK
        task = response.json()
        assert task["status"] == "completed"  # Sync mode
        assert task["total_test_cases"] == 3  # One from each agent
        
        # Step 3: Get generated test cases
        response = client.get(f"/test-cases/{task_data['spec_id']}")
        assert response.status_code == status.HTTP_200_OK
        test_cases = response.json()
        assert len(test_cases) == 3
        
        # Verify test case types
        test_types = [tc["type"] for tc in test_cases]
        assert "positive" in test_types
        assert "negative" in test_types
        assert "security" in test_types
    
    @pytest.mark.unit
    def test_multiple_specs_workflow(self, client):
        """Test handling multiple specifications."""
        spec_ids = [1, 2, 3]
        task_ids = []
        
        # Generate tests for multiple specs
        for spec_id in spec_ids:
            response = client.post("/generate-tests", json={
                "spec_id": spec_id,
                "agent_types": ["Functional-Positive-Agent"]
            })
            assert response.status_code == status.HTTP_200_OK
            task_ids.append(response.json()["task_id"])
        
        # Verify all tasks are tracked
        response = client.get("/tasks")
        assert response.status_code == status.HTTP_200_OK
        tasks = response.json()
        assert len(tasks) >= 3
        
        # Verify each spec has test cases
        for spec_id in spec_ids:
            response = client.get(f"/test-cases/{spec_id}")
            assert response.status_code == status.HTTP_200_OK
            test_cases = response.json()
            assert len(test_cases) > 0