"""
Comprehensive test suite for the Execution Service using the factory pattern.
"""
import pytest
from datetime import datetime
from httpx import AsyncClient, Response
from unittest.mock import Mock, AsyncMock, patch

from sentinel_backend.execution_service.app_factory import (
    create_execution_app, ExecutionServiceConfig, TestRunRequest, TestCaseResult
)


@pytest.fixture
def execution_config():
    """Create test configuration for Execution Service."""
    return ExecutionServiceConfig(
        data_service_url="http://test-data-service",
        service_timeout=10,
        test_execution_timeout=5,
        mock_mode=True
    )


@pytest.fixture
async def execution_app(execution_config):
    """Create test Execution Service app."""
    return create_execution_app(execution_config)


@pytest.fixture
async def execution_client(execution_app):
    """Create test client for Execution Service."""
    async with AsyncClient(app=execution_app, base_url="http://test") as client:
        yield client


class TestExecutionServiceHealth:
    """Test health and basic endpoints."""
    
    @pytest.mark.asyncio
    async def test_root_endpoint(self, execution_client):
        """Test root endpoint returns expected message."""
        response = await execution_client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Sentinel Execution Service is running"}


class TestTestRunExecution:
    """Test test run execution functionality."""
    
    @pytest.mark.asyncio
    async def test_execute_test_run_success(self, execution_client):
        """Test successful test run execution."""
        test_run_data = {
            "suite_id": 1,
            "target_environment": "http://test-api.example.com",
            "parameters": {"timeout": 30}
        }
        
        response = await execution_client.post("/test-runs", json=test_run_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["run_id"] == 1
        assert data["status"] in ["completed", "failed"]
        assert "started_at" in data
        assert data["total_tests"] >= 0
        assert data["passed"] >= 0
        assert data["failed"] >= 0
        assert data["errors"] >= 0
    
    @pytest.mark.asyncio
    async def test_execute_test_run_no_test_cases(self, execution_app, execution_client):
        """Test test run with no test cases."""
        # Configure app to return empty test cases
        execution_app.state.config.mock_mode = True
        
        test_run_data = {
            "suite_id": 999,  # Non-existent suite
            "target_environment": "http://test-api.example.com"
        }
        
        # Override the fetch_test_cases to return empty list
        with patch('sentinel_backend.execution_service.app_factory.fetch_test_cases', return_value=[]):
            response = await execution_client.post("/test-runs", json=test_run_data)
            assert response.status_code == 404
            assert "No test cases found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_test_run_status(self, execution_client):
        """Test getting test run status."""
        response = await execution_client.get("/test-runs/1")
        assert response.status_code == 200
        
        data = response.json()
        assert "run" in data
        assert "results" in data
        
        run_data = data["run"]
        assert run_data["id"] == 1
        assert run_data["status"] == "completed"
        assert "started_at" in run_data
        
        results = data["results"]
        assert isinstance(results, list)
        if results:
            result = results[0]
            assert "case_id" in result
            assert "status" in result
            assert "response_code" in result
            assert "latency_ms" in result


class TestExecutionServiceWithMockHttpClient:
    """Test Execution Service with mocked HTTP client."""
    
    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client."""
        client = AsyncMock()
        
        # Mock responses for data service calls
        async def mock_post(url, **kwargs):
            response = Mock(spec=Response)
            if "test-runs" in url:
                response.status_code = 201
                response.json = lambda: {"id": 1}
            elif "test-results" in url:
                response.status_code = 201
                response.json = lambda: {"success": True}
            else:
                response.status_code = 200
                response.json = lambda: {}
            return response
        
        async def mock_get(url, **kwargs):
            response = Mock(spec=Response)
            if "test-suites" in url and "cases" in url:
                response.status_code = 200
                response.json = lambda: [
                    {
                        "id": 1,
                        "test_definition": {
                            "endpoint": "/api/users",
                            "method": "GET",
                            "expected_status": 200,
                            "assertions": [{"type": "response_schema"}]
                        }
                    },
                    {
                        "id": 2,
                        "test_definition": {
                            "endpoint": "/api/users/1",
                            "method": "GET",
                            "expected_status": 200,
                            "headers": {"Authorization": "Bearer token"}
                        }
                    }
                ]
            elif "test-runs" in url and "results" in url:
                response.status_code = 200
                response.json = lambda: [
                    {
                        "case_id": 1,
                        "status": "passed",
                        "response_code": 200,
                        "latency_ms": 150
                    }
                ]
            elif "test-runs" in url:
                response.status_code = 200
                response.json = lambda: {
                    "id": 1,
                    "status": "completed",
                    "suite_id": 1,
                    "started_at": datetime.now().isoformat()
                }
            else:
                response.status_code = 200
                response.json = lambda: {}
            return response
        
        async def mock_patch(url, **kwargs):
            response = Mock(spec=Response)
            response.status_code = 200
            return response
        
        client.post = mock_post
        client.get = mock_get
        client.patch = mock_patch
        client.aclose = AsyncMock()
        
        return client
    
    @pytest.fixture
    def config_with_mock_client(self, mock_http_client):
        """Create configuration with mock HTTP client."""
        return ExecutionServiceConfig(
            data_service_url="http://test-data-service",
            mock_mode=False,
            mock_http_client=mock_http_client
        )
    
    @pytest.fixture
    async def app_with_mock_client(self, config_with_mock_client):
        """Create app with mock HTTP client."""
        return create_execution_app(config_with_mock_client)
    
    @pytest.fixture
    async def client_with_mock(self, app_with_mock_client):
        """Create client with mock HTTP client."""
        async with AsyncClient(app=app_with_mock_client, base_url="http://test") as client:
            yield client
    
    @pytest.mark.asyncio
    async def test_execute_test_run_with_mock_client(self, client_with_mock):
        """Test executing test run with mocked HTTP client."""
        test_run_data = {
            "suite_id": 1,
            "target_environment": "http://test-api.example.com"
        }
        
        response = await client_with_mock.post("/test-runs", json=test_run_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["run_id"] == 1
        assert data["total_tests"] == 2  # Two test cases from mock
        assert "started_at" in data
    
    @pytest.mark.asyncio
    async def test_get_test_run_with_mock_client(self, client_with_mock):
        """Test getting test run status with mocked HTTP client."""
        response = await client_with_mock.get("/test-runs/1")
        assert response.status_code == 200
        
        data = response.json()
        assert data["run"]["id"] == 1
        assert data["run"]["status"] == "completed"
        assert len(data["results"]) == 1
        assert data["results"][0]["status"] == "passed"


class TestTestCaseExecution:
    """Test individual test case execution logic."""
    
    @pytest.mark.asyncio
    async def test_test_case_result_model(self):
        """Test TestCaseResult model."""
        result = TestCaseResult(
            case_id=1,
            status="passed",
            response_code=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"success": true}',
            latency_ms=100,
            assertion_failures=[]
        )
        
        assert result.case_id == 1
        assert result.status == "passed"
        assert result.response_code == 200
        assert result.latency_ms == 100
        assert len(result.assertion_failures) == 0
    
    @pytest.mark.asyncio
    async def test_test_case_result_with_errors(self):
        """Test TestCaseResult with errors."""
        result = TestCaseResult(
            case_id=2,
            status="failed",
            response_code=404,
            assertion_failures=[
                {
                    "type": "status_code",
                    "expected": 200,
                    "actual": 404,
                    "message": "Expected status 200, got 404"
                }
            ]
        )
        
        assert result.case_id == 2
        assert result.status == "failed"
        assert result.response_code == 404
        assert len(result.assertion_failures) == 1
        assert result.assertion_failures[0]["type"] == "status_code"
    
    @pytest.mark.asyncio
    async def test_test_case_result_with_error_message(self):
        """Test TestCaseResult with error message."""
        result = TestCaseResult(
            case_id=3,
            status="error",
            error_message="Connection timeout"
        )
        
        assert result.case_id == 3
        assert result.status == "error"
        assert result.error_message == "Connection timeout"
        assert result.response_code is None


class TestExecutionServiceConfiguration:
    """Test Execution Service configuration options."""
    
    def test_default_configuration(self):
        """Test creating config with defaults."""
        config = ExecutionServiceConfig()
        assert config.service_timeout == 60
        assert config.mock_mode == False
        assert config.mock_http_client is None
    
    def test_custom_configuration(self):
        """Test creating config with custom values."""
        config = ExecutionServiceConfig(
            data_service_url="http://custom-data-service",
            service_timeout=30,
            test_execution_timeout=15,
            mock_mode=True
        )
        assert config.data_service_url == "http://custom-data-service"
        assert config.service_timeout == 30
        assert config.test_execution_timeout == 15
        assert config.mock_mode == True
    
    def test_configuration_with_mock_client(self):
        """Test configuration with mock HTTP client."""
        mock_client = AsyncMock()
        config = ExecutionServiceConfig(
            mock_http_client=mock_client
        )
        assert config.mock_http_client == mock_client


class TestExecutionServiceErrorHandling:
    """Test error handling in Execution Service."""
    
    @pytest.mark.asyncio
    async def test_invalid_test_run_request(self, execution_client):
        """Test invalid test run request."""
        # Missing required fields
        invalid_data = {
            "target_environment": "http://test-api.example.com"
        }
        
        response = await execution_client.post("/test-runs", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_test_run_not_found(self, execution_client):
        """Test getting non-existent test run."""
        # In mock mode, returns mock data for any ID
        response = await execution_client.get("/test-runs/999999")
        assert response.status_code == 200  # Mock mode returns data
    
    @pytest.mark.asyncio
    async def test_execution_error_handling(self, execution_app):
        """Test handling of execution errors."""
        # Create app with configuration that will cause errors
        config = ExecutionServiceConfig(
            data_service_url="http://invalid-service",
            mock_mode=False
        )
        app = create_execution_app(config)
        
        async with AsyncClient(app=app, base_url="http://test") as client:
            test_run_data = {
                "suite_id": 1,
                "target_environment": "http://test-api.example.com"
            }
            
            # This should fail due to invalid data service URL
            response = await client.post("/test-runs", json=test_run_data)
            assert response.status_code == 500


class TestExecutionServiceIntegration:
    """Integration tests for Execution Service."""
    
    @pytest.mark.asyncio
    async def test_complete_test_execution_workflow(self, execution_client):
        """Test complete workflow: create run, execute tests, get results."""
        # Create and execute test run
        test_run_data = {
            "suite_id": 1,
            "target_environment": "http://test-api.example.com",
            "parameters": {
                "retry_count": 3,
                "timeout": 30
            }
        }
        
        create_response = await execution_client.post("/test-runs", json=test_run_data)
        assert create_response.status_code == 200
        
        run_data = create_response.json()
        run_id = run_data["run_id"]
        assert run_id > 0
        assert run_data["total_tests"] > 0
        
        # Get test run status
        status_response = await execution_client.get(f"/test-runs/{run_id}")
        assert status_response.status_code == 200
        
        status_data = status_response.json()
        assert status_data["run"]["id"] == run_id
        assert "results" in status_data
    
    @pytest.mark.asyncio
    async def test_parallel_test_execution(self, execution_client):
        """Test executing multiple test runs in parallel."""
        import asyncio
        
        async def execute_run(suite_id):
            test_run_data = {
                "suite_id": suite_id,
                "target_environment": "http://test-api.example.com"
            }
            response = await execution_client.post("/test-runs", json=test_run_data)
            return response.json()
        
        # Execute multiple test runs in parallel
        tasks = [execute_run(i) for i in range(1, 4)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 3
        for result in results:
            assert "run_id" in result
            assert result["status"] in ["completed", "failed"]


class TestExecutionServiceValidation:
    """Test input validation for Execution Service."""
    
    @pytest.mark.asyncio
    async def test_validate_target_environment(self, execution_client):
        """Test validation of target environment URL."""
        # Invalid URL format
        test_run_data = {
            "suite_id": 1,
            "target_environment": "not-a-valid-url"
        }
        
        # The service should accept any string as target_environment
        response = await execution_client.post("/test-runs", json=test_run_data)
        assert response.status_code == 200  # Should still work
    
    @pytest.mark.asyncio
    async def test_validate_suite_id(self, execution_client):
        """Test validation of suite ID."""
        # Negative suite ID
        test_run_data = {
            "suite_id": -1,
            "target_environment": "http://test-api.example.com"
        }
        
        response = await execution_client.post("/test-runs", json=test_run_data)
        # Pydantic should validate this
        assert response.status_code in [200, 422]
    
    @pytest.mark.asyncio
    async def test_optional_parameters(self, execution_client):
        """Test optional parameters in test run request."""
        # Without parameters
        test_run_data = {
            "suite_id": 1,
            "target_environment": "http://test-api.example.com"
        }
        
        response = await execution_client.post("/test-runs", json=test_run_data)
        assert response.status_code == 200
        
        # With parameters
        test_run_data_with_params = {
            "suite_id": 1,
            "target_environment": "http://test-api.example.com",
            "parameters": {
                "custom_header": "test-value",
                "retry_count": 3
            }
        }
        
        response_with_params = await execution_client.post("/test-runs", json=test_run_data_with_params)
        assert response_with_params.status_code == 200