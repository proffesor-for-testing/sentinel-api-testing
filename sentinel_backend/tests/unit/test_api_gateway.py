"""
Unit tests for API Gateway service.

Tests middleware, endpoint routing, service communication, error handling,
and the complete end-to-end testing workflow.
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import status, HTTPException
import httpx
import json

# Import fixtures
from sentinel_backend.tests.fixtures.api_gateway_fixtures import *
from sentinel_backend.tests.fixtures.auth_fixtures import mock_correlation_id


@pytest.fixture
def gateway_app():
    """Create test FastAPI app instance for API Gateway."""
    # Add path for imports
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    
    with patch('api_gateway.main.setup_logging'), \
         patch('api_gateway.main.setup_tracing'), \
         patch('api_gateway.main.Instrumentator'):
        
        # Mock the settings
        with patch('api_gateway.main.get_service_settings') as mock_svc, \
             patch('api_gateway.main.get_application_settings') as mock_app, \
             patch('api_gateway.main.get_network_settings') as mock_net:
            
            # Setup mock settings
            mock_svc.return_value = Mock(
                spec_service_url="http://spec:8001",
                orchestration_service_url="http://orchestration:8002", 
                data_service_url="http://data:8004",
                execution_service_url="http://execution:8003",
                auth_service_url="http://auth:8005",
                service_timeout=30.0,
                health_check_timeout=5.0
            )
            mock_app.return_value = Mock(app_version="1.0.0-test")
            mock_net.return_value = Mock()
            
            from api_gateway.main import app
            return app


@pytest.fixture
def client(gateway_app):
    """Create test client for API Gateway."""
    return TestClient(gateway_app)


class TestRootAndHealthEndpoints:
    """Test root and health check endpoints."""
    
    @pytest.mark.unit
    def test_root_endpoint(self, client):
        """Test root endpoint returns gateway information."""
        response = client.get("/")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Sentinel API Gateway is running"
        assert data["version"] == "1.0.0"
        assert data["phase"] == "Phase 2 - MVP"
        assert "endpoints" in data
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_health_check_all_services_healthy(self, mock_client, health_check_response):
        """Test health check with all services healthy."""
        # Mock successful responses from all services
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds.return_value = 0.025
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        # Import and test the function directly
        from api_gateway.main import health_check
        result = await health_check()
        
        assert result["status"] == "healthy"
        assert "services" in result
        # Should have called all services
        assert mock_client_instance.get.call_count == 4
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_health_check_service_unavailable(self):
        """Test health check with one service unavailable."""
        with patch('sentinel_backend.api_gateway.main.httpx.AsyncClient') as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.__aenter__.return_value = mock_client_instance
            mock_client_instance.__aexit__.return_value = None
            
            # Mock one service failing
            async def async_side_effect(url):
                if "spec" in url:
                    raise httpx.RequestError("Connection failed", request=None)
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.elapsed.total_seconds.return_value = 0.025
                return mock_response
            
            mock_client_instance.get.side_effect = async_side_effect
            mock_client.return_value = mock_client_instance
            
            from sentinel_backend.api_gateway.main import health_check
            result = await health_check()
            
            assert result["status"] == "degraded"
            assert "services" in result


class TestMiddleware:
    """Test API Gateway middleware functionality."""
    
    @pytest.mark.unit
    def test_correlation_id_middleware_new_id(self, client):
        """Test correlation ID middleware creates new ID when not provided."""
        response = client.get("/")
        
        # Should have correlation ID in response headers
        assert "x-correlation-id" in [h.lower() for h in response.headers.keys()]
        correlation_id = response.headers.get("X-Correlation-ID")
        assert correlation_id is not None
        assert len(correlation_id) > 0
    
    @pytest.mark.unit
    def test_correlation_id_middleware_preserves_existing_id(self, client, mock_correlation_id):
        """Test correlation ID middleware preserves existing ID."""
        response = client.get("/", headers={"X-Correlation-ID": mock_correlation_id})
        
        # Should preserve the provided correlation ID
        assert response.headers.get("X-Correlation-ID") == mock_correlation_id
    
    @pytest.mark.unit
    def test_security_headers_middleware(self, client):
        """Test security headers middleware adds required headers."""
        response = client.get("/")
        
        # Check for security headers
        headers = {k.lower(): v for k, v in response.headers.items()}
        assert "strict-transport-security" in headers
        assert "x-content-type-options" in headers
        assert "x-frame-options" in headers
        assert "content-security-policy" in headers
        
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
    
    @pytest.mark.unit
    @patch('api_gateway.main.structlog.contextvars.get_contextvars')
    def test_get_correlation_id_headers(self, mock_context, mock_correlation_id):
        """Test correlation ID header extraction."""
        mock_context.return_value = {"correlation_id": mock_correlation_id}
        
        from api_gateway.main import get_correlation_id_headers
        mock_request = Mock()
        
        headers = get_correlation_id_headers(mock_request)
        assert headers["X-Correlation-ID"] == mock_correlation_id
    
    @pytest.mark.unit
    @patch('api_gateway.main.structlog.contextvars.get_contextvars')
    def test_get_correlation_id_headers_empty(self, mock_context):
        """Test correlation ID header extraction when no context."""
        mock_context.return_value = {}
        
        from api_gateway.main import get_correlation_id_headers
        mock_request = Mock()
        
        headers = get_correlation_id_headers(mock_request)
        assert headers == {}


class TestSpecificationEndpoints:
    """Test specification management endpoints."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    @patch('api_gateway.main.require_permission')
    async def test_upload_specification_success(self, mock_auth, mock_client, specification_upload_request, specification_response_data, mock_auth_data):
        """Test successful specification upload."""
        # Mock authentication
        mock_auth.return_value = lambda: mock_auth_data
        
        # Mock successful response from spec service
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = specification_response_data
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        # Test the endpoint
        from api_gateway.main import upload_specification
        mock_request = Mock()
        
        result = await upload_specification(mock_request, specification_upload_request, mock_auth_data)
        
        assert result == specification_response_data
        mock_client_instance.post.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    @patch('api_gateway.main.require_permission')
    async def test_upload_specification_service_error(self, mock_auth, mock_client, specification_upload_request, mock_auth_data):
        """Test specification upload with service error."""
        mock_auth.return_value = lambda: mock_auth_data
        
        # Mock error response from spec service
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.text = "Invalid specification format"
        
        def raise_for_status():
            raise httpx.HTTPStatusError("400 Bad Request", request=Mock(), response=mock_response)
        
        mock_response.raise_for_status = raise_for_status
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import upload_specification
        mock_request = Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await upload_specification(mock_request, specification_upload_request, mock_auth_data)
        
        assert exc_info.value.status_code == 400
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    @patch('api_gateway.main.optional_auth')
    async def test_list_specifications_success(self, mock_auth, mock_client):
        """Test listing specifications."""
        mock_auth.return_value = None  # Anonymous access allowed
        
        # Mock successful response from spec service
        specs_data = [
            {"id": 1, "name": "API v1", "version": "1.0.0"},
            {"id": 2, "name": "API v2", "version": "2.0.0"}
        ]
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = specs_data
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import list_specifications
        mock_request = Mock()
        
        result = await list_specifications(mock_request, None)
        
        assert result == specs_data
        mock_client_instance.get.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_get_specification_success(self, mock_client, specification_response_data):
        """Test getting specific specification."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = specification_response_data
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import get_specification
        mock_request = Mock()
        
        result = await get_specification(mock_request, 1)
        
        assert result == specification_response_data
        mock_client_instance.get.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_get_specification_not_found(self, mock_client):
        """Test getting non-existent specification."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Specification not found"
        
        def raise_for_status():
            raise httpx.HTTPStatusError("404 Not Found", request=Mock(), response=mock_response)
        
        mock_response.raise_for_status = raise_for_status
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import get_specification
        mock_request = Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await get_specification(mock_request, 999)
        
        assert exc_info.value.status_code == 404


class TestTestGenerationEndpoints:
    """Test test generation endpoints."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_generate_tests_success(self, mock_client, test_generation_request, test_generation_response):
        """Test successful test generation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = test_generation_response
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import generate_tests
        mock_request = Mock()
        
        result = await generate_tests(mock_request, test_generation_request)
        
        assert result == test_generation_response
        mock_client_instance.post.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_list_test_cases_success(self, mock_client, test_cases_response):
        """Test listing test cases."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = test_cases_response
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import list_test_cases
        mock_request = Mock()
        
        result = await list_test_cases(mock_request, spec_id=1)
        
        assert result == test_cases_response
        mock_client_instance.get.assert_called_once()
        # Verify spec_id was included in URL
        call_args = mock_client_instance.get.call_args
        assert "spec_id=1" in call_args[0][0]


class TestTestSuiteEndpoints:
    """Test test suite management endpoints."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_create_test_suite_success(self, mock_client, test_suite_create_request, test_suite_response):
        """Test successful test suite creation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = test_suite_response
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import create_test_suite
        mock_request = Mock()
        
        result = await create_test_suite(mock_request, test_suite_create_request)
        
        assert result == test_suite_response
        mock_client_instance.post.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_list_test_suites_success(self, mock_client):
        """Test listing test suites."""
        suites_data = [
            {"id": 1, "name": "Suite 1", "test_case_count": 5},
            {"id": 2, "name": "Suite 2", "test_case_count": 3}
        ]
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = suites_data
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import list_test_suites
        mock_request = Mock()
        
        result = await list_test_suites(mock_request)
        
        assert result == suites_data
        mock_client_instance.get.assert_called_once()


class TestTestExecutionEndpoints:
    """Test test execution endpoints."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_run_tests_success(self, mock_client, test_run_request, test_run_response):
        """Test successful test execution."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = test_run_response
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import run_tests
        mock_request = Mock()
        
        result = await run_tests(mock_request, test_run_request)
        
        assert result == test_run_response
        mock_client_instance.post.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_get_test_run_success(self, mock_client, test_run_response):
        """Test getting test run details."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = test_run_response
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import get_test_run
        mock_request = Mock()
        
        result = await get_test_run(mock_request, "run-123")
        
        assert result == test_run_response
        mock_client_instance.get.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_get_test_run_results_success(self, mock_client):
        """Test getting test run results."""
        results_data = {
            "run_id": "run-123",
            "status": "completed",
            "test_results": [
                {"test_case_id": 1, "status": "passed", "response_time_ms": 150},
                {"test_case_id": 2, "status": "failed", "error": "Assertion failed"}
            ]
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = results_data
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import get_test_run_results_endpoint
        mock_request = Mock()
        
        result = await get_test_run_results_endpoint(mock_request, "run-123")
        
        assert result == results_data
        mock_client_instance.get.assert_called_once()


class TestEndToEndWorkflow:
    """Test complete end-to-end testing workflow."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.upload_specification')
    @patch('api_gateway.main.generate_tests')
    @patch('api_gateway.main.get_test_cases_for_spec')
    @patch('api_gateway.main.create_test_suite')
    @patch('api_gateway.main.run_tests')
    @patch('api_gateway.main.get_test_run_results')
    async def test_complete_testing_flow_success(self, mock_get_results, mock_run_tests, mock_create_suite,
                                                mock_get_cases, mock_generate, mock_upload,
                                                end_to_end_test_request, end_to_end_test_response):
        """Test successful complete end-to-end testing flow."""
        # Mock each step of the workflow
        mock_upload.return_value = {"id": 1}
        mock_generate.return_value = {"total_test_cases": 10}
        mock_get_cases.return_value = [{"id": 1}, {"id": 2}, {"id": 3}]
        mock_create_suite.return_value = {"id": 1}
        mock_run_tests.return_value = {
            "run_id": "run-123",
            "total_tests": 10,
            "passed": 8,
            "failed": 2,
            "errors": 0
        }
        mock_get_results.return_value = {
            "run_id": "run-123",
            "test_results": []
        }
        
        from api_gateway.main import complete_testing_flow, EndToEndTestRequest
        from unittest.mock import Mock
        
        mock_request = Mock()
        # Convert dict to Pydantic model
        request_model = EndToEndTestRequest(**end_to_end_test_request)
        result = await complete_testing_flow(mock_request, request_model)
        
        # Verify all steps were called
        mock_upload.assert_called_once()
        mock_generate.assert_called_once()
        mock_get_cases.assert_called_once()
        mock_create_suite.assert_called_once()
        mock_run_tests.assert_called_once()
        mock_get_results.assert_called_once()
        
        # Verify response structure
        assert result["message"] == "Complete testing flow executed successfully"
        assert result["spec_id"] == 1
        assert result["suite_id"] == 1
        assert result["run_id"] == "run-123"
        assert "summary" in result
        assert "results" in result


class TestErrorHandling:
    """Test error handling across all endpoints."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_service_unavailable_handling(self, mock_client):
        """Test handling when downstream service is unavailable."""
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.side_effect = httpx.RequestError("Connection failed")
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import get_specification
        mock_request = Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await get_specification(mock_request, 1)
        
        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert "service is unavailable" in exc_info.value.detail.lower()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('api_gateway.main.httpx.AsyncClient')
    async def test_timeout_handling(self, mock_client):
        """Test handling of request timeouts."""
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.get.side_effect = httpx.TimeoutException("Request timeout")
        mock_client.return_value = mock_client_instance
        
        from api_gateway.main import get_specification
        mock_request = Mock()
        
        with pytest.raises(HTTPException) as exc_info:
            await get_specification(mock_request, 1)
        
        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE