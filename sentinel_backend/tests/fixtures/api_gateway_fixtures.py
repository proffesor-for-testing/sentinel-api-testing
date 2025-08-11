"""
API Gateway test fixtures and test data.
"""
import pytest
from unittest.mock import Mock, AsyncMock
from datetime import datetime
from typing import Dict, Any


@pytest.fixture
def mock_service_settings():
    """Mock service settings for API Gateway."""
    mock_settings = Mock()
    mock_settings.spec_service_url = "http://spec:8001"
    mock_settings.orchestration_service_url = "http://orchestration:8002"
    mock_settings.data_service_url = "http://data:8004"
    mock_settings.execution_service_url = "http://execution:8003"
    mock_settings.auth_service_url = "http://auth:8005"
    mock_settings.service_timeout = 30.0
    mock_settings.health_check_timeout = 5.0
    return mock_settings


@pytest.fixture
def mock_app_settings():
    """Mock application settings for API Gateway."""
    mock_settings = Mock()
    mock_settings.app_version = "1.0.0-test"
    mock_settings.debug = True
    mock_settings.log_level = "DEBUG"
    return mock_settings


@pytest.fixture
def mock_network_settings():
    """Mock network settings for API Gateway."""
    mock_settings = Mock()
    mock_settings.cors_origins = ["http://localhost:3000"]
    mock_settings.cors_allow_credentials = True
    mock_settings.cors_allow_methods = ["*"]
    mock_settings.cors_allow_headers = ["*"]
    return mock_settings


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "description": "A test API for unit tests"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "responses": {
                        "200": {
                            "description": "List of users"
                        }
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
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "User created"
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def specification_upload_request(sample_openapi_spec):
    """Sample specification upload request."""
    import json
    return {
        "raw_spec": json.dumps(sample_openapi_spec),
        "source_filename": "test_api.json",
        "source_url": None
    }


@pytest.fixture
def specification_response_data(sample_openapi_spec):
    """Sample specification response data."""
    return {
        "id": 1,
        "project_id": None,
        "raw_spec": sample_openapi_spec,
        "parsed_spec": sample_openapi_spec,
        "internal_graph": None,
        "source_filename": "test_api.json",
        "source_url": None,
        "llm_readiness_score": 0.85,
        "version": "1.0.0",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }


@pytest.fixture
def test_generation_request():
    """Sample test generation request."""
    return {
        "spec_id": 1,
        "agent_types": ["Functional-Positive-Agent", "Security-Auth-Agent"],
        "target_environment": "https://api.example.com"
    }


@pytest.fixture
def test_generation_response():
    """Sample test generation response."""
    return {
        "task_id": "test-gen-123",
        "spec_id": 1,
        "agent_types": ["Functional-Positive-Agent", "Security-Auth-Agent"],
        "total_test_cases": 15,
        "status": "completed",
        "created_at": datetime.utcnow().isoformat()
    }


@pytest.fixture
def test_suite_create_request():
    """Sample test suite creation request."""
    return {
        "name": "User API Test Suite",
        "description": "Comprehensive tests for user management API",
        "test_case_ids": [1, 2, 3, 4, 5]
    }


@pytest.fixture
def test_suite_response():
    """Sample test suite response."""
    return {
        "id": 1,
        "name": "User API Test Suite",
        "description": "Comprehensive tests for user management API",
        "test_case_ids": [1, 2, 3, 4, 5],
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }


@pytest.fixture
def test_run_request():
    """Sample test run request."""
    return {
        "suite_id": 1,
        "target_environment": "https://api.example.com"
    }


@pytest.fixture
def test_run_response():
    """Sample test run response."""
    return {
        "run_id": "run-123",
        "suite_id": 1,
        "target_environment": "https://api.example.com",
        "status": "completed",
        "total_tests": 5,
        "passed": 4,
        "failed": 1,
        "errors": 0,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": datetime.utcnow().isoformat()
    }


@pytest.fixture
def test_cases_response():
    """Sample test cases response."""
    return [
        {
            "id": 1,
            "spec_id": 1,
            "name": "Test user creation with valid data",
            "description": "Positive test case for creating a user",
            "agent_type": "Functional-Positive-Agent",
            "test_data": {"name": "John Doe", "email": "john@example.com"},
            "expected_response": {"status": 201},
            "created_at": datetime.utcnow().isoformat()
        },
        {
            "id": 2,
            "spec_id": 1,
            "name": "Test user creation with invalid email",
            "description": "Negative test case for invalid email format",
            "agent_type": "Functional-Negative-Agent",
            "test_data": {"name": "John Doe", "email": "invalid-email"},
            "expected_response": {"status": 400},
            "created_at": datetime.utcnow().isoformat()
        }
    ]


@pytest.fixture
def health_check_response():
    """Sample health check response."""
    return {
        "status": "healthy",
        "services": {
            "spec_service": {
                "status": "healthy",
                "response_time_ms": 25
            },
            "orchestration_service": {
                "status": "healthy", 
                "response_time_ms": 30
            },
            "data_service": {
                "status": "healthy",
                "response_time_ms": 15
            },
            "execution_service": {
                "status": "healthy",
                "response_time_ms": 20
            }
        }
    }


@pytest.fixture
def degraded_health_check_response():
    """Sample degraded health check response."""
    return {
        "status": "degraded",
        "services": {
            "spec_service": {
                "status": "healthy",
                "response_time_ms": 25
            },
            "orchestration_service": {
                "status": "unhealthy",
                "error": "Connection refused"
            },
            "data_service": {
                "status": "healthy", 
                "response_time_ms": 15
            },
            "execution_service": {
                "status": "healthy",
                "response_time_ms": 20
            }
        }
    }


@pytest.fixture
def end_to_end_test_request(sample_openapi_spec):
    """Sample end-to-end test request."""
    import json
    return {
        "raw_spec": json.dumps(sample_openapi_spec),
        "target_environment": "https://api.example.com",
        "source_filename": "user_api.json",
        "agent_types": ["Functional-Positive-Agent", "Functional-Negative-Agent"]
    }


@pytest.fixture
def end_to_end_test_response():
    """Sample end-to-end test response."""
    return {
        "message": "Complete testing flow executed successfully",
        "spec_id": 1,
        "suite_id": 1,
        "run_id": "run-123",
        "summary": {
            "total_test_cases": 10,
            "total_tests_executed": 10,
            "passed": 8,
            "failed": 2,
            "errors": 0
        },
        "results": {
            "run_id": "run-123",
            "status": "completed",
            "test_results": [
                {
                    "test_case_id": 1,
                    "status": "passed",
                    "response_time_ms": 150
                },
                {
                    "test_case_id": 2,
                    "status": "failed",
                    "error": "Expected status 400, got 200"
                }
            ]
        }
    }


@pytest.fixture
def mock_auth_data():
    """Mock authentication data for testing."""
    return {
        "user": {
            "id": 1,
            "email": "test@example.com",
            "role": "admin"
        },
        "token": "mock-jwt-token",
        "permissions": [
            "spec:create", "spec:read", "spec:update", "spec:delete",
            "test_case:create", "test_case:read", "test_case:update", "test_case:delete"
        ]
    }


@pytest.fixture
def mock_correlation_id():
    """Mock correlation ID for testing."""
    return "gateway-test-correlation-id-12345"


@pytest.fixture
def mock_request_with_correlation_id(mock_correlation_id):
    """Mock FastAPI request with correlation ID."""
    mock_request = Mock()
    mock_request.headers = {"X-Correlation-ID": mock_correlation_id}
    return mock_request


@pytest.fixture
def mock_httpx_client():
    """Mock httpx.AsyncClient for testing."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


@pytest.fixture
def mock_successful_response():
    """Mock successful HTTP response."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.raise_for_status = Mock()
    return mock_response


@pytest.fixture
def mock_error_response():
    """Mock error HTTP response."""
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    
    def raise_for_status():
        from httpx import HTTPStatusError
        raise HTTPStatusError("500 Internal Server Error", request=Mock(), response=mock_response)
    
    mock_response.raise_for_status = raise_for_status
    return mock_response


@pytest.fixture
def mock_service_unavailable_response():
    """Mock service unavailable response."""
    def raise_request_error():
        from httpx import RequestError
        raise RequestError("Connection failed")
    
    return raise_request_error


@pytest.fixture
def user_login_data():
    """Sample user login data."""
    return {
        "email": "test@example.com",
        "password": "TestPassword123!"
    }


@pytest.fixture
def user_create_data():
    """Sample user creation data."""
    return {
        "email": "newuser@example.com",
        "full_name": "New Test User",
        "password": "NewPassword123!",
        "role": "tester"
    }


@pytest.fixture
def user_update_data():
    """Sample user update data."""
    return {
        "full_name": "Updated Test User",
        "role": "manager",
        "is_active": True
    }