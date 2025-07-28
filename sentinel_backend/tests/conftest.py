"""
Pytest configuration and shared fixtures for Sentinel tests.

This module provides common test fixtures, configuration, and utilities
used across all test modules in the Sentinel test suite.
"""

import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from fastapi import FastAPI

# Import configuration
from config.settings import get_database_settings, get_service_settings, get_application_settings

# Set testing environment
os.environ["SENTINEL_ENVIRONMENT"] = "testing"

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def database_settings():
    """Get database settings for testing."""
    return get_database_settings()

@pytest.fixture(scope="session")
def service_settings():
    """Get service settings for testing."""
    return get_service_settings()

@pytest.fixture(scope="session")
def app_settings():
    """Get application settings for testing."""
    return get_application_settings()

@pytest_asyncio.fixture(scope="session")
async def test_engine(database_settings):
    """Create test database engine."""
    engine = create_async_engine(
        database_settings.database_url,
        pool_size=database_settings.pool_size,
        max_overflow=database_settings.max_overflow,
        pool_timeout=database_settings.pool_timeout,
        pool_recycle=database_settings.pool_recycle,
        echo=False  # Disable SQL logging in tests
    )
    yield engine
    await engine.dispose()

@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing."""
    mock_client = MagicMock()
    mock_client.chat.completions.create = AsyncMock(return_value=MagicMock(
        choices=[MagicMock(
            message=MagicMock(
                content='{"test_cases": [{"name": "Test Case", "method": "GET", "path": "/test"}]}'
            )
        )]
    ))
    return mock_client

@pytest.fixture
def mock_http_client():
    """Mock HTTP client for testing external API calls."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=MagicMock(
        status_code=200,
        json=AsyncMock(return_value={"status": "success"}),
        text="Success response"
    ))
    mock_client.post = AsyncMock(return_value=MagicMock(
        status_code=201,
        json=AsyncMock(return_value={"id": 1, "status": "created"}),
        text="Created response"
    ))
    mock_client.put = AsyncMock(return_value=MagicMock(
        status_code=200,
        json=AsyncMock(return_value={"status": "updated"}),
        text="Updated response"
    ))
    mock_client.delete = AsyncMock(return_value=MagicMock(
        status_code=204,
        text="Deleted"
    ))
    return mock_client

@pytest_asyncio.fixture
async def test_client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    """Create test HTTP client for FastAPI app."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"},
                                                "email": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
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
                                    },
                                    "required": ["name", "email"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{user_id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "User not found"
                        }
                    }
                }
            }
        }
    }

@pytest.fixture
def sample_test_case():
    """Sample test case data for testing."""
    return {
        "name": "Test Get Users",
        "method": "GET",
        "path": "/users",
        "headers": {"Content-Type": "application/json"},
        "query_params": {},
        "body": None,
        "expected_status": 200,
        "expected_response_schema": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                    "email": {"type": "string"}
                }
            }
        },
        "tags": ["functional", "positive"],
        "agent_type": "functional-positive"
    }

@pytest.fixture
def sample_test_suite():
    """Sample test suite data for testing."""
    return {
        "name": "User API Test Suite",
        "description": "Comprehensive tests for user management API",
        "spec_id": 1,
        "tags": ["functional", "user-management"],
        "test_cases": []
    }

@pytest.fixture
def sample_test_run():
    """Sample test run data for testing."""
    return {
        "suite_id": 1,
        "environment": "testing",
        "base_url": "http://test-api.example.com",
        "status": "pending",
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0,
        "execution_time": 0.0,
        "results": []
    }

@pytest.fixture
def auth_headers():
    """Sample authentication headers for testing."""
    return {
        "Authorization": "Bearer test-jwt-token",
        "Content-Type": "application/json"
    }

@pytest.fixture
def mock_jwt_token():
    """Mock JWT token for testing authentication."""
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJyb2xlIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.test"

# Test data cleanup fixtures
@pytest_asyncio.fixture(autouse=True)
async def cleanup_test_data(db_session):
    """Automatically cleanup test data after each test."""
    yield
    # Add cleanup logic here if needed
    await db_session.rollback()

# Performance testing fixtures
@pytest.fixture
def performance_test_config():
    """Configuration for performance tests."""
    return {
        "virtual_users": 10,
        "duration": "30s",
        "ramp_up_time": "10s",
        "thresholds": {
            "http_req_duration": ["p(95)<500"],
            "http_req_failed": ["rate<0.1"]
        }
    }

# Security testing fixtures
@pytest.fixture
def security_test_payloads():
    """Common security test payloads."""
    return {
        "sql_injection": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users --"
        ],
        "xss": [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ],
        "command_injection": [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd"
        ]
    }

# Mock external service responses
@pytest.fixture
def mock_external_api_responses():
    """Mock responses for external API calls."""
    return {
        "success": {
            "status_code": 200,
            "json": {"status": "success", "data": {"id": 1, "name": "test"}}
        },
        "not_found": {
            "status_code": 404,
            "json": {"error": "Not found"}
        },
        "server_error": {
            "status_code": 500,
            "json": {"error": "Internal server error"}
        },
        "timeout": {
            "status_code": 408,
            "json": {"error": "Request timeout"}
        }
    }
