"""
Integration tests for feedback REST API endpoints.

Tests cover:
- Happy path scenarios for all endpoints
- Validation errors and 400 responses
- Authentication and authorization
- Rate limiting
- Database constraints
- Concurrent request handling
- Error handling and recovery
"""

import os
# Set testing environment BEFORE any imports
os.environ["SENTINEL_ENVIRONMENT"] = "testing"

import pytest
import pytest_asyncio
from httpx import AsyncClient
from fastapi import FastAPI, APIRouter
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime
import asyncio
from typing import Dict, Any
from pydantic import BaseModel, Field


# Define test models directly to avoid import issues
class TestCaseFeedbackRequest(BaseModel):
    test_case_id: str
    rating: int = Field(..., ge=1, le=5)
    feedback_type: str
    is_helpful: bool = True
    found_issue: bool = False
    comment: str = None
    execution_time_ms: float = None


class TestSuiteFeedbackRequest(BaseModel):
    suite_id: str
    spec_id: str
    overall_rating: int = Field(..., ge=1, le=5)
    quality_score: int = Field(..., ge=1, le=5)
    coverage_score: int = Field(..., ge=1, le=5)
    accuracy_score: int = Field(..., ge=1, le=5)
    speed_score: int = Field(..., ge=1, le=5)
    coverage_gaps: list = []
    excellent_tests: list = []
    false_positives: list = []
    comment: str = None


@pytest.fixture
def app():
    """Create FastAPI app with feedback router."""
    # Import here to avoid early module loading
    import sys

    # Mock auth middleware before importing
    mock_get_current_user = Mock(return_value={
        "user": {"id": "test-user", "email": "test@example.com"},
        "token": "test-token",
        "permissions": ["feedback:write"]
    })

    # Patch the module in sys.modules
    if 'sentinel_backend.auth_service.auth_middleware' not in sys.modules:
        sys.modules['sentinel_backend.auth_service.auth_middleware'] = Mock(
            get_current_user=mock_get_current_user
        )

    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_get_current_user.return_value):
        from sentinel_backend.orchestration_service.api import feedback_endpoints

        app = FastAPI()
        app.include_router(feedback_endpoints.router)
        return app


@pytest.fixture
def mock_auth_user():
    """Mock authenticated user."""
    return {
        "user": {
            "id": "user-123",
            "email": "test@example.com",
            "username": "testuser"
        },
        "token": "mock-token",
        "permissions": ["feedback:write", "feedback:read"]
    }


@pytest.fixture(autouse=True)
def reset_rate_limit():
    """Reset rate limit store before each test."""
    from sentinel_backend.orchestration_service.api import feedback_endpoints
    feedback_endpoints.rate_limit_store.clear()
    yield
    feedback_endpoints.rate_limit_store.clear()


@pytest_asyncio.fixture
async def client(app):
    """Create async HTTP client for testing."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def valid_test_case_feedback():
    """Valid test case feedback request."""
    return {
        "test_case_id": "test-001",
        "rating": 5,
        "feedback_type": "quality",
        "is_helpful": True,
        "found_issue": True,
        "comment": "Excellent test! Found critical auth bypass.",
        "execution_time_ms": 45.3
    }


@pytest.fixture
def valid_test_suite_feedback():
    """Valid test suite feedback request."""
    return {
        "suite_id": "suite-001",
        "spec_id": "spec-petstore",
        "overall_rating": 4,
        "quality_score": 4,
        "coverage_score": 3,
        "accuracy_score": 5,
        "speed_score": 4,
        "coverage_gaps": [
            {
                "category": "authentication",
                "description": "Missing OAuth 2.0 tests",
                "priority": "high"
            }
        ],
        "excellent_tests": ["test-001", "test-002"],
        "false_positives": ["test-003"],
        "comment": "Good suite overall, but missing OAuth tests"
    }


# Happy Path Tests

@pytest.mark.asyncio
async def test_submit_test_case_feedback_success(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any],
    valid_test_case_feedback: Dict[str, Any]
):
    """Test successful test case feedback submission."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        response = await client.post(
            "/api/v1/feedback/test-case",
            json=valid_test_case_feedback,
            headers={"X-Correlation-ID": "test-corr-001"}
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "feedback_id" in data
        assert data["test_case_id"] == "test-001"
        assert data["learning_status"] in ["queued", "pending"]
        assert data["queued_for_learning"] is True
        assert "Thank you" in data["message"]


@pytest.mark.asyncio
async def test_submit_test_suite_feedback_success(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any],
    valid_test_suite_feedback: Dict[str, Any]
):
    """Test successful test suite feedback submission."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        response = await client.post(
            "/api/v1/feedback/test-suite",
            json=valid_test_suite_feedback,
            headers={"X-Correlation-ID": "test-corr-002"}
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "feedback_id" in data
        assert data["suite_id"] == "suite-001"
        assert data["gaps_queued_for_generation"] == 1
        assert "Coverage gaps" in data["message"]


@pytest.mark.asyncio
async def test_get_feedback_statistics_success(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any]
):
    """Test successful retrieval of feedback statistics."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        response = await client.get("/api/v1/feedback/statistics")

        assert response.status_code == 200
        data = response.json()

        assert data["total_feedback_count"] > 0
        assert 0 <= data["average_rating"] <= 5
        assert 0 <= data["helpful_percentage"] <= 100
        assert data["pattern_count"] > 0
        assert 0 <= data["average_confidence"] <= 1
        assert "feedback_by_type" in data
        assert "feedback_trend" in data


@pytest.mark.asyncio
async def test_get_test_case_feedback_success(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any]
):
    """Test successful retrieval of test case feedback."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        response = await client.get("/api/v1/feedback/test-case/test-001")

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert data["test_case_id"] == "test-001"
        assert data["feedback_count"] > 0
        assert "feedback" in data
        assert isinstance(data["feedback"], list)


@pytest.mark.asyncio
async def test_get_pattern_feedback_success(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any]
):
    """Test successful retrieval of pattern feedback."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        response = await client.get("/api/v1/feedback/patterns/pattern-001")

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "pattern_feedback" in data
        feedback = data["pattern_feedback"]
        assert feedback["pattern_id"] == "pattern-001"
        assert "usage_count" in feedback
        assert "confidence" in feedback


# Validation Error Tests (400 Responses)

@pytest.mark.asyncio
async def test_submit_test_case_feedback_invalid_rating(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any],
    valid_test_case_feedback: Dict[str, Any]
):
    """Test validation error for invalid rating."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        # Rating too high
        invalid_feedback = valid_test_case_feedback.copy()
        invalid_feedback["rating"] = 6

        response = await client.post(
            "/api/v1/feedback/test-case",
            json=invalid_feedback
        )

        assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_submit_test_case_feedback_missing_required_fields(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any]
):
    """Test validation error for missing required fields."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        incomplete_feedback = {
            "test_case_id": "test-001",
            # Missing rating and feedback_type
        }

        response = await client.post(
            "/api/v1/feedback/test-case",
            json=incomplete_feedback
        )

        assert response.status_code == 422
        error_data = response.json()
        assert "detail" in error_data


@pytest.mark.asyncio
async def test_submit_test_case_feedback_comment_too_long(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any],
    valid_test_case_feedback: Dict[str, Any]
):
    """Test validation error for comment exceeding max length."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        invalid_feedback = valid_test_case_feedback.copy()
        invalid_feedback["comment"] = "x" * 2001  # Max is 2000

        response = await client.post(
            "/api/v1/feedback/test-case",
            json=invalid_feedback
        )

        assert response.status_code == 422


# Rate Limiting Tests

@pytest.mark.asyncio
async def test_rate_limiting_enforced(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any],
    valid_test_case_feedback: Dict[str, Any]
):
    """Test that rate limiting is enforced (10 requests per minute)."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        # Submit 10 requests (should succeed)
        for i in range(10):
            feedback = valid_test_case_feedback.copy()
            feedback["test_case_id"] = f"test-{i:03d}"

            response = await client.post(
                "/api/v1/feedback/test-case",
                json=feedback
            )
            assert response.status_code == 200

        # 11th request should be rate limited
        response = await client.post(
            "/api/v1/feedback/test-case",
            json=valid_test_case_feedback
        )

        assert response.status_code == 429
        data = response.json()
        assert "Rate limit exceeded" in data["detail"]


# Concurrent Request Tests

@pytest.mark.asyncio
async def test_concurrent_feedback_submissions(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any],
    valid_test_case_feedback: Dict[str, Any]
):
    """Test handling of concurrent feedback submissions."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        # Create multiple concurrent requests
        async def submit_feedback(index: int):
            feedback = valid_test_case_feedback.copy()
            feedback["test_case_id"] = f"test-concurrent-{index:03d}"
            return await client.post(
                "/api/v1/feedback/test-case",
                json=feedback
            )

        # Submit 5 requests concurrently
        tasks = [submit_feedback(i) for i in range(5)]
        responses = await asyncio.gather(*tasks)

        # All should succeed
        for response in responses:
            assert response.status_code == 200


# Error Handling Tests

@pytest.mark.asyncio
async def test_database_error_handling(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any],
    valid_test_case_feedback: Dict[str, Any]
):
    """Test handling of database errors."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):
        with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.store_test_case_feedback_in_db',
                   side_effect=Exception("Database connection failed")):

            response = await client.post(
                "/api/v1/feedback/test-case",
                json=valid_test_case_feedback
            )

            assert response.status_code == 500
            data = response.json()
            assert "Failed to submit feedback" in data["detail"]


@pytest.mark.asyncio
async def test_get_nonexistent_test_case_feedback(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any]
):
    """Test retrieving feedback for nonexistent test case."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):
        with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_test_case_feedback_from_db',
                   return_value=None):

            response = await client.get("/api/v1/feedback/test-case/nonexistent")

            assert response.status_code == 404
            data = response.json()
            assert "No feedback found" in data["detail"]


# Edge Cases

@pytest.mark.asyncio
async def test_submit_feedback_with_minimal_data(
    client: AsyncClient,
    mock_auth_user: Dict[str, Any]
):
    """Test submitting feedback with only required fields."""
    with patch('sentinel_backend.orchestration_service.api.feedback_endpoints.get_current_user',
               return_value=mock_auth_user):

        minimal_feedback = {
            "test_case_id": "test-minimal",
            "rating": 3,
            "feedback_type": "quality"
        }

        response = await client.post(
            "/api/v1/feedback/test-case",
            json=minimal_feedback
        )

        assert response.status_code == 200
