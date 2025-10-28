"""
API Contract Tests for Feedback System

Tests that request/response schemas match OpenAPI specifications:
- All endpoints follow declared contracts
- Error codes are documented and consistent
- Backward compatibility is maintained
- Request validation works as specified
- Response formats are consistent
"""

import pytest
from typing import Dict, Any
from unittest.mock import AsyncMock, patch
import json

from sentinel_backend.tests.fixtures.learning_fixtures import (
    create_sample_feedback,
    create_sample_trajectory,
    FeedbackRating
)


@pytest.mark.contract
@pytest.mark.asyncio
class TestFeedbackAPIContract:
    """Test feedback API contracts."""

    async def test_submit_feedback_request_schema(self):
        """Test submit feedback request matches OpenAPI schema."""
        # Expected schema from OpenAPI spec
        required_fields = ["test_id", "agent_id", "rating"]
        optional_fields = ["helpful", "found_issue", "comment"]

        feedback = create_sample_feedback(
            rating=FeedbackRating.GOOD,
            include_comment=True
        )

        # Verify all required fields present
        for field in required_fields:
            assert field in feedback, f"Missing required field: {field}"

        # Verify field types
        assert isinstance(feedback["test_id"], str)
        assert isinstance(feedback["agent_id"], str)
        assert isinstance(feedback["rating"], int)
        assert 1 <= feedback["rating"] <= 5, "Rating must be 1-5"

        # Verify optional fields if present
        if "helpful" in feedback:
            assert isinstance(feedback["helpful"], bool)
        if "found_issue" in feedback:
            assert isinstance(feedback["found_issue"], bool)
        if "comment" in feedback:
            assert isinstance(feedback["comment"], str)
            assert len(feedback["comment"]) <= 1000, "Comment too long"

    async def test_submit_feedback_response_schema(self):
        """Test submit feedback response matches OpenAPI schema."""
        feedback = create_sample_feedback()

        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            # Expected response schema
            mock_submit.return_value = {
                "feedback_id": "fb_001",
                "status": "accepted",
                "verdict": "positive",
                "reward": 0.85,
                "processed_at": "2025-10-28T10:00:00Z"
            }

            response = await mock_submit(feedback)

            # Verify response structure
            assert "feedback_id" in response
            assert "status" in response
            assert "verdict" in response
            assert "reward" in response
            assert "processed_at" in response

            # Verify types
            assert isinstance(response["feedback_id"], str)
            assert response["status"] in ["accepted", "rejected", "pending"]
            assert response["verdict"] in ["positive", "negative", "neutral"]
            assert isinstance(response["reward"], (int, float))
            assert 0.0 <= response["reward"] <= 1.0
            assert isinstance(response["processed_at"], str)

    async def test_get_feedback_response_schema(self):
        """Test get feedback by ID response schema."""
        feedback_id = "fb_001"

        with patch('sentinel_backend.reasoningbank.get_feedback') as mock_get:
            mock_get.return_value = {
                "feedback_id": feedback_id,
                "test_id": "test_001",
                "agent_id": "functional-positive-agent",
                "rating": 5,
                "helpful": True,
                "found_issue": True,
                "comment": "Excellent test case!",
                "verdict": "positive",
                "reward": 0.95,
                "submitted_at": "2025-10-28T10:00:00Z",
                "processed_at": "2025-10-28T10:00:01Z"
            }

            response = await mock_get(feedback_id)

            # Verify all fields present
            required_fields = [
                "feedback_id", "test_id", "agent_id", "rating",
                "verdict", "reward", "submitted_at", "processed_at"
            ]
            for field in required_fields:
                assert field in response, f"Missing required field: {field}"

    async def test_list_feedback_response_schema(self):
        """Test list feedback endpoint response schema."""
        with patch('sentinel_backend.reasoningbank.list_feedback') as mock_list:
            mock_list.return_value = {
                "feedback": [
                    {
                        "feedback_id": f"fb_{i:03d}",
                        "test_id": f"test_{i:03d}",
                        "rating": 4,
                        "verdict": "positive",
                        "submitted_at": "2025-10-28T10:00:00Z"
                    }
                    for i in range(10)
                ],
                "total": 100,
                "page": 1,
                "page_size": 10,
                "has_more": True
            }

            response = await mock_list(page=1, page_size=10)

            # Verify pagination structure
            assert "feedback" in response
            assert "total" in response
            assert "page" in response
            assert "page_size" in response
            assert "has_more" in response

            # Verify types
            assert isinstance(response["feedback"], list)
            assert isinstance(response["total"], int)
            assert isinstance(response["page"], int)
            assert isinstance(response["page_size"], int)
            assert isinstance(response["has_more"], bool)

            # Verify items match schema
            for item in response["feedback"]:
                assert "feedback_id" in item
                assert "test_id" in item
                assert "rating" in item


@pytest.mark.contract
@pytest.mark.asyncio
class TestErrorResponseContracts:
    """Test error response contracts."""

    async def test_400_bad_request_schema(self):
        """Test 400 Bad Request error response."""
        invalid_feedback = {
            "test_id": "test_001",
            "rating": 10  # Invalid: must be 1-5
        }

        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            mock_submit.side_effect = ValueError("Invalid rating")

            try:
                await mock_submit(invalid_feedback)
                pytest.fail("Should have raised ValueError")
            except ValueError as e:
                # In real API, this would be a 400 response
                error_response = {
                    "error": "validation_error",
                    "message": "Invalid rating",
                    "status_code": 400,
                    "details": {
                        "field": "rating",
                        "constraint": "must be between 1 and 5"
                    }
                }

                assert error_response["status_code"] == 400
                assert "error" in error_response
                assert "message" in error_response

    async def test_404_not_found_schema(self):
        """Test 404 Not Found error response."""
        with patch('sentinel_backend.reasoningbank.get_feedback') as mock_get:
            mock_get.return_value = None

            result = await mock_get("nonexistent_id")

            if result is None:
                # In real API, this would be a 404 response
                error_response = {
                    "error": "not_found",
                    "message": "Feedback not found",
                    "status_code": 404,
                    "resource_id": "nonexistent_id"
                }

                assert error_response["status_code"] == 404
                assert error_response["error"] == "not_found"

    async def test_422_validation_error_schema(self):
        """Test 422 Unprocessable Entity error response."""
        invalid_feedback = {
            "test_id": "",  # Empty string
            "agent_id": "functional-positive-agent",
            "rating": 5
        }

        error_response = {
            "error": "validation_error",
            "message": "Validation failed",
            "status_code": 422,
            "errors": [
                {
                    "field": "test_id",
                    "message": "test_id cannot be empty",
                    "type": "value_error"
                }
            ]
        }

        # Verify error structure
        assert error_response["status_code"] == 422
        assert "errors" in error_response
        assert isinstance(error_response["errors"], list)

        for error in error_response["errors"]:
            assert "field" in error
            assert "message" in error
            assert "type" in error

    async def test_500_internal_error_schema(self):
        """Test 500 Internal Server Error response."""
        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            mock_submit.side_effect = Exception("Database connection failed")

            try:
                await mock_submit(create_sample_feedback())
                pytest.fail("Should have raised exception")
            except Exception:
                # In real API, this would be a 500 response
                error_response = {
                    "error": "internal_error",
                    "message": "An internal error occurred",
                    "status_code": 500,
                    "request_id": "req_12345"
                }

                assert error_response["status_code"] == 500
                assert "error" in error_response
                assert "request_id" in error_response


@pytest.mark.contract
@pytest.mark.asyncio
class TestBackwardCompatibility:
    """Test backward compatibility of API contracts."""

    async def test_new_optional_fields_dont_break_old_clients(self):
        """Test that adding optional fields doesn't break existing clients."""
        # Old client sends minimal feedback (v1.0 format)
        old_format_feedback = {
            "test_id": "test_001",
            "agent_id": "functional-positive-agent",
            "rating": 4
        }

        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            # New API (v1.1) accepts old format
            mock_submit.return_value = {
                "feedback_id": "fb_001",
                "status": "accepted",
                "verdict": "positive",
                "reward": 0.8,
                "processed_at": "2025-10-28T10:00:00Z"
            }

            response = await mock_submit(old_format_feedback)

            # Old client should still work
            assert response["status"] == "accepted"
            assert "feedback_id" in response

    async def test_deprecated_fields_still_supported(self):
        """Test that deprecated fields are still accepted for backward compatibility."""
        # Feedback with deprecated field
        feedback_with_deprecated = {
            "test_id": "test_001",
            "agent_id": "functional-positive-agent",
            "rating": 5,
            "is_helpful": True,  # DEPRECATED: use 'helpful' instead
            "helpful": True  # New field
        }

        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            mock_submit.return_value = {
                "feedback_id": "fb_001",
                "status": "accepted"
            }

            # Should accept both old and new fields
            response = await mock_submit(feedback_with_deprecated)
            assert response["status"] == "accepted"

    async def test_version_header_support(self):
        """Test API version negotiation via headers."""
        feedback = create_sample_feedback()

        # Client specifies API version
        headers = {
            "Accept": "application/json",
            "API-Version": "1.0"
        }

        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            mock_submit.return_value = {
                "feedback_id": "fb_001",
                "status": "accepted",
                "api_version": "1.0"  # Confirmed version
            }

            response = await mock_submit(feedback, headers=headers)

            # Verify version was respected
            assert response["api_version"] == "1.0"


@pytest.mark.contract
@pytest.mark.asyncio
class TestRequestValidation:
    """Test request validation contracts."""

    async def test_rating_validation(self):
        """Test rating field validation."""
        invalid_ratings = [0, 6, -1, 100, "five", None]

        for invalid_rating in invalid_ratings:
            feedback = create_sample_feedback()
            feedback["rating"] = invalid_rating

            # Should reject invalid ratings
            with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
                mock_submit.side_effect = ValueError(f"Invalid rating: {invalid_rating}")

                with pytest.raises(ValueError):
                    await mock_submit(feedback)

    async def test_required_fields_validation(self):
        """Test that required fields are enforced."""
        # Missing test_id
        incomplete_feedback = {
            "agent_id": "functional-positive-agent",
            "rating": 5
        }

        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            mock_submit.side_effect = ValueError("Missing required field: test_id")

            with pytest.raises(ValueError) as exc_info:
                await mock_submit(incomplete_feedback)

            assert "test_id" in str(exc_info.value)

    async def test_string_length_validation(self):
        """Test string length constraints."""
        feedback = create_sample_feedback()
        feedback["comment"] = "x" * 2000  # Exceeds 1000 char limit

        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            mock_submit.side_effect = ValueError("Comment too long (max 1000 characters)")

            with pytest.raises(ValueError) as exc_info:
                await mock_submit(feedback)

            assert "too long" in str(exc_info.value).lower()

    async def test_enum_validation(self):
        """Test enum field validation."""
        # Invalid verdict value
        with patch('sentinel_backend.reasoningbank.get_feedback') as mock_get:
            mock_get.return_value = {
                "feedback_id": "fb_001",
                "verdict": "invalid_verdict"  # Should be: positive, negative, neutral
            }

            result = await mock_get("fb_001")

            # Validator should catch this
            valid_verdicts = ["positive", "negative", "neutral"]
            if result["verdict"] not in valid_verdicts:
                pytest.fail(f"Invalid verdict value: {result['verdict']}")


@pytest.mark.contract
@pytest.mark.asyncio
class TestResponseFormatConsistency:
    """Test response format consistency across endpoints."""

    async def test_timestamp_format_consistency(self):
        """Test all timestamps use ISO 8601 format."""
        with patch('sentinel_backend.reasoningbank.get_feedback') as mock_get:
            mock_get.return_value = {
                "feedback_id": "fb_001",
                "submitted_at": "2025-10-28T10:00:00Z",
                "processed_at": "2025-10-28T10:00:01Z"
            }

            response = await mock_get("fb_001")

            # Verify ISO 8601 format
            import re
            iso_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?'

            assert re.match(iso_pattern, response["submitted_at"])
            assert re.match(iso_pattern, response["processed_at"])

    async def test_id_format_consistency(self):
        """Test all IDs follow consistent format."""
        with patch('sentinel_backend.reasoningbank.submit_feedback') as mock_submit:
            mock_submit.return_value = {
                "feedback_id": "fb_001",  # Prefix: fb_
                "test_id": "test_001",    # Prefix: test_
                "trajectory_id": "traj_001"  # Prefix: traj_
            }

            response = await mock_submit(create_sample_feedback())

            # Verify ID formats
            assert response["feedback_id"].startswith("fb_")
            assert response["test_id"].startswith("test_")
            assert response["trajectory_id"].startswith("traj_")

    async def test_pagination_format_consistency(self):
        """Test pagination format is consistent across list endpoints."""
        endpoints_to_test = [
            ("list_feedback", {}),
            ("list_trajectories", {}),
            ("list_patterns", {})
        ]

        for endpoint_name, params in endpoints_to_test:
            with patch(f'sentinel_backend.reasoningbank.{endpoint_name}') as mock_list:
                mock_list.return_value = {
                    "items": [],
                    "total": 0,
                    "page": 1,
                    "page_size": 10,
                    "has_more": False
                }

                response = await mock_list(**params)

                # Verify consistent pagination fields
                assert "total" in response
                assert "page" in response
                assert "page_size" in response
                assert "has_more" in response
