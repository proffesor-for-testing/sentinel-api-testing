"""
Unit tests for Pattern Recognition Service.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch

from sentinel_backend.orchestration_service.services.pattern_recognition_service import (
    PatternRecognitionService,
    Pattern,
    PatternType,
    PatternContext,
    PatternMatch
)


@pytest.fixture
def pattern_service():
    """Create pattern recognition service instance."""
    return PatternRecognitionService(vector_db_client=None, reasoning_bank_client=None)


@pytest.fixture
def sample_test_case():
    """Sample test case for pattern extraction."""
    return {
        "endpoint": "/api/v1/users/123",
        "method": "GET",
        "test_type": "functional-positive",
        "query_params": {"limit": 10, "offset": 0},
        "expected_status": 200,
        "assertions": [
            {"type": "status_code", "expected": 200},
            {"type": "response_schema", "validate": True}
        ],
        "tags": ["functional", "positive"]
    }


@pytest.fixture
def sample_api_spec():
    """Sample API specification."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/api/v1/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def sample_execution_result():
    """Sample execution result."""
    return {
        "status": "success",
        "status_code": 200,
        "execution_time": 150.5
    }


class TestPatternExtraction:
    """Test pattern extraction from test cases."""

    @pytest.mark.asyncio
    async def test_extract_api_patterns(self, pattern_service, sample_test_case, sample_api_spec, sample_execution_result):
        """Test extracting API structure patterns."""
        patterns = await pattern_service.extract_pattern_from_test(
            test_case=sample_test_case,
            execution_result=sample_execution_result,
            api_spec=sample_api_spec
        )

        assert len(patterns) > 0

        # Find API pattern
        api_patterns = [p for p in patterns if p.pattern_type == PatternType.API_PATTERN]
        assert len(api_patterns) > 0

        api_pattern = api_patterns[0]
        assert api_pattern.structure["method"] == "GET"
        assert "{id}" in api_pattern.structure["path_pattern"]

    @pytest.mark.asyncio
    async def test_extract_parameter_patterns(self, pattern_service, sample_test_case, sample_api_spec, sample_execution_result):
        """Test extracting parameter patterns."""
        patterns = await pattern_service.extract_pattern_from_test(
            test_case=sample_test_case,
            execution_result=sample_execution_result,
            api_spec=sample_api_spec
        )

        param_patterns = [p for p in patterns if p.pattern_type == PatternType.PARAMETER_PATTERN]
        assert len(param_patterns) > 0

        param_pattern = param_patterns[0]
        assert "param_names" in param_pattern.structure
        assert "limit" in param_pattern.structure["param_names"]

    @pytest.mark.asyncio
    async def test_extract_assertion_patterns(self, pattern_service, sample_test_case, sample_api_spec, sample_execution_result):
        """Test extracting assertion patterns."""
        patterns = await pattern_service.extract_pattern_from_test(
            test_case=sample_test_case,
            execution_result=sample_execution_result,
            api_spec=sample_api_spec
        )

        assertion_patterns = [p for p in patterns if p.pattern_type == PatternType.ASSERTION_PATTERN]
        assert len(assertion_patterns) > 0

        assertion_pattern = assertion_patterns[0]
        assert assertion_pattern.structure["expected_status"] == 200
        assert assertion_pattern.structure["has_schema_validation"] is True

    @pytest.mark.asyncio
    async def test_extract_error_patterns(self, pattern_service, sample_test_case, sample_api_spec):
        """Test extracting error patterns from failed tests."""
        failed_result = {
            "status": "failed",
            "status_code": 404,
            "error_type": "NotFound",
            "error_message": "User not found"
        }

        patterns = await pattern_service.extract_pattern_from_test(
            test_case=sample_test_case,
            execution_result=failed_result,
            api_spec=sample_api_spec
        )

        error_patterns = [p for p in patterns if p.pattern_type == PatternType.ERROR_PATTERN]
        assert len(error_patterns) > 0

        error_pattern = error_patterns[0]
        assert error_pattern.structure["error_type"] == "NotFound"
        assert error_pattern.structure["status_code"] == 404


class TestPatternMatching:
    """Test pattern matching functionality."""

    @pytest.mark.asyncio
    async def test_find_matching_patterns_empty(self, pattern_service, sample_api_spec):
        """Test finding patterns when none exist."""
        matches = await pattern_service.find_matching_patterns(
            api_spec=sample_api_spec,
            endpoint="/api/v1/users/123",
            method="GET"
        )

        assert isinstance(matches, list)
        # Should return empty list when no patterns exist
        assert len(matches) == 0

    @pytest.mark.asyncio
    async def test_find_matching_patterns_with_patterns(self, pattern_service, sample_api_spec):
        """Test finding patterns when patterns exist."""
        # Add a pattern
        pattern = Pattern(
            pattern_id="test_pattern_1",
            pattern_type=PatternType.API_PATTERN,
            name="GET /api/v1/users/{id}",
            description="Get user by ID pattern",
            structure={
                "method": "GET",
                "path_pattern": "/api/v1/users/{id}",
                "resource_type": "users"
            },
            context=PatternContext(
                endpoint="/api/v1/users/{id}",
                method="GET"
            ),
            confidence=0.95
        )

        pattern_service.patterns[pattern.pattern_id] = pattern

        matches = await pattern_service.find_matching_patterns(
            api_spec=sample_api_spec,
            endpoint="/api/v1/users/123",
            method="GET",
            similarity_threshold=0.5
        )

        assert len(matches) > 0

    def test_normalize_path(self, pattern_service):
        """Test path normalization."""
        # Test numeric ID replacement
        assert pattern_service._normalize_path("/api/v1/users/123") == "/api/v1/users/{id}"
        assert pattern_service._normalize_path("/api/v1/posts/456/comments/789") == "/api/v1/posts/{id}/comments/{id}"

        # Test UUID replacement
        uuid_path = "/api/v1/users/550e8400-e29b-41d4-a716-446655440000"
        assert pattern_service._normalize_path(uuid_path) == "/api/v1/users/{id}"

    def test_identify_resource_type(self, pattern_service):
        """Test resource type identification."""
        assert pattern_service._identify_resource_type("/api/v1/users") == "users"
        assert pattern_service._identify_resource_type("/api/v1/users/{id}") == "users"
        assert pattern_service._identify_resource_type("/api/v1/posts/{id}/comments") == "comments"


class TestPatternGeneration:
    """Test test generation from patterns."""

    @pytest.mark.asyncio
    async def test_generate_test_from_pattern(self, pattern_service, sample_api_spec):
        """Test generating test from a pattern."""
        pattern = Pattern(
            pattern_id="test_pattern_1",
            pattern_type=PatternType.API_PATTERN,
            name="GET /api/v1/users/{id}",
            description="Get user by ID pattern",
            structure={
                "method": "GET",
                "path_pattern": "/api/v1/users/{id}",
                "resource_type": "users"
            },
            context=PatternContext(
                endpoint="/api/v1/users/{id}",
                method="GET",
                test_type="functional-positive"
            ),
            confidence=0.95
        )

        test = await pattern_service.generate_test_from_pattern(
            pattern=pattern,
            api_spec=sample_api_spec,
            endpoint="/api/v1/users/123",
            method="GET"
        )

        assert test is not None
        assert test["method"] == "GET"
        assert test["endpoint"] == "/api/v1/users/123"
        assert test["pattern_id"] == pattern.pattern_id


class TestPatternFeedback:
    """Test pattern feedback and learning."""

    @pytest.mark.asyncio
    async def test_update_pattern_success(self, pattern_service):
        """Test updating pattern with success feedback."""
        pattern = Pattern(
            pattern_id="test_pattern_1",
            pattern_type=PatternType.API_PATTERN,
            name="Test Pattern",
            description="Test pattern description",
            structure={},
            context=PatternContext(),
            confidence=0.5,
            usage_count=0,
            success_count=0
        )

        pattern_service.patterns[pattern.pattern_id] = pattern

        # Update with success
        await pattern_service.update_pattern_feedback(
            pattern_id=pattern.pattern_id,
            success=True
        )

        updated_pattern = pattern_service.patterns[pattern.pattern_id]
        assert updated_pattern.usage_count == 1
        assert updated_pattern.success_count == 1
        assert updated_pattern.confidence > 0.5  # Should increase

    @pytest.mark.asyncio
    async def test_update_pattern_failure(self, pattern_service):
        """Test updating pattern with failure feedback."""
        pattern = Pattern(
            pattern_id="test_pattern_1",
            pattern_type=PatternType.API_PATTERN,
            name="Test Pattern",
            description="Test pattern description",
            structure={},
            context=PatternContext(),
            confidence=0.8,
            usage_count=0,
            success_count=0,
            failure_count=0
        )

        pattern_service.patterns[pattern.pattern_id] = pattern

        # Update with failure
        await pattern_service.update_pattern_feedback(
            pattern_id=pattern.pattern_id,
            success=False
        )

        updated_pattern = pattern_service.patterns[pattern.pattern_id]
        assert updated_pattern.usage_count == 1
        assert updated_pattern.failure_count == 1


class TestPatternStatistics:
    """Test pattern statistics."""

    @pytest.mark.asyncio
    async def test_get_pattern_statistics_empty(self, pattern_service):
        """Test statistics with no patterns."""
        stats = await pattern_service.get_pattern_statistics()

        assert stats["total_patterns"] == 0
        assert stats["average_confidence"] == 0

    @pytest.mark.asyncio
    async def test_get_pattern_statistics_with_patterns(self, pattern_service):
        """Test statistics with patterns."""
        # Add test patterns
        for i in range(3):
            pattern = Pattern(
                pattern_id=f"test_pattern_{i}",
                pattern_type=PatternType.API_PATTERN,
                name=f"Test Pattern {i}",
                description="Test pattern",
                structure={},
                context=PatternContext(),
                confidence=0.8 + (i * 0.05),
                usage_count=10 + i,
                success_count=8 + i
            )
            pattern_service.patterns[pattern.pattern_id] = pattern

        stats = await pattern_service.get_pattern_statistics()

        assert stats["total_patterns"] == 3
        assert stats["total_usage"] == 33  # 10 + 11 + 12
        assert stats["total_success"] == 27  # 8 + 9 + 10
        assert stats["average_confidence"] > 0.8


class TestPatternEmbedding:
    """Test pattern embedding generation."""

    @pytest.mark.asyncio
    async def test_generate_pattern_embedding(self, pattern_service):
        """Test embedding generation for patterns."""
        pattern = Pattern(
            pattern_id="test_pattern_1",
            pattern_type=PatternType.API_PATTERN,
            name="Test Pattern",
            description="Test pattern description",
            structure={"method": "GET", "path": "/api/v1/users"},
            context=PatternContext()
        )

        embedding = await pattern_service._generate_pattern_embedding(pattern)

        assert embedding is not None
        assert isinstance(embedding, list)
        assert len(embedding) > 0

    @pytest.mark.asyncio
    async def test_generate_embedding_fallback(self, pattern_service):
        """Test embedding generation with fallback."""
        text = "test pattern text"
        embedding = await pattern_service._generate_embedding(text)

        assert embedding is not None
        assert isinstance(embedding, list)
        assert len(embedding) == 128  # Fallback creates 128-dim vector

    def test_calculate_similarity(self, pattern_service):
        """Test similarity calculation between embeddings."""
        embedding1 = [1.0, 0.0, 0.5, 0.3]
        embedding2 = [0.9, 0.1, 0.6, 0.2]

        similarity = pattern_service._calculate_similarity(embedding1, embedding2)

        assert 0.0 <= similarity <= 1.0
        assert similarity > 0.8  # Should be high similarity

    def test_calculate_similarity_zero(self, pattern_service):
        """Test similarity with zero vectors."""
        embedding1 = [0.0, 0.0, 0.0, 0.0]
        embedding2 = [1.0, 1.0, 1.0, 1.0]

        similarity = pattern_service._calculate_similarity(embedding1, embedding2)

        assert similarity == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
