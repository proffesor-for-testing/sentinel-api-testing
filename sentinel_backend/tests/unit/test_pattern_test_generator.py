"""
Unit tests for Pattern Test Generator.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch

from sentinel_backend.orchestration_service.services.pattern_recognition_service import (
    PatternRecognitionService,
    Pattern,
    PatternType,
    PatternContext,
    PatternMatch
)
from sentinel_backend.orchestration_service.services.pattern_test_generator import (
    PatternTestGenerator
)


@pytest.fixture
def pattern_service():
    """Create mock pattern service."""
    service = Mock(spec=PatternRecognitionService)
    service.find_matching_patterns = AsyncMock()
    service.generate_test_from_pattern = AsyncMock()
    service.get_pattern_statistics = AsyncMock()
    return service


@pytest.fixture
def pattern_generator(pattern_service):
    """Create pattern test generator."""
    return PatternTestGenerator(pattern_service)


@pytest.fixture
def sample_pattern():
    """Sample pattern for testing."""
    return Pattern(
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
                        {"name": "id", "in": "path", "required": True}
                    ],
                    "responses": {"200": {"description": "Success"}}
                }
            }
        }
    }


class TestPatternBasedGeneration:
    """Test pattern-based test generation."""

    @pytest.mark.asyncio
    async def test_generate_tests_no_patterns(self, pattern_generator, pattern_service, sample_api_spec):
        """Test generation when no patterns match."""
        pattern_service.find_matching_patterns.return_value = []

        tests = await pattern_generator.generate_tests_from_patterns(
            api_spec=sample_api_spec,
            endpoint="/api/v1/users/123",
            method="GET"
        )

        assert tests == []
        pattern_service.find_matching_patterns.assert_called_once()

    @pytest.mark.asyncio
    async def test_generate_tests_with_patterns(self, pattern_generator, pattern_service, sample_pattern, sample_api_spec):
        """Test generation with matching patterns."""
        # Setup mock
        pattern_match = PatternMatch(
            pattern=sample_pattern,
            similarity_score=0.9,
            match_reason="Semantic similarity",
            confidence=0.95
        )

        pattern_service.find_matching_patterns.return_value = [pattern_match]
        pattern_service.generate_test_from_pattern.return_value = {
            "method": "GET",
            "endpoint": "/api/v1/users/123",
            "test_type": "functional-positive",
            "pattern_id": sample_pattern.pattern_id
        }

        tests = await pattern_generator.generate_tests_from_patterns(
            api_spec=sample_api_spec,
            endpoint="/api/v1/users/123",
            method="GET",
            max_patterns=5
        )

        assert len(tests) == 1
        assert tests[0]["method"] == "GET"
        assert tests[0]["endpoint"] == "/api/v1/users/123"
        assert "_pattern_metadata" in tests[0]
        assert tests[0]["_pattern_metadata"]["pattern_id"] == sample_pattern.pattern_id

    @pytest.mark.asyncio
    async def test_generate_tests_max_patterns_limit(self, pattern_generator, pattern_service, sample_pattern, sample_api_spec):
        """Test that max_patterns limit is respected."""
        # Create multiple pattern matches
        matches = [
            PatternMatch(
                pattern=Pattern(
                    pattern_id=f"pattern_{i}",
                    pattern_type=PatternType.API_PATTERN,
                    name=f"Pattern {i}",
                    description="Test pattern",
                    structure={},
                    context=PatternContext()
                ),
                similarity_score=0.9 - (i * 0.1),
                match_reason="Semantic similarity",
                confidence=0.9
            )
            for i in range(10)
        ]

        pattern_service.find_matching_patterns.return_value = matches
        pattern_service.generate_test_from_pattern.return_value = {
            "method": "GET",
            "endpoint": "/api/v1/test"
        }

        tests = await pattern_generator.generate_tests_from_patterns(
            api_spec=sample_api_spec,
            endpoint="/api/v1/test",
            method="GET",
            max_patterns=3
        )

        # Should only use top 3 patterns
        assert len(tests) <= 3


class TestTestSuiteGeneration:
    """Test complete test suite generation."""

    @pytest.mark.asyncio
    async def test_generate_empty_suite(self, pattern_generator, pattern_service):
        """Test suite generation with no endpoints."""
        api_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Empty API"},
            "paths": {}
        }

        suite = await pattern_generator.generate_test_suite_from_patterns(api_spec)

        assert suite["total_endpoints"] == 0
        assert suite["total_tests"] == 0

    @pytest.mark.asyncio
    async def test_generate_full_suite(self, pattern_generator, pattern_service, sample_api_spec):
        """Test suite generation with multiple endpoints."""
        pattern_service.find_matching_patterns.return_value = [
            PatternMatch(
                pattern=Pattern(
                    pattern_id="pattern_1",
                    pattern_type=PatternType.API_PATTERN,
                    name="Test",
                    description="Test",
                    structure={},
                    context=PatternContext()
                ),
                similarity_score=0.9,
                match_reason="Match",
                confidence=0.9
            )
        ]

        pattern_service.generate_test_from_pattern.return_value = {
            "method": "GET",
            "endpoint": "/api/v1/users/123"
        }

        suite = await pattern_generator.generate_test_suite_from_patterns(sample_api_spec)

        assert suite["total_endpoints"] >= 1
        assert suite["total_tests"] >= 1
        assert "endpoints" in suite


class TestHybridGeneration:
    """Test hybrid generation approach."""

    @pytest.mark.asyncio
    async def test_hybrid_uses_patterns_first(self, pattern_generator, pattern_service, sample_api_spec):
        """Test that hybrid generation tries patterns first."""
        pattern_service.find_matching_patterns.return_value = [
            PatternMatch(
                pattern=Pattern(
                    pattern_id="pattern_1",
                    pattern_type=PatternType.API_PATTERN,
                    name="Test",
                    description="Test",
                    structure={},
                    context=PatternContext()
                ),
                similarity_score=0.9,
                match_reason="Match",
                confidence=0.9
            )
        ]

        pattern_service.generate_test_from_pattern.return_value = {
            "method": "GET",
            "endpoint": "/api/v1/test"
        }

        traditional_generator = Mock()
        traditional_generator.generate_tests = AsyncMock()

        tests = await pattern_generator.hybrid_generation(
            api_spec=sample_api_spec,
            endpoint="/api/v1/test",
            method="GET",
            traditional_generator=traditional_generator
        )

        # Should use patterns, not traditional
        assert len(tests) > 0
        assert tests[0]["generation_method"] == "pattern_based"
        traditional_generator.generate_tests.assert_not_called()

    @pytest.mark.asyncio
    async def test_hybrid_falls_back_to_traditional(self, pattern_generator, pattern_service, sample_api_spec):
        """Test fallback to traditional generation."""
        pattern_service.find_matching_patterns.return_value = []

        traditional_generator = Mock()
        traditional_generator.generate_tests = AsyncMock(return_value=[
            {"method": "GET", "endpoint": "/api/v1/test"}
        ])

        tests = await pattern_generator.hybrid_generation(
            api_spec=sample_api_spec,
            endpoint="/api/v1/test",
            method="GET",
            traditional_generator=traditional_generator
        )

        # Should fall back to traditional
        assert len(tests) > 0
        assert tests[0]["generation_method"] == "traditional"
        traditional_generator.generate_tests.assert_called_once()


class TestImprovementSuggestions:
    """Test test improvement suggestions."""

    @pytest.mark.asyncio
    async def test_suggest_improvements_no_patterns(self, pattern_generator, pattern_service, sample_api_spec):
        """Test suggestions when no patterns available."""
        pattern_service.find_matching_patterns.return_value = []

        test_case = {
            "endpoint": "/api/v1/test",
            "method": "GET",
            "assertions": []
        }

        suggestions = await pattern_generator.suggest_test_improvements(
            test_case=test_case,
            api_spec=sample_api_spec
        )

        assert suggestions == []

    @pytest.mark.asyncio
    async def test_suggest_missing_assertions(self, pattern_generator, pattern_service, sample_api_spec):
        """Test suggesting missing assertions."""
        assertion_pattern = Pattern(
            pattern_id="assertion_pattern",
            pattern_type=PatternType.ASSERTION_PATTERN,
            name="Standard Assertions",
            description="Common assertions",
            structure={
                "assertion_types": ["status_code", "response_schema", "response_time"]
            },
            context=PatternContext()
        )

        pattern_service.find_matching_patterns.return_value = [
            PatternMatch(
                pattern=assertion_pattern,
                similarity_score=0.8,
                match_reason="Match",
                confidence=0.85
            )
        ]

        test_case = {
            "endpoint": "/api/v1/test",
            "method": "GET",
            "assertions": [{"type": "status_code"}]
        }

        suggestions = await pattern_generator.suggest_test_improvements(
            test_case=test_case,
            api_spec=sample_api_spec
        )

        # Should suggest adding missing assertions
        assert len(suggestions) > 0
        missing_assertion_suggestions = [
            s for s in suggestions if s["type"] == "missing_assertion"
        ]
        assert len(missing_assertion_suggestions) > 0


class TestDeduplication:
    """Test test deduplication."""

    def test_deduplicate_identical_tests(self, pattern_generator):
        """Test deduplication of identical tests."""
        tests = [
            {
                "endpoint": "/api/v1/test",
                "method": "GET",
                "query_params": {"limit": 10},
                "body": {},
                "expected_status": 200
            },
            {
                "endpoint": "/api/v1/test",
                "method": "GET",
                "query_params": {"limit": 10},
                "body": {},
                "expected_status": 200
            }
        ]

        unique = pattern_generator._deduplicate_tests(tests)

        assert len(unique) == 1

    def test_deduplicate_different_tests(self, pattern_generator):
        """Test that different tests are not deduplicated."""
        tests = [
            {
                "endpoint": "/api/v1/test",
                "method": "GET",
                "query_params": {"limit": 10},
                "body": {},
                "expected_status": 200
            },
            {
                "endpoint": "/api/v1/test",
                "method": "GET",
                "query_params": {"limit": 20},  # Different param
                "body": {},
                "expected_status": 200
            }
        ]

        unique = pattern_generator._deduplicate_tests(tests)

        assert len(unique) == 2


class TestStatistics:
    """Test generation statistics."""

    @pytest.mark.asyncio
    async def test_get_generation_statistics(self, pattern_generator, pattern_service):
        """Test getting generation statistics."""
        # Add some cached tests
        pattern_generator.generated_tests_cache = {
            "GET_/api/v1/users": [{"test": 1}, {"test": 2}],
            "POST_/api/v1/users": [{"test": 3}]
        }

        pattern_service.get_pattern_statistics.return_value = {
            "total_patterns": 5,
            "average_confidence": 0.85
        }

        stats = await pattern_generator.get_generation_statistics()

        assert stats["total_tests_generated"] == 3
        assert stats["cached_endpoints"] == 2
        assert "pattern_statistics" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
