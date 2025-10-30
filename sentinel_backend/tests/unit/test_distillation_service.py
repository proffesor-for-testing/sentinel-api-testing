"""
Unit tests for DistillationService

Tests pattern extraction, embedding generation, and trajectory distillation.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from uuid import uuid4

from sentinel_backend.reasoningbank.services.distillation_service import DistillationService
from sentinel_backend.reasoningbank.models.task_trajectories import (
    TaskTrajectory,
    TrajectoryOutcome,
)
from sentinel_backend.reasoningbank.models.pattern_embeddings import PatternEmbedding


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_anthropic_client():
    """Mock Anthropic client."""
    client = AsyncMock()
    return client


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client."""
    client = AsyncMock()
    return client


@pytest.fixture
def sample_trajectory():
    """Sample successful trajectory for testing."""
    return TaskTrajectory(
        id=1,
        trajectory_id="traj_test123",
        task_type="test_generation",
        task_description="Generate comprehensive unit tests for UserService",
        context_data={"module": "UserService", "language": "python"},
        agent_type="qe-test-generator",
        actions=[
            {
                "description": "Analyzed API specification",
                "timestamp": "2025-01-15T10:00:00",
                "metadata": {"endpoints": 5},
            },
            {
                "description": "Generated test cases for CRUD operations",
                "timestamp": "2025-01-15T10:01:00",
                "metadata": {"test_count": 15},
            },
            {
                "description": "Added edge case tests",
                "timestamp": "2025-01-15T10:02:00",
                "metadata": {"edge_cases": 8},
            },
        ],
        final_output={
            "tests_generated": 23,
            "coverage": 0.92,
            "frameworks": ["pytest"],
        },
        outcome=TrajectoryOutcome.SUCCESS,
        outcome_confidence=0.95,
        judgment_reasoning="Excellent test coverage with comprehensive edge cases",
        execution_time_ms=2500,
        test_success_rate=0.96,
        coverage_score=0.92,
        distillation_performed=0,
        created_at=datetime.utcnow(),
        judged_at=datetime.utcnow(),
        tenant_id="tenant_123",
    )


@pytest.fixture
def sample_pattern_response():
    """Sample Claude response for pattern extraction."""
    return {
        "patterns": [
            {
                "title": "Comprehensive API Test Generation",
                "description": "Systematic approach to generating complete test suites for RESTful APIs",
                "content": """1. Analyze API specification to identify all endpoints and operations
2. Generate tests for each CRUD operation (Create, Read, Update, Delete)
3. Add boundary value tests for input validation
4. Include authentication and authorization test cases
5. Test error handling and edge cases
6. Validate response schemas and status codes
7. Measure and optimize test coverage""",
                "domain_tags": ["api_testing", "test_generation", "rest_api"],
                "confidence": 0.9,
                "applicability": "Use when generating test suites for RESTful APIs with comprehensive coverage requirements",
            },
            {
                "title": "Edge Case Identification Strategy",
                "description": "Systematic method for identifying and testing edge cases in API endpoints",
                "content": """1. Identify input parameters and their valid ranges
2. Test boundary values (min, max, just inside, just outside)
3. Test null and empty values
4. Test invalid data types
5. Test concurrent operations and race conditions""",
                "domain_tags": ["test_generation", "edge_cases", "quality_assurance"],
                "confidence": 0.85,
                "applicability": "Apply when testing APIs that handle user input or complex data validation",
            },
        ],
        "key_insights": [
            "Starting with CRUD operations provides a solid foundation",
            "Edge cases often reveal critical bugs that normal testing misses",
            "High test coverage correlates with better bug detection",
        ],
        "risk_factors": [
            "Over-testing trivial functionality can waste time",
            "Complex edge cases may be hard to reproduce in production",
        ],
    }


@pytest.fixture
def sample_embedding():
    """Sample embedding vector."""
    return [0.1] * 1536  # 1536-dimensional vector


class TestDistillationService:
    """Test suite for DistillationService."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_db_session):
        """Test service initialization."""
        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        assert service.db == mock_db_session
        assert service.model == "claude-sonnet-4-20250514"
        assert service.temperature == 0.0
        assert service.embedding_model == "text-embedding-3-large"
        assert service.embedding_dimensions == 1536

    @pytest.mark.asyncio
    async def test_extract_principles_success(
        self,
        mock_db_session,
        mock_anthropic_client,
        sample_trajectory,
        sample_pattern_response,
    ):
        """Test successful pattern extraction."""
        # Mock Claude response
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text=str(sample_pattern_response))]
        mock_anthropic_client.messages.create = AsyncMock(return_value=mock_response)

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=mock_anthropic_client,
            openai_client=AsyncMock(),
        )

        # Extract principles
        with patch.object(service, "_parse_patterns", return_value=sample_pattern_response):
            result = await service.extract_principles(sample_trajectory)

        assert "patterns" in result
        assert len(result["patterns"]) == 2
        assert result["patterns"][0]["title"] == "Comprehensive API Test Generation"
        assert "key_insights" in result
        assert "risk_factors" in result

        # Verify Claude was called correctly
        mock_anthropic_client.messages.create.assert_called_once()
        call_args = mock_anthropic_client.messages.create.call_args
        assert call_args.kwargs["model"] == "claude-sonnet-4-20250514"
        assert call_args.kwargs["temperature"] == 0.0

    @pytest.mark.asyncio
    async def test_generate_embedding_success(
        self, mock_db_session, mock_openai_client, sample_embedding
    ):
        """Test successful embedding generation."""
        # Mock OpenAI response
        mock_response = MagicMock()
        mock_response.data = [MagicMock(embedding=sample_embedding)]
        mock_openai_client.embeddings.create = AsyncMock(return_value=mock_response)

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=mock_openai_client,
        )

        # Generate embedding
        text = "Test pattern for embedding generation"
        result = await service.generate_embedding(text)

        assert len(result) == 1536
        assert result == sample_embedding

        # Verify OpenAI was called correctly
        mock_openai_client.embeddings.create.assert_called_once()
        call_args = mock_openai_client.embeddings.create.call_args
        assert call_args.kwargs["model"] == "text-embedding-3-large"
        assert call_args.kwargs["input"] == text
        assert call_args.kwargs["dimensions"] == 1536

    @pytest.mark.asyncio
    async def test_generate_embedding_failure_fallback(
        self, mock_db_session, mock_openai_client
    ):
        """Test embedding generation fallback on error."""
        # Mock OpenAI to raise error
        mock_openai_client.embeddings.create = AsyncMock(
            side_effect=Exception("API Error")
        )

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=mock_openai_client,
        )

        # Generate embedding (should fallback to zero vector)
        result = await service.generate_embedding("test text")

        assert len(result) == 1536
        assert all(x == 0.0 for x in result)

    @pytest.mark.asyncio
    async def test_distill_pattern_success(
        self,
        mock_db_session,
        mock_anthropic_client,
        mock_openai_client,
        sample_trajectory,
        sample_pattern_response,
        sample_embedding,
    ):
        """Test successful pattern distillation."""
        # Mock Claude response
        mock_claude_response = MagicMock()
        mock_claude_response.content = [MagicMock(text=str(sample_pattern_response))]
        mock_anthropic_client.messages.create = AsyncMock(
            return_value=mock_claude_response
        )

        # Mock OpenAI response
        mock_openai_response = MagicMock()
        mock_openai_response.data = [MagicMock(embedding=sample_embedding)]
        mock_openai_client.embeddings.create = AsyncMock(
            return_value=mock_openai_response
        )

        # Mock trajectory service
        mock_trajectory_service = AsyncMock()
        mock_trajectory_service.mark_distilled = AsyncMock()

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=mock_anthropic_client,
            openai_client=mock_openai_client,
        )
        service.trajectory_service = mock_trajectory_service

        # Mock pattern parsing
        with patch.object(service, "_parse_patterns", return_value=sample_pattern_response):
            # Distill patterns
            patterns = await service.distill_pattern(sample_trajectory)

        assert len(patterns) == 2
        assert all(isinstance(p, PatternEmbedding) for p in patterns)
        assert patterns[0].title == "Comprehensive API Test Generation"
        assert patterns[0].confidence == 0.9
        assert patterns[0].source_trajectory_id == "traj_test123"

        # Verify trajectory marked as distilled
        mock_trajectory_service.mark_distilled.assert_called_once()
        call_args = mock_trajectory_service.mark_distilled.call_args
        assert call_args.args[0] == "traj_test123"
        assert len(call_args.args[1]) == 2  # Two pattern IDs

    @pytest.mark.asyncio
    async def test_distill_pattern_unjudged_trajectory(
        self, mock_db_session, sample_trajectory
    ):
        """Test distillation fails for unjudged trajectory."""
        # Set trajectory as unjudged
        sample_trajectory.outcome = TrajectoryOutcome.UNKNOWN

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        # Should raise ValueError
        with pytest.raises(ValueError, match="has not been judged yet"):
            await service.distill_pattern(sample_trajectory)

    @pytest.mark.asyncio
    async def test_distill_pattern_failed_trajectory(
        self, mock_db_session, sample_trajectory
    ):
        """Test distillation skips failed trajectory."""
        # Set trajectory as failed
        sample_trajectory.outcome = TrajectoryOutcome.FAILURE

        mock_trajectory_service = AsyncMock()
        mock_trajectory_service.mark_distilled = AsyncMock()

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )
        service.trajectory_service = mock_trajectory_service

        # Should return empty list
        patterns = await service.distill_pattern(sample_trajectory)

        assert patterns == []
        mock_trajectory_service.mark_distilled.assert_called_once_with("traj_test123", [])

    @pytest.mark.asyncio
    async def test_distill_pattern_already_distilled(
        self, mock_db_session, sample_trajectory
    ):
        """Test distillation skips already distilled trajectory."""
        # Mark as already distilled
        sample_trajectory.distillation_performed = 1

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        # Should return empty list
        patterns = await service.distill_pattern(sample_trajectory)

        assert patterns == []

    @pytest.mark.asyncio
    async def test_batch_distill_trajectories(
        self,
        mock_db_session,
        mock_anthropic_client,
        mock_openai_client,
        sample_pattern_response,
        sample_embedding,
    ):
        """Test batch distillation of multiple trajectories."""
        # Create multiple trajectories
        trajectories = []
        for i in range(3):
            traj = TaskTrajectory(
                id=i + 1,
                trajectory_id=f"traj_test{i}",
                task_type="test_generation",
                task_description=f"Test task {i}",
                context_data={},
                actions=[],
                final_output={},
                outcome=TrajectoryOutcome.SUCCESS,
                outcome_confidence=0.9,
                distillation_performed=0,
            )
            trajectories.append(traj)

        # Mock Claude and OpenAI
        mock_claude_response = MagicMock()
        mock_claude_response.content = [MagicMock(text=str(sample_pattern_response))]
        mock_anthropic_client.messages.create = AsyncMock(
            return_value=mock_claude_response
        )

        mock_openai_response = MagicMock()
        mock_openai_response.data = [MagicMock(embedding=sample_embedding)]
        mock_openai_client.embeddings.create = AsyncMock(
            return_value=mock_openai_response
        )

        mock_trajectory_service = AsyncMock()
        mock_trajectory_service.mark_distilled = AsyncMock()

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=mock_anthropic_client,
            openai_client=mock_openai_client,
        )
        service.trajectory_service = mock_trajectory_service

        # Mock pattern parsing
        with patch.object(service, "_parse_patterns", return_value=sample_pattern_response):
            # Batch distill
            results = await service.batch_distill_trajectories(trajectories)

        assert len(results) == 3
        assert all(len(patterns) == 2 for _, patterns in results)

    def test_validate_pattern_success(self, mock_db_session):
        """Test pattern validation with valid pattern."""
        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        valid_pattern = {
            "title": "Test Pattern",
            "description": "A test pattern",
            "content": """1. First step
2. Second step
3. Third step
4. Fourth step
5. Fifth step""",
            "confidence": 0.85,
        }

        assert service._validate_pattern(valid_pattern) is True

    def test_validate_pattern_missing_fields(self, mock_db_session):
        """Test pattern validation with missing required fields."""
        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        invalid_pattern = {
            "title": "Test Pattern",
            # Missing description and content
        }

        assert service._validate_pattern(invalid_pattern) is False

    def test_validate_pattern_invalid_steps(self, mock_db_session):
        """Test pattern validation with invalid step count."""
        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        # Too few steps
        invalid_pattern = {
            "title": "Test Pattern",
            "description": "A test pattern",
            "content": "1. Only one step",
        }

        assert service._validate_pattern(invalid_pattern) is False

    def test_validate_pattern_invalid_confidence(self, mock_db_session):
        """Test pattern validation with invalid confidence value."""
        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        invalid_pattern = {
            "title": "Test Pattern",
            "description": "A test pattern",
            "content": """1. First step
2. Second step
3. Third step
4. Fourth step""",
            "confidence": 1.5,  # Invalid: > 1.0
        }

        assert service._validate_pattern(invalid_pattern) is False

    def test_format_distillation_prompt(self, mock_db_session, sample_trajectory):
        """Test distillation prompt formatting."""
        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=AsyncMock(),
            openai_client=AsyncMock(),
        )

        prompt = service._format_distillation_prompt(sample_trajectory)

        # Verify key elements in prompt
        assert "test_generation" in prompt
        assert "Generate comprehensive unit tests for UserService" in prompt
        assert "Analyzed API specification" in prompt
        assert "SUCCESS" in prompt.lower()
        assert "0.95" in prompt  # confidence

    @pytest.mark.asyncio
    async def test_distill_undistilled_trajectories(
        self,
        mock_db_session,
        mock_anthropic_client,
        mock_openai_client,
        sample_trajectory,
        sample_pattern_response,
        sample_embedding,
    ):
        """Test automatic distillation of undistilled trajectories."""
        # Mock trajectory service
        mock_trajectory_service = AsyncMock()
        mock_trajectory_service.get_undistilled_trajectories = AsyncMock(
            return_value=[sample_trajectory]
        )
        mock_trajectory_service.mark_distilled = AsyncMock()

        # Mock Claude and OpenAI
        mock_claude_response = MagicMock()
        mock_claude_response.content = [MagicMock(text=str(sample_pattern_response))]
        mock_anthropic_client.messages.create = AsyncMock(
            return_value=mock_claude_response
        )

        mock_openai_response = MagicMock()
        mock_openai_response.data = [MagicMock(embedding=sample_embedding)]
        mock_openai_client.embeddings.create = AsyncMock(
            return_value=mock_openai_response
        )

        service = DistillationService(
            db_session=mock_db_session,
            anthropic_client=mock_anthropic_client,
            openai_client=mock_openai_client,
        )
        service.trajectory_service = mock_trajectory_service

        # Mock pattern parsing
        with patch.object(service, "_parse_patterns", return_value=sample_pattern_response):
            # Run automatic distillation
            summary = await service.distill_undistilled_trajectories(
                task_type="test_generation", limit=10
            )

        assert summary["trajectories_processed"] == 1
        assert summary["patterns_extracted"] == 2
        assert summary["success_count"] == 1
        assert summary["failure_count"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
