"""
Unit Tests for ReasoningBankService

Tests the main orchestrator for the ReasoningBank learning system.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_backend.reasoningbank.services.reasoningbank_service import (
    ReasoningBankService,
)
from sentinel_backend.reasoningbank.services.trajectory_service import TrajectoryService
from sentinel_backend.reasoningbank.services.judgment_service import JudgmentService
from sentinel_backend.reasoningbank.models.task_trajectories import (
    TaskTrajectory,
    TrajectoryOutcome,
)
from sentinel_backend.reasoningbank.models.pattern_embeddings import PatternEmbedding


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    return session


@pytest.fixture
def mock_judgment_service():
    """Mock judgment service."""
    service = AsyncMock(spec=JudgmentService)
    service.judge_trajectory = AsyncMock(
        return_value=(
            TrajectoryOutcome.SUCCESS,
            0.95,
            "High-quality test generation with comprehensive coverage",
            {"quality_score": 0.92, "key_issues": []},
        )
    )
    return service


@pytest.fixture
def sample_trajectory():
    """Sample trajectory for testing."""
    return TaskTrajectory(
        id=1,
        trajectory_id="traj_test123",
        task_type="test_generation",
        task_description="Generate unit tests for UserService",
        context_data={"api_spec": "openapi.json", "module": "UserService"},
        agent_type="qe-test-generator",
        actions=[
            {"description": "Analyzing API specification", "timestamp": "2025-01-01T10:00:00"},
            {"description": "Generating test cases", "timestamp": "2025-01-01T10:00:05"},
        ],
        final_output={"test_count": 15, "coverage": 0.92},
        outcome=TrajectoryOutcome.UNKNOWN,
        outcome_confidence=0.0,
        execution_time_ms=5000,
        token_count=2500,
        test_success_rate=0.95,
        coverage_score=0.92,
        created_at=datetime.utcnow(),
        tenant_id="tenant_123",
    )


@pytest.fixture
def sample_pattern():
    """Sample pattern embedding for testing."""
    return PatternEmbedding(
        id=1,
        pattern_id="pattern_test123",
        title="Security Test Best Practice",
        description="Pattern for generating comprehensive security tests",
        content="1. Analyze auth endpoints\n2. Test BOLA vulnerabilities\n3. Verify token handling",
        embedding=[0.1] * 1536,  # Mock embedding vector
        confidence=0.85,
        usage_count=50,
        success_count=45,
        failure_count=5,
        domain_tags=["security", "authentication"],
        source_trajectory_id="traj_abc123",
        created_at=datetime.utcnow(),
        last_used_at=datetime.utcnow(),
        tenant_id="tenant_123",
    )


class TestReasoningBankServiceInit:
    """Test ReasoningBankService initialization."""

    def test_init_with_all_services(self, mock_db_session, mock_judgment_service):
        """Test initialization with all services configured."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
            enable_background_consolidation=True,
            consolidation_interval_hours=24,
        )

        assert rb.db == mock_db_session
        assert rb.judgment_service == mock_judgment_service
        assert rb.enable_background_consolidation is True
        assert rb.consolidation_interval_hours == 24
        assert isinstance(rb.trajectory_service, TrajectoryService)

    def test_init_without_judgment_service(self, mock_db_session):
        """Test initialization without judgment service."""
        rb = ReasoningBankService(db_session=mock_db_session)

        assert rb.db == mock_db_session
        assert rb.judgment_service is None
        assert rb.enable_background_consolidation is True

    def test_init_without_background_consolidation(self, mock_db_session):
        """Test initialization with consolidation disabled."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            enable_background_consolidation=False,
        )

        assert rb.enable_background_consolidation is False


class TestProcessTrajectoryForLearning:
    """Test process_trajectory_for_learning method."""

    @pytest.mark.asyncio
    async def test_process_trajectory_with_judgment(
        self, mock_db_session, mock_judgment_service, sample_trajectory
    ):
        """Test processing trajectory that needs judgment."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        # Mock trajectory service
        rb.trajectory_service.get_trajectory = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.update_judgment = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.mark_distilled = AsyncMock(return_value=sample_trajectory)

        result = await rb.process_trajectory_for_learning(
            trajectory_id="traj_test123",
            force_judgment=False,
            auto_distill=True,
        )

        assert result["trajectory_id"] == "traj_test123"
        assert result["judgment_performed"] is True
        assert result["outcome"] == "success"
        assert result["confidence"] == 0.95
        assert "processing_time_ms" in result

        # Verify judgment service was called
        mock_judgment_service.judge_trajectory.assert_called_once()
        rb.trajectory_service.update_judgment.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_trajectory_already_judged(
        self, mock_db_session, mock_judgment_service, sample_trajectory
    ):
        """Test processing trajectory that's already judged."""
        sample_trajectory.outcome = TrajectoryOutcome.SUCCESS
        sample_trajectory.outcome_confidence = 0.95

        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        rb.trajectory_service.get_trajectory = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.mark_distilled = AsyncMock(return_value=sample_trajectory)

        result = await rb.process_trajectory_for_learning(
            trajectory_id="traj_test123",
            force_judgment=False,
        )

        # Should skip judgment since already judged
        assert result["judgment_performed"] is False
        mock_judgment_service.judge_trajectory.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_trajectory_force_rejudgment(
        self, mock_db_session, mock_judgment_service, sample_trajectory
    ):
        """Test forcing re-judgment of already judged trajectory."""
        sample_trajectory.outcome = TrajectoryOutcome.SUCCESS
        sample_trajectory.outcome_confidence = 0.95

        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        rb.trajectory_service.get_trajectory = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.update_judgment = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.mark_distilled = AsyncMock(return_value=sample_trajectory)

        result = await rb.process_trajectory_for_learning(
            trajectory_id="traj_test123",
            force_judgment=True,  # Force re-judgment
        )

        # Should perform judgment even though already judged
        assert result["judgment_performed"] is True
        mock_judgment_service.judge_trajectory.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_trajectory_not_found(
        self, mock_db_session, mock_judgment_service
    ):
        """Test processing non-existent trajectory."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        rb.trajectory_service.get_trajectory = AsyncMock(return_value=None)

        with pytest.raises(ValueError, match="Trajectory not found"):
            await rb.process_trajectory_for_learning(trajectory_id="nonexistent")

    @pytest.mark.asyncio
    async def test_process_trajectory_without_judgment_service(
        self, mock_db_session, sample_trajectory
    ):
        """Test processing without judgment service configured."""
        rb = ReasoningBankService(db_session=mock_db_session)  # No judgment service

        rb.trajectory_service.get_trajectory = AsyncMock(return_value=sample_trajectory)

        result = await rb.process_trajectory_for_learning(
            trajectory_id="traj_test123"
        )

        # Should not perform judgment
        assert result["judgment_performed"] is False
        assert result["outcome"] == "unknown"  # Original outcome


class TestBatchProcessing:
    """Test batch_process_trajectories method."""

    @pytest.mark.asyncio
    async def test_batch_process_specific_trajectories(
        self, mock_db_session, mock_judgment_service, sample_trajectory
    ):
        """Test batch processing with specific trajectory IDs."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        # Mock trajectory retrieval
        rb.trajectory_service.get_trajectory = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.update_judgment = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.mark_distilled = AsyncMock(return_value=sample_trajectory)

        result = await rb.batch_process_trajectories(
            trajectory_ids=["traj_1", "traj_2", "traj_3"]
        )

        assert result["total_processed"] == 3
        assert result["judgments_performed"] == 3
        assert result["success_count"] == 3
        assert result["failure_count"] == 0
        assert len(result["errors"]) == 0

    @pytest.mark.asyncio
    async def test_batch_process_auto_discover(
        self, mock_db_session, mock_judgment_service, sample_trajectory
    ):
        """Test batch processing with auto-discovery of unjudged trajectories."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        # Create multiple trajectory instances
        trajectories = []
        for i in range(5):
            traj = TaskTrajectory(
                id=i+1,
                trajectory_id=f"traj_test{i}",
                task_type="test_generation",
                task_description="Generate unit tests",
                context_data={},
                agent_type="qe-test-generator",
                actions=[],
                final_output={"test_count": 15},
                outcome=TrajectoryOutcome.UNKNOWN,
                outcome_confidence=0.0,
                execution_time_ms=5000,
                created_at=datetime.utcnow(),
                tenant_id="tenant_123",
            )
            trajectories.append(traj)

        # Mock auto-discovery
        rb.trajectory_service.get_unjudged_trajectories = AsyncMock(
            return_value=trajectories
        )
        rb.trajectory_service.get_trajectory = AsyncMock(side_effect=trajectories)
        rb.trajectory_service.update_judgment = AsyncMock(return_value=sample_trajectory)
        rb.trajectory_service.mark_distilled = AsyncMock(return_value=sample_trajectory)

        result = await rb.batch_process_trajectories(
            task_type="test_generation",
            limit=10,
        )

        assert result["total_processed"] == 5
        rb.trajectory_service.get_unjudged_trajectories.assert_called_once()

    @pytest.mark.asyncio
    async def test_batch_process_with_errors(
        self, mock_db_session, mock_judgment_service, sample_trajectory
    ):
        """Test batch processing handles individual trajectory errors."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        trajectories = [sample_trajectory] * 3
        rb.trajectory_service.get_unjudged_trajectories = AsyncMock(
            return_value=trajectories
        )

        # Make one trajectory fail
        call_count = 0

        async def mock_process(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise Exception("Processing error")
            return {
                "judgment_performed": True,
                "distillation_performed": True,
                "outcome": "success",
                "confidence": 0.95,
                "patterns_extracted": 1,
            }

        with patch.object(rb, "process_trajectory_for_learning", side_effect=mock_process):
            result = await rb.batch_process_trajectories(limit=10)

        assert result["total_processed"] == 2  # 2 succeeded, 1 failed
        assert len(result["errors"]) == 1
        assert "Processing error" in result["errors"][0]["error"]


class TestKnowledgeRetrieval:
    """Test knowledge retrieval methods."""

    @pytest.mark.asyncio
    async def test_retrieve_relevant_knowledge_placeholder(self, mock_db_session):
        """Test retrieve_relevant_knowledge returns placeholder."""
        rb = ReasoningBankService(db_session=mock_db_session)

        patterns = await rb.retrieve_relevant_knowledge(
            task_description="Generate security tests for auth API",
            task_type="test_generation",
            limit=5,
        )

        # Should return empty list (not implemented yet)
        assert isinstance(patterns, list)
        assert len(patterns) == 0

    @pytest.mark.asyncio
    async def test_get_best_practices_for_task(
        self, mock_db_session, sample_pattern
    ):
        """Test getting best practices for a task type."""
        rb = ReasoningBankService(db_session=mock_db_session)

        # Mock database query
        mock_result = MagicMock()
        mock_result.scalars().all.return_value = [sample_pattern]
        mock_db_session.execute.return_value = mock_result

        practices = await rb.get_best_practices_for_task(
            task_type="test_generation",
            limit=10,
        )

        assert len(practices) == 1
        assert practices[0]["pattern_id"] == "pattern_test123"
        assert practices[0]["confidence"] == 0.85

    @pytest.mark.asyncio
    async def test_get_best_practices_empty_result(self, mock_db_session):
        """Test getting best practices when none exist."""
        rb = ReasoningBankService(db_session=mock_db_session)

        # Mock empty result
        mock_result = MagicMock()
        mock_result.scalars().all.return_value = []
        mock_db_session.execute.return_value = mock_result

        practices = await rb.get_best_practices_for_task(
            task_type="test_generation"
        )

        assert len(practices) == 0


class TestStatistics:
    """Test statistics and monitoring methods."""

    @pytest.mark.asyncio
    async def test_get_learning_statistics(self, mock_db_session):
        """Test getting comprehensive learning statistics."""
        rb = ReasoningBankService(db_session=mock_db_session)

        # Mock trajectory statistics
        rb.trajectory_service.get_trajectory_statistics = AsyncMock(
            return_value={
                "total_trajectories": 100,
                "success_count": 80,
                "failure_count": 15,
                "partial_count": 5,
                "success_rate": 0.8,
                "distilled_count": 70,
            }
        )

        # Mock pattern statistics
        mock_result = MagicMock()
        mock_result.scalars().all.return_value = []
        mock_db_session.execute.return_value = mock_result

        stats = await rb.get_learning_statistics(
            task_type="test_generation",
            use_cache=False,
        )

        assert "trajectories" in stats
        assert "patterns" in stats
        assert "learning_metrics" in stats
        assert stats["trajectories"]["total_trajectories"] == 100
        assert stats["trajectories"]["success_rate"] == 0.8

    @pytest.mark.asyncio
    async def test_get_learning_statistics_with_cache(self, mock_db_session):
        """Test statistics caching."""
        rb = ReasoningBankService(db_session=mock_db_session)

        # Mock trajectory statistics
        rb.trajectory_service.get_trajectory_statistics = AsyncMock(
            return_value={"total_trajectories": 100}
        )

        # Mock pattern statistics
        mock_result = MagicMock()
        mock_result.scalars().all.return_value = []
        mock_db_session.execute.return_value = mock_result

        # First call - should fetch from database
        stats1 = await rb.get_learning_statistics(use_cache=True)
        assert stats1["trajectories"]["total_trajectories"] == 100

        # Second call - should use cache
        stats2 = await rb.get_learning_statistics(use_cache=True)
        assert stats2["trajectories"]["total_trajectories"] == 100

        # Should only call service once due to caching
        assert rb.trajectory_service.get_trajectory_statistics.call_count == 1

    @pytest.mark.asyncio
    async def test_get_recent_learning_activity(self, mock_db_session, sample_trajectory):
        """Test getting recent learning activity."""
        rb = ReasoningBankService(db_session=mock_db_session)

        # Mock database queries
        mock_traj_result = MagicMock()
        mock_traj_result.scalars().all.return_value = [sample_trajectory] * 5

        mock_pattern_result = MagicMock()
        mock_pattern_result.scalars().all.return_value = []

        mock_db_session.execute.side_effect = [
            mock_traj_result,
            mock_pattern_result,
        ]

        activity = await rb.get_recent_learning_activity(hours=24)

        assert activity["lookback_hours"] == 24
        assert activity["trajectories_created"] == 5
        assert activity["patterns_learned"] == 0
        assert "period_start" in activity
        assert "period_end" in activity


class TestConsolidation:
    """Test consolidation methods."""

    @pytest.mark.asyncio
    async def test_run_consolidation_cycle_placeholder(self, mock_db_session):
        """Test consolidation cycle returns placeholder."""
        rb = ReasoningBankService(db_session=mock_db_session)

        result = await rb.run_consolidation_cycle(
            task_type="test_generation"
        )

        assert result["status"] == "not_implemented"
        assert result["duplicates_merged"] == 0
        assert rb._last_consolidation_run is not None

    @pytest.mark.asyncio
    async def test_should_run_consolidation_first_time(self, mock_db_session):
        """Test consolidation should run on first check."""
        rb = ReasoningBankService(db_session=mock_db_session)

        should_run = await rb.should_run_consolidation()
        assert should_run is True

    @pytest.mark.asyncio
    async def test_should_run_consolidation_disabled(self, mock_db_session):
        """Test consolidation check when disabled."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            enable_background_consolidation=False,
        )

        should_run = await rb.should_run_consolidation()
        assert should_run is False

    @pytest.mark.asyncio
    async def test_should_run_consolidation_schedule(self, mock_db_session):
        """Test consolidation scheduling."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            consolidation_interval_hours=1,
        )

        # Set last run to recent
        rb._last_consolidation_run = datetime.utcnow() - timedelta(minutes=30)
        should_run = await rb.should_run_consolidation()
        assert should_run is False

        # Set last run to old
        rb._last_consolidation_run = datetime.utcnow() - timedelta(hours=2)
        should_run = await rb.should_run_consolidation()
        assert should_run is True


class TestUtilityMethods:
    """Test utility and helper methods."""

    @pytest.mark.asyncio
    async def test_health_check_healthy(self, mock_db_session):
        """Test health check when system is healthy."""
        rb = ReasoningBankService(db_session=mock_db_session)

        # Mock recent activity
        rb.get_recent_learning_activity = AsyncMock(
            return_value={"trajectories_created": 10}
        )

        health = await rb.health_check()

        assert health["status"] == "healthy"
        assert health["database"] == "ok"
        assert health["recent_activity_1h"] == 10

    @pytest.mark.asyncio
    async def test_health_check_degraded(self, mock_db_session):
        """Test health check when database fails."""
        mock_db_session.execute.side_effect = Exception("Database error")

        rb = ReasoningBankService(db_session=mock_db_session)

        health = await rb.health_check()

        assert health["status"] == "degraded"
        assert health["database"] == "error"

    @pytest.mark.asyncio
    async def test_clear_cache(self, mock_db_session):
        """Test clearing statistics cache."""
        rb = ReasoningBankService(db_session=mock_db_session)

        # Add some cache data
        rb._stats_cache["test_key"] = {"data": "test"}
        rb._stats_cache_expiry = datetime.utcnow() + timedelta(minutes=5)

        await rb.clear_cache()

        assert len(rb._stats_cache) == 0
        assert rb._stats_cache_expiry is None

    def test_get_service_info(self, mock_db_session, mock_judgment_service):
        """Test getting service configuration info."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        info = rb.get_service_info()

        assert info["trajectory_service"] == "configured"
        assert info["judgment_service"] == "configured"
        assert info["retrieval_service"] == "not_implemented"
        assert info["distillation_service"] == "not_implemented"
        assert info["consolidation_service"] == "not_implemented"
        assert info["background_consolidation"] is True


class TestPrivateHelperMethods:
    """Test private helper methods."""

    @pytest.mark.asyncio
    async def test_judge_trajectory(
        self, mock_db_session, mock_judgment_service, sample_trajectory
    ):
        """Test _judge_trajectory helper method."""
        rb = ReasoningBankService(
            db_session=mock_db_session,
            judgment_service=mock_judgment_service,
        )

        rb.trajectory_service.update_judgment = AsyncMock(return_value=sample_trajectory)

        result = await rb._judge_trajectory(sample_trajectory)

        assert result["outcome"] == "success"
        assert result["confidence"] == 0.95
        assert "reasoning" in result
        assert "quality_score" in result

    @pytest.mark.asyncio
    async def test_distill_trajectory_placeholder(
        self, mock_db_session, sample_trajectory
    ):
        """Test _distill_trajectory returns placeholder."""
        rb = ReasoningBankService(db_session=mock_db_session)

        rb.trajectory_service.mark_distilled = AsyncMock(return_value=sample_trajectory)

        result = await rb._distill_trajectory(sample_trajectory)

        assert result["patterns_extracted"] == 0
        assert result["distillation_status"] == "not_implemented"

    def test_calculate_growth_rate(self, mock_db_session):
        """Test knowledge growth rate calculation."""
        rb = ReasoningBankService(db_session=mock_db_session)

        rate = rb._calculate_growth_rate(pattern_count=50, trajectory_count=100)
        assert rate == 0.5

        rate = rb._calculate_growth_rate(pattern_count=100, trajectory_count=0)
        assert rate == 0.0

    def test_calculate_health_score(self, mock_db_session):
        """Test system health score calculation."""
        rb = ReasoningBankService(db_session=mock_db_session)

        traj_stats = {
            "total_trajectories": 100,
            "success_rate": 0.8,
        }

        pattern_stats = {
            "total_patterns": 50,
            "avg_confidence": 0.85,
        }

        score = rb._calculate_health_score(traj_stats, pattern_stats)

        assert 0.0 <= score <= 1.0
        assert isinstance(score, float)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
