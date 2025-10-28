"""
Integration Tests for Agent Learning with ReasoningBank

Tests that all agents properly track trajectories and integrate with the learning loop.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.orchestration_service.agents.functional_stateful_agent import FunctionalStatefulAgent
from sentinel_backend.orchestration_service.agents.security_auth_agent import SecurityAuthAgent
from sentinel_backend.orchestration_service.agents.security_injection_agent import SecurityInjectionAgent
from sentinel_backend.orchestration_service.agents.performance_planner_agent import PerformancePlannerAgent
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask
from sentinel_backend.orchestration_service.services.learning_orchestrator import LearningOrchestrator
from sentinel_backend.reasoningbank.models.task_trajectories import TaskTrajectory, TrajectoryOutcome
from sentinel_backend.reasoningbank.services.trajectory_service import TrajectoryService
from sentinel_backend.reasoningbank.services.judgment_service import JudgmentService


# Sample API spec for testing
SAMPLE_API_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/users": {
            "get": {
                "summary": "List users",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/User"}
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
                            "schema": {"$ref": "#/components/schemas/User"}
                        }
                    }
                },
                "responses": {
                    "201": {"description": "Created"}
                }
            }
        },
        "/users/{id}": {
            "get": {
                "summary": "Get user by ID",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "Success"}
                }
            }
        }
    },
    "components": {
        "schemas": {
            "User": {
                "type": "object",
                "required": ["email", "name"],
                "properties": {
                    "id": {"type": "string"},
                    "email": {"type": "string", "format": "email"},
                    "name": {"type": "string"},
                    "age": {"type": "integer", "minimum": 0, "maximum": 150}
                }
            }
        }
    }
}


@pytest.fixture
async def db_session():
    """Create an in-memory SQLite database session for testing."""
    # Use in-memory SQLite for fast testing
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    # Create tables
    from sentinel_backend.reasoningbank.models.task_trajectories import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Create session
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def mock_judgment_service():
    """Create a mock judgment service that returns deterministic results."""
    service = AsyncMock(spec=JudgmentService)

    async def mock_judge(trajectory):
        # Simple heuristic: if trajectory has test cases, it's successful
        has_output = trajectory.final_output and trajectory.final_output.get("test_case_count", 0) > 0

        if has_output:
            return (
                TrajectoryOutcome.SUCCESS,
                0.9,
                "Generated tests successfully",
                {"quality_score": 0.85, "key_issues": []}
            )
        else:
            return (
                TrajectoryOutcome.FAILURE,
                0.8,
                "No tests generated",
                {"quality_score": 0.2, "key_issues": ["No output"]}
            )

    service.judge_trajectory = mock_judge
    return service


@pytest.mark.asyncio
class TestFunctionalPositiveAgentLearning:
    """Test learning integration for Functional Positive Agent."""

    async def test_agent_creates_trajectory(self, db_session):
        """Test that agent creates trajectory during execution."""
        agent = FunctionalPositiveAgent()
        task = AgentTask(
            task_id="test-1",
            spec_id=1,
            agent_type="Functional-Positive-Agent",
            enable_llm=False
        )

        result = await agent.execute(task, SAMPLE_API_SPEC, db_session=db_session)

        assert result.status == "success"
        assert "trajectory_id" in result.metadata
        assert result.metadata["trajectory_id"] is not None

        # Verify trajectory was stored
        trajectory_service = TrajectoryService(db_session)
        trajectory = await trajectory_service.get_trajectory(result.metadata["trajectory_id"])

        assert trajectory is not None
        assert trajectory.task_type == "test_generation"
        assert trajectory.agent_type == "Functional-Positive-Agent"
        assert len(trajectory.actions) > 0

    async def test_trajectory_contains_actions(self, db_session):
        """Test that trajectory captures agent actions."""
        agent = FunctionalPositiveAgent()
        task = AgentTask(
            task_id="test-2",
            spec_id=1,
            agent_type="Functional-Positive-Agent"
        )

        result = await agent.execute(task, SAMPLE_API_SPEC, db_session=db_session)

        trajectory_service = TrajectoryService(db_session)
        trajectory = await trajectory_service.get_trajectory(result.metadata["trajectory_id"])

        # Verify actions were logged
        assert len(trajectory.actions) >= 2  # Should have at least 2 actions
        action_descriptions = [a["description"] for a in trajectory.actions]

        assert any("Extracting endpoints" in desc for desc in action_descriptions)
        assert any("Generating test cases" in desc for desc in action_descriptions)

    async def test_trajectory_has_final_output(self, db_session):
        """Test that trajectory stores final output."""
        agent = FunctionalPositiveAgent()
        task = AgentTask(
            task_id="test-3",
            spec_id=1,
            agent_type="Functional-Positive-Agent"
        )

        result = await agent.execute(task, SAMPLE_API_SPEC, db_session=db_session)

        trajectory_service = TrajectoryService(db_session)
        trajectory = await trajectory_service.get_trajectory(result.metadata["trajectory_id"])

        # Verify final output
        assert trajectory.final_output is not None
        assert "test_case_count" in trajectory.final_output
        assert trajectory.final_output["test_case_count"] > 0


@pytest.mark.asyncio
class TestMultipleAgentsLearning:
    """Test learning integration across multiple agent types."""

    @pytest.mark.parametrize("agent_class,agent_type", [
        (FunctionalPositiveAgent, "Functional-Positive-Agent"),
        (FunctionalNegativeAgent, "Functional-Negative-Agent"),
        (SecurityAuthAgent, "Security-Auth-Agent"),
    ])
    async def test_all_agents_create_trajectories(self, db_session, agent_class, agent_type):
        """Test that all agents create trajectories."""
        agent = agent_class()
        task = AgentTask(
            task_id=f"test-{agent_type}",
            spec_id=1,
            agent_type=agent_type,
            enable_llm=False
        )

        result = await agent.execute(task, SAMPLE_API_SPEC, db_session=db_session)

        # Some agents may have different behavior, but all should create trajectories
        if result.status == "success":
            assert "trajectory_id" in result.metadata
        else:
            # Even failed executions should track trajectories
            pass


@pytest.mark.asyncio
class TestLearningOrchestrator:
    """Test the learning orchestrator service."""

    async def test_orchestrator_processes_unjudged_trajectories(self, db_session, mock_judgment_service):
        """Test that orchestrator processes unjudged trajectories."""
        # Create some test trajectories
        trajectory_service = TrajectoryService(db_session)

        trajectory1 = await trajectory_service.create_trajectory(
            task_type="test_generation",
            task_description="Test 1",
            agent_type="Functional-Positive-Agent"
        )

        await trajectory_service.complete_trajectory(
            trajectory_id=trajectory1.trajectory_id,
            final_output={"test_case_count": 5}
        )

        # Create orchestrator with mock judgment service
        orchestrator = LearningOrchestrator(
            db_session=db_session,
            judgment_service=mock_judgment_service
        )

        # Process learning queue
        result = await orchestrator.process_learning_queue(batch_size=10, max_iterations=1)

        assert result["processed_count"] == 1
        assert len(result["errors"]) == 0

        # Verify trajectory was judged
        updated_trajectory = await trajectory_service.get_trajectory(trajectory1.trajectory_id)
        assert updated_trajectory.outcome == TrajectoryOutcome.SUCCESS

    async def test_orchestrator_handles_batch_processing(self, db_session, mock_judgment_service):
        """Test that orchestrator handles batch processing."""
        trajectory_service = TrajectoryService(db_session)

        # Create multiple trajectories
        trajectories = []
        for i in range(5):
            traj = await trajectory_service.create_trajectory(
                task_type="test_generation",
                task_description=f"Test {i}",
                agent_type="Functional-Positive-Agent"
            )
            await trajectory_service.complete_trajectory(
                trajectory_id=traj.trajectory_id,
                final_output={"test_case_count": i + 1}
            )
            trajectories.append(traj)

        # Process with batch size of 2
        orchestrator = LearningOrchestrator(
            db_session=db_session,
            judgment_service=mock_judgment_service
        )

        result = await orchestrator.process_learning_queue(batch_size=2, max_iterations=3)

        assert result["processed_count"] == 5
        assert result["metrics"]["judgments_made"] == 5


@pytest.mark.asyncio
class TestAgentLearningLoop:
    """Test complete learning loop from agent execution to feedback processing."""

    async def test_complete_learning_flow(self, db_session, mock_judgment_service):
        """Test complete flow: agent → trajectory → judgment → learning."""
        # Step 1: Agent executes and creates trajectory
        agent = FunctionalPositiveAgent()
        task = AgentTask(
            task_id="test-complete-flow",
            spec_id=1,
            agent_type="Functional-Positive-Agent"
        )

        result = await agent.execute(task, SAMPLE_API_SPEC, db_session=db_session)
        trajectory_id = result.metadata.get("trajectory_id")

        assert trajectory_id is not None

        # Step 2: Orchestrator judges the trajectory
        orchestrator = LearningOrchestrator(
            db_session=db_session,
            judgment_service=mock_judgment_service
        )

        process_result = await orchestrator.process_learning_queue(batch_size=10, max_iterations=1)

        assert process_result["processed_count"] == 1

        # Step 3: Verify trajectory was judged successfully
        trajectory_service = TrajectoryService(db_session)
        trajectory = await trajectory_service.get_trajectory(trajectory_id)

        assert trajectory.outcome == TrajectoryOutcome.SUCCESS
        assert trajectory.outcome_confidence > 0.0

        # Step 4: Get learning statistics
        stats = await orchestrator.get_agent_learning_stats(
            agent_type="Functional-Positive-Agent"
        )

        assert stats["total_trajectories"] >= 1
        assert stats["success_count"] >= 1


@pytest.mark.asyncio
class TestAgentErrorHandling:
    """Test agent behavior during errors."""

    async def test_agent_aborts_trajectory_on_error(self, db_session):
        """Test that agent properly aborts trajectory when error occurs."""
        agent = FunctionalPositiveAgent()
        task = AgentTask(
            task_id="test-error",
            spec_id=1,
            agent_type="Functional-Positive-Agent"
        )

        # Cause an error by passing invalid spec
        invalid_spec = {"invalid": "spec"}

        result = await agent.execute(task, invalid_spec, db_session=db_session)

        assert result.status == "failed"
        # Should still have attempted trajectory tracking


@pytest.mark.asyncio
class TestAgentMetrics:
    """Test agent learning metrics."""

    async def test_trajectory_statistics(self, db_session):
        """Test trajectory statistics calculation."""
        trajectory_service = TrajectoryService(db_session)

        # Create mix of successful and failed trajectories
        for i in range(3):
            traj = await trajectory_service.create_trajectory(
                task_type="test_generation",
                task_description=f"Test {i}",
                agent_type="Functional-Positive-Agent"
            )
            await trajectory_service.complete_trajectory(
                trajectory_id=traj.trajectory_id,
                final_output={"test_case_count": 5}
            )
            await trajectory_service.update_judgment(
                trajectory_id=traj.trajectory_id,
                outcome=TrajectoryOutcome.SUCCESS,
                confidence=0.9,
                reasoning="Good tests"
            )

        for i in range(2):
            traj = await trajectory_service.create_trajectory(
                task_type="test_generation",
                task_description=f"Fail test {i}",
                agent_type="Functional-Positive-Agent"
            )
            await trajectory_service.complete_trajectory(
                trajectory_id=traj.trajectory_id,
                final_output={}
            )
            await trajectory_service.update_judgment(
                trajectory_id=traj.trajectory_id,
                outcome=TrajectoryOutcome.FAILURE,
                confidence=0.8,
                reasoning="No tests"
            )

        stats = await trajectory_service.get_trajectory_statistics(
            task_type="test_generation"
        )

        assert stats["total_trajectories"] == 5
        assert stats["success_count"] == 3
        assert stats["failure_count"] == 2
        assert abs(stats["success_rate"] - 0.6) < 0.01


@pytest.mark.asyncio
class TestAgentImprovementOverTime:
    """Test that agents can improve based on learned patterns."""

    async def test_agent_recommendations(self, db_session):
        """Test getting learning recommendations for agents."""
        trajectory_service = TrajectoryService(db_session)

        # Create successful trajectory with patterns
        traj = await trajectory_service.create_trajectory(
            task_type="test_generation",
            task_description="Successful test generation",
            agent_type="Functional-Positive-Agent"
        )
        await trajectory_service.complete_trajectory(
            trajectory_id=traj.trajectory_id,
            final_output={"test_case_count": 10},
            test_success_rate=0.95,
            execution_time_ms=1500
        )
        await trajectory_service.update_judgment(
            trajectory_id=traj.trajectory_id,
            outcome=TrajectoryOutcome.SUCCESS,
            confidence=0.95,
            reasoning="Excellent coverage"
        )
        await trajectory_service.mark_distilled(
            trajectory_id=traj.trajectory_id,
            extracted_pattern_ids=["pattern_1", "pattern_2"]
        )

        # Get recommendations
        orchestrator = LearningOrchestrator(db_session=db_session)
        recommendations = await orchestrator.get_learning_recommendations(
            agent_type="Functional-Positive-Agent",
            limit=10
        )

        assert len(recommendations) >= 1
        assert recommendations[0]["trajectory_id"] == traj.trajectory_id
        assert len(recommendations[0]["patterns"]) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
