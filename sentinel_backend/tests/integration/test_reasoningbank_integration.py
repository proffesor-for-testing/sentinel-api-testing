"""
ReasoningBank Integration Tests

Tests the integration of ReasoningBank services with Sentinel's orchestration layer.
"""

import pytest
import asyncio
from datetime import datetime
from typing import Dict, Any

from sentinel_backend.reasoningbank.integration import (
    ReasoningBankOrchestrator,
    initialize_reasoningbank_orchestrator
)
from sentinel_backend.reasoningbank.models.task_trajectories import TrajectoryOutcome
from sentinel_backend.reasoningbank.services.trajectory_service import TrajectoryService


@pytest.fixture
async def orchestrator(db_session):
    """Create ReasoningBank orchestrator for testing"""
    return ReasoningBankOrchestrator(
        db_session=db_session,
        enable_background_tasks=False  # Disable for testing
    )


@pytest.mark.asyncio
async def test_trajectory_lifecycle(orchestrator):
    """Test complete trajectory lifecycle"""
    # 1. Start trajectory
    trajectory_id = await orchestrator.start_trajectory(
        agent_type="Functional-Positive-Agent",
        task_description="Generate positive test cases for Pet Store API",
        context_data={"spec_id": 1, "endpoint": "/api/v1/pets"},
        task_type="test_generation"
    )

    assert trajectory_id is not None
    assert trajectory_id.startswith("traj_")

    # 2. Record actions
    await orchestrator.record_action(
        trajectory_id=trajectory_id,
        action_type="analysis",
        action_description="Analyzed API specification",
        action_data={"endpoints_found": 5}
    )

    await orchestrator.record_action(
        trajectory_id=trajectory_id,
        action_type="generation",
        action_description="Generated test cases",
        action_data={"tests_generated": 10}
    )

    # 3. Complete trajectory
    result = await orchestrator.complete_trajectory(
        trajectory_id=trajectory_id,
        final_output={"test_cases": [{"name": "test_list_pets"}]},
        test_success_rate=0.9,
        coverage_score=0.85,
        auto_process=False  # Manual processing for testing
    )

    assert result["status"] == "completed"


@pytest.mark.asyncio
async def test_agent_execution_context(orchestrator):
    """Test agent execution context manager"""
    async with orchestrator.agent_execution_context(
        agent_type="Security-Auth-Agent",
        task_description="Test authentication mechanisms",
        context_data={"spec_id": 1}
    ) as ctx:
        # Get patterns (will be empty initially)
        patterns = await ctx.get_patterns()
        assert isinstance(patterns, list)

        # Record action
        await ctx.record_action(
            "analysis",
            "Analyzed auth endpoints",
            {"auth_type": "JWT"}
        )

        # Complete
        result = await ctx.complete({
            "test_cases": [{"name": "test_auth"}],
            "success": True
        })

        assert "trajectory_id" in result or "status" in result


@pytest.mark.asyncio
async def test_pattern_retrieval_empty(orchestrator):
    """Test pattern retrieval when no patterns exist"""
    patterns = await orchestrator.get_relevant_patterns(
        task_description="Generate API tests",
        agent_type="Functional-Positive-Agent",
        limit=5
    )

    assert isinstance(patterns, list)
    # Should be empty initially (no patterns learned yet)


@pytest.mark.asyncio
async def test_health_check(orchestrator):
    """Test health check"""
    health = await orchestrator.health_check()

    assert "status" in health
    assert "database" in health
    assert "timestamp" in health


@pytest.mark.asyncio
async def test_statistics(orchestrator):
    """Test statistics retrieval"""
    stats = await orchestrator.get_statistics()

    assert "trajectories" in stats
    assert "patterns" in stats
    assert "learning_metrics" in stats


@pytest.mark.asyncio
async def test_multiple_trajectories_sequential(orchestrator):
    """Test multiple trajectories in sequence"""
    trajectory_ids = []

    for i in range(3):
        traj_id = await orchestrator.start_trajectory(
            agent_type="Data-Mocking-Agent",
            task_description=f"Generate mock data iteration {i+1}",
            context_data={"iteration": i+1}
        )
        trajectory_ids.append(traj_id)

        await orchestrator.complete_trajectory(
            trajectory_id=traj_id,
            final_output={"mock_data": [{"id": i}]},
            auto_process=False
        )

    assert len(trajectory_ids) == 3
    assert all(tid.startswith("traj_") for tid in trajectory_ids)


@pytest.mark.asyncio
async def test_trajectory_with_failure(orchestrator):
    """Test trajectory that fails"""
    trajectory_id = await orchestrator.start_trajectory(
        agent_type="Performance-Planner-Agent",
        task_description="Generate performance tests",
        context_data={"spec_id": 1}
    )

    await orchestrator.record_action(
        trajectory_id=trajectory_id,
        action_type="error",
        action_description="Failed to parse specification",
        action_data={"error": "Invalid JSON"}
    )

    # Get trajectory service to mark as failed
    trajectory = await orchestrator.trajectory_service.get_trajectory(trajectory_id)
    await orchestrator.trajectory_service.update_judgment(
        trajectory_id=trajectory_id,
        outcome=TrajectoryOutcome.FAILURE,
        confidence=1.0,
        reasoning="Specification parsing failed"
    )

    # Verify failure recorded
    trajectory = await orchestrator.trajectory_service.get_trajectory(trajectory_id)
    assert trajectory.outcome == TrajectoryOutcome.FAILURE


@pytest.mark.asyncio
@pytest.mark.slow
async def test_background_tasks_lifecycle(db_session):
    """Test background tasks start and stop"""
    orchestrator = ReasoningBankOrchestrator(
        db_session=db_session,
        enable_background_tasks=True
    )

    # Start background tasks
    await orchestrator.start_background_tasks()

    assert len(orchestrator._background_tasks) > 0

    # Let them run briefly
    await asyncio.sleep(2)

    # Stop background tasks
    await orchestrator.stop_background_tasks()

    assert all(task.cancelled() or task.done() for task in orchestrator._background_tasks)


@pytest.mark.asyncio
async def test_pattern_usage_update(orchestrator):
    """Test updating pattern usage"""
    # This will be a no-op if retrieval service not configured
    # But should not raise an error
    await orchestrator.update_pattern_usage(
        pattern_id="pat_test123",
        success=True
    )

    # No assertion needed - just verify it doesn't crash


@pytest.mark.asyncio
async def test_concurrent_trajectories(orchestrator):
    """Test concurrent trajectory creation and completion"""
    async def create_and_complete(index: int):
        traj_id = await orchestrator.start_trajectory(
            agent_type="Functional-Negative-Agent",
            task_description=f"Concurrent test {index}",
            context_data={"index": index}
        )

        await orchestrator.record_action(
            trajectory_id=traj_id,
            action_type="test",
            action_description=f"Action {index}"
        )

        return await orchestrator.complete_trajectory(
            trajectory_id=traj_id,
            final_output={"result": index},
            auto_process=False
        )

    # Create 5 concurrent trajectories
    results = await asyncio.gather(*[
        create_and_complete(i) for i in range(5)
    ])

    assert len(results) == 5
    assert all(r["status"] == "completed" for r in results)


# Integration with existing agent tests

@pytest.mark.asyncio
async def test_integration_with_python_agent(orchestrator):
    """Test integration with actual Python agent execution"""
    from sentinel_backend.orchestration_service.agents.python_agents import (
        functional_positive_python
    )

    # Start trajectory
    trajectory_id = await orchestrator.start_trajectory(
        agent_type="Functional-Positive-Agent",
        task_description="Generate positive tests for Pet Store",
        context_data={
            "spec": {
                "paths": {
                    "/pets": {
                        "get": {"operationId": "list_pets"}
                    }
                }
            }
        }
    )

    # Execute agent (simplified)
    try:
        result = await functional_positive_python({
            "paths": {
                "/pets": {"get": {"operationId": "list_pets"}}
            }
        })

        # Record success
        await orchestrator.complete_trajectory(
            trajectory_id=trajectory_id,
            final_output=result,
            test_success_rate=0.95,
            auto_process=False
        )

    except Exception as e:
        # Record failure
        await orchestrator.trajectory_service.update_judgment(
            trajectory_id=trajectory_id,
            outcome=TrajectoryOutcome.FAILURE,
            confidence=1.0,
            reasoning=str(e)
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
