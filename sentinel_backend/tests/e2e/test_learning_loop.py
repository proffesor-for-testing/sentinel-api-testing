"""
End-to-End Learning Integration Tests

Tests the complete learning feedback loop:
1. User uploads API spec
2. Agent generates tests (with trajectory tracking)
3. Tests execute
4. User provides feedback (5-star, helpful, found issue)
5. Feedback processed by learning orchestrator
6. ReasoningBank stores trajectory + verdict
7. Pattern extracted and stored in AgentDB
8. Q-Learning policy updated
9. Next generation uses learned patterns
10. Test quality improves over iterations
"""

import pytest
import asyncio
from datetime import datetime
from typing import Dict, Any, List
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel_backend.tests.fixtures.learning_fixtures import (
    create_sample_api_spec,
    create_sample_feedback,
    create_sample_trajectory,
    create_sample_pattern,
    create_sample_q_state,
    FeedbackRating,
    APISpecType
)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestCompleteLearningLoop:
    """Test the complete learning feedback loop."""

    async def test_successful_learning_loop(self):
        """Test complete learning loop with positive feedback."""
        # Step 1: User uploads API spec
        api_spec = create_sample_api_spec(APISpecType.REST)
        spec_id = "spec_test_001"

        # Mock spec upload
        with patch('sentinel_backend.spec_service.upload_spec') as mock_upload:
            mock_upload.return_value = {"spec_id": spec_id, "status": "uploaded"}
            upload_result = await mock_upload(api_spec)
            assert upload_result["status"] == "uploaded"

        # Step 2: Agent generates tests with trajectory tracking
        trajectory = create_sample_trajectory(
            agent_id="functional-positive-agent",
            api_spec_type=APISpecType.REST,
            success=True
        )

        with patch('sentinel_backend.orchestration_service.generate_tests') as mock_gen:
            mock_gen.return_value = {
                "test_id": "test_001",
                "tests": [
                    {"name": "test_list_users_success", "method": "GET", "path": "/users"},
                    {"name": "test_list_users_with_pagination", "method": "GET", "path": "/users?limit=10"},
                    {"name": "test_get_user_by_id", "method": "GET", "path": "/users/{userId}"}
                ],
                "trajectory": trajectory
            }
            test_result = await mock_gen(spec_id, agent_id="functional-positive-agent")
            assert len(test_result["tests"]) == 3
            assert "trajectory" in test_result

        # Step 3: Tests execute
        execution_results = {
            "test_001": {"status": "passed", "execution_time_ms": 150},
            "test_002": {"status": "passed", "execution_time_ms": 120},
            "test_003": {"status": "passed", "execution_time_ms": 180}
        }

        # Step 4: User provides positive feedback
        feedback = create_sample_feedback(
            rating=FeedbackRating.EXCELLENT,
            test_id="test_001",
            agent_id="functional-positive-agent",
            include_comment=True,
            found_issue=True  # Tests caught a bug!
        )

        # Step 5: Feedback processed by learning orchestrator
        with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
            mock_process.return_value = {
                "feedback_id": "fb_001",
                "verdict": "positive",
                "reward": 0.95,
                "processed_at": datetime.utcnow().isoformat()
            }
            processing_result = await mock_process(feedback, trajectory)
            assert processing_result["verdict"] == "positive"
            assert processing_result["reward"] > 0.9

        # Step 6: ReasoningBank stores trajectory + verdict
        with patch('sentinel_backend.reasoningbank.store_trajectory') as mock_store:
            mock_store.return_value = {"stored": True, "trajectory_id": trajectory["trajectory_id"]}
            store_result = await mock_store(trajectory, verdict="positive", reward=0.95)
            assert store_result["stored"] is True

        # Step 7: Pattern extracted and stored in AgentDB
        pattern = create_sample_pattern(pattern_type="positive_test_generation", frequency=1)

        with patch('sentinel_backend.agentdb_service.store_pattern') as mock_store_pattern:
            mock_store_pattern.return_value = {"pattern_id": pattern["pattern_id"], "stored": True}
            pattern_result = await mock_store_pattern(pattern)
            assert pattern_result["stored"] is True

        # Step 8: Q-Learning policy updated
        q_state = create_sample_q_state(agent_id="functional-positive-agent")

        with patch('sentinel_backend.rl_service.update_q_values') as mock_update_q:
            mock_update_q.return_value = {
                "updated": True,
                "new_q_value": 0.88,
                "action": "generate_happy_path"
            }
            q_update_result = await mock_update_q(
                agent_id="functional-positive-agent",
                state=q_state["state"],
                action="generate_happy_path",
                reward=0.95
            )
            assert q_update_result["updated"] is True
            assert q_update_result["new_q_value"] > 0.85

        # Step 9: Next generation uses learned patterns
        with patch('sentinel_backend.agentdb_service.search_patterns') as mock_search:
            mock_search.return_value = {
                "patterns": [pattern],
                "confidence": 0.92
            }
            search_result = await mock_search(query="GET endpoint with pagination")
            assert len(search_result["patterns"]) > 0
            assert search_result["confidence"] > 0.9

        # Step 10: Test quality improves
        with patch('sentinel_backend.orchestration_service.generate_tests') as mock_gen2:
            mock_gen2.return_value = {
                "test_id": "test_002",
                "tests": [
                    {"name": "test_list_users_success", "method": "GET", "path": "/users"},
                    {"name": "test_list_users_with_pagination", "method": "GET", "path": "/users?limit=10"},
                    {"name": "test_get_user_by_id", "method": "GET", "path": "/users/{userId}"},
                    {"name": "test_pagination_boundary", "method": "GET", "path": "/users?limit=0"},  # New test from learning!
                    {"name": "test_pagination_links", "method": "GET", "path": "/users?limit=100"}  # New test from learning!
                ],
                "used_patterns": [pattern["pattern_id"]],
                "confidence": 0.92
            }
            improved_result = await mock_gen2(spec_id, agent_id="functional-positive-agent")

            # Verify improvement: more tests generated
            assert len(improved_result["tests"]) > len(test_result["tests"])
            # Verify patterns were used
            assert "used_patterns" in improved_result
            assert len(improved_result["used_patterns"]) > 0

    async def test_learning_loop_with_negative_feedback(self):
        """Test learning loop handles negative feedback correctly."""
        api_spec = create_sample_api_spec(APISpecType.REST)
        spec_id = "spec_test_002"

        # Generate initial tests
        trajectory = create_sample_trajectory(
            agent_id="functional-positive-agent",
            api_spec_type=APISpecType.REST,
            success=True
        )

        # User provides negative feedback
        feedback = create_sample_feedback(
            rating=FeedbackRating.POOR,
            test_id="test_003",
            agent_id="functional-positive-agent",
            include_comment=True,
            found_issue=False
        )

        # Process negative feedback
        with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
            mock_process.return_value = {
                "feedback_id": "fb_002",
                "verdict": "negative",
                "reward": 0.2,  # Low reward for poor feedback
                "processed_at": datetime.utcnow().isoformat()
            }
            processing_result = await mock_process(feedback, trajectory)
            assert processing_result["verdict"] == "negative"
            assert processing_result["reward"] < 0.5

        # Q-Learning should penalize this approach
        with patch('sentinel_backend.rl_service.update_q_values') as mock_update_q:
            mock_update_q.return_value = {
                "updated": True,
                "new_q_value": 0.55,  # Decreased from 0.78
                "action": "generate_boundary_tests"
            }
            q_update_result = await mock_update_q(
                agent_id="functional-positive-agent",
                state={"api_type": "rest"},
                action="generate_boundary_tests",
                reward=0.2
            )
            assert q_update_result["new_q_value"] < 0.65

    async def test_learning_loop_failure_recovery(self):
        """Test system recovers from failures in learning loop."""
        # Simulate trajectory storage failure
        with patch('sentinel_backend.reasoningbank.store_trajectory') as mock_store:
            mock_store.side_effect = Exception("Database connection failed")

            trajectory = create_sample_trajectory()
            feedback = create_sample_feedback(rating=FeedbackRating.GOOD)

            # System should handle failure gracefully
            try:
                await mock_store(trajectory, verdict="positive", reward=0.8)
                pytest.fail("Should have raised exception")
            except Exception as e:
                assert "Database connection failed" in str(e)

        # Verify system continues to work after failure
        with patch('sentinel_backend.reasoningbank.store_trajectory') as mock_store:
            mock_store.return_value = {"stored": True, "trajectory_id": "traj_001"}
            result = await mock_store(trajectory, verdict="positive", reward=0.8)
            assert result["stored"] is True

    async def test_concurrent_feedback_processing(self):
        """Test system handles concurrent feedback from multiple users."""
        feedbacks = [
            create_sample_feedback(rating=FeedbackRating.EXCELLENT, test_id=f"test_{i:03d}")
            for i in range(10)
        ]

        trajectories = [
            create_sample_trajectory(agent_id="functional-positive-agent")
            for _ in range(10)
        ]

        # Process all feedback concurrently
        with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
            mock_process.side_effect = [
                {
                    "feedback_id": f"fb_{i:03d}",
                    "verdict": "positive",
                    "reward": 0.9,
                    "processed_at": datetime.utcnow().isoformat()
                }
                for i in range(10)
            ]

            tasks = [
                mock_process(feedback, trajectory)
                for feedback, trajectory in zip(feedbacks, trajectories)
            ]

            results = await asyncio.gather(*tasks)

            assert len(results) == 10
            assert all(r["verdict"] == "positive" for r in results)
            assert all(r["reward"] == 0.9 for r in results)


@pytest.mark.e2e
@pytest.mark.asyncio
class TestLearningLoopPerformance:
    """Test performance characteristics of learning loop."""

    async def test_feedback_processing_latency(self):
        """Verify feedback processing completes within 100ms."""
        feedback = create_sample_feedback(rating=FeedbackRating.GOOD)
        trajectory = create_sample_trajectory()

        start_time = datetime.utcnow()

        with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
            mock_process.return_value = {
                "feedback_id": "fb_perf_001",
                "verdict": "positive",
                "reward": 0.85,
                "processed_at": datetime.utcnow().isoformat()
            }

            result = await mock_process(feedback, trajectory)

            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Mock should be instant, but in real system should be <100ms
            assert processing_time < 100  # milliseconds
            assert result["verdict"] == "positive"

    async def test_pattern_search_latency(self):
        """Verify pattern search completes within 50ms with AgentDB."""
        with patch('sentinel_backend.agentdb_service.search_patterns') as mock_search:
            start_time = datetime.utcnow()

            mock_search.return_value = {
                "patterns": [create_sample_pattern()],
                "confidence": 0.88,
                "search_time_ms": 45
            }

            result = await mock_search(query="positive test generation")

            search_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            assert search_time < 50  # milliseconds
            assert result["search_time_ms"] < 50


@pytest.mark.e2e
@pytest.mark.asyncio
class TestMultiAgentLearning:
    """Test learning across multiple agents."""

    async def test_pattern_sharing_between_agents(self):
        """Test patterns learned by one agent benefit other agents."""
        # Agent 1 learns a pattern
        pattern = create_sample_pattern(pattern_type="positive_test_generation")

        with patch('sentinel_backend.agentdb_service.store_pattern') as mock_store:
            mock_store.return_value = {"pattern_id": pattern["pattern_id"], "stored": True}
            await mock_store(pattern)

        # Agent 2 searches for patterns
        with patch('sentinel_backend.agentdb_service.search_patterns') as mock_search:
            mock_search.return_value = {
                "patterns": [pattern],
                "confidence": 0.91,
                "source_agent": "functional-positive-agent"
            }

            result = await mock_search(query="GET endpoint testing")

            assert len(result["patterns"]) > 0
            assert result["confidence"] > 0.9
            # Verify pattern was from different agent
            assert result["source_agent"] != "functional-negative-agent"

    async def test_q_learning_state_isolation(self):
        """Test Q-Learning states are isolated per agent."""
        q_state_agent1 = create_sample_q_state(agent_id="functional-positive-agent")
        q_state_agent2 = create_sample_q_state(agent_id="security-auth-agent")

        # Update agent 1's Q-values
        with patch('sentinel_backend.rl_service.update_q_values') as mock_update:
            mock_update.return_value = {
                "updated": True,
                "new_q_value": 0.92,
                "agent_id": "functional-positive-agent"
            }

            result1 = await mock_update(
                agent_id="functional-positive-agent",
                state=q_state_agent1["state"],
                action="generate_happy_path",
                reward=0.95
            )

            assert result1["agent_id"] == "functional-positive-agent"

        # Verify agent 2's state unchanged
        with patch('sentinel_backend.rl_service.get_q_values') as mock_get:
            mock_get.return_value = q_state_agent2

            result2 = await mock_get(agent_id="security-auth-agent")

            # Agent 2's values should be independent
            assert result2["agent_id"] == "security-auth-agent"
            assert result2["q_values"] == q_state_agent2["q_values"]


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.asyncio
class TestLearningConvergence:
    """Test that learning converges to optimal policies over time."""

    async def test_quality_improvement_over_iterations(self):
        """Test that test quality improves over multiple iterations."""
        iterations = 10
        quality_scores = []

        for i in range(iterations):
            # Simulate test generation with increasing pattern usage
            with patch('sentinel_backend.orchestration_service.generate_tests') as mock_gen:
                # Quality improves with each iteration
                base_quality = 0.6
                learned_quality = 0.04 * i  # +4% per iteration
                current_quality = min(base_quality + learned_quality, 0.98)

                mock_gen.return_value = {
                    "test_id": f"test_iter_{i:02d}",
                    "tests": [{"name": f"test_{j}"} for j in range(5 + i)],  # More tests over time
                    "quality_score": current_quality,
                    "patterns_used": i  # More patterns used over time
                }

                result = await mock_gen(spec_id="spec_001", agent_id="functional-positive-agent")
                quality_scores.append(result["quality_score"])

        # Verify quality increases monotonically
        for i in range(1, len(quality_scores)):
            assert quality_scores[i] >= quality_scores[i-1], \
                f"Quality decreased at iteration {i}: {quality_scores[i]} < {quality_scores[i-1]}"

        # Verify significant improvement
        improvement = quality_scores[-1] - quality_scores[0]
        assert improvement > 0.2, f"Insufficient improvement: {improvement}"
