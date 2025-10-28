"""
Unit tests for Q-Learning reward system.

Tests:
- Reward calculations from feedback
- Q-table updates
- Policy selection
- Exploration vs exploitation
- Cumulative reward tracking
"""

import pytest
import numpy as np
from unittest.mock import Mock, patch

from sentinel_backend.rl_service.services.feedback_reward_mapper import (
    FeedbackRewardMapper
)
from sentinel_backend.rl_service.services.agent_policy_updater import (
    AgentPolicyUpdater,
    TestStrategy
)
from sentinel_backend.rl_service.algorithms.q_learning import QLearning


class TestFeedbackRewardMapper:
    """Tests for FeedbackRewardMapper."""

    @pytest.fixture
    def mapper(self):
        """Create FeedbackRewardMapper instance."""
        return FeedbackRewardMapper()

    def test_reward_calculation_5_star_helpful(self, mapper):
        """Test reward for 5-star rating + helpful flag."""
        reward = mapper.calculate_reward(
            rating=5,
            is_helpful=True,
            found_issue=False,
            not_helpful=False
        )
        # Expected: 1.0 (5-star) + 0.3 (helpful) = 1.3, clamped to 1.0
        assert reward == 1.0

    def test_reward_calculation_5_star_found_issue(self, mapper):
        """Test reward for 5-star rating + found issue."""
        reward = mapper.calculate_reward(
            rating=5,
            is_helpful=False,
            found_issue=True,
            not_helpful=False
        )
        # Expected: 1.0 (5-star) + 0.3 (found issue) = 1.3, clamped to 1.0
        assert reward == 1.0

    def test_reward_calculation_4_star(self, mapper):
        """Test reward for 4-star rating."""
        reward = mapper.calculate_reward(
            rating=4,
            is_helpful=False,
            found_issue=False,
            not_helpful=False
        )
        assert reward == 0.5

    def test_reward_calculation_3_star_neutral(self, mapper):
        """Test reward for 3-star rating (neutral)."""
        reward = mapper.calculate_reward(
            rating=3,
            is_helpful=False,
            found_issue=False,
            not_helpful=False
        )
        assert reward == 0.0

    def test_reward_calculation_2_star(self, mapper):
        """Test reward for 2-star rating."""
        reward = mapper.calculate_reward(
            rating=2,
            is_helpful=False,
            found_issue=False,
            not_helpful=False
        )
        assert reward == -0.3

    def test_reward_calculation_1_star(self, mapper):
        """Test reward for 1-star rating."""
        reward = mapper.calculate_reward(
            rating=1,
            is_helpful=False,
            found_issue=False,
            not_helpful=False
        )
        assert reward == -0.5

    def test_reward_calculation_not_helpful_penalty(self, mapper):
        """Test penalty for not helpful flag."""
        reward = mapper.calculate_reward(
            rating=4,
            is_helpful=False,
            found_issue=False,
            not_helpful=True
        )
        # Expected: 0.5 (4-star) - 0.3 (not helpful) = 0.2
        assert reward == 0.2

    def test_reward_calculation_with_execution_result(self, mapper):
        """Test reward with execution result."""
        execution_result = {
            "status": "passed",
            "execution_time_ms": 500,
            "found_bug": False
        }

        reward = mapper.calculate_reward(
            rating=4,
            is_helpful=False,
            found_issue=False,
            not_helpful=False,
            execution_result=execution_result
        )
        # Expected: 0.5 (4-star) + 0.1 (passed) + 0.05 (fast) = 0.65
        assert reward == 0.65

    def test_reward_calculation_clamping_positive(self, mapper):
        """Test reward clamping at maximum."""
        reward = mapper.calculate_reward(
            rating=5,
            is_helpful=True,
            found_issue=True,
            not_helpful=False
        )
        # Would be 1.0 + 0.3 + 0.3 = 1.6, but clamped to 1.0
        assert reward == 1.0

    def test_reward_calculation_clamping_negative(self, mapper):
        """Test reward clamping at minimum."""
        reward = mapper.calculate_reward(
            rating=1,
            is_helpful=False,
            found_issue=False,
            not_helpful=True
        )
        # Would be -0.5 - 0.3 = -0.8
        assert reward == -0.8
        assert reward >= -1.0  # Within clamp range

    def test_cumulative_reward_tracking(self, mapper):
        """Test cumulative reward tracking."""
        agent_id = "test-agent-1"

        # Add multiple rewards
        mapper.add_feedback_reward(agent_id, 0.8, {"test": 1})
        mapper.add_feedback_reward(agent_id, 0.5, {"test": 2})
        mapper.add_feedback_reward(agent_id, -0.3, {"test": 3})

        cumulative = mapper.get_cumulative_reward(agent_id)
        assert cumulative == pytest.approx(1.0, abs=0.01)

    def test_average_reward_calculation(self, mapper):
        """Test average reward calculation."""
        agent_id = "test-agent-2"

        mapper.add_feedback_reward(agent_id, 0.8, {})
        mapper.add_feedback_reward(agent_id, 0.6, {})
        mapper.add_feedback_reward(agent_id, 0.4, {})

        average = mapper.get_average_reward(agent_id)
        assert average == pytest.approx(0.6, abs=0.01)

    def test_reward_trend_improving(self, mapper):
        """Test reward trend detection (improving)."""
        agent_id = "test-agent-3"

        # Add increasing rewards
        for i in range(10):
            mapper.add_feedback_reward(agent_id, i * 0.1, {})

        trend = mapper.get_reward_trend(agent_id)
        assert trend["trend"] == "improving"
        assert trend["slope"] > 0

    def test_reward_trend_declining(self, mapper):
        """Test reward trend detection (declining)."""
        agent_id = "test-agent-4"

        # Add decreasing rewards
        for i in range(10):
            mapper.add_feedback_reward(agent_id, 1.0 - i * 0.1, {})

        trend = mapper.get_reward_trend(agent_id)
        assert trend["trend"] == "declining"
        assert trend["slope"] < 0

    def test_reward_trend_stable(self, mapper):
        """Test reward trend detection (stable)."""
        agent_id = "test-agent-5"

        # Add stable rewards
        for _ in range(10):
            mapper.add_feedback_reward(agent_id, 0.5, {})

        trend = mapper.get_reward_trend(agent_id)
        assert trend["trend"] == "stable"
        assert abs(trend["slope"]) < 0.1


class TestAgentPolicyUpdater:
    """Tests for AgentPolicyUpdater."""

    @pytest.fixture
    def policy_updater(self):
        """Create AgentPolicyUpdater instance."""
        return AgentPolicyUpdater(epsilon=0.1)

    @pytest.fixture
    def sample_api_spec(self):
        """Create sample API specification."""
        return {
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "limit", "in": "query"}
                        ],
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "id": {"type": "integer"},
                                                    "name": {"type": "string"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {}
                        }
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            },
            "security": [
                {"bearerAuth": []}
            ]
        }

    def test_state_encoding_get_request(self, policy_updater, sample_api_spec):
        """Test state encoding for GET request."""
        state = policy_updater.encode_api_state(
            api_spec=sample_api_spec,
            endpoint="/users",
            method="GET"
        )

        assert isinstance(state, np.ndarray)
        assert state.shape[0] == 18  # 18 features
        assert state[0] == 1  # GET method one-hot

    def test_state_encoding_post_request(self, policy_updater, sample_api_spec):
        """Test state encoding for POST request."""
        state = policy_updater.encode_api_state(
            api_spec=sample_api_spec,
            endpoint="/users",
            method="POST"
        )

        assert state[1] == 1  # POST method one-hot
        assert state[7] == 1  # Has request body

    def test_strategy_selection_exploit(self, policy_updater, sample_api_spec):
        """Test strategy selection in exploit mode."""
        # Train a bit first
        state = policy_updater.encode_api_state(
            sample_api_spec, "/users", "GET"
        )
        policy_updater.q_learning.set_q_value(
            state,
            policy_updater.strategy_to_action[TestStrategy.POSITIVE],
            0.9
        )

        # Select strategy (exploit)
        strategy, metadata = policy_updater.select_strategy(
            api_spec=sample_api_spec,
            endpoint="/users",
            method="GET",
            mode="exploit"
        )

        assert strategy == TestStrategy.POSITIVE
        assert metadata["selected_q_value"] == 0.9

    def test_strategy_selection_explore(self, policy_updater, sample_api_spec):
        """Test strategy selection in explore mode."""
        # Set high epsilon for exploration
        policy_updater.q_learning.epsilon = 0.5

        strategy, metadata = policy_updater.select_strategy(
            api_spec=sample_api_spec,
            endpoint="/users",
            method="GET",
            mode="explore"
        )

        assert isinstance(strategy, TestStrategy)
        assert "exploration" in metadata

    def test_policy_update_positive_reward(self, policy_updater, sample_api_spec):
        """Test policy update with positive reward."""
        initial_state = policy_updater.encode_api_state(
            sample_api_spec, "/users", "GET"
        )
        initial_q = policy_updater.q_learning.get_q_value(
            initial_state,
            policy_updater.strategy_to_action[TestStrategy.POSITIVE]
        )

        # Update with positive reward
        update_metrics = policy_updater.update_policy(
            api_spec=sample_api_spec,
            endpoint="/users",
            method="GET",
            strategy_used=TestStrategy.POSITIVE,
            reward=0.8
        )

        assert update_metrics["new_q"] > initial_q
        assert update_metrics["reward"] == 0.8

    def test_policy_update_negative_reward(self, policy_updater, sample_api_spec):
        """Test policy update with negative reward."""
        # Set initial positive Q-value
        state = policy_updater.encode_api_state(
            sample_api_spec, "/users", "GET"
        )
        policy_updater.q_learning.set_q_value(
            state,
            policy_updater.strategy_to_action[TestStrategy.NEGATIVE],
            0.5
        )

        # Update with negative reward
        update_metrics = policy_updater.update_policy(
            api_spec=sample_api_spec,
            endpoint="/users",
            method="GET",
            strategy_used=TestStrategy.NEGATIVE,
            reward=-0.5
        )

        assert update_metrics["new_q"] < 0.5
        assert update_metrics["reward"] == -0.5

    def test_q_values_for_endpoint(self, policy_updater, sample_api_spec):
        """Test getting Q-values for all strategies."""
        q_values = policy_updater.get_q_values_for_endpoint(
            api_spec=sample_api_spec,
            endpoint="/users",
            method="GET"
        )

        assert len(q_values) == len(TestStrategy)
        assert all(isinstance(v, float) for v in q_values.values())

    def test_policy_statistics(self, policy_updater, sample_api_spec):
        """Test policy statistics retrieval."""
        # Do some updates
        for i in range(5):
            policy_updater.update_policy(
                api_spec=sample_api_spec,
                endpoint="/users",
                method="GET",
                strategy_used=TestStrategy.POSITIVE,
                reward=0.5
            )

        stats = policy_updater.get_policy_statistics()

        assert stats["total_updates"] == 5
        assert "q_learning_stats" in stats
        assert "strategy_usage" in stats


class TestQLearningIntegration:
    """Integration tests for Q-Learning with reward mapper."""

    @pytest.fixture
    def integrated_system(self):
        """Create integrated system with mapper and updater."""
        mapper = FeedbackRewardMapper()
        updater = AgentPolicyUpdater(epsilon=0.1)
        return mapper, updater

    @pytest.fixture
    def sample_api_spec(self):
        """Create sample API specification."""
        return {
            "paths": {
                "/api/test": {
                    "get": {
                        "responses": {"200": {}}
                    }
                }
            }
        }

    def test_full_learning_loop(self, integrated_system, sample_api_spec):
        """Test complete learning loop: feedback -> reward -> policy update."""
        mapper, updater = integrated_system
        agent_id = "test-agent"

        # Simulate 100 iterations of learning
        initial_avg_q = []
        final_avg_q = []

        for iteration in range(100):
            # Select strategy
            strategy, _ = updater.select_strategy(
                api_spec=sample_api_spec,
                endpoint="/api/test",
                method="GET",
                mode="explore" if iteration < 50 else "exploit"
            )

            # Simulate feedback (improving over time)
            rating = min(5, 3 + iteration // 25)
            is_helpful = iteration > 30

            # Calculate reward
            reward = mapper.calculate_reward(
                rating=rating,
                is_helpful=is_helpful,
                found_issue=False
            )

            # Track reward
            mapper.add_feedback_reward(agent_id, reward, {})

            # Update policy
            updater.update_policy(
                api_spec=sample_api_spec,
                endpoint="/api/test",
                method="GET",
                strategy_used=strategy,
                reward=reward
            )

            # Track Q-values
            if iteration == 10:
                q_vals = updater.get_q_values_for_endpoint(
                    sample_api_spec, "/api/test", "GET"
                )
                initial_avg_q = np.mean(list(q_vals.values()))
            elif iteration == 99:
                q_vals = updater.get_q_values_for_endpoint(
                    sample_api_spec, "/api/test", "GET"
                )
                final_avg_q = np.mean(list(q_vals.values()))

        # Verify learning occurred
        trend = mapper.get_reward_trend(agent_id)
        assert trend["trend"] in ["improving", "stable"]

        # Verify Q-values improved
        assert final_avg_q > initial_avg_q

        # Verify cumulative reward is positive
        cumulative = mapper.get_cumulative_reward(agent_id)
        assert cumulative > 0

    def test_exploration_vs_exploitation(self, integrated_system, sample_api_spec):
        """Test that exploration decreases over time."""
        mapper, updater = integrated_system

        # Track exploration rate
        exploration_rates = []

        for i in range(50):
            exploration_rates.append(updater.q_learning.epsilon)

            # Do an update (epsilon decays)
            updater.update_policy(
                api_spec=sample_api_spec,
                endpoint="/api/test",
                method="GET",
                strategy_used=TestStrategy.POSITIVE,
                reward=0.5
            )

        # Verify epsilon decays
        assert exploration_rates[-1] < exploration_rates[0]
        assert updater.q_learning.epsilon >= updater.q_learning.min_epsilon

    def test_strategy_preference_develops(self, integrated_system, sample_api_spec):
        """Test that agent develops preference for rewarded strategies."""
        mapper, updater = integrated_system

        # Strongly reward POSITIVE strategy
        state = updater.encode_api_state(
            sample_api_spec, "/api/test", "GET"
        )

        for _ in range(20):
            updater.update_policy(
                api_spec=sample_api_spec,
                endpoint="/api/test",
                method="GET",
                strategy_used=TestStrategy.POSITIVE,
                reward=0.9
            )

        # Penalize NEGATIVE strategy
        for _ in range(20):
            updater.update_policy(
                api_spec=sample_api_spec,
                endpoint="/api/test",
                method="GET",
                strategy_used=TestStrategy.NEGATIVE,
                reward=-0.5
            )

        # Get Q-values
        q_values = updater.get_q_values_for_endpoint(
            sample_api_spec, "/api/test", "GET"
        )

        # POSITIVE should have higher Q-value than NEGATIVE
        assert q_values["positive"] > q_values["negative"]


@pytest.mark.benchmark
class TestPerformance:
    """Performance benchmarks for Q-Learning system."""

    def test_reward_calculation_performance(self, benchmark):
        """Benchmark reward calculation speed."""
        mapper = FeedbackRewardMapper()

        def calculate():
            return mapper.calculate_reward(
                rating=4,
                is_helpful=True,
                found_issue=False
            )

        result = benchmark(calculate)
        assert result >= 0

    def test_state_encoding_performance(self, benchmark):
        """Benchmark state encoding speed."""
        updater = AgentPolicyUpdater()
        api_spec = {"paths": {"/test": {"get": {}}}}

        def encode():
            return updater.encode_api_state(api_spec, "/test", "GET")

        result = benchmark(encode)
        assert isinstance(result, np.ndarray)

    def test_policy_update_performance(self, benchmark):
        """Benchmark policy update speed."""
        updater = AgentPolicyUpdater()
        api_spec = {"paths": {"/test": {"get": {}}}}

        def update():
            return updater.update_policy(
                api_spec=api_spec,
                endpoint="/test",
                method="GET",
                strategy_used=TestStrategy.POSITIVE,
                reward=0.5
            )

        result = benchmark(update)
        assert "new_q" in result
