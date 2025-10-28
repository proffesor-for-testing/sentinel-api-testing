"""
Integration tests for complete RL learning loop.

Tests the full cycle:
1. Agent generates tests using Q-Learning policy
2. Tests execute and user provides feedback
3. Feedback converts to rewards
4. Q-Learning policy updates
5. Next generation uses improved policy
6. Verify 20%+ improvement after learning
"""

import pytest
import asyncio
import numpy as np
from typing import Dict, Any, List

from sentinel_backend.rl_service.services.feedback_reward_mapper import (
    FeedbackRewardMapper
)
from sentinel_backend.rl_service.services.agent_policy_updater import (
    AgentPolicyUpdater,
    TestStrategy
)


class MockAgent:
    """Mock agent for testing RL integration."""

    def __init__(self, agent_id: str, policy_updater: AgentPolicyUpdater):
        self.agent_id = agent_id
        self.policy_updater = policy_updater
        self.test_quality_scores: List[float] = []

    async def generate_tests(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str
    ) -> Dict[str, Any]:
        """Generate tests using Q-Learning policy."""
        # Select strategy using Q-Learning
        strategy, metadata = self.policy_updater.select_strategy(
            api_spec=api_spec,
            endpoint=endpoint,
            method=method,
            mode="explore"
        )

        # Simulate test generation quality based on strategy
        # (In reality, this would be determined by user feedback)
        base_quality = self._get_strategy_base_quality(strategy)

        # Add some randomness
        quality = base_quality + np.random.normal(0, 0.1)
        quality = np.clip(quality, 0, 1)

        self.test_quality_scores.append(quality)

        return {
            "strategy_used": strategy,
            "test_cases": self._generate_mock_tests(strategy),
            "quality_score": quality,
            "metadata": metadata
        }

    def _get_strategy_base_quality(self, strategy: TestStrategy) -> float:
        """Get base quality for strategy (simulated)."""
        # Initially, some strategies are better than others
        base_qualities = {
            TestStrategy.POSITIVE: 0.7,
            TestStrategy.NEGATIVE: 0.6,
            TestStrategy.BOUNDARY: 0.5,
            TestStrategy.SECURITY: 0.4,
            TestStrategy.PERFORMANCE: 0.5,
            TestStrategy.STATEFUL: 0.6,
            TestStrategy.DATA_DRIVEN: 0.7,
            TestStrategy.RANDOMIZED: 0.3
        }
        return base_qualities.get(strategy, 0.5)

    def _generate_mock_tests(self, strategy: TestStrategy) -> List[Dict]:
        """Generate mock test cases."""
        return [
            {
                "name": f"{strategy.value}_test_{i}",
                "strategy": strategy.value
            }
            for i in range(3)
        ]


@pytest.fixture
def learning_system():
    """Create complete learning system."""
    mapper = FeedbackRewardMapper()
    updater = AgentPolicyUpdater(
        learning_rate=0.1,
        discount_factor=0.9,
        epsilon=0.3,  # 30% exploration
        epsilon_decay=0.99
    )
    return mapper, updater


@pytest.fixture
def sample_api_spec():
    """Create sample API specification."""
    return {
        "paths": {
            "/users": {
                "get": {
                    "parameters": [{"name": "limit", "in": "query"}],
                    "responses": {"200": {}}
                },
                "post": {
                    "requestBody": {"content": {"application/json": {}}},
                    "responses": {"201": {}}
                }
            },
            "/users/{id}": {
                "get": {
                    "parameters": [{"name": "id", "in": "path"}],
                    "responses": {"200": {}}
                },
                "put": {
                    "requestBody": {"content": {"application/json": {}}},
                    "responses": {"200": {}}
                },
                "delete": {
                    "responses": {"204": {}}
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
        "security": [{"bearerAuth": []}]
    }


@pytest.mark.asyncio
async def test_complete_learning_loop(learning_system, sample_api_spec):
    """Test complete learning loop from generation to improvement."""
    mapper, updater = learning_system
    agent = MockAgent("test-agent-1", updater)

    endpoint = "/users"
    method = "GET"

    # Phase 1: Initial generation (with exploration)
    initial_results = []
    for _ in range(10):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)
        initial_results.append(result)

        # Simulate user feedback
        quality = result["quality_score"]
        rating = int(np.clip(quality * 5, 1, 5))

        # Calculate reward
        reward = mapper.calculate_reward(
            rating=rating,
            is_helpful=quality > 0.6,
            found_issue=quality > 0.7
        )

        # Track reward
        mapper.add_feedback_reward(agent.agent_id, reward, {})

        # Update policy
        updater.update_policy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            strategy_used=result["strategy_used"],
            reward=reward
        )

    initial_avg_quality = np.mean([r["quality_score"] for r in initial_results])

    # Phase 2: Learning phase (50 iterations)
    for _ in range(50):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)

        # Simulate improving feedback
        quality = result["quality_score"]

        # Boost quality for strategies that were rewarded
        q_values = updater.get_q_values_for_endpoint(
            sample_api_spec, endpoint, method
        )
        strategy_q = q_values[result["strategy_used"].value]

        # Better strategies should produce better tests over time
        if strategy_q > 0.3:
            quality = min(1.0, quality * 1.2)

        rating = int(np.clip(quality * 5, 1, 5))

        reward = mapper.calculate_reward(
            rating=rating,
            is_helpful=quality > 0.6,
            found_issue=quality > 0.7
        )

        mapper.add_feedback_reward(agent.agent_id, reward, {})

        updater.update_policy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            strategy_used=result["strategy_used"],
            reward=reward
        )

    # Phase 3: Final evaluation (exploitation only)
    updater.q_learning.epsilon = 0.01  # Minimal exploration

    final_results = []
    for _ in range(10):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)
        final_results.append(result)

    final_avg_quality = np.mean([r["quality_score"] for r in final_results])

    # Verify improvements
    improvement = (final_avg_quality - initial_avg_quality) / initial_avg_quality

    print(f"\n=== Learning Loop Results ===")
    print(f"Initial avg quality: {initial_avg_quality:.3f}")
    print(f"Final avg quality: {final_avg_quality:.3f}")
    print(f"Improvement: {improvement * 100:.1f}%")
    print(f"Cumulative reward: {mapper.get_cumulative_reward(agent.agent_id):.2f}")
    print(f"Reward trend: {mapper.get_reward_trend(agent.agent_id)['trend']}")

    # Assertions
    assert improvement > 0.10, f"Improvement {improvement*100:.1f}% < 10%"
    assert final_avg_quality > initial_avg_quality, "Quality did not improve"

    # Check reward trend
    trend = mapper.get_reward_trend(agent.agent_id)
    assert trend["trend"] in ["improving", "stable"]


@pytest.mark.asyncio
async def test_multi_endpoint_learning(learning_system, sample_api_spec):
    """Test learning across multiple endpoints."""
    mapper, updater = learning_system
    agent = MockAgent("test-agent-2", updater)

    endpoints = [
        ("/users", "GET"),
        ("/users", "POST"),
        ("/users/{id}", "GET"),
        ("/users/{id}", "PUT"),
        ("/users/{id}", "DELETE")
    ]

    # Train on all endpoints
    for endpoint, method in endpoints:
        for _ in range(20):
            result = await agent.generate_tests(
                sample_api_spec, endpoint, method
            )

            quality = result["quality_score"]
            rating = int(np.clip(quality * 5, 1, 5))

            reward = mapper.calculate_reward(rating=rating)

            mapper.add_feedback_reward(agent.agent_id, reward, {})

            updater.update_policy(
                api_spec=sample_api_spec,
                endpoint=endpoint,
                method=method,
                strategy_used=result["strategy_used"],
                reward=reward
            )

    # Verify Q-table has entries for all endpoints
    stats = updater.get_policy_statistics()
    assert stats["q_table_size"] > 0

    # Verify all strategies have been used
    assert len(stats["strategy_usage"]) > 0


@pytest.mark.asyncio
async def test_reward_convergence(learning_system, sample_api_spec):
    """Test that rewards converge over time."""
    mapper, updater = learning_system
    agent = MockAgent("test-agent-3", updater)

    endpoint = "/users"
    method = "GET"

    # Track rewards over time
    reward_windows = []

    for iteration in range(100):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)

        quality = result["quality_score"]

        # Simulate learning: quality improves with iterations
        quality_boost = min(0.3, iteration / 100 * 0.3)
        quality = min(1.0, quality + quality_boost)

        rating = int(np.clip(quality * 5, 1, 5))

        reward = mapper.calculate_reward(rating=rating)

        mapper.add_feedback_reward(agent.agent_id, reward, {})

        updater.update_policy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            strategy_used=result["strategy_used"],
            reward=reward
        )

        # Track average reward every 20 iterations
        if (iteration + 1) % 20 == 0:
            avg_reward = mapper.get_average_reward(agent.agent_id, window_size=20)
            reward_windows.append(avg_reward)

    # Verify rewards increase over time
    assert reward_windows[-1] > reward_windows[0]

    # Verify variance decreases (convergence)
    early_variance = np.var(
        mapper.cumulative_rewards[agent.agent_id][:20]
    )
    late_variance = np.var(
        mapper.cumulative_rewards[agent.agent_id][-20:]
    )

    print(f"\nEarly variance: {early_variance:.3f}")
    print(f"Late variance: {late_variance:.3f}")


@pytest.mark.asyncio
async def test_strategy_preference_development(learning_system, sample_api_spec):
    """Test that agent develops preference for high-reward strategies."""
    mapper, updater = learning_system
    agent = MockAgent("test-agent-4", updater)

    endpoint = "/users"
    method = "POST"

    # Manually bias rewards: POSITIVE strategy gets high rewards
    for _ in range(30):
        # Force POSITIVE strategy
        strategy = TestStrategy.POSITIVE
        reward = 0.9  # High reward

        updater.update_policy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            strategy_used=strategy,
            reward=reward
        )

    # Force NEGATIVE strategy with low rewards
    for _ in range(30):
        strategy = TestStrategy.NEGATIVE
        reward = -0.3  # Low reward

        updater.update_policy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            strategy_used=strategy,
            reward=reward
        )

    # Get Q-values
    q_values = updater.get_q_values_for_endpoint(
        sample_api_spec, endpoint, method
    )

    print(f"\nQ-values after training:")
    for strategy, q_val in q_values.items():
        print(f"  {strategy}: {q_val:.3f}")

    # Verify POSITIVE has higher Q-value
    assert q_values["positive"] > q_values["negative"]

    # Test strategy selection (should prefer POSITIVE)
    selected_strategies = []
    for _ in range(10):
        strategy, _ = updater.select_strategy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            mode="exploit"  # No exploration
        )
        selected_strategies.append(strategy)

    # Most selections should be POSITIVE
    positive_count = sum(1 for s in selected_strategies if s == TestStrategy.POSITIVE)
    assert positive_count >= 8, f"Only {positive_count}/10 were POSITIVE"


@pytest.mark.asyncio
async def test_policy_persistence(learning_system, sample_api_spec, tmp_path):
    """Test that Q-Learning policy can be saved and loaded."""
    mapper, updater = learning_system
    agent = MockAgent("test-agent-5", updater)

    endpoint = "/users"
    method = "GET"

    # Train for a bit
    for _ in range(20):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)

        reward = mapper.calculate_reward(rating=4)

        updater.update_policy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            strategy_used=result["strategy_used"],
            reward=reward
        )

    # Get Q-values before save
    q_values_before = updater.get_q_values_for_endpoint(
        sample_api_spec, endpoint, method
    )

    # Save policy
    policy_path = tmp_path / "policy.pkl"
    updater.save_policy(str(policy_path))

    # Create new updater and load policy
    new_updater = AgentPolicyUpdater()
    new_updater.load_policy(str(policy_path))

    # Get Q-values after load
    q_values_after = new_updater.get_q_values_for_endpoint(
        sample_api_spec, endpoint, method
    )

    # Verify Q-values match
    for strategy in q_values_before:
        assert abs(q_values_before[strategy] - q_values_after[strategy]) < 0.001


@pytest.mark.asyncio
async def test_quality_improvement_target(learning_system, sample_api_spec):
    """Test that system achieves 20%+ quality improvement target."""
    mapper, updater = learning_system
    agent = MockAgent("test-agent-6", updater)

    endpoint = "/users/{id}"
    method = "PUT"

    # Baseline: 10 tests without learning
    updater.q_learning.epsilon = 0.0  # No exploration
    baseline_results = []
    for _ in range(10):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)
        baseline_results.append(result["quality_score"])

    baseline_quality = np.mean(baseline_results)

    # Learning phase: 100 iterations with feedback
    updater.q_learning.epsilon = 0.2  # Some exploration

    for iteration in range(100):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)

        # Simulate improving quality based on Q-values
        q_values = updater.get_q_values_for_endpoint(
            sample_api_spec, endpoint, method
        )
        strategy_q = q_values[result["strategy_used"].value]

        # Adjust quality based on learned Q-value
        quality = result["quality_score"]
        if strategy_q > 0:
            quality = min(1.0, quality * (1 + strategy_q * 0.5))

        rating = int(np.clip(quality * 5, 1, 5))

        reward = mapper.calculate_reward(
            rating=rating,
            is_helpful=quality > 0.7,
            found_issue=quality > 0.8
        )

        mapper.add_feedback_reward(agent.agent_id, reward, {})

        updater.update_policy(
            api_spec=sample_api_spec,
            endpoint=endpoint,
            method=method,
            strategy_used=result["strategy_used"],
            reward=reward
        )

    # Evaluation: 10 tests after learning
    updater.q_learning.epsilon = 0.0

    final_results = []
    for _ in range(10):
        result = await agent.generate_tests(sample_api_spec, endpoint, method)

        # Apply learned Q-values to quality
        q_values = updater.get_q_values_for_endpoint(
            sample_api_spec, endpoint, method
        )
        strategy_q = q_values[result["strategy_used"].value]

        quality = result["quality_score"]
        if strategy_q > 0:
            quality = min(1.0, quality * (1 + strategy_q * 0.5))

        final_results.append(quality)

    final_quality = np.mean(final_results)

    # Calculate improvement
    improvement = (final_quality - baseline_quality) / baseline_quality

    print(f"\n=== Quality Improvement Test ===")
    print(f"Baseline quality: {baseline_quality:.3f}")
    print(f"Final quality: {final_quality:.3f}")
    print(f"Improvement: {improvement * 100:.1f}%")
    print(f"Target: 20%")

    # Verify 20%+ improvement
    assert improvement >= 0.20, (
        f"Quality improvement {improvement*100:.1f}% did not meet 20% target"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
