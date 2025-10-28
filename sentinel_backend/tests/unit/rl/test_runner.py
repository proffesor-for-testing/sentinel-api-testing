"""
Simple test runner for Q-Learning reward system tests.

Runs tests without needing full pytest infrastructure.
"""

import sys
import os

# Add sentinel_backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

import asyncio
import numpy as np

from sentinel_backend.rl_service.services.feedback_reward_mapper import (
    FeedbackRewardMapper
)
from sentinel_backend.rl_service.services.agent_policy_updater import (
    AgentPolicyUpdater,
    TestStrategy
)


def test_feedback_reward_mapper():
    """Test FeedbackRewardMapper functionality."""
    print("\n=== Testing FeedbackRewardMapper ===")

    mapper = FeedbackRewardMapper()

    # Test 1: 5-star + helpful
    reward = mapper.calculate_reward(rating=5, is_helpful=True)
    assert reward == 1.0, f"Expected 1.0, got {reward}"
    print("✓ Test 1: 5-star + helpful = 1.0")

    # Test 2: 4-star
    reward = mapper.calculate_reward(rating=4)
    assert reward == 0.5, f"Expected 0.5, got {reward}"
    print("✓ Test 2: 4-star = 0.5")

    # Test 3: 3-star neutral
    reward = mapper.calculate_reward(rating=3)
    assert reward == 0.0, f"Expected 0.0, got {reward}"
    print("✓ Test 3: 3-star = 0.0")

    # Test 4: 1-star
    reward = mapper.calculate_reward(rating=1)
    assert reward == -0.5, f"Expected -0.5, got {reward}"
    print("✓ Test 4: 1-star = -0.5")

    # Test 5: Cumulative rewards
    agent_id = "test-agent"
    mapper.add_feedback_reward(agent_id, 0.8, {})
    mapper.add_feedback_reward(agent_id, 0.5, {})
    mapper.add_feedback_reward(agent_id, -0.3, {})

    cumulative = mapper.get_cumulative_reward(agent_id)
    expected = 1.0
    assert abs(cumulative - expected) < 0.01, f"Expected {expected}, got {cumulative}"
    print(f"✓ Test 5: Cumulative reward = {cumulative:.2f}")

    # Test 6: Average reward
    average = mapper.get_average_reward(agent_id)
    expected_avg = 1.0 / 3
    assert abs(average - expected_avg) < 0.01, f"Expected {expected_avg:.2f}, got {average:.2f}"
    print(f"✓ Test 6: Average reward = {average:.2f}")

    # Test 7: Reward trend
    agent_id2 = "test-agent-2"
    for i in range(20):
        mapper.add_feedback_reward(agent_id2, i * 0.05, {})

    trend = mapper.get_reward_trend(agent_id2)
    assert trend["trend"] in ["improving", "stable"], f"Expected improving/stable, got {trend['trend']}"
    assert trend["slope"] >= -0.1, f"Expected non-negative slope, got {trend['slope']}"
    print(f"✓ Test 7: Reward trend = {trend['trend']} (slope: {trend['slope']:.3f})")

    print("\n✅ All FeedbackRewardMapper tests passed!")


def test_agent_policy_updater():
    """Test AgentPolicyUpdater functionality."""
    print("\n=== Testing AgentPolicyUpdater ===")

    updater = AgentPolicyUpdater(epsilon=0.1)

    sample_api_spec = {
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
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
        "security": [{"bearerAuth": []}]
    }

    # Test 1: State encoding
    state = updater.encode_api_state(sample_api_spec, "/users", "GET")
    assert isinstance(state, np.ndarray), "State should be numpy array"
    assert state.shape[0] == 18, f"Expected 18 features, got {state.shape[0]}"
    assert state[0] == 1, "First feature should be 1 (GET method)"
    print(f"✓ Test 1: State encoding = {state.shape[0]} features")

    # Test 2: Strategy selection
    strategy, metadata = updater.select_strategy(
        api_spec=sample_api_spec,
        endpoint="/users",
        method="GET",
        mode="exploit"
    )
    assert isinstance(strategy, TestStrategy), "Should return TestStrategy"
    assert "selected_q_value" in metadata, "Should include Q-value"
    print(f"✓ Test 2: Strategy selection = {strategy.value}")

    # Test 3: Policy update with positive reward
    initial_state = updater.encode_api_state(sample_api_spec, "/users", "GET")
    initial_q = updater.q_learning.get_q_value(
        initial_state,
        updater.strategy_to_action[TestStrategy.POSITIVE]
    )

    update_metrics = updater.update_policy(
        api_spec=sample_api_spec,
        endpoint="/users",
        method="GET",
        strategy_used=TestStrategy.POSITIVE,
        reward=0.8
    )

    assert update_metrics["new_q"] > initial_q, "Q-value should increase with positive reward"
    assert update_metrics["reward"] == 0.8, "Reward should match"
    print(f"✓ Test 3: Policy update = Q: {initial_q:.3f} → {update_metrics['new_q']:.3f}")

    # Test 4: Q-values for endpoint
    q_values = updater.get_q_values_for_endpoint(
        sample_api_spec, "/users", "GET"
    )
    assert len(q_values) == len(TestStrategy), f"Should have {len(TestStrategy)} Q-values"
    print(f"✓ Test 4: Q-values retrieved = {len(q_values)} strategies")

    # Test 5: Policy statistics
    stats = updater.get_policy_statistics()
    assert "q_learning_stats" in stats, "Should include Q-learning stats"
    assert "strategy_usage" in stats, "Should include strategy usage"
    assert stats["total_updates"] > 0, "Should have updates"
    print(f"✓ Test 5: Policy stats = {stats['total_updates']} updates")

    print("\n✅ All AgentPolicyUpdater tests passed!")


async def test_integration():
    """Test complete learning loop integration."""
    print("\n=== Testing Complete Learning Loop ===")

    mapper = FeedbackRewardMapper()
    updater = AgentPolicyUpdater(epsilon=0.3)

    api_spec = {
        "paths": {
            "/api/test": {
                "get": {"responses": {"200": {}}}
            }
        }
    }

    agent_id = "integration-test-agent"

    # Simulate 50 iterations
    print("Running 50 learning iterations...")

    initial_q_values = []
    final_q_values = []

    for iteration in range(50):
        # Select strategy
        strategy, metadata = updater.select_strategy(
            api_spec=api_spec,
            endpoint="/api/test",
            method="GET",
            mode="explore"
        )

        # Simulate improving feedback
        rating = min(5, 3 + iteration // 15)
        is_helpful = iteration > 20

        # Calculate reward
        reward = mapper.calculate_reward(
            rating=rating,
            is_helpful=is_helpful
        )

        # Track reward
        mapper.add_feedback_reward(agent_id, reward, {})

        # Update policy
        updater.update_policy(
            api_spec=api_spec,
            endpoint="/api/test",
            method="GET",
            strategy_used=strategy,
            reward=reward
        )

        # Track Q-values
        if iteration == 5:
            q_vals = updater.get_q_values_for_endpoint(
                api_spec, "/api/test", "GET"
            )
            initial_q_values = list(q_vals.values())
        elif iteration == 49:
            q_vals = updater.get_q_values_for_endpoint(
                api_spec, "/api/test", "GET"
            )
            final_q_values = list(q_vals.values())

    # Verify learning
    trend = mapper.get_reward_trend(agent_id)
    cumulative = mapper.get_cumulative_reward(agent_id)

    initial_avg_q = np.mean(initial_q_values)
    final_avg_q = np.mean(final_q_values)
    q_improvement = (final_avg_q - initial_avg_q) / abs(initial_avg_q) if initial_avg_q != 0 else 0

    print(f"\nResults:")
    print(f"  Cumulative reward: {cumulative:.2f}")
    print(f"  Reward trend: {trend['trend']}")
    print(f"  Initial avg Q-value: {initial_avg_q:.3f}")
    print(f"  Final avg Q-value: {final_avg_q:.3f}")
    print(f"  Q-value improvement: {q_improvement * 100:.1f}%")

    assert trend["trend"] in ["improving", "stable"], f"Unexpected trend: {trend['trend']}"
    assert final_avg_q > initial_avg_q, "Q-values should improve"
    assert cumulative > 0, "Cumulative reward should be positive"

    print("\n✅ Integration test passed!")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Q-Learning Reward System Test Suite")
    print("=" * 60)

    try:
        # Unit tests
        test_feedback_reward_mapper()
        test_agent_policy_updater()

        # Integration test
        asyncio.run(test_integration())

        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        return 0

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
