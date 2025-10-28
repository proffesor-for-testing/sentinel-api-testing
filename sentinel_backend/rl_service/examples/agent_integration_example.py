"""
Example: Integrating Q-Learning policies into agents.

This example shows how to modify an agent to use Q-Learning policies
for test generation strategy selection.
"""

from typing import Dict, Any, List
import logging

from sentinel_backend.rl_service.services.agent_policy_updater import (
    AgentPolicyUpdater,
    TestStrategy
)
from sentinel_backend.orchestration_service.agents.base_agent import (
    BaseAgent,
    AgentTask,
    AgentResult
)

logger = logging.getLogger(__name__)


class QLearningEnhancedAgent(BaseAgent):
    """
    Example agent enhanced with Q-Learning policy.

    This agent uses Q-Learning to select the best test generation
    strategy based on API spec features and learned rewards.
    """

    def __init__(
        self,
        agent_type: str,
        policy_updater: AgentPolicyUpdater
    ):
        """
        Initialize agent with Q-Learning policy.

        Args:
            agent_type: Agent identifier
            policy_updater: Q-Learning policy updater instance
        """
        super().__init__(agent_type)
        self.policy_updater = policy_updater
        self.logger = logging.getLogger(f"agent.{agent_type}.qlearning")

    async def execute(
        self,
        task: AgentTask,
        api_spec: Dict[str, Any]
    ) -> AgentResult:
        """
        Execute task with Q-Learning strategy selection.

        Args:
            task: Agent task
            api_spec: API specification

        Returns:
            Agent result with generated tests
        """
        test_cases = []

        # Iterate over endpoints in API spec
        for endpoint_path, methods in api_spec.get("paths", {}).items():
            for method, endpoint_spec in methods.items():
                # Use Q-Learning to select strategy
                strategy, metadata = self.policy_updater.select_strategy(
                    api_spec=api_spec,
                    endpoint=endpoint_path,
                    method=method.upper(),
                    mode="exploit"  # Use learned policy
                )

                self.logger.info(
                    f"Selected strategy '{strategy.value}' for {endpoint_path} {method} "
                    f"(Q-value: {metadata['selected_q_value']:.3f})"
                )

                # Generate tests using selected strategy
                endpoint_tests = await self._generate_tests_with_strategy(
                    endpoint_path=endpoint_path,
                    method=method.upper(),
                    endpoint_spec=endpoint_spec,
                    strategy=strategy,
                    api_spec=api_spec
                )

                # Store strategy metadata in each test
                for test in endpoint_tests:
                    test["metadata"] = test.get("metadata", {})
                    test["metadata"]["strategy_used"] = strategy.value
                    test["metadata"]["q_value"] = metadata["selected_q_value"]
                    test["metadata"]["exploration"] = metadata.get("exploration", False)

                test_cases.extend(endpoint_tests)

        return AgentResult(
            task_id=task.task_id,
            agent_type=self.agent_type,
            status="success",
            test_cases=test_cases,
            metadata={
                "total_tests": len(test_cases),
                "policy_stats": self.policy_updater.get_policy_statistics()
            }
        )

    async def _generate_tests_with_strategy(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any],
        strategy: TestStrategy,
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate tests using specific strategy.

        Args:
            endpoint_path: Endpoint path
            method: HTTP method
            endpoint_spec: Endpoint specification
            strategy: Test generation strategy
            api_spec: Full API spec

        Returns:
            List of generated test cases
        """
        if strategy == TestStrategy.POSITIVE:
            return await self._generate_positive_tests(
                endpoint_path, method, endpoint_spec
            )
        elif strategy == TestStrategy.NEGATIVE:
            return await self._generate_negative_tests(
                endpoint_path, method, endpoint_spec
            )
        elif strategy == TestStrategy.BOUNDARY:
            return await self._generate_boundary_tests(
                endpoint_path, method, endpoint_spec
            )
        elif strategy == TestStrategy.SECURITY:
            return await self._generate_security_tests(
                endpoint_path, method, endpoint_spec
            )
        elif strategy == TestStrategy.PERFORMANCE:
            return await self._generate_performance_tests(
                endpoint_path, method, endpoint_spec
            )
        elif strategy == TestStrategy.STATEFUL:
            return await self._generate_stateful_tests(
                endpoint_path, method, endpoint_spec, api_spec
            )
        elif strategy == TestStrategy.DATA_DRIVEN:
            return await self._generate_data_driven_tests(
                endpoint_path, method, endpoint_spec
            )
        elif strategy == TestStrategy.RANDOMIZED:
            return await self._generate_randomized_tests(
                endpoint_path, method, endpoint_spec
            )
        else:
            self.logger.warning(f"Unknown strategy: {strategy}, using positive")
            return await self._generate_positive_tests(
                endpoint_path, method, endpoint_spec
            )

    async def _generate_positive_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate happy path tests."""
        return [
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Valid {method} request to {endpoint_path}",
                expected_status=200
            )
        ]

    async def _generate_negative_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate error handling tests."""
        tests = []

        # Missing required parameters
        tests.append(
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Missing required parameters for {endpoint_path}",
                expected_status=400
            )
        )

        # Invalid data types
        tests.append(
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Invalid data types for {endpoint_path}",
                body={"invalid": "data"},
                expected_status=400
            )
        )

        return tests

    async def _generate_boundary_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate boundary value tests."""
        return [
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Boundary test: maximum values",
                expected_status=200
            ),
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Boundary test: minimum values",
                expected_status=200
            )
        ]

    async def _generate_security_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate security tests."""
        return [
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Security test: unauthorized access",
                expected_status=401
            ),
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Security test: BOLA attempt",
                expected_status=403
            )
        ]

    async def _generate_performance_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate performance tests."""
        return [
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Performance test: response time < 500ms",
                expected_status=200
            )
        ]

    async def _generate_stateful_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate multi-step workflow tests."""
        return [
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Workflow step for {endpoint_path}",
                expected_status=200
            )
        ]

    async def _generate_data_driven_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate schema-based tests."""
        return [
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Schema validation test",
                expected_status=200
            )
        ]

    async def _generate_randomized_tests(
        self,
        endpoint_path: str,
        method: str,
        endpoint_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate fuzzing tests."""
        return [
            self._create_test_case(
                endpoint=endpoint_path,
                method=method,
                description=f"Fuzzing test with random data",
                expected_status=200
            )
        ]


# Example usage
async def main():
    """Example usage of Q-Learning enhanced agent."""
    from sentinel_backend.rl_service.services.feedback_reward_mapper import (
        FeedbackRewardMapper
    )

    # Initialize services
    feedback_mapper = FeedbackRewardMapper()
    policy_updater = AgentPolicyUpdater(
        learning_rate=0.1,
        discount_factor=0.9,
        epsilon=0.1  # 10% exploration
    )

    # Create agent
    agent = QLearningEnhancedAgent(
        agent_type="functional-positive",
        policy_updater=policy_updater
    )

    # Sample API spec
    api_spec = {
        "paths": {
            "/users": {
                "get": {"responses": {"200": {}}},
                "post": {"responses": {"201": {}}}
            }
        }
    }

    # Create task
    task = AgentTask(
        task_id="test-task-1",
        spec_id=1,
        agent_type="functional-positive"
    )

    # Execute agent
    result = await agent.execute(task, api_spec)

    print(f"Generated {len(result.test_cases)} tests")
    print(f"Strategies used:")
    for test in result.test_cases:
        strategy = test["metadata"]["strategy_used"]
        q_value = test["metadata"]["q_value"]
        print(f"  - {test['description']}: {strategy} (Q={q_value:.3f})")

    # Simulate user feedback
    for test in result.test_cases:
        # Assume tests get good ratings
        reward = feedback_mapper.calculate_reward(
            rating=5,
            is_helpful=True
        )

        # Update policy
        strategy_name = test["metadata"]["strategy_used"]
        strategy = TestStrategy(strategy_name)

        policy_updater.update_policy(
            api_spec=api_spec,
            endpoint=test["endpoint"],
            method=test["method"],
            strategy_used=strategy,
            reward=reward
        )

    print(f"\nPolicy updated. Cumulative reward: "
          f"{feedback_mapper.get_cumulative_reward('functional-positive'):.2f}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
