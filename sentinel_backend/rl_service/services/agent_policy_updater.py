"""
Agent Policy Updater - Updates Q-Learning policies based on feedback rewards.

This module manages the Q-Learning policy for agents, updating Q-tables
when feedback is received and selecting optimal test generation strategies
based on API spec features.

State Space: API spec features (endpoint type, auth, parameters, etc.)
Action Space: Test generation strategies (positive, negative, boundary, etc.)
"""

from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import hashlib
import json
import logging
from enum import Enum

from ..algorithms.q_learning import QLearning

logger = logging.getLogger(__name__)


class TestStrategy(str, Enum):
    """Test generation strategies (action space)."""
    POSITIVE = "positive"  # Happy path tests
    NEGATIVE = "negative"  # Error/boundary tests
    BOUNDARY = "boundary"  # Edge cases
    SECURITY = "security"  # Security tests
    PERFORMANCE = "performance"  # Performance tests
    STATEFUL = "stateful"  # Multi-step workflows
    DATA_DRIVEN = "data_driven"  # Schema-based tests
    RANDOMIZED = "randomized"  # Fuzzing/random inputs


class AgentPolicyUpdater:
    """
    Manages Q-Learning policies for agents with feedback-based updates.
    """

    def __init__(
        self,
        q_learning: Optional[QLearning] = None,
        learning_rate: float = 0.1,
        discount_factor: float = 0.9,
        epsilon: float = 0.1,
        epsilon_decay: float = 0.995,
        min_epsilon: float = 0.01
    ):
        """
        Initialize agent policy updater.

        Args:
            q_learning: Optional pre-initialized Q-Learning instance
            learning_rate: Learning rate (alpha)
            discount_factor: Discount factor (gamma)
            epsilon: Initial exploration rate
            epsilon_decay: Epsilon decay rate
            min_epsilon: Minimum epsilon value
        """
        self.q_learning = q_learning or QLearning(
            learning_rate=learning_rate,
            discount_factor=discount_factor,
            epsilon=epsilon,
            epsilon_decay=epsilon_decay,
            min_epsilon=min_epsilon
        )

        # Map strategies to action IDs
        self.strategy_to_action = {
            strategy: idx
            for idx, strategy in enumerate(TestStrategy)
        }
        self.action_to_strategy = {
            idx: strategy
            for strategy, idx in self.strategy_to_action.items()
        }

        # Track strategy usage
        self.strategy_usage: Dict[str, int] = {
            strategy.value: 0 for strategy in TestStrategy
        }

        # Track Q-value updates
        self.update_count = 0

        logger.info(
            f"Initialized AgentPolicyUpdater with {len(TestStrategy)} strategies"
        )

    def encode_api_state(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str
    ) -> np.ndarray:
        """
        Encode API spec features into state vector.

        State space features:
        - HTTP method (one-hot: GET, POST, PUT, DELETE, PATCH)
        - Has path parameters (boolean)
        - Has query parameters (boolean)
        - Has request body (boolean)
        - Authentication type (one-hot: none, basic, bearer, oauth, api_key)
        - Resource type (categorical: CRUD indicators)
        - Response complexity (continuous: 0-1)

        Args:
            api_spec: Full API specification
            endpoint: Endpoint path
            method: HTTP method

        Returns:
            State vector (numpy array)
        """
        state_features = []

        # Feature 1-5: HTTP method (one-hot)
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        method_onehot = [1 if m == method.upper() else 0 for m in methods]
        state_features.extend(method_onehot)

        # Feature 6: Has path parameters
        has_path_params = "{" in endpoint or ":" in endpoint
        state_features.append(1 if has_path_params else 0)

        # Feature 7: Has query parameters
        endpoint_spec = self._get_endpoint_spec(api_spec, endpoint, method)
        has_query_params = bool(endpoint_spec.get("parameters", []))
        state_features.append(1 if has_query_params else 0)

        # Feature 8: Has request body
        has_body = "requestBody" in endpoint_spec or method.upper() in ["POST", "PUT", "PATCH"]
        state_features.append(1 if has_body else 0)

        # Feature 9-13: Authentication type (one-hot)
        auth_types = ["none", "basic", "bearer", "oauth", "api_key"]
        auth_type = self._detect_auth_type(api_spec, endpoint_spec)
        auth_onehot = [1 if a == auth_type else 0 for a in auth_types]
        state_features.extend(auth_onehot)

        # Feature 14-17: Resource type (CRUD indicators)
        is_create = method.upper() == "POST"
        is_read = method.upper() == "GET"
        is_update = method.upper() in ["PUT", "PATCH"]
        is_delete = method.upper() == "DELETE"
        state_features.extend([
            1 if is_create else 0,
            1 if is_read else 0,
            1 if is_update else 0,
            1 if is_delete else 0
        ])

        # Feature 18: Response complexity (0-1)
        response_complexity = self._calculate_response_complexity(endpoint_spec)
        state_features.append(response_complexity)

        # Convert to numpy array
        state_vector = np.array(state_features, dtype=np.float32)

        logger.debug(
            f"Encoded state: {endpoint} {method} -> {state_vector.shape[0]} features"
        )

        return state_vector

    def _get_endpoint_spec(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str
    ) -> Dict[str, Any]:
        """Extract endpoint specification from API spec."""
        paths = api_spec.get("paths", {})
        endpoint_data = paths.get(endpoint, {})
        return endpoint_data.get(method.lower(), {})

    def _detect_auth_type(
        self,
        api_spec: Dict[str, Any],
        endpoint_spec: Dict[str, Any]
    ) -> str:
        """Detect authentication type from API spec."""
        # Check global security
        security = api_spec.get("security", [])
        if not security:
            security = endpoint_spec.get("security", [])

        if not security:
            return "none"

        # Get first security scheme
        security_schemes = api_spec.get("components", {}).get("securitySchemes", {})

        for sec_req in security:
            for scheme_name in sec_req:
                scheme = security_schemes.get(scheme_name, {})
                scheme_type = scheme.get("type", "").lower()

                if scheme_type == "http":
                    scheme_name_lower = scheme.get("scheme", "").lower()
                    if "basic" in scheme_name_lower:
                        return "basic"
                    elif "bearer" in scheme_name_lower:
                        return "bearer"
                elif scheme_type == "oauth2":
                    return "oauth"
                elif scheme_type == "apikey":
                    return "api_key"

        return "none"

    def _calculate_response_complexity(
        self,
        endpoint_spec: Dict[str, Any]
    ) -> float:
        """
        Calculate response complexity score (0-1).

        Based on:
        - Number of response fields
        - Nesting depth
        - Array presence
        """
        responses = endpoint_spec.get("responses", {})

        if not responses:
            return 0.0

        # Get success response (200, 201, etc.)
        success_response = None
        for code in ["200", "201", "202"]:
            if code in responses:
                success_response = responses[code]
                break

        if not success_response:
            return 0.0

        # Get response schema
        content = success_response.get("content", {})
        schema = None

        for content_type in ["application/json", "application/xml"]:
            if content_type in content:
                schema = content[content_type].get("schema", {})
                break

        if not schema:
            return 0.0

        # Calculate complexity
        complexity = 0.0

        # Count properties
        properties = schema.get("properties", {})
        complexity += min(len(properties) / 20.0, 0.5)  # Max 0.5 for 20+ properties

        # Check for arrays (increases complexity)
        if schema.get("type") == "array" or any(
            p.get("type") == "array" for p in properties.values()
        ):
            complexity += 0.3

        # Check for nested objects
        if any(p.get("type") == "object" for p in properties.values()):
            complexity += 0.2

        return min(complexity, 1.0)

    def select_strategy(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        available_strategies: Optional[List[TestStrategy]] = None,
        mode: str = "exploit"
    ) -> Tuple[TestStrategy, Dict[str, Any]]:
        """
        Select best test generation strategy using Q-Learning.

        Args:
            api_spec: Full API specification
            endpoint: Endpoint path
            method: HTTP method
            available_strategies: Optional list of allowed strategies
            mode: "exploit" for greedy, "explore" for epsilon-greedy

        Returns:
            Tuple of (selected_strategy, metadata)
        """
        # Encode state
        state = self.encode_api_state(api_spec, endpoint, method)

        # Get available actions
        if available_strategies:
            available_actions = [
                self.strategy_to_action[s] for s in available_strategies
            ]
        else:
            available_actions = list(range(len(TestStrategy)))

        # Select action using Q-Learning
        action_id, metadata = self.q_learning.select_action(
            state=state,
            available_actions=available_actions,
            mode="train" if mode == "explore" else "eval"
        )

        # Convert action to strategy
        strategy = self.action_to_strategy[action_id]

        # Track usage
        self.strategy_usage[strategy.value] += 1

        logger.info(
            f"Selected strategy '{strategy.value}' for {endpoint} {method} "
            f"(Q-value: {metadata['selected_q_value']:.3f}, "
            f"exploration: {metadata.get('exploration', False)})"
        )

        return strategy, metadata

    def update_policy(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        strategy_used: TestStrategy,
        reward: float,
        next_api_spec: Optional[Dict[str, Any]] = None,
        next_endpoint: Optional[str] = None,
        next_method: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update Q-Learning policy based on feedback reward.

        Args:
            api_spec: API specification for current state
            endpoint: Endpoint path for current state
            method: HTTP method for current state
            strategy_used: Strategy that was used
            reward: Reward received from feedback
            next_api_spec: API spec for next state (if applicable)
            next_endpoint: Next endpoint (if applicable)
            next_method: Next method (if applicable)

        Returns:
            Dictionary of update metrics
        """
        # Encode current state
        state = self.encode_api_state(api_spec, endpoint, method)
        action = self.strategy_to_action[strategy_used]

        # Encode next state (or use current if no next state)
        if next_api_spec and next_endpoint and next_method:
            next_state = self.encode_api_state(next_api_spec, next_endpoint, next_method)
            done = False
        else:
            next_state = state
            done = True

        # Update Q-table
        update_metrics = self.q_learning.update(
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            done=done
        )

        self.update_count += 1

        logger.info(
            f"Updated policy: {endpoint} {method} -> {strategy_used.value} "
            f"(reward: {reward:+.2f}, Q: {update_metrics['current_q']:.2f} "
            f"-> {update_metrics['new_q']:.2f})"
        )

        return update_metrics

    def get_q_values_for_endpoint(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str
    ) -> Dict[str, float]:
        """
        Get Q-values for all strategies for a specific endpoint.

        Args:
            api_spec: API specification
            endpoint: Endpoint path
            method: HTTP method

        Returns:
            Dictionary mapping strategy name to Q-value
        """
        state = self.encode_api_state(api_spec, endpoint, method)
        available_actions = list(range(len(TestStrategy)))

        q_values = self.q_learning.get_q_values(state, available_actions)

        return {
            self.action_to_strategy[action].value: q_value
            for action, q_value in q_values.items()
        }

    def get_policy_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive policy statistics.

        Returns:
            Dictionary of statistics
        """
        q_stats = self.q_learning.get_statistics()

        return {
            "q_learning_stats": q_stats,
            "strategy_usage": self.strategy_usage,
            "total_updates": self.update_count,
            "exploration_rate": self.q_learning.epsilon,
            "q_table_size": len(self.q_learning.q_table),
            "most_used_strategy": max(
                self.strategy_usage.items(),
                key=lambda x: x[1]
            )[0] if self.strategy_usage else None
        }

    def get_best_strategies_by_context(
        self,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get top-k best strategies across all contexts.

        Args:
            top_k: Number of top strategies to return

        Returns:
            List of (state_hash, strategy, q_value) tuples
        """
        best_actions = self.q_learning.get_best_actions(top_k)

        return [
            {
                "state_hash": action["state_hash"],
                "strategy": self.action_to_strategy[action["action"]].value,
                "q_value": action["q_value"],
                "visit_count": action["visit_count"]
            }
            for action in best_actions
        ]

    def save_policy(self, path: str):
        """
        Save Q-Learning policy to disk.

        Args:
            path: Path to save policy
        """
        self.q_learning.save_model(path)
        logger.info(f"Saved policy to {path}")

    def load_policy(self, path: str):
        """
        Load Q-Learning policy from disk.

        Args:
            path: Path to load policy from
        """
        self.q_learning.load_model(path)
        logger.info(f"Loaded policy from {path}")

    def export_policy_for_db(self) -> List[Dict[str, Any]]:
        """
        Export policy data for database storage.

        Returns:
            List of policy entries for database
        """
        entries = self.q_learning.export_q_table_for_db()

        # Add strategy names
        for entry in entries:
            action_id = entry["action_id"]
            entry["strategy"] = self.action_to_strategy[action_id].value

        return entries

    def import_policy_from_db(self, entries: List[Dict[str, Any]]):
        """
        Import policy from database entries.

        Args:
            entries: List of policy entries from database
        """
        self.q_learning.import_q_table_from_db(entries)
        logger.info(f"Imported policy: {len(entries)} entries")
