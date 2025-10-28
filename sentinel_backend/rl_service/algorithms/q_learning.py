"""
Q-Learning algorithm implementation.

Classic tabular Q-Learning for discrete state-action spaces.
Ideal for test selection and simple coordination tasks.
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np
import hashlib
import json
import pickle
from pathlib import Path

from .base_algorithm import BaseRLAlgorithm


class QLearning(BaseRLAlgorithm):
    """
    Q-Learning implementation with tabular Q-values.

    Q-Learning is an off-policy TD control algorithm that learns
    the optimal action-value function Q*(s,a) directly, without
    needing a model of the environment.

    Update rule:
        Q(s,a) = Q(s,a) + α * [r + γ * max Q(s',a') - Q(s,a)]

    where:
        α = learning rate
        γ = discount factor
        r = reward
        s,a = current state, action
        s' = next state
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.995,
        min_epsilon: float = 0.01,
        default_q_value: float = 0.0,
        **kwargs
    ):
        """
        Initialize Q-Learning algorithm.

        Args:
            learning_rate: Learning rate (alpha)
            discount_factor: Discount factor (gamma)
            epsilon: Initial exploration rate
            epsilon_decay: Epsilon decay rate
            min_epsilon: Minimum epsilon value
            default_q_value: Initial Q-value for new state-action pairs
            **kwargs: Additional parameters
        """
        super().__init__(
            learning_rate=learning_rate,
            discount_factor=discount_factor,
            epsilon=epsilon,
            epsilon_decay=epsilon_decay,
            min_epsilon=min_epsilon,
            **kwargs
        )

        # Q-table: dict of (state_hash, action) -> Q-value
        self.q_table: Dict[Tuple[str, int], float] = {}

        # Visit counts for each state-action pair
        self.visit_counts: Dict[Tuple[str, int], int] = {}

        # Default Q-value for unseen state-action pairs
        self.default_q_value = default_q_value

        self.update_count = 0

    @property
    def algorithm_name(self) -> str:
        """Return algorithm name."""
        return "Q-Learning"

    def _hash_state(self, state: np.ndarray) -> str:
        """
        Hash state vector for Q-table lookup.

        Args:
            state: State vector

        Returns:
            SHA-256 hash of state
        """
        # Convert state to bytes for hashing
        state_bytes = state.tobytes()
        return hashlib.sha256(state_bytes).hexdigest()

    def get_q_value(self, state: np.ndarray, action: int) -> float:
        """
        Get Q-value for specific state-action pair.

        Args:
            state: State vector
            action: Action ID

        Returns:
            Q-value (default if not seen before)
        """
        state_hash = self._hash_state(state)
        key = (state_hash, action)
        return self.q_table.get(key, self.default_q_value)

    def set_q_value(self, state: np.ndarray, action: int, value: float):
        """
        Set Q-value for specific state-action pair.

        Args:
            state: State vector
            action: Action ID
            value: New Q-value
        """
        state_hash = self._hash_state(state)
        key = (state_hash, action)
        self.q_table[key] = value

        # Increment visit count
        self.visit_counts[key] = self.visit_counts.get(key, 0) + 1

    def get_q_values(
        self,
        state: np.ndarray,
        available_actions: list
    ) -> Dict[int, float]:
        """
        Get Q-values for all available actions.

        Args:
            state: Current state
            available_actions: List of available action IDs

        Returns:
            Dictionary mapping action_id to Q-value
        """
        return {
            action: self.get_q_value(state, action)
            for action in available_actions
        }

    def select_action(
        self,
        state: np.ndarray,
        available_actions: list,
        mode: str = "train"
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Select action using epsilon-greedy (train) or greedy (eval).

        Args:
            state: Current state
            available_actions: List of available actions
            mode: "train" for epsilon-greedy, "eval" for greedy

        Returns:
            Tuple of (action_id, metadata)
        """
        q_values = self.get_q_values(state, available_actions)

        if mode == "train":
            # Epsilon-greedy
            action = self.epsilon_greedy_action(state, available_actions)
            exploration = (np.random.random() < self.epsilon)
        else:
            # Greedy (exploit only)
            action = max(q_values, key=q_values.get)
            exploration = False

        metadata = {
            "q_values": q_values,
            "selected_q_value": q_values[action],
            "exploration": exploration,
            "epsilon": self.epsilon,
            "mode": mode
        }

        return action, metadata

    def update(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool
    ) -> Dict[str, Any]:
        """
        Update Q-value using Q-Learning update rule.

        Q(s,a) = Q(s,a) + α * [r + γ * max Q(s',a') - Q(s,a)]

        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode is done

        Returns:
            Dictionary of update metrics
        """
        # Current Q-value
        current_q = self.get_q_value(state, action)

        # Max Q-value for next state (or 0 if done)
        if done:
            max_next_q = 0.0
        else:
            # Get Q-values for all possible actions in next state
            # For simplicity, assume same action space
            # In practice, this should be passed or retrieved
            next_q_values = {
                a: self.get_q_value(next_state, a)
                for a in range(100)  # Assume max 100 actions
            }
            max_next_q = max(next_q_values.values()) if next_q_values else 0.0

        # Q-Learning update
        td_target = reward + self.discount_factor * max_next_q
        td_error = td_target - current_q
        new_q = current_q + self.learning_rate * td_error

        # Update Q-table
        self.set_q_value(state, action, new_q)
        self.update_count += 1

        # Metrics
        state_hash = self._hash_state(state)
        visit_count = self.visit_counts.get((state_hash, action), 0)

        metrics = {
            "current_q": current_q,
            "new_q": new_q,
            "td_error": td_error,
            "td_target": td_target,
            "max_next_q": max_next_q,
            "reward": reward,
            "visit_count": visit_count,
            "update_count": self.update_count,
            "q_table_size": len(self.q_table)
        }

        self.logger.debug(
            f"Q-Learning update: state={state_hash[:8]}..., "
            f"action={action}, reward={reward:.2f}, "
            f"Q: {current_q:.2f} -> {new_q:.2f}, "
            f"TD_error={td_error:.2f}"
        )

        return metrics

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get detailed Q-Learning statistics.

        Returns:
            Dictionary of statistics
        """
        if not self.q_table:
            return {
                "q_table_size": 0,
                "total_updates": 0,
                "avg_q_value": 0.0,
                "max_q_value": 0.0,
                "min_q_value": 0.0
            }

        q_values = list(self.q_table.values())
        visit_counts = list(self.visit_counts.values())

        return {
            "q_table_size": len(self.q_table),
            "total_updates": self.update_count,
            "avg_q_value": np.mean(q_values),
            "max_q_value": np.max(q_values),
            "min_q_value": np.min(q_values),
            "std_q_value": np.std(q_values),
            "total_visits": sum(visit_counts),
            "avg_visits_per_state_action": np.mean(visit_counts),
            "max_visits": np.max(visit_counts),
            **self.get_metrics()
        }

    def get_best_actions(
        self,
        top_k: int = 10
    ) -> list[Dict[str, Any]]:
        """
        Get top-k best actions across all states.

        Args:
            top_k: Number of top actions to return

        Returns:
            List of (state_hash, action, q_value, visit_count) tuples
        """
        # Sort Q-table by Q-value
        sorted_pairs = sorted(
            self.q_table.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_k]

        return [
            {
                "state_hash": state_hash,
                "action": action,
                "q_value": q_value,
                "visit_count": self.visit_counts.get((state_hash, action), 0)
            }
            for (state_hash, action), q_value in sorted_pairs
        ]

    def save_model(self, path: str):
        """
        Save Q-table to disk.

        Args:
            path: Path to save model (directory or file)
        """
        save_path = Path(path)

        # Ensure directory exists
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # Save Q-table and metadata
        model_data = {
            "algorithm": self.algorithm_name,
            "q_table": self.q_table,
            "visit_counts": self.visit_counts,
            "hyperparameters": {
                "learning_rate": self.learning_rate,
                "discount_factor": self.discount_factor,
                "epsilon": self.epsilon,
                "epsilon_decay": self.epsilon_decay,
                "min_epsilon": self.min_epsilon,
                "default_q_value": self.default_q_value
            },
            "statistics": self.get_statistics()
        }

        with open(save_path, "wb") as f:
            pickle.dump(model_data, f)

        self.logger.info(
            f"Saved Q-Learning model to {save_path} "
            f"(Q-table size: {len(self.q_table)})"
        )

    def load_model(self, path: str):
        """
        Load Q-table from disk.

        Args:
            path: Path to load model from
        """
        load_path = Path(path)

        if not load_path.exists():
            raise FileNotFoundError(f"Model file not found: {load_path}")

        with open(load_path, "rb") as f:
            model_data = pickle.load(f)

        # Validate algorithm
        if model_data.get("algorithm") != self.algorithm_name:
            raise ValueError(
                f"Model is not Q-Learning: {model_data.get('algorithm')}"
            )

        # Load Q-table and visit counts
        self.q_table = model_data["q_table"]
        self.visit_counts = model_data["visit_counts"]

        # Load hyperparameters
        hp = model_data.get("hyperparameters", {})
        self.learning_rate = hp.get("learning_rate", self.learning_rate)
        self.discount_factor = hp.get("discount_factor", self.discount_factor)
        self.epsilon = hp.get("epsilon", self.epsilon)
        self.epsilon_decay = hp.get("epsilon_decay", self.epsilon_decay)
        self.min_epsilon = hp.get("min_epsilon", self.min_epsilon)
        self.default_q_value = hp.get("default_q_value", self.default_q_value)

        self.logger.info(
            f"Loaded Q-Learning model from {load_path} "
            f"(Q-table size: {len(self.q_table)})"
        )

    def export_q_table_for_db(self) -> list[Dict[str, Any]]:
        """
        Export Q-table in format suitable for database insertion.

        Returns:
            List of Q-table entries for database
        """
        entries = []

        for (state_hash, action), q_value in self.q_table.items():
            visit_count = self.visit_counts.get((state_hash, action), 0)

            entries.append({
                "state_hash": state_hash,
                "action_id": action,
                "q_value": float(q_value),
                "visit_count": int(visit_count),
                "algorithm": self.algorithm_name
            })

        return entries

    def import_q_table_from_db(self, entries: list[Dict[str, Any]]):
        """
        Import Q-table from database entries.

        Args:
            entries: List of Q-table entries from database
        """
        self.q_table.clear()
        self.visit_counts.clear()

        for entry in entries:
            state_hash = entry["state_hash"]
            action = entry["action_id"]
            q_value = entry["q_value"]
            visit_count = entry.get("visit_count", 0)

            key = (state_hash, action)
            self.q_table[key] = q_value
            self.visit_counts[key] = visit_count

        self.logger.info(
            f"Imported Q-table from database: "
            f"{len(entries)} entries loaded"
        )
