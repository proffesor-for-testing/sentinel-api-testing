"""
Base class for all RL algorithms.

Provides the common interface and shared functionality for reinforcement learning
algorithms in the Sentinel platform.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
import numpy as np
import logging

logger = logging.getLogger(__name__)


class BaseRLAlgorithm(ABC):
    """
    Abstract base class for reinforcement learning algorithms.

    Each algorithm implements the core RL loop: observe state, select action,
    receive reward, update policy.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.95,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.995,
        min_epsilon: float = 0.01,
        **kwargs
    ):
        """
        Initialize RL algorithm.

        Args:
            learning_rate: Learning rate (alpha) for value updates
            discount_factor: Discount factor (gamma) for future rewards
            epsilon: Initial exploration rate for epsilon-greedy
            epsilon_decay: Decay rate for epsilon after each episode
            min_epsilon: Minimum epsilon value
            **kwargs: Additional algorithm-specific parameters
        """
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.min_epsilon = min_epsilon

        self.episode_count = 0
        self.total_reward = 0.0
        self.episode_rewards = []

        self.logger = logging.getLogger(f"rl.{self.__class__.__name__}")
        self.logger.info(
            f"Initialized {self.__class__.__name__} with "
            f"lr={learning_rate}, gamma={discount_factor}, "
            f"epsilon={epsilon}"
        )

    @property
    @abstractmethod
    def algorithm_name(self) -> str:
        """Return the algorithm name."""
        pass

    @abstractmethod
    def select_action(
        self,
        state: np.ndarray,
        available_actions: list,
        mode: str = "train"
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Select an action given the current state.

        Args:
            state: Current state representation
            available_actions: List of available actions
            mode: "train" for epsilon-greedy, "eval" for greedy

        Returns:
            Tuple of (action_id, metadata)
        """
        pass

    @abstractmethod
    def update(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool
    ) -> Dict[str, Any]:
        """
        Update the algorithm's policy based on experience.

        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode is done

        Returns:
            Dictionary of update metrics
        """
        pass

    @abstractmethod
    def get_q_values(
        self,
        state: np.ndarray,
        available_actions: list
    ) -> Dict[int, float]:
        """
        Get Q-values for all available actions in the given state.

        Args:
            state: Current state
            available_actions: List of available actions

        Returns:
            Dictionary mapping action_id to Q-value
        """
        pass

    def epsilon_greedy_action(
        self,
        state: np.ndarray,
        available_actions: list
    ) -> int:
        """
        Select action using epsilon-greedy strategy.

        Args:
            state: Current state
            available_actions: List of available actions

        Returns:
            Selected action_id
        """
        if np.random.random() < self.epsilon:
            # Explore: random action
            action = np.random.choice(available_actions)
            self.logger.debug(f"Exploring: random action {action}")
            return action
        else:
            # Exploit: best action
            q_values = self.get_q_values(state, available_actions)
            action = max(q_values, key=q_values.get)
            self.logger.debug(
                f"Exploiting: best action {action} "
                f"(Q={q_values[action]:.2f})"
            )
            return action

    def decay_epsilon(self):
        """Decay exploration rate."""
        old_epsilon = self.epsilon
        self.epsilon = max(
            self.min_epsilon,
            self.epsilon * self.epsilon_decay
        )
        if old_epsilon != self.epsilon:
            self.logger.debug(
                f"Epsilon decayed: {old_epsilon:.4f} -> {self.epsilon:.4f}"
            )

    def end_episode(self, episode_reward: float):
        """
        End current episode and update statistics.

        Args:
            episode_reward: Total reward for completed episode
        """
        self.episode_count += 1
        self.total_reward += episode_reward
        self.episode_rewards.append(episode_reward)
        self.decay_epsilon()

        avg_reward = self.total_reward / self.episode_count

        self.logger.info(
            f"Episode {self.episode_count} complete: "
            f"reward={episode_reward:.2f}, "
            f"avg_reward={avg_reward:.2f}, "
            f"epsilon={self.epsilon:.4f}"
        )

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current learning metrics.

        Returns:
            Dictionary of metrics
        """
        if len(self.episode_rewards) == 0:
            return {
                "episode_count": 0,
                "total_reward": 0.0,
                "avg_reward": 0.0,
                "best_reward": 0.0,
                "epsilon": self.epsilon,
                "recent_rewards": []
            }

        return {
            "episode_count": self.episode_count,
            "total_reward": self.total_reward,
            "avg_reward": self.total_reward / self.episode_count,
            "best_reward": max(self.episode_rewards),
            "epsilon": self.epsilon,
            "recent_rewards": self.episode_rewards[-10:],  # Last 10 episodes
            "convergence_indicator": self._calculate_convergence()
        }

    def _calculate_convergence(self, window: int = 20) -> float:
        """
        Calculate convergence indicator based on reward variance.

        Lower variance indicates convergence.

        Args:
            window: Number of recent episodes to consider

        Returns:
            Convergence score (0-1, higher is more converged)
        """
        if len(self.episode_rewards) < window:
            return 0.0

        recent_rewards = self.episode_rewards[-window:]
        variance = np.var(recent_rewards)
        mean = np.mean(recent_rewards)

        # Coefficient of variation
        if mean == 0:
            return 0.0

        cv = np.sqrt(variance) / abs(mean)

        # Convert to 0-1 score (lower CV = higher convergence)
        convergence = 1.0 / (1.0 + cv)

        return float(convergence)

    @abstractmethod
    def save_model(self, path: str):
        """
        Save the algorithm's model to disk.

        Args:
            path: Path to save model
        """
        pass

    @abstractmethod
    def load_model(self, path: str):
        """
        Load the algorithm's model from disk.

        Args:
            path: Path to load model from
        """
        pass

    def reset(self):
        """Reset algorithm to initial state."""
        self.episode_count = 0
        self.total_reward = 0.0
        self.episode_rewards = []
        self.epsilon = 1.0  # Reset to initial exploration
        self.logger.info("Algorithm reset to initial state")
