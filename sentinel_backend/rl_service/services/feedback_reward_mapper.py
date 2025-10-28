"""
Feedback Reward Mapper - Maps user feedback to Q-Learning rewards.

This module converts user feedback (ratings, helpful flags, etc.) into
numerical rewards that can be used by Q-Learning algorithms to improve
agent behavior over time.

Reward Mapping:
- 5-star rating + helpful → +1.0 reward
- 4-star rating → +0.5 reward
- 3-star rating → 0.0 reward
- 2-star rating → -0.3 reward
- 1-star rating → -0.5 reward
- "Found issue" → +0.3 bonus
- "Not helpful" → -0.3 penalty
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import numpy as np
import logging

logger = logging.getLogger(__name__)


class FeedbackRewardMapper:
    """
    Maps user feedback to Q-Learning rewards with cumulative tracking.
    """

    def __init__(
        self,
        base_rating_rewards: Optional[Dict[int, float]] = None,
        helpful_bonus: float = 0.3,
        found_issue_bonus: float = 0.3,
        not_helpful_penalty: float = -0.3,
        reward_clamp_range: tuple = (-1.0, 1.0)
    ):
        """
        Initialize feedback reward mapper.

        Args:
            base_rating_rewards: Mapping of star rating to base reward
            helpful_bonus: Bonus reward for "helpful" flag
            found_issue_bonus: Bonus reward for "found issue" flag
            not_helpful_penalty: Penalty for "not helpful" flag
            reward_clamp_range: Min/max reward values (default: -1.0 to 1.0)
        """
        self.base_rating_rewards = base_rating_rewards or {
            1: -0.5,
            2: -0.3,
            3: 0.0,
            4: 0.5,
            5: 1.0
        }
        self.helpful_bonus = helpful_bonus
        self.found_issue_bonus = found_issue_bonus
        self.not_helpful_penalty = not_helpful_penalty
        self.reward_clamp_range = reward_clamp_range

        # Track cumulative rewards per agent
        self.cumulative_rewards: Dict[str, List[float]] = {}
        self.reward_history: List[Dict[str, Any]] = []

        logger.info(
            f"Initialized FeedbackRewardMapper with rating rewards: "
            f"{self.base_rating_rewards}"
        )

    def calculate_reward(
        self,
        rating: int,
        is_helpful: bool = False,
        found_issue: bool = False,
        not_helpful: bool = False,
        execution_result: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        Calculate reward from user feedback.

        Args:
            rating: Star rating (1-5)
            is_helpful: Whether user marked as helpful
            found_issue: Whether test found a real issue
            not_helpful: Whether user marked as not helpful
            execution_result: Optional execution result for additional context
            metadata: Optional metadata for logging

        Returns:
            Calculated reward (clamped to reward_clamp_range)
        """
        # Validate rating
        if rating not in self.base_rating_rewards:
            logger.warning(
                f"Invalid rating {rating}, using neutral reward 0.0"
            )
            rating = 3  # Default to neutral

        # Start with base rating reward
        reward = self.base_rating_rewards[rating]

        # Add bonuses/penalties
        if is_helpful:
            reward += self.helpful_bonus
            logger.debug(f"Added helpful bonus: +{self.helpful_bonus}")

        if found_issue:
            reward += self.found_issue_bonus
            logger.debug(f"Added found_issue bonus: +{self.found_issue_bonus}")

        if not_helpful:
            reward += self.not_helpful_penalty
            logger.debug(f"Added not_helpful penalty: {self.not_helpful_penalty}")

        # Add execution-based rewards
        if execution_result:
            execution_reward = self._calculate_execution_reward(execution_result)
            reward += execution_reward
            if execution_reward != 0:
                logger.debug(
                    f"Added execution reward: {execution_reward:+.2f}"
                )

        # Clamp reward to valid range
        min_reward, max_reward = self.reward_clamp_range
        reward = np.clip(reward, min_reward, max_reward)

        logger.info(
            f"Calculated reward: {reward:.2f} "
            f"(rating={rating}, helpful={is_helpful}, "
            f"found_issue={found_issue})"
        )

        return float(reward)

    def _calculate_execution_reward(
        self,
        execution_result: Dict[str, Any]
    ) -> float:
        """
        Calculate additional reward based on test execution result.

        Args:
            execution_result: Test execution result with status, timing, etc.

        Returns:
            Additional reward based on execution
        """
        reward = 0.0

        # Check execution status
        status = execution_result.get("status", "unknown")
        if status == "passed":
            reward += 0.1
        elif status == "failed":
            # Failed test might have found a real bug
            if execution_result.get("found_bug", False):
                reward += 0.2
            else:
                # False positive
                reward -= 0.1

        # Reward fast execution (< 1 second)
        execution_time_ms = execution_result.get("execution_time_ms", 0)
        if 0 < execution_time_ms < 1000:
            reward += 0.05

        # Penalize very slow execution (> 10 seconds)
        elif execution_time_ms > 10000:
            reward -= 0.05

        return reward

    def add_feedback_reward(
        self,
        agent_id: str,
        reward: float,
        feedback_data: Dict[str, Any]
    ):
        """
        Track cumulative reward for an agent.

        Args:
            agent_id: Agent identifier
            reward: Reward value to add
            feedback_data: Feedback metadata for logging
        """
        if agent_id not in self.cumulative_rewards:
            self.cumulative_rewards[agent_id] = []

        self.cumulative_rewards[agent_id].append(reward)

        # Track in history
        self.reward_history.append({
            "agent_id": agent_id,
            "reward": reward,
            "timestamp": datetime.utcnow().isoformat(),
            "feedback_data": feedback_data
        })

        logger.debug(
            f"Added reward {reward:.2f} for agent {agent_id}. "
            f"Cumulative count: {len(self.cumulative_rewards[agent_id])}"
        )

    def get_cumulative_reward(
        self,
        agent_id: str,
        window_size: Optional[int] = None
    ) -> float:
        """
        Get cumulative reward for an agent.

        Args:
            agent_id: Agent identifier
            window_size: Optional window size for recent rewards only

        Returns:
            Cumulative reward (sum of all rewards)
        """
        if agent_id not in self.cumulative_rewards:
            return 0.0

        rewards = self.cumulative_rewards[agent_id]

        if window_size:
            rewards = rewards[-window_size:]

        return float(np.sum(rewards))

    def get_average_reward(
        self,
        agent_id: str,
        window_size: Optional[int] = None
    ) -> float:
        """
        Get average reward for an agent.

        Args:
            agent_id: Agent identifier
            window_size: Optional window size for recent rewards only

        Returns:
            Average reward
        """
        if agent_id not in self.cumulative_rewards:
            return 0.0

        rewards = self.cumulative_rewards[agent_id]

        if not rewards:
            return 0.0

        if window_size:
            rewards = rewards[-window_size:]

        return float(np.mean(rewards))

    def get_reward_trend(
        self,
        agent_id: str,
        window_size: int = 10
    ) -> Dict[str, Any]:
        """
        Analyze reward trend over time.

        Args:
            agent_id: Agent identifier
            window_size: Number of recent rewards to analyze

        Returns:
            Dictionary with trend analysis
        """
        if agent_id not in self.cumulative_rewards:
            return {
                "trend": "no_data",
                "slope": 0.0,
                "recent_avg": 0.0,
                "overall_avg": 0.0
            }

        rewards = self.cumulative_rewards[agent_id]

        if len(rewards) < 2:
            return {
                "trend": "insufficient_data",
                "slope": 0.0,
                "recent_avg": float(rewards[0]) if rewards else 0.0,
                "overall_avg": float(rewards[0]) if rewards else 0.0
            }

        # Calculate recent vs overall average
        recent_rewards = rewards[-window_size:]
        recent_avg = np.mean(recent_rewards)
        overall_avg = np.mean(rewards)

        # Calculate trend (simple linear regression)
        if len(recent_rewards) >= 2:
            x = np.arange(len(recent_rewards))
            y = np.array(recent_rewards)
            slope = np.polyfit(x, y, 1)[0]
        else:
            slope = 0.0

        # Determine trend direction
        if slope > 0.1:
            trend = "improving"
        elif slope < -0.1:
            trend = "declining"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "slope": float(slope),
            "recent_avg": float(recent_avg),
            "overall_avg": float(overall_avg),
            "total_feedback_count": len(rewards)
        }

    def get_all_agent_rewards(self) -> Dict[str, Dict[str, Any]]:
        """
        Get reward summary for all agents.

        Returns:
            Dictionary mapping agent_id to reward statistics
        """
        summary = {}

        for agent_id in self.cumulative_rewards:
            summary[agent_id] = {
                "cumulative_reward": self.get_cumulative_reward(agent_id),
                "average_reward": self.get_average_reward(agent_id),
                "feedback_count": len(self.cumulative_rewards[agent_id]),
                "trend": self.get_reward_trend(agent_id)
            }

        return summary

    def get_recent_history(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get recent reward history.

        Args:
            agent_id: Optional agent filter
            limit: Maximum number of entries

        Returns:
            List of recent reward history entries
        """
        history = self.reward_history

        if agent_id:
            history = [
                entry for entry in history
                if entry["agent_id"] == agent_id
            ]

        return history[-limit:]

    def reset_agent_rewards(self, agent_id: str):
        """
        Reset cumulative rewards for an agent.

        Args:
            agent_id: Agent identifier
        """
        if agent_id in self.cumulative_rewards:
            del self.cumulative_rewards[agent_id]
            logger.info(f"Reset rewards for agent {agent_id}")

    def export_rewards_for_db(self) -> List[Dict[str, Any]]:
        """
        Export reward data for database storage.

        Returns:
            List of reward entries for database insertion
        """
        entries = []

        for agent_id, rewards in self.cumulative_rewards.items():
            trend = self.get_reward_trend(agent_id)

            entries.append({
                "agent_id": agent_id,
                "cumulative_reward": float(np.sum(rewards)),
                "average_reward": float(np.mean(rewards)),
                "feedback_count": len(rewards),
                "trend_slope": trend["slope"],
                "trend_direction": trend["trend"],
                "last_updated": datetime.utcnow().isoformat()
            })

        return entries
