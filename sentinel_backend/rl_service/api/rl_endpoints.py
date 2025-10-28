"""
RL Service REST API endpoints for Q-Learning policy management.

Endpoints:
- GET /api/v1/rl/agent/{agent_id}/policy - Get current Q-values
- GET /api/v1/rl/agent/{agent_id}/rewards - Get reward history
- POST /api/v1/rl/agent/{agent_id}/train - Trigger policy update
- GET /api/v1/rl/statistics - Get overall RL statistics
- POST /api/v1/rl/feedback - Process feedback and update policy
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
import logging

from ..services.feedback_reward_mapper import FeedbackRewardMapper
from ..services.agent_policy_updater import AgentPolicyUpdater, TestStrategy
from ..algorithms.q_learning import QLearning

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/rl", tags=["reinforcement-learning"])

# Global instances (in production, use dependency injection)
feedback_mapper = FeedbackRewardMapper()
policy_updater = AgentPolicyUpdater()


# Request/Response Models
class FeedbackRequest(BaseModel):
    """Request model for feedback submission."""
    agent_id: str = Field(..., description="Agent identifier")
    api_spec: Dict[str, Any] = Field(..., description="API specification")
    endpoint: str = Field(..., description="Endpoint path")
    method: str = Field(..., description="HTTP method")
    strategy_used: str = Field(..., description="Strategy used")
    rating: int = Field(..., ge=1, le=5, description="Star rating (1-5)")
    is_helpful: bool = Field(False, description="Helpful flag")
    found_issue: bool = Field(False, description="Found issue flag")
    not_helpful: bool = Field(False, description="Not helpful flag")
    execution_result: Optional[Dict[str, Any]] = Field(None, description="Execution result")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class TrainRequest(BaseModel):
    """Request model for policy training."""
    agent_id: str = Field(..., description="Agent identifier")
    api_spec: Dict[str, Any] = Field(..., description="API specification")
    endpoint: str = Field(..., description="Endpoint path")
    method: str = Field(..., description="HTTP method")
    strategy_used: str = Field(..., description="Strategy used")
    reward: float = Field(..., description="Reward value")


class PolicyResponse(BaseModel):
    """Response model for policy queries."""
    agent_id: str
    endpoint: str
    method: str
    q_values: Dict[str, float]
    best_strategy: str
    best_q_value: float
    exploration_rate: float


class RewardHistoryResponse(BaseModel):
    """Response model for reward history."""
    agent_id: str
    cumulative_reward: float
    average_reward: float
    feedback_count: int
    trend: Dict[str, Any]
    recent_history: List[Dict[str, Any]]


class StatisticsResponse(BaseModel):
    """Response model for overall statistics."""
    q_learning_stats: Dict[str, Any]
    strategy_usage: Dict[str, int]
    agent_rewards: Dict[str, Dict[str, Any]]
    total_updates: int
    exploration_rate: float


# Endpoints
@router.get("/agent/{agent_id}/policy", response_model=PolicyResponse)
async def get_agent_policy(
    agent_id: str,
    api_spec: Dict[str, Any],
    endpoint: str,
    method: str
):
    """
    Get current Q-values for an agent's policy.

    Args:
        agent_id: Agent identifier
        api_spec: API specification
        endpoint: Endpoint path
        method: HTTP method

    Returns:
        Policy with Q-values for all strategies
    """
    try:
        # Get Q-values for endpoint
        q_values = policy_updater.get_q_values_for_endpoint(
            api_spec=api_spec,
            endpoint=endpoint,
            method=method
        )

        # Find best strategy
        best_strategy = max(q_values.items(), key=lambda x: x[1])

        return PolicyResponse(
            agent_id=agent_id,
            endpoint=endpoint,
            method=method,
            q_values=q_values,
            best_strategy=best_strategy[0],
            best_q_value=best_strategy[1],
            exploration_rate=policy_updater.q_learning.epsilon
        )

    except Exception as e:
        logger.error(f"Error getting policy for {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agent/{agent_id}/rewards", response_model=RewardHistoryResponse)
async def get_agent_rewards(
    agent_id: str,
    limit: int = Query(100, ge=1, le=1000)
):
    """
    Get reward history for an agent.

    Args:
        agent_id: Agent identifier
        limit: Maximum number of history entries

    Returns:
        Reward history and statistics
    """
    try:
        # Get reward statistics
        cumulative_reward = feedback_mapper.get_cumulative_reward(agent_id)
        average_reward = feedback_mapper.get_average_reward(agent_id)
        trend = feedback_mapper.get_reward_trend(agent_id)
        history = feedback_mapper.get_recent_history(agent_id, limit)

        return RewardHistoryResponse(
            agent_id=agent_id,
            cumulative_reward=cumulative_reward,
            average_reward=average_reward,
            feedback_count=len(feedback_mapper.cumulative_rewards.get(agent_id, [])),
            trend=trend,
            recent_history=history
        )

    except Exception as e:
        logger.error(f"Error getting rewards for {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agent/{agent_id}/train")
async def train_agent_policy(
    agent_id: str,
    request: TrainRequest
):
    """
    Trigger policy update for an agent.

    Args:
        agent_id: Agent identifier
        request: Training request with state/action/reward

    Returns:
        Update metrics
    """
    try:
        # Validate strategy
        try:
            strategy = TestStrategy(request.strategy_used)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid strategy: {request.strategy_used}"
            )

        # Update policy
        update_metrics = policy_updater.update_policy(
            api_spec=request.api_spec,
            endpoint=request.endpoint,
            method=request.method,
            strategy_used=strategy,
            reward=request.reward
        )

        logger.info(f"Policy updated for {agent_id}: {update_metrics}")

        return {
            "agent_id": agent_id,
            "status": "success",
            "update_metrics": update_metrics
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error training policy for {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/feedback")
async def process_feedback(request: FeedbackRequest):
    """
    Process user feedback and update agent policy.

    This is the main endpoint for the learning loop:
    1. Calculate reward from feedback
    2. Update Q-Learning policy
    3. Track cumulative rewards

    Args:
        request: Feedback data

    Returns:
        Processing results with reward and update metrics
    """
    try:
        # Calculate reward
        reward = feedback_mapper.calculate_reward(
            rating=request.rating,
            is_helpful=request.is_helpful,
            found_issue=request.found_issue,
            not_helpful=request.not_helpful,
            execution_result=request.execution_result,
            metadata=request.metadata
        )

        # Track cumulative reward
        feedback_mapper.add_feedback_reward(
            agent_id=request.agent_id,
            reward=reward,
            feedback_data={
                "rating": request.rating,
                "is_helpful": request.is_helpful,
                "found_issue": request.found_issue,
                "endpoint": request.endpoint,
                "method": request.method,
                "strategy": request.strategy_used
            }
        )

        # Validate strategy
        try:
            strategy = TestStrategy(request.strategy_used)
        except ValueError:
            logger.warning(
                f"Invalid strategy '{request.strategy_used}', "
                f"skipping policy update"
            )
            strategy = None

        # Update policy
        update_metrics = None
        if strategy:
            update_metrics = policy_updater.update_policy(
                api_spec=request.api_spec,
                endpoint=request.endpoint,
                method=request.method,
                strategy_used=strategy,
                reward=reward
            )

        logger.info(
            f"Processed feedback for {request.agent_id}: "
            f"reward={reward:.2f}, strategy={request.strategy_used}"
        )

        return {
            "status": "success",
            "agent_id": request.agent_id,
            "reward": reward,
            "cumulative_reward": feedback_mapper.get_cumulative_reward(
                request.agent_id
            ),
            "average_reward": feedback_mapper.get_average_reward(
                request.agent_id
            ),
            "update_metrics": update_metrics
        }

    except Exception as e:
        logger.error(f"Error processing feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics", response_model=StatisticsResponse)
async def get_rl_statistics():
    """
    Get overall RL system statistics.

    Returns:
        Comprehensive statistics for all agents and policies
    """
    try:
        # Get policy statistics
        policy_stats = policy_updater.get_policy_statistics()

        # Get all agent rewards
        agent_rewards = feedback_mapper.get_all_agent_rewards()

        return StatisticsResponse(
            q_learning_stats=policy_stats["q_learning_stats"],
            strategy_usage=policy_stats["strategy_usage"],
            agent_rewards=agent_rewards,
            total_updates=policy_stats["total_updates"],
            exploration_rate=policy_stats["exploration_rate"]
        )

    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/strategies")
async def list_strategies():
    """
    List all available test generation strategies.

    Returns:
        List of strategy names and descriptions
    """
    return {
        "strategies": [
            {
                "name": strategy.value,
                "description": _get_strategy_description(strategy)
            }
            for strategy in TestStrategy
        ]
    }


def _get_strategy_description(strategy: TestStrategy) -> str:
    """Get human-readable strategy description."""
    descriptions = {
        TestStrategy.POSITIVE: "Happy path tests with valid inputs",
        TestStrategy.NEGATIVE: "Error handling and invalid input tests",
        TestStrategy.BOUNDARY: "Edge cases and boundary value tests",
        TestStrategy.SECURITY: "Security vulnerability tests (BOLA, injection, etc.)",
        TestStrategy.PERFORMANCE: "Performance and load testing",
        TestStrategy.STATEFUL: "Multi-step workflow tests",
        TestStrategy.DATA_DRIVEN: "Schema-based data generation tests",
        TestStrategy.RANDOMIZED: "Fuzzing and randomized input tests"
    }
    return descriptions.get(strategy, "Unknown strategy")


@router.post("/reset/{agent_id}")
async def reset_agent_learning(agent_id: str):
    """
    Reset learning data for an agent.

    WARNING: This will delete all reward history and Q-values for the agent.

    Args:
        agent_id: Agent identifier

    Returns:
        Reset confirmation
    """
    try:
        feedback_mapper.reset_agent_rewards(agent_id)

        logger.warning(f"Reset learning data for agent {agent_id}")

        return {
            "status": "success",
            "agent_id": agent_id,
            "message": "Learning data reset"
        }

    except Exception as e:
        logger.error(f"Error resetting agent {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
