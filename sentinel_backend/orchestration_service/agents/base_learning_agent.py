"""
Base Learning Agent Mixin

Provides trajectory tracking capabilities for all Sentinel agents.
Integrates with ReasoningBank for learning from experience.

This mixin enables agents to:
- Track complete execution paths (input → actions → output)
- Store trajectories in ReasoningBank
- Learn from feedback and judgments
- Improve over time through pattern recognition
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
from uuid import uuid4

from sentinel_backend.reasoningbank.services.trajectory_service import TrajectoryService
from sentinel_backend.reasoningbank.models.task_trajectories import TaskTrajectory
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


class BaseLearningAgent:
    """
    Mixin class that adds trajectory tracking to any agent.

    Usage:
        class MyAgent(BaseAgent, BaseLearningAgent):
            def __init__(self):
                BaseAgent.__init__(self, "my-agent")
                BaseLearningAgent.__init__(self)

            async def execute(self, task, api_spec):
                # Start trajectory tracking
                trajectory = await self.start_trajectory(
                    task_type="test_generation",
                    task_description=f"Generate tests for {task.task_id}",
                    context_data={"api_spec": api_spec, "task": task.dict()},
                    db_session=db_session
                )

                # Log actions during execution
                await self.log_action(
                    "Analyzing API specification",
                    metadata={"endpoint_count": len(endpoints)}
                )

                # Complete trajectory with results
                await self.complete_trajectory(
                    final_output={"test_cases": test_cases},
                    execution_time_ms=execution_time,
                    test_success_rate=0.95
                )

                return result
    """

    def __init__(self):
        """Initialize learning agent mixin."""
        self._current_trajectory: Optional[TaskTrajectory] = None
        self._trajectory_service: Optional[TrajectoryService] = None
        self._trajectory_start_time: Optional[datetime] = None
        self._db_session: Optional[AsyncSession] = None

        # Get logger from parent class or create new one
        if hasattr(self, 'logger'):
            self.learning_logger = self.logger
        else:
            self.learning_logger = logging.getLogger(f"learning.{self.__class__.__name__}")

    async def start_trajectory(
        self,
        task_type: str,
        task_description: str,
        context_data: Optional[Dict[str, Any]] = None,
        db_session: Optional[AsyncSession] = None,
        tenant_id: Optional[str] = None
    ) -> TaskTrajectory:
        """
        Start tracking a new trajectory for this execution.

        Args:
            task_type: Type of task (e.g., "test_generation", "security_scan")
            task_description: Human-readable description
            context_data: Additional context (API spec, requirements, etc.)
            db_session: Database session for persistence
            tenant_id: Tenant identifier

        Returns:
            TaskTrajectory: Created trajectory object
        """
        self._trajectory_start_time = datetime.utcnow()
        self._db_session = db_session

        # Determine agent type from class name or attribute
        agent_type = getattr(self, 'agent_type', self.__class__.__name__)

        if db_session:
            # Create trajectory service if not already created
            if not self._trajectory_service:
                self._trajectory_service = TrajectoryService(db_session)

            try:
                # Create trajectory in database
                self._current_trajectory = await self._trajectory_service.create_trajectory(
                    task_type=task_type,
                    task_description=task_description,
                    context_data=context_data or {},
                    agent_type=agent_type,
                    tenant_id=tenant_id
                )

                self.learning_logger.info(
                    f"Started trajectory tracking: {self._current_trajectory.trajectory_id}"
                )

                return self._current_trajectory

            except Exception as e:
                self.learning_logger.error(f"Failed to create trajectory: {e}")
                # Create a minimal in-memory trajectory as fallback
                self._current_trajectory = self._create_fallback_trajectory(
                    task_type, task_description, context_data, agent_type, tenant_id
                )
                return self._current_trajectory
        else:
            # No database session - create in-memory trajectory
            self.learning_logger.debug("No DB session provided, creating in-memory trajectory")
            self._current_trajectory = self._create_fallback_trajectory(
                task_type, task_description, context_data, agent_type, tenant_id
            )
            return self._current_trajectory

    def _create_fallback_trajectory(
        self,
        task_type: str,
        task_description: str,
        context_data: Optional[Dict[str, Any]],
        agent_type: str,
        tenant_id: Optional[str]
    ) -> TaskTrajectory:
        """Create an in-memory trajectory when database is unavailable."""
        from sentinel_backend.reasoningbank.models.task_trajectories import TrajectoryOutcome

        trajectory = TaskTrajectory(
            trajectory_id=f"traj_{uuid4().hex[:16]}",
            task_type=task_type,
            task_description=task_description,
            context_data=context_data or {},
            agent_type=agent_type,
            actions=[],
            final_output={},
            outcome="UNKNOWN",
            tenant_id=tenant_id,
            created_at=datetime.utcnow()
        )
        return trajectory

    async def log_action(
        self,
        action_description: str,
        action_metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an action step during trajectory execution.

        Args:
            action_description: Description of what was done
            action_metadata: Additional metadata about the action
        """
        if not self._current_trajectory:
            self.learning_logger.warning("Cannot log action: no active trajectory")
            return

        action = {
            "description": action_description,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": action_metadata or {}
        }

        # Add to in-memory trajectory
        if not self._current_trajectory.actions:
            self._current_trajectory.actions = []
        self._current_trajectory.actions.append(action)

        # Persist to database if available
        if self._trajectory_service and self._db_session:
            try:
                await self._trajectory_service.add_action(
                    trajectory_id=self._current_trajectory.trajectory_id,
                    action_description=action_description,
                    action_metadata=action_metadata
                )
                self.learning_logger.debug(f"Logged action: {action_description}")
            except Exception as e:
                self.learning_logger.error(f"Failed to persist action: {e}")

    async def complete_trajectory(
        self,
        final_output: Dict[str, Any],
        execution_time_ms: Optional[int] = None,
        token_count: Optional[int] = None,
        test_success_rate: Optional[float] = None,
        coverage_score: Optional[float] = None
    ) -> Optional[TaskTrajectory]:
        """
        Complete the current trajectory with final results.

        Args:
            final_output: Final result of the task
            execution_time_ms: Total execution time in milliseconds
            token_count: Total tokens used (for LLM calls)
            test_success_rate: Success rate of generated tests (0.0-1.0)
            coverage_score: Code coverage achieved (0.0-1.0)

        Returns:
            Optional[TaskTrajectory]: Completed trajectory or None
        """
        if not self._current_trajectory:
            self.learning_logger.warning("Cannot complete trajectory: no active trajectory")
            return None

        # Calculate execution time if not provided
        if execution_time_ms is None and self._trajectory_start_time:
            elapsed = (datetime.utcnow() - self._trajectory_start_time).total_seconds()
            execution_time_ms = int(elapsed * 1000)

        # Update in-memory trajectory
        self._current_trajectory.final_output = final_output
        self._current_trajectory.execution_time_ms = execution_time_ms
        self._current_trajectory.token_count = token_count
        self._current_trajectory.test_success_rate = test_success_rate
        self._current_trajectory.coverage_score = coverage_score

        # Persist to database if available
        if self._trajectory_service and self._db_session:
            try:
                completed = await self._trajectory_service.complete_trajectory(
                    trajectory_id=self._current_trajectory.trajectory_id,
                    final_output=final_output,
                    execution_time_ms=execution_time_ms,
                    token_count=token_count,
                    test_success_rate=test_success_rate,
                    coverage_score=coverage_score
                )

                self.learning_logger.info(
                    f"Completed trajectory: {self._current_trajectory.trajectory_id} "
                    f"({execution_time_ms}ms, {len(self._current_trajectory.actions or [])} actions)"
                )

                # Store trajectory ID for return
                completed_trajectory = completed

            except Exception as e:
                self.learning_logger.error(f"Failed to complete trajectory: {e}")
                completed_trajectory = self._current_trajectory
        else:
            completed_trajectory = self._current_trajectory

        # Clear current trajectory
        result = completed_trajectory
        self._current_trajectory = None
        self._trajectory_start_time = None

        return result

    def get_current_trajectory_id(self) -> Optional[str]:
        """Get the ID of the current trajectory being tracked."""
        if self._current_trajectory:
            return self._current_trajectory.trajectory_id
        return None

    def is_tracking_trajectory(self) -> bool:
        """Check if currently tracking a trajectory."""
        return self._current_trajectory is not None

    async def abort_trajectory(self, error_message: str) -> None:
        """
        Abort the current trajectory due to an error.

        Args:
            error_message: Description of why the trajectory was aborted
        """
        if not self._current_trajectory:
            return

        await self.log_action(
            "Trajectory aborted due to error",
            action_metadata={"error": error_message}
        )

        await self.complete_trajectory(
            final_output={"error": error_message, "aborted": True},
            execution_time_ms=None,
            test_success_rate=0.0
        )


class LearningAgentMetrics:
    """Helper class for tracking learning metrics across agent executions."""

    def __init__(self):
        self.total_trajectories = 0
        self.successful_trajectories = 0
        self.failed_trajectories = 0
        self.total_actions_logged = 0
        self.avg_execution_time_ms = 0.0
        self.trajectories: List[str] = []

    def record_trajectory(
        self,
        trajectory_id: str,
        success: bool,
        action_count: int,
        execution_time_ms: int
    ):
        """Record metrics from a completed trajectory."""
        self.total_trajectories += 1
        if success:
            self.successful_trajectories += 1
        else:
            self.failed_trajectories += 1

        self.total_actions_logged += action_count
        self.trajectories.append(trajectory_id)

        # Update rolling average execution time
        if self.total_trajectories == 1:
            self.avg_execution_time_ms = execution_time_ms
        else:
            self.avg_execution_time_ms = (
                (self.avg_execution_time_ms * (self.total_trajectories - 1) + execution_time_ms)
                / self.total_trajectories
            )

    def get_success_rate(self) -> float:
        """Calculate trajectory success rate."""
        if self.total_trajectories == 0:
            return 0.0
        return self.successful_trajectories / self.total_trajectories

    def get_avg_actions_per_trajectory(self) -> float:
        """Calculate average number of actions per trajectory."""
        if self.total_trajectories == 0:
            return 0.0
        return self.total_actions_logged / self.total_trajectories

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_trajectories": self.total_trajectories,
            "successful_trajectories": self.successful_trajectories,
            "failed_trajectories": self.failed_trajectories,
            "success_rate": self.get_success_rate(),
            "total_actions_logged": self.total_actions_logged,
            "avg_actions_per_trajectory": self.get_avg_actions_per_trajectory(),
            "avg_execution_time_ms": self.avg_execution_time_ms,
            "recent_trajectories": self.trajectories[-10:]  # Last 10
        }
