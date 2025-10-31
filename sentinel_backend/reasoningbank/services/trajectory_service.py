"""
Trajectory Service

Captures and stores complete test generation execution paths.
Tracks: input → actions → output → judgment → learnings
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..models.task_trajectories import TaskTrajectory, TrajectoryOutcome


class TrajectoryService:
    """Service for managing task execution trajectories."""

    def __init__(self, db_session: AsyncSession):
        """
        Initialize trajectory service.

        Args:
            db_session: AsyncSession for database operations
        """
        self.db = db_session

    async def create_trajectory(
        self,
        task_type: str,
        task_description: str,
        context_data: Optional[Dict[str, Any]] = None,
        agent_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> TaskTrajectory:
        """
        Create a new trajectory for tracking execution.

        Args:
            task_type: Type of task (e.g., "test_generation", "security_scan")
            task_description: Human-readable task description
            context_data: Additional context (API spec, requirements, etc.)
            agent_type: Which agent is executing this task
            tenant_id: Tenant identifier for multi-tenancy

        Returns:
            TaskTrajectory: Created trajectory object
        """
        trajectory = TaskTrajectory(
            trajectory_id=f"traj_{uuid4().hex[:16]}",
            task_type=task_type,
            task_description=task_description,
            context_data=context_data or {},
            agent_type=agent_type,
            actions=[],  # Will be populated as task executes
            final_output={},  # Will be set when task completes
            tenant_id=tenant_id,
        )

        self.db.add(trajectory)
        await self.db.commit()
        await self.db.refresh(trajectory)

        return trajectory

    async def add_action(
        self,
        trajectory_id: str,
        action_description: str,
        action_metadata: Optional[Dict[str, Any]] = None,
    ) -> TaskTrajectory:
        """
        Add an action step to a trajectory.

        Args:
            trajectory_id: Trajectory to update
            action_description: Description of the action taken
            action_metadata: Additional metadata about the action

        Returns:
            TaskTrajectory: Updated trajectory
        """
        result = await self.db.execute(
            select(TaskTrajectory).where(TaskTrajectory.trajectory_id == trajectory_id)
        )
        trajectory = result.scalar_one_or_none()

        if not trajectory:
            raise ValueError(f"Trajectory not found: {trajectory_id}")

        action = {
            "description": action_description,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": action_metadata or {},
        }

        if not trajectory.actions:
            trajectory.actions = []
        trajectory.actions.append(action)

        await self.db.commit()
        await self.db.refresh(trajectory)

        return trajectory

    async def complete_trajectory(
        self,
        trajectory_id: str,
        final_output: Dict[str, Any],
        execution_time_ms: Optional[int] = None,
        token_count: Optional[int] = None,
        test_success_rate: Optional[float] = None,
        coverage_score: Optional[float] = None,
    ) -> TaskTrajectory:
        """
        Mark trajectory as complete with final output.

        Args:
            trajectory_id: Trajectory to complete
            final_output: Final result of the task
            execution_time_ms: Total execution time in milliseconds
            token_count: Total tokens used
            test_success_rate: Success rate of generated tests
            coverage_score: Code coverage achieved

        Returns:
            TaskTrajectory: Completed trajectory
        """
        result = await self.db.execute(
            select(TaskTrajectory).where(TaskTrajectory.trajectory_id == trajectory_id)
        )
        trajectory = result.scalar_one_or_none()

        if not trajectory:
            raise ValueError(f"Trajectory not found: {trajectory_id}")

        trajectory.final_output = final_output
        trajectory.execution_time_ms = execution_time_ms
        trajectory.token_count = token_count
        trajectory.test_success_rate = test_success_rate
        trajectory.coverage_score = coverage_score

        await self.db.commit()
        await self.db.refresh(trajectory)

        return trajectory

    async def get_trajectory(self, trajectory_id: str) -> Optional[TaskTrajectory]:
        """
        Retrieve trajectory by ID.

        Args:
            trajectory_id: Trajectory identifier

        Returns:
            Optional[TaskTrajectory]: Trajectory if found
        """
        result = await self.db.execute(
            select(TaskTrajectory).where(TaskTrajectory.trajectory_id == trajectory_id)
        )
        return result.scalar_one_or_none()

    async def get_unjudged_trajectories(
        self,
        task_type: Optional[str] = None,
        limit: int = 10,
        tenant_id: Optional[str] = None,
    ) -> List[TaskTrajectory]:
        """
        Get trajectories that need judgment.

        Args:
            task_type: Filter by task type
            limit: Maximum number of trajectories to return
            tenant_id: Filter by tenant

        Returns:
            List[TaskTrajectory]: List of unjudged trajectories
        """
        query = select(TaskTrajectory).where(
            TaskTrajectory.outcome == "UNKNOWN"
        )

        if task_type:
            query = query.where(TaskTrajectory.task_type == task_type)

        if tenant_id:
            query = query.where(TaskTrajectory.tenant_id == tenant_id)

        query = query.order_by(TaskTrajectory.created_at).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_undistilled_trajectories(
        self,
        task_type: Optional[str] = None,
        limit: int = 10,
        tenant_id: Optional[str] = None,
    ) -> List[TaskTrajectory]:
        """
        Get trajectories that need pattern distillation.

        Args:
            task_type: Filter by task type
            limit: Maximum number of trajectories to return
            tenant_id: Filter by tenant

        Returns:
            List[TaskTrajectory]: List of undistilled trajectories
        """
        query = select(TaskTrajectory).where(
            and_(
                TaskTrajectory.distillation_performed == 0,
                TaskTrajectory.outcome != "UNKNOWN",
            )
        )

        if task_type:
            query = query.where(TaskTrajectory.task_type == task_type)

        if tenant_id:
            query = query.where(TaskTrajectory.tenant_id == tenant_id)

        query = query.order_by(TaskTrajectory.judged_at).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_trajectories_by_outcome(
        self,
        outcome: TrajectoryOutcome,
        task_type: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> List[TaskTrajectory]:
        """
        Get trajectories filtered by outcome.

        Args:
            outcome: Trajectory outcome to filter by
            task_type: Filter by task type
            limit: Maximum number of trajectories to return
            tenant_id: Filter by tenant

        Returns:
            List[TaskTrajectory]: List of trajectories
        """
        query = select(TaskTrajectory).where(TaskTrajectory.outcome == outcome)

        if task_type:
            query = query.where(TaskTrajectory.task_type == task_type)

        if tenant_id:
            query = query.where(TaskTrajectory.tenant_id == tenant_id)

        query = query.order_by(TaskTrajectory.created_at.desc()).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def update_judgment(
        self,
        trajectory_id: str,
        outcome: str,
        confidence: float,
        reasoning: Optional[str] = None,
    ) -> TaskTrajectory:
        """
        Update trajectory with judgment verdict.

        Args:
            trajectory_id: Trajectory to update
            outcome: Judged outcome (SUCCESS, FAILURE, PARTIAL)
            confidence: Confidence score (0.0-1.0)
            reasoning: Explanation for the judgment

        Returns:
            TaskTrajectory: Updated trajectory
        """
        result = await self.db.execute(
            select(TaskTrajectory).where(TaskTrajectory.trajectory_id == trajectory_id)
        )
        trajectory = result.scalar_one_or_none()

        if not trajectory:
            raise ValueError(f"Trajectory not found: {trajectory_id}")

        trajectory.outcome = outcome
        trajectory.outcome_confidence = confidence
        trajectory.judgment_reasoning = reasoning
        trajectory.judged_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(trajectory)

        return trajectory

    async def mark_distilled(
        self,
        trajectory_id: str,
        extracted_pattern_ids: List[str],
    ) -> TaskTrajectory:
        """
        Mark trajectory as distilled with extracted patterns.

        Args:
            trajectory_id: Trajectory to update
            extracted_pattern_ids: List of pattern IDs learned from this trajectory

        Returns:
            TaskTrajectory: Updated trajectory
        """
        result = await self.db.execute(
            select(TaskTrajectory).where(TaskTrajectory.trajectory_id == trajectory_id)
        )
        trajectory = result.scalar_one_or_none()

        if not trajectory:
            raise ValueError(f"Trajectory not found: {trajectory_id}")

        trajectory.distillation_performed = 1
        trajectory.extracted_pattern_ids = extracted_pattern_ids
        trajectory.distilled_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(trajectory)

        return trajectory

    async def get_trajectory_statistics(
        self,
        task_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get statistics about trajectories.

        Args:
            task_type: Filter by task type
            tenant_id: Filter by tenant

        Returns:
            Dict[str, Any]: Statistics including counts, success rates, etc.
        """
        # TODO: Implement with proper aggregation queries
        # For now, fetch all and calculate in-memory (not efficient for large datasets)

        query = select(TaskTrajectory)
        if task_type:
            query = query.where(TaskTrajectory.task_type == task_type)
        if tenant_id:
            query = query.where(TaskTrajectory.tenant_id == tenant_id)

        result = await self.db.execute(query)
        trajectories = list(result.scalars().all())

        total = len(trajectories)
        success = sum(1 for t in trajectories if t.outcome == "SUCCESS")
        failure = sum(1 for t in trajectories if t.outcome == "FAILURE")
        partial = sum(1 for t in trajectories if t.outcome == "PARTIAL")
        unjudged = sum(1 for t in trajectories if t.outcome == "UNKNOWN")
        distilled = sum(1 for t in trajectories if t.distillation_performed)

        return {
            "total_trajectories": total,
            "success_count": success,
            "failure_count": failure,
            "partial_count": partial,
            "unjudged_count": unjudged,
            "distilled_count": distilled,
            "success_rate": success / total if total > 0 else 0.0,
            "distillation_rate": distilled / total if total > 0 else 0.0,
        }
