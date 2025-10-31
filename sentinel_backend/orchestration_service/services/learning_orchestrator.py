"""
Learning Orchestrator Service

Coordinates the learning loop between feedback, ReasoningBank, and agents.

Flow:
1. Feedback arrives → learning queue
2. Orchestrator processes feedback → requests verdict from JudgmentService
3. Verdict updates trajectory → triggers pattern distillation
4. Learned patterns → influence future agent behavior

This service acts as the central coordinator for the learning system.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from sentinel_backend.reasoningbank.services.trajectory_service import TrajectoryService
from sentinel_backend.reasoningbank.services.judgment_service import JudgmentService
from sentinel_backend.reasoningbank.models.task_trajectories import (
    TaskTrajectory,
    TrajectoryOutcome
)


logger = logging.getLogger(__name__)


class LearningOrchestrator:
    """
    Orchestrates the learning loop for all agents.

    Responsibilities:
    - Process feedback from learning queue
    - Request judgments from JudgmentService
    - Update agent behavior based on learnings
    - Coordinate pattern distillation
    - Track learning metrics
    """

    def __init__(
        self,
        db_session: AsyncSession,
        judgment_service: Optional[JudgmentService] = None,
        anthropic_api_key: Optional[str] = None
    ):
        """
        Initialize learning orchestrator.

        Args:
            db_session: Database session for operations
            judgment_service: Pre-configured judgment service (optional)
            anthropic_api_key: API key for Claude if judgment_service not provided
        """
        self.db = db_session
        self.trajectory_service = TrajectoryService(db_session)

        # Initialize judgment service
        if judgment_service:
            self.judgment_service = judgment_service
        elif anthropic_api_key:
            self.judgment_service = JudgmentService(api_key=anthropic_api_key)
        else:
            # Try to create with environment variable
            try:
                self.judgment_service = JudgmentService()
                logger.info("Judgment service initialized with environment API key")
            except Exception as e:
                logger.warning(f"Could not initialize judgment service: {e}")
                self.judgment_service = None

        self.learning_metrics = {
            "total_processed": 0,
            "judgments_made": 0,
            "patterns_distilled": 0,
            "agent_updates": 0,
            "errors": 0
        }

    async def process_learning_queue(
        self,
        batch_size: int = 10,
        max_iterations: int = 100
    ) -> Dict[str, Any]:
        """
        Process pending items in the learning queue.

        Args:
            batch_size: Number of trajectories to process per batch
            max_iterations: Maximum number of batches to process

        Returns:
            Dict with processing statistics
        """
        logger.info("Starting learning queue processing")

        processed_count = 0
        errors = []

        for iteration in range(max_iterations):
            # Get unjudged trajectories
            unjudged = await self.trajectory_service.get_unjudged_trajectories(
                limit=batch_size
            )

            if not unjudged:
                logger.info("No more unjudged trajectories to process")
                break

            logger.info(f"Processing batch {iteration + 1}: {len(unjudged)} trajectories")

            # Process each trajectory
            for trajectory in unjudged:
                try:
                    await self._process_single_trajectory(trajectory)
                    processed_count += 1
                    self.learning_metrics["total_processed"] += 1
                except Exception as e:
                    error_msg = f"Error processing trajectory {trajectory.trajectory_id}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
                    self.learning_metrics["errors"] += 1

            # Small delay between batches
            await asyncio.sleep(0.1)

        # Process pattern distillation
        distilled_count = await self._process_pattern_distillation(batch_size)

        return {
            "processed_count": processed_count,
            "distilled_count": distilled_count,
            "errors": errors,
            "metrics": self.learning_metrics
        }

    async def _process_single_trajectory(self, trajectory: TaskTrajectory) -> None:
        """
        Process a single trajectory through the learning pipeline.

        Steps:
        1. Request judgment from JudgmentService
        2. Update trajectory with verdict
        3. Queue for pattern distillation if successful

        Args:
            trajectory: Trajectory to process
        """
        logger.debug(f"Processing trajectory: {trajectory.trajectory_id}")

        # Skip if already judged
        if trajectory.outcome != "UNKNOWN":
            logger.debug(f"Trajectory already judged: {trajectory.trajectory_id}")
            return

        # Request judgment
        if not self.judgment_service:
            logger.warning("No judgment service available, skipping judgment")
            return

        try:
            outcome, confidence, reasoning, additional_data = (
                await self.judgment_service.judge_trajectory(trajectory)
            )

            # Update trajectory with judgment
            await self.trajectory_service.update_judgment(
                trajectory_id=trajectory.trajectory_id,
                outcome=outcome,
                confidence=confidence,
                reasoning=reasoning
            )

            self.learning_metrics["judgments_made"] += 1

            logger.info(
                f"Judged trajectory {trajectory.trajectory_id}: "
                f"{outcome} (confidence: {confidence:.2f})"
            )

            # Log additional metrics
            quality_score = additional_data.get("quality_score")
            if quality_score:
                logger.debug(f"Quality score: {quality_score:.2f}")

        except Exception as e:
            logger.error(f"Failed to judge trajectory {trajectory.trajectory_id}: {e}")
            raise

    async def _process_pattern_distillation(self, batch_size: int = 10) -> int:
        """
        Process trajectories that need pattern distillation.

        Args:
            batch_size: Number of trajectories to distill per batch

        Returns:
            int: Number of trajectories distilled
        """
        logger.debug("Checking for trajectories needing distillation")

        # Get undistilled trajectories
        undistilled = await self.trajectory_service.get_undistilled_trajectories(
            limit=batch_size
        )

        if not undistilled:
            return 0

        logger.info(f"Distilling patterns from {len(undistilled)} trajectories")

        distilled_count = 0

        for trajectory in undistilled:
            try:
                # Extract patterns from successful trajectories
                if trajectory.outcome == "SUCCESS":
                    patterns = await self._extract_patterns(trajectory)

                    if patterns:
                        # Mark as distilled
                        await self.trajectory_service.mark_distilled(
                            trajectory_id=trajectory.trajectory_id,
                            extracted_pattern_ids=patterns
                        )

                        distilled_count += 1
                        self.learning_metrics["patterns_distilled"] += len(patterns)

                        logger.info(
                            f"Extracted {len(patterns)} patterns from {trajectory.trajectory_id}"
                        )
                else:
                    # Mark as distilled even if no patterns extracted (failure case)
                    await self.trajectory_service.mark_distilled(
                        trajectory_id=trajectory.trajectory_id,
                        extracted_pattern_ids=[]
                    )

            except Exception as e:
                logger.error(f"Error distilling patterns from {trajectory.trajectory_id}: {e}")
                continue

        return distilled_count

    async def _extract_patterns(self, trajectory: TaskTrajectory) -> List[str]:
        """
        Extract reusable patterns from a successful trajectory.

        This is a placeholder for more sophisticated pattern extraction.
        Future enhancements could include:
        - LLM-based pattern extraction
        - Code pattern mining
        - Test case template generation
        - API usage pattern detection

        Args:
            trajectory: Successful trajectory to analyze

        Returns:
            List[str]: List of extracted pattern IDs
        """
        patterns = []

        # Simple pattern extraction based on task type
        task_type = trajectory.task_type
        agent_type = trajectory.agent_type

        # Generate pattern ID
        pattern_id = f"pattern_{agent_type}_{task_type}_{trajectory.trajectory_id[:8]}"
        patterns.append(pattern_id)

        # TODO: Implement more sophisticated pattern extraction
        # - Analyze action sequences
        # - Extract common test case structures
        # - Identify successful API interaction patterns
        # - Learn from test data generation strategies

        logger.debug(f"Extracted patterns: {patterns}")

        return patterns

    async def get_agent_learning_stats(
        self,
        agent_type: Optional[str] = None,
        task_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get learning statistics for agents.

        Args:
            agent_type: Filter by agent type (optional)
            task_type: Filter by task type (optional)

        Returns:
            Dict with learning statistics
        """
        stats = await self.trajectory_service.get_trajectory_statistics(
            task_type=task_type
        )

        # Add orchestrator metrics
        stats["orchestrator_metrics"] = self.learning_metrics

        return stats

    async def trigger_agent_update(
        self,
        agent_type: str,
        learned_patterns: List[str]
    ) -> bool:
        """
        Trigger an agent to update its behavior based on learned patterns.

        This is a placeholder for agent behavior updates.
        Future enhancements could include:
        - Dynamic prompt updates
        - Test generation strategy adjustments
        - Parameter tuning based on success patterns

        Args:
            agent_type: Type of agent to update
            learned_patterns: Pattern IDs to incorporate

        Returns:
            bool: True if update successful
        """
        logger.info(f"Triggering update for {agent_type} with {len(learned_patterns)} patterns")

        # TODO: Implement agent behavior updates
        # For now, just log the update
        self.learning_metrics["agent_updates"] += 1

        return True

    async def get_learning_recommendations(
        self,
        agent_type: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get learning recommendations for a specific agent.

        Args:
            agent_type: Agent type to get recommendations for
            limit: Maximum number of recommendations

        Returns:
            List of recommendation dictionaries
        """
        # Get successful trajectories for this agent
        successful = await self.trajectory_service.get_trajectories_by_outcome(
            outcome="SUCCESS",
            limit=limit
        )

        recommendations = []

        for trajectory in successful:
            if trajectory.agent_type != agent_type:
                continue

            recommendation = {
                "trajectory_id": trajectory.trajectory_id,
                "task_description": trajectory.task_description,
                "confidence": trajectory.outcome_confidence,
                "execution_time_ms": trajectory.execution_time_ms,
                "test_success_rate": trajectory.test_success_rate,
                "patterns": trajectory.extracted_pattern_ids or [],
                "reasoning": trajectory.judgment_reasoning
            }

            recommendations.append(recommendation)

        return recommendations

    async def feedback_to_learning_loop(
        self,
        feedback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process feedback and feed it into the learning loop.

        Args:
            feedback_data: Feedback from users/tests

        Returns:
            Dict with processing status
        """
        logger.info("Processing feedback into learning loop")

        # Extract relevant information
        test_case_id = feedback_data.get("test_case_id")
        rating = feedback_data.get("rating")
        feedback_type = feedback_data.get("feedback_type")
        comment = feedback_data.get("comment")

        # TODO: Link feedback to trajectories
        # This requires the test_results table to have trajectory_id column

        # For now, log the feedback
        logger.info(
            f"Received feedback: test_case={test_case_id}, "
            f"rating={rating}, type={feedback_type}"
        )

        return {
            "status": "processed",
            "feedback_id": feedback_data.get("id"),
            "queued_for_learning": True
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get current learning metrics."""
        return self.learning_metrics.copy()

    async def reset_metrics(self) -> None:
        """Reset learning metrics."""
        self.learning_metrics = {
            "total_processed": 0,
            "judgments_made": 0,
            "patterns_distilled": 0,
            "agent_updates": 0,
            "errors": 0
        }
        logger.info("Learning metrics reset")
