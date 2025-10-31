"""
ReasoningBank Service - Main Orchestrator

Coordinates the complete learning loop for Sentinel's self-improving memory system:
1. Trajectory Capture: Track complete execution paths
2. Judgment: LLM-based success/failure evaluation
3. Distillation: Extract reusable strategic patterns (future)
4. Consolidation: Deduplicate and strengthen memories (future)
5. Retrieval: Semantic search for relevant patterns (future)

This is the primary entry point for agents to interact with ReasoningBank.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from ..models.task_trajectories import TaskTrajectory, TrajectoryOutcome
from ..models.pattern_embeddings import PatternEmbedding
from .trajectory_service import TrajectoryService
from .judgment_service import JudgmentService

logger = logging.getLogger(__name__)


class ReasoningBankService:
    """
    Main orchestrator for the ReasoningBank learning system.

    Provides high-level API for agents to:
    - Process trajectories through the full learning loop
    - Retrieve relevant knowledge for new tasks
    - Track learning statistics and performance
    - Schedule background consolidation tasks

    Example Usage:
        ```python
        # Initialize service
        rb = ReasoningBankService(
            db_session=db_session,
            judgment_service=judgment_service
        )

        # Process a completed trajectory
        result = await rb.process_trajectory_for_learning(
            trajectory_id="traj_abc123",
            force_judgment=False
        )

        # Retrieve relevant knowledge for a new task
        patterns = await rb.retrieve_relevant_knowledge(
            task_description="Generate security tests for auth API",
            task_type="test_generation",
            limit=5
        )

        # Get learning statistics
        stats = await rb.get_learning_statistics(
            task_type="test_generation",
            tenant_id="tenant_123"
        )
        ```
    """

    def __init__(
        self,
        db_session: AsyncSession,
        judgment_service: Optional[JudgmentService] = None,
        enable_background_consolidation: bool = True,
        consolidation_interval_hours: int = 24,
    ):
        """
        Initialize ReasoningBank orchestrator.

        Args:
            db_session: AsyncSession for database operations
            judgment_service: Optional pre-configured judgment service
            enable_background_consolidation: Whether to run periodic consolidation
            consolidation_interval_hours: Hours between consolidation runs
        """
        self.db = db_session
        self.trajectory_service = TrajectoryService(db_session)
        self.judgment_service = judgment_service

        # Configuration
        self.enable_background_consolidation = enable_background_consolidation
        self.consolidation_interval_hours = consolidation_interval_hours
        self._last_consolidation_run: Optional[datetime] = None

        # Statistics tracking
        self._stats_cache: Dict[str, Any] = {}
        self._stats_cache_expiry: Optional[datetime] = None
        self._stats_cache_ttl_seconds = 300  # 5 minutes

        logger.info("ReasoningBankService initialized")

    # ==================== Core Learning Loop ====================

    async def process_trajectory_for_learning(
        self,
        trajectory_id: str,
        force_judgment: bool = False,
        auto_distill: bool = True,
    ) -> Dict[str, Any]:
        """
        Process a trajectory through the complete learning loop.

        Flow:
        1. Retrieve trajectory
        2. Judge if needed (SUCCESS/FAILURE/PARTIAL)
        3. Distill patterns if successful (future implementation)
        4. Update confidence scores
        5. Return processing results

        Args:
            trajectory_id: Trajectory to process
            force_judgment: Force re-judgment even if already judged
            auto_distill: Automatically distill patterns after judgment

        Returns:
            Dict with processing results:
            {
                "trajectory_id": str,
                "judgment_performed": bool,
                "outcome": str,
                "confidence": float,
                "patterns_extracted": int,
                "processing_time_ms": int
            }
        """
        start_time = datetime.utcnow()

        try:
            # 1. Retrieve trajectory
            trajectory = await self.trajectory_service.get_trajectory(trajectory_id)
            if not trajectory:
                raise ValueError(f"Trajectory not found: {trajectory_id}")

            logger.info(f"Processing trajectory {trajectory_id} for learning")

            result = {
                "trajectory_id": trajectory_id,
                "judgment_performed": False,
                "distillation_performed": False,
                "outcome": str(trajectory.outcome).upper() if trajectory.outcome else "UNKNOWN",
                "confidence": trajectory.outcome_confidence,
                "patterns_extracted": 0,
                "processing_time_ms": 0,
            }

            # 2. Judge trajectory if needed
            if trajectory.needs_judgment or force_judgment:
                if not self.judgment_service:
                    logger.warning(
                        f"Cannot judge trajectory {trajectory_id}: judgment_service not configured"
                    )
                else:
                    judgment_result = await self._judge_trajectory(trajectory)
                    result.update(judgment_result)
                    result["judgment_performed"] = True

            # 3. Distill patterns if successful and not yet distilled
            if auto_distill and trajectory.needs_distillation:
                distillation_result = await self._distill_trajectory(trajectory)
                result.update(distillation_result)
                result["distillation_performed"] = True

            # 4. Calculate processing time
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            result["processing_time_ms"] = int(elapsed * 1000)

            logger.info(
                f"Completed processing trajectory {trajectory_id}: "
                f"outcome={result['outcome']}, patterns={result['patterns_extracted']}"
            )

            return result

        except Exception as e:
            logger.error(f"Error processing trajectory {trajectory_id}: {e}", exc_info=True)
            raise

    async def batch_process_trajectories(
        self,
        trajectory_ids: Optional[List[str]] = None,
        task_type: Optional[str] = None,
        limit: int = 50,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process multiple trajectories in batch.

        If trajectory_ids not provided, processes unjudged trajectories.

        Args:
            trajectory_ids: Specific trajectories to process (optional)
            task_type: Filter by task type if auto-discovering
            limit: Maximum trajectories to process
            tenant_id: Tenant filter

        Returns:
            Dict with batch processing results
        """
        start_time = datetime.utcnow()

        try:
            # Get trajectories to process
            if trajectory_ids:
                trajectories = []
                for tid in trajectory_ids:
                    traj = await self.trajectory_service.get_trajectory(tid)
                    if traj:
                        trajectories.append(traj)
            else:
                # Auto-discover unjudged trajectories
                trajectories = await self.trajectory_service.get_unjudged_trajectories(
                    task_type=task_type,
                    limit=limit,
                    tenant_id=tenant_id,
                )

            logger.info(f"Batch processing {len(trajectories)} trajectories")

            results = {
                "total_processed": 0,
                "judgments_performed": 0,
                "distillations_performed": 0,
                "patterns_extracted": 0,
                "success_count": 0,
                "failure_count": 0,
                "partial_count": 0,
                "errors": [],
                "processing_time_ms": 0,
            }

            # Process each trajectory
            for trajectory in trajectories:
                try:
                    result = await self.process_trajectory_for_learning(
                        trajectory_id=trajectory.trajectory_id,
                        force_judgment=False,
                        auto_distill=True,
                    )

                    results["total_processed"] += 1
                    if result["judgment_performed"]:
                        results["judgments_performed"] += 1
                    if result["distillation_performed"]:
                        results["distillations_performed"] += 1
                    results["patterns_extracted"] += result["patterns_extracted"]

                    # Count outcomes
                    if result["outcome"] == "success":
                        results["success_count"] += 1
                    elif result["outcome"] == "failure":
                        results["failure_count"] += 1
                    elif result["outcome"] == "partial":
                        results["partial_count"] += 1

                except Exception as e:
                    logger.error(
                        f"Error processing trajectory {trajectory.trajectory_id}: {e}"
                    )
                    results["errors"].append({
                        "trajectory_id": trajectory.trajectory_id,
                        "error": str(e),
                    })

            # Calculate total processing time
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            results["processing_time_ms"] = int(elapsed * 1000)

            logger.info(
                f"Batch processing complete: {results['total_processed']} trajectories, "
                f"{results['judgments_performed']} judgments, "
                f"{results['patterns_extracted']} patterns extracted"
            )

            return results

        except Exception as e:
            logger.error(f"Error in batch processing: {e}", exc_info=True)
            raise

    # ==================== Knowledge Retrieval ====================

    async def retrieve_relevant_knowledge(
        self,
        task_description: str,
        task_type: Optional[str] = None,
        domain_tags: Optional[List[str]] = None,
        limit: int = 5,
        min_confidence: float = 0.5,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant patterns for a new task.

        Uses semantic similarity search with MMR (Maximal Marginal Relevance)
        to balance relevance and diversity.

        NOTE: This is a placeholder implementation. Full semantic retrieval
        requires the RetrievalService with vector embeddings.

        Args:
            task_description: Description of the task to find patterns for
            task_type: Filter by task type
            domain_tags: Filter by domain tags
            limit: Maximum patterns to return
            min_confidence: Minimum confidence threshold
            tenant_id: Tenant filter

        Returns:
            List of pattern dictionaries with relevance scores
        """
        logger.info(
            f"Retrieving knowledge for task: {task_description[:100]}... "
            f"(type={task_type}, limit={limit})"
        )

        try:
            # TODO: Implement semantic retrieval with vector search
            # For now, return placeholder structure

            # This will be replaced with:
            # patterns = await self.retrieval_service.semantic_search(
            #     query_text=task_description,
            #     task_type=task_type,
            #     domain_tags=domain_tags,
            #     limit=limit,
            #     min_confidence=min_confidence,
            #     tenant_id=tenant_id,
            # )

            logger.warning(
                "retrieve_relevant_knowledge: Semantic retrieval not yet implemented. "
                "Returning empty results. Implement RetrievalService for full functionality."
            )

            return []

        except Exception as e:
            logger.error(f"Error retrieving knowledge: {e}", exc_info=True)
            return []

    async def get_best_practices_for_task(
        self,
        task_type: str,
        limit: int = 10,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get highest-confidence patterns for a task type.

        Returns patterns sorted by confidence and usage statistics.

        Args:
            task_type: Task type to get best practices for
            limit: Maximum patterns to return
            tenant_id: Tenant filter

        Returns:
            List of high-confidence patterns
        """
        logger.info(f"Retrieving best practices for task_type={task_type}")

        try:
            # Query for patterns with high confidence and usage
            query = select(PatternEmbedding).where(
                PatternEmbedding.confidence >= 0.7
            )

            if tenant_id:
                query = query.where(PatternEmbedding.tenant_id == tenant_id)

            # Sort by combined score: confidence * usage_count
            query = query.order_by(
                (PatternEmbedding.confidence * PatternEmbedding.usage_count).desc()
            ).limit(limit)

            result = await self.db.execute(query)
            patterns = result.scalars().all()

            return [p.to_dict() for p in patterns]

        except Exception as e:
            logger.error(f"Error getting best practices: {e}", exc_info=True)
            return []

    # ==================== Statistics & Monitoring ====================

    async def get_learning_statistics(
        self,
        task_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
        use_cache: bool = True,
    ) -> Dict[str, Any]:
        """
        Get comprehensive learning statistics.

        Includes:
        - Total trajectories and outcomes
        - Pattern library size
        - Success rates and trends
        - Recent activity

        Args:
            task_type: Filter by task type
            tenant_id: Filter by tenant
            use_cache: Whether to use cached statistics

        Returns:
            Dict with comprehensive statistics
        """
        # Check cache
        cache_key = f"{task_type or 'all'}:{tenant_id or 'all'}"
        if use_cache and self._is_stats_cache_valid():
            cached = self._stats_cache.get(cache_key)
            if cached:
                logger.debug(f"Returning cached statistics for {cache_key}")
                return cached

        logger.info(
            f"Computing learning statistics for task_type={task_type}, "
            f"tenant_id={tenant_id}"
        )

        try:
            # Get trajectory statistics
            traj_stats = await self.trajectory_service.get_trajectory_statistics(
                task_type=task_type,
                tenant_id=tenant_id,
            )

            # Get pattern statistics
            pattern_stats = await self._get_pattern_statistics(
                task_type=task_type,
                tenant_id=tenant_id,
            )

            # Combine statistics
            stats = {
                "trajectories": traj_stats,
                "patterns": pattern_stats,
                "learning_metrics": {
                    "knowledge_growth_rate": self._calculate_growth_rate(
                        pattern_stats["total_patterns"],
                        traj_stats["total_trajectories"],
                    ),
                    "pattern_density": (
                        pattern_stats["total_patterns"] / traj_stats["total_trajectories"]
                        if traj_stats["total_trajectories"] > 0
                        else 0.0
                    ),
                    "avg_pattern_confidence": pattern_stats["avg_confidence"],
                    "system_health_score": self._calculate_health_score(
                        traj_stats, pattern_stats
                    ),
                },
                "generated_at": datetime.utcnow().isoformat(),
            }

            # Update cache
            self._stats_cache[cache_key] = stats
            self._stats_cache_expiry = datetime.utcnow() + timedelta(
                seconds=self._stats_cache_ttl_seconds
            )

            return stats

        except Exception as e:
            logger.error(f"Error computing statistics: {e}", exc_info=True)
            raise

    async def get_recent_learning_activity(
        self,
        hours: int = 24,
        task_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get recent learning activity.

        Args:
            hours: Lookback window in hours
            task_type: Filter by task type
            tenant_id: Filter by tenant

        Returns:
            Dict with recent activity metrics
        """
        since = datetime.utcnow() - timedelta(hours=hours)

        try:
            # Recent trajectories
            query = select(TaskTrajectory).where(
                TaskTrajectory.created_at >= since
            )

            if task_type:
                query = query.where(TaskTrajectory.task_type == task_type)
            if tenant_id:
                query = query.where(TaskTrajectory.tenant_id == tenant_id)

            result = await self.db.execute(query)
            recent_trajectories = list(result.scalars().all())

            # Recent patterns
            pattern_query = select(PatternEmbedding).where(
                PatternEmbedding.created_at >= since
            )
            if tenant_id:
                pattern_query = pattern_query.where(
                    PatternEmbedding.tenant_id == tenant_id
                )

            result = await self.db.execute(pattern_query)
            recent_patterns = list(result.scalars().all())

            return {
                "lookback_hours": hours,
                "trajectories_created": len(recent_trajectories),
                "patterns_learned": len(recent_patterns),
                "success_count": sum(
                    1 for t in recent_trajectories
                    if t.outcome == "SUCCESS"
                ),
                "failure_count": sum(
                    1 for t in recent_trajectories
                    if t.outcome == "FAILURE"
                ),
                "avg_execution_time_ms": (
                    sum(t.execution_time_ms or 0 for t in recent_trajectories)
                    / len(recent_trajectories)
                    if recent_trajectories
                    else 0
                ),
                "period_start": since.isoformat(),
                "period_end": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting recent activity: {e}", exc_info=True)
            raise

    # ==================== Consolidation ====================

    async def run_consolidation_cycle(
        self,
        task_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run memory consolidation cycle.

        Performs:
        1. Deduplication: Merge similar patterns
        2. Contradiction detection: Flag conflicting patterns
        3. Aging: Reduce confidence of unused patterns
        4. Pruning: Remove low-value patterns

        NOTE: This is a placeholder. Full consolidation requires ConsolidationService.

        Args:
            task_type: Filter by task type
            tenant_id: Filter by tenant

        Returns:
            Dict with consolidation results
        """
        logger.info(
            f"Running consolidation cycle for task_type={task_type}, "
            f"tenant_id={tenant_id}"
        )

        start_time = datetime.utcnow()

        try:
            # TODO: Implement full consolidation
            # This will be replaced with:
            # result = await self.consolidation_service.consolidate(
            #     task_type=task_type,
            #     tenant_id=tenant_id,
            # )

            result = {
                "status": "not_implemented",
                "message": "Consolidation service not yet implemented",
                "duplicates_merged": 0,
                "contradictions_detected": 0,
                "patterns_aged": 0,
                "patterns_pruned": 0,
                "processing_time_ms": 0,
            }

            # Mark last run time
            self._last_consolidation_run = datetime.utcnow()

            elapsed = (datetime.utcnow() - start_time).total_seconds()
            result["processing_time_ms"] = int(elapsed * 1000)

            logger.warning(
                "Consolidation cycle skipped: ConsolidationService not implemented"
            )

            return result

        except Exception as e:
            logger.error(f"Error in consolidation cycle: {e}", exc_info=True)
            raise

    async def should_run_consolidation(self) -> bool:
        """
        Check if consolidation should run based on schedule.

        Returns:
            bool: True if consolidation is due
        """
        if not self.enable_background_consolidation:
            return False

        if not self._last_consolidation_run:
            return True

        time_since_last = datetime.utcnow() - self._last_consolidation_run
        due_time = timedelta(hours=self.consolidation_interval_hours)

        return time_since_last >= due_time

    # ==================== Private Helper Methods ====================

    async def _judge_trajectory(
        self, trajectory: TaskTrajectory
    ) -> Dict[str, Any]:
        """Judge a trajectory and update database."""
        try:
            outcome, confidence, reasoning, additional_data = (
                await self.judgment_service.judge_trajectory(trajectory)
            )

            # Update trajectory in database
            await self.trajectory_service.update_judgment(
                trajectory_id=trajectory.trajectory_id,
                outcome=outcome,
                confidence=confidence,
                reasoning=reasoning,
            )

            logger.info(
                f"Judged trajectory {trajectory.trajectory_id}: "
                f"outcome={outcome.value}, confidence={confidence:.2f}"
            )

            return {
                "outcome": outcome.value,
                "confidence": confidence,
                "reasoning": reasoning,
                "quality_score": additional_data.get("quality_score", 0.0),
            }

        except Exception as e:
            logger.error(f"Error judging trajectory: {e}", exc_info=True)
            return {
                "outcome": "unknown",
                "confidence": 0.0,
                "reasoning": f"Judgment failed: {str(e)}",
                "quality_score": 0.0,
            }

    async def _distill_trajectory(
        self, trajectory: TaskTrajectory
    ) -> Dict[str, Any]:
        """
        Distill patterns from a trajectory.

        NOTE: Placeholder for future DistillationService integration.
        """
        try:
            # TODO: Implement pattern distillation
            # This will be replaced with:
            # patterns = await self.distillation_service.distill_patterns(trajectory)

            logger.warning(
                f"Pattern distillation not implemented for trajectory "
                f"{trajectory.trajectory_id}"
            )

            # Mark as distilled even though we didn't extract patterns
            await self.trajectory_service.mark_distilled(
                trajectory_id=trajectory.trajectory_id,
                extracted_pattern_ids=[],
            )

            return {
                "patterns_extracted": 0,
                "distillation_status": "not_implemented",
            }

        except Exception as e:
            logger.error(f"Error distilling trajectory: {e}", exc_info=True)
            return {
                "patterns_extracted": 0,
                "distillation_status": "error",
                "error": str(e),
            }

    async def _get_pattern_statistics(
        self,
        task_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get statistics about pattern library."""
        try:
            query = select(PatternEmbedding)

            if tenant_id:
                query = query.where(PatternEmbedding.tenant_id == tenant_id)

            result = await self.db.execute(query)
            patterns = list(result.scalars().all())

            if not patterns:
                return {
                    "total_patterns": 0,
                    "avg_confidence": 0.0,
                    "avg_usage_count": 0.0,
                    "high_confidence_count": 0,
                    "total_usage": 0,
                }

            return {
                "total_patterns": len(patterns),
                "avg_confidence": sum(p.confidence for p in patterns) / len(patterns),
                "avg_usage_count": sum(p.usage_count for p in patterns) / len(patterns),
                "high_confidence_count": sum(
                    1 for p in patterns if p.confidence >= 0.8
                ),
                "total_usage": sum(p.usage_count for p in patterns),
            }

        except Exception as e:
            logger.error(f"Error getting pattern statistics: {e}", exc_info=True)
            return {
                "total_patterns": 0,
                "avg_confidence": 0.0,
                "avg_usage_count": 0.0,
                "high_confidence_count": 0,
                "total_usage": 0,
            }

    def _calculate_growth_rate(
        self, pattern_count: int, trajectory_count: int
    ) -> float:
        """Calculate knowledge growth rate."""
        if trajectory_count == 0:
            return 0.0
        return pattern_count / trajectory_count

    def _calculate_health_score(
        self,
        traj_stats: Dict[str, Any],
        pattern_stats: Dict[str, Any],
    ) -> float:
        """
        Calculate overall system health score (0.0-1.0).

        Considers:
        - Success rate
        - Pattern library size
        - Average confidence
        """
        success_rate = traj_stats.get("success_rate", 0.0)
        pattern_density = (
            pattern_stats["total_patterns"] / traj_stats["total_trajectories"]
            if traj_stats["total_trajectories"] > 0
            else 0.0
        )
        avg_confidence = pattern_stats.get("avg_confidence", 0.0)

        # Weighted average
        health_score = (
            0.5 * success_rate
            + 0.2 * min(1.0, pattern_density / 10)  # Normalize to 0-1
            + 0.3 * avg_confidence
        )

        return round(health_score, 3)

    def _is_stats_cache_valid(self) -> bool:
        """Check if statistics cache is still valid."""
        if not self._stats_cache_expiry:
            return False
        return datetime.utcnow() < self._stats_cache_expiry

    # ==================== Utility Methods ====================

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on ReasoningBank system.

        Returns:
            Dict with health status
        """
        try:
            # Check database connectivity
            await self.db.execute(select(1))
            db_healthy = True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            db_healthy = False

        # Check judgment service
        judgment_healthy = self.judgment_service is not None

        # Get recent activity
        try:
            recent = await self.get_recent_learning_activity(hours=1)
            recent_activity = recent["trajectories_created"]
        except Exception:
            recent_activity = 0

        return {
            "status": "healthy" if db_healthy else "degraded",
            "database": "ok" if db_healthy else "error",
            "judgment_service": "configured" if judgment_healthy else "not_configured",
            "recent_activity_1h": recent_activity,
            "last_consolidation_run": (
                self._last_consolidation_run.isoformat()
                if self._last_consolidation_run
                else None
            ),
            "consolidation_enabled": self.enable_background_consolidation,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def clear_cache(self) -> None:
        """Clear statistics cache."""
        self._stats_cache.clear()
        self._stats_cache_expiry = None
        logger.info("Statistics cache cleared")

    def get_service_info(self) -> Dict[str, Any]:
        """
        Get information about configured services.

        Returns:
            Dict with service configuration
        """
        return {
            "trajectory_service": "configured",
            "judgment_service": (
                "configured" if self.judgment_service else "not_configured"
            ),
            "retrieval_service": "not_implemented",
            "distillation_service": "not_implemented",
            "consolidation_service": "not_implemented",
            "background_consolidation": self.enable_background_consolidation,
            "consolidation_interval_hours": self.consolidation_interval_hours,
        }
