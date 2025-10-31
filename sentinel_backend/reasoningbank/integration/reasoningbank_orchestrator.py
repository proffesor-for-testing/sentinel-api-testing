"""
ReasoningBank Integration Orchestrator

Integrates ReasoningBank services with Sentinel's orchestration layer,
enabling agents to learn from trajectories and retrieve relevant patterns.

Architecture:
1. Trajectory Capture: Hook into agent execution to capture trajectories
2. Automatic Judgment: Asynchronously judge completed trajectories
3. Pattern Distillation: Extract reusable patterns from successful runs
4. Pattern Retrieval: Provide patterns to agents for new tasks
5. Consolidation: Periodic memory cleanup and optimization

Integration Points:
- orchestration_service/main.py: Hook trajectory capture
- agents/*.py: Inject pattern retrieval before execution
- Background tasks: Judgment, distillation, consolidation
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine, create_async_engine
from sqlalchemy.orm import sessionmaker
from anthropic import AsyncAnthropic
from openai import AsyncOpenAI

from .session_manager import SessionManager
from ..services.reasoningbank_service import ReasoningBankService
from ..services.trajectory_service import TrajectoryService
from ..services.judgment_service import JudgmentService
from ..services.distillation_service import DistillationService
from ..services.retrieval_service import RetrievalService
from ..services.consolidation_service import ConsolidationService
from ..models.task_trajectories import TaskTrajectory, TrajectoryOutcome
from ..models.worker_checkpoints import WorkerCheckpoint

logger = logging.getLogger(__name__)


class ReasoningBankOrchestrator:
    """
    Main orchestrator for ReasoningBank integration with Sentinel.

    Provides:
    - Trajectory lifecycle management
    - Background processing for judgment and distillation
    - Pattern retrieval API for agents
    - Consolidation scheduling
    """

    def __init__(
        self,
        db_engine: AsyncEngine,
        anthropic_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        enable_background_tasks: bool = True,
    ):
        """
        Initialize ReasoningBank orchestrator.

        Args:
            db_engine: AsyncEngine for database connections (NOT a session)
            anthropic_api_key: Anthropic API key for judgment/distillation
            openai_api_key: OpenAI API key for embeddings
            enable_background_tasks: Whether to run background processing
        """
        # Create session manager instead of using shared session
        self.session_manager = SessionManager(db_engine)
        self.enable_background_tasks = enable_background_tasks

        # Initialize AI clients
        self.anthropic_client = AsyncAnthropic(api_key=anthropic_api_key) if anthropic_api_key else None
        self.openai_client = AsyncOpenAI(api_key=openai_api_key) if openai_api_key else None

        # Store service configuration for lazy initialization
        # Services will be created per-request with their own sessions
        self._anthropic_client = self.anthropic_client
        self._openai_client = self.openai_client

        # Background task handles
        self._background_tasks: List[asyncio.Task] = []
        self._shutdown_event = asyncio.Event()

        # Worker checkpoint tracking
        self._current_task_id: Optional[str] = None
        self._checkpoint_data: Dict[str, Any] = {}

        logger.info("ReasoningBankOrchestrator initialized with session factory pattern")

    # ==================== Trajectory Management ====================

    async def start_trajectory(
        self,
        agent_type: str,
        task_description: str,
        context_data: Dict[str, Any],
        task_type: str = "test_generation",
        tenant_id: Optional[str] = None,
    ) -> str:
        """
        Start a new trajectory for an agent execution.

        Args:
            agent_type: Type of agent executing
            task_description: Description of the task
            context_data: Context information (API spec, config, etc.)
            task_type: Type of task being performed
            tenant_id: Optional tenant identifier

        Returns:
            trajectory_id for the new trajectory
        """
        async with self.session_manager.get_session() as session:
            trajectory_service = TrajectoryService(session)
            trajectory = await trajectory_service.create_trajectory(
                agent_type=agent_type,
                task_type=task_type,
                task_description=task_description,
                context_data=context_data,
                tenant_id=tenant_id
            )

            logger.info(f"Started trajectory {trajectory.trajectory_id} for {agent_type}")
            return trajectory.trajectory_id

    async def record_action(
        self,
        trajectory_id: str,
        action_type: str,
        action_description: str,
        action_data: Optional[Dict[str, Any]] = None,
    ):
        """
        Record an action taken during trajectory execution.

        Args:
            trajectory_id: Trajectory to record action for
            action_type: Type of action (e.g., "analysis", "generation", "validation")
            action_description: Human-readable description
            action_data: Optional structured data about the action
        """
        async with self.session_manager.get_session() as session:
            trajectory_service = TrajectoryService(session)
            await trajectory_service.add_action(
                trajectory_id=trajectory_id,
                action_type=action_type,
                description=action_description,
                data=action_data or {}
            )

    async def complete_trajectory(
        self,
        trajectory_id: str,
        final_output: Dict[str, Any],
        test_success_rate: Optional[float] = None,
        coverage_score: Optional[float] = None,
        auto_process: bool = True,
    ) -> Dict[str, Any]:
        """
        Complete a trajectory and optionally trigger processing.

        Args:
            trajectory_id: Trajectory to complete
            final_output: Final output from agent execution
            test_success_rate: Optional test success rate
            coverage_score: Optional coverage score
            auto_process: Whether to automatically judge and distill

        Returns:
            Processing result summary
        """
        # Mark trajectory complete using dedicated session
        async with self.session_manager.get_session() as session:
            trajectory_service = TrajectoryService(session)
            await trajectory_service.complete_trajectory(
                trajectory_id=trajectory_id,
                final_output=final_output,
                test_success_rate=test_success_rate,
                coverage_score=coverage_score
            )

        logger.info(f"Completed trajectory {trajectory_id}")

        # Auto-process if enabled (uses its own session internally)
        if auto_process:
            async with self.session_manager.get_session() as session:
                reasoningbank = ReasoningBankService(
                    db_session=session,
                    judgment_service=self._create_judgment_service(session),
                    enable_background_consolidation=self.enable_background_tasks
                )
                return await reasoningbank.process_trajectory_for_learning(
                    trajectory_id=trajectory_id,
                    force_judgment=False,
                    auto_distill=True
                )

        return {"status": "completed", "auto_process": False}

    def _create_judgment_service(self, session: AsyncSession) -> Optional[JudgmentService]:
        """Create judgment service with given session."""
        if self._anthropic_client:
            return JudgmentService(
                db_session=session,
                anthropic_client=self._anthropic_client
            )
        return None

    # ==================== Pattern Retrieval ====================

    async def get_relevant_patterns(
        self,
        task_description: str,
        agent_type: str,
        limit: int = 5,
        min_confidence: float = 0.6,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant patterns for a new task.

        This is the main API for agents to get learned knowledge.

        Args:
            task_description: Description of the task
            agent_type: Type of agent requesting patterns
            limit: Maximum patterns to return
            min_confidence: Minimum confidence threshold
            tenant_id: Optional tenant filter

        Returns:
            List of relevant pattern dictionaries
        """
        if not (self._anthropic_client and self._openai_client):
            logger.warning("AI services not configured, returning empty patterns")
            return []

        async with self.session_manager.get_read_only_session() as session:
            # Create services with this session
            distillation_service = DistillationService(
                db_session=session,
                anthropic_client=self._anthropic_client,
                openai_client=self._openai_client
            )

            retrieval_service = RetrievalService(
                db_session=session,
                embedding_service=distillation_service
            )

            # Generate embedding for task description
            embedding = await distillation_service.generate_embedding(task_description)

            # Retrieve patterns
            patterns = await retrieval_service.retrieve_relevant_patterns(
                query_text=task_description,
                query_embedding=embedding,
                limit=limit,
                min_confidence=min_confidence,
                tenant_id=tenant_id,
                use_mmr=True  # Use MMR for diversity
            )

            # Convert to dictionaries
            return [p.to_dict() for p in patterns]

    async def update_pattern_usage(
        self,
        pattern_id: str,
        success: bool,
    ):
        """
        Update pattern confidence based on usage outcome.

        Args:
            pattern_id: Pattern that was used
            success: Whether using the pattern was successful
        """
        if not self.retrieval_service:
            return

        await self.retrieval_service.update_pattern_usage(
            pattern_id=pattern_id,
            success=success
        )

        logger.info(f"Updated pattern {pattern_id} usage: success={success}")

    # ==================== Background Processing ====================

    async def start_background_tasks(self):
        """Start background processing tasks"""
        if not self.enable_background_tasks:
            logger.info("Background tasks disabled")
            return

        logger.info("Starting ReasoningBank background tasks")

        # Task 1: Judgment processing
        self._background_tasks.append(
            asyncio.create_task(self._judgment_worker())
        )

        # Task 2: Distillation processing
        self._background_tasks.append(
            asyncio.create_task(self._distillation_worker())
        )

        # Task 3: Consolidation scheduling
        self._background_tasks.append(
            asyncio.create_task(self._consolidation_worker())
        )

        logger.info(f"Started {len(self._background_tasks)} background tasks")

    async def stop_background_tasks(self, timeout: int = 60):
        """
        Stop all background tasks gracefully with timeout.

        Args:
            timeout: Maximum seconds to wait for graceful shutdown

        Flow:
            1. Set shutdown event (workers check this)
            2. Wait up to 'timeout' seconds for workers to finish
            3. If timeout exceeded, force cancel remaining tasks
            4. Verify all sessions closed
            5. Log final statistics
        """
        logger.info(f"Stopping ReasoningBank background tasks (timeout={timeout}s)")
        start_time = asyncio.get_event_loop().time()

        # Phase 1: Signal graceful shutdown
        self._shutdown_event.set()
        logger.info("Shutdown signal sent to all workers")

        # Phase 2: Wait for graceful completion (with timeout)
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._background_tasks, return_exceptions=True),
                timeout=timeout
            )
            elapsed = asyncio.get_event_loop().time() - start_time
            logger.info(f"All background tasks stopped gracefully in {elapsed:.2f}s")

        except asyncio.TimeoutError:
            elapsed = asyncio.get_event_loop().time() - start_time
            logger.warning(
                f"Graceful shutdown timeout after {elapsed:.2f}s, "
                f"forcing cancellation of {len(self._background_tasks)} tasks"
            )

            # Phase 3: Force cancellation
            still_running = [task for task in self._background_tasks if not task.done()]
            logger.warning(f"Force-cancelling {len(still_running)} tasks")

            for task in still_running:
                task.cancel()

            # Wait for force-cancelled tasks
            await asyncio.gather(*still_running, return_exceptions=True)

            logger.info("All tasks force-cancelled")

        # Phase 4: Verify resource cleanup
        await self._verify_resource_cleanup()

        # Phase 5: Log shutdown statistics
        await self._log_shutdown_statistics()

        logger.info("Background task shutdown complete")

    async def _verify_resource_cleanup(self):
        """Verify all resources cleaned up"""
        # Check session manager
        if hasattr(self.session_manager, 'active_sessions'):
            active = self.session_manager.active_sessions
            if active > 0:
                logger.warning(f"Warning: {active} sessions still active after shutdown")

        # Check database connection pool
        try:
            pool = self.session_manager.engine.pool
            if hasattr(pool, 'size'):
                logger.info(
                    f"Connection pool status: "
                    f"{pool.size()} total connections"
                )
        except Exception as e:
            logger.error(f"Could not check connection pool: {e}")

    async def _log_shutdown_statistics(self):
        """Log final statistics about shutdown"""
        completed = sum(1 for task in self._background_tasks if task.done() and not task.cancelled())
        cancelled = sum(1 for task in self._background_tasks if task.cancelled())
        errored = sum(1 for task in self._background_tasks if task.done() and task.exception())

        logger.info(
            f"Shutdown statistics: "
            f"{completed} completed gracefully, "
            f"{cancelled} cancelled, "
            f"{errored} errored"
        )

    async def _checkpoint(self, task_id: str, worker_name: str, data: Dict[str, Any]):
        """Save checkpoint for current task"""
        self._current_task_id = task_id
        self._checkpoint_data[task_id] = {
            "timestamp": datetime.utcnow(),
            "state": data,
            "worker": worker_name
        }

        # Persist to database
        async with self.session_manager.get_session() as session:
            checkpoint = WorkerCheckpoint(
                task_id=task_id,
                worker_name=worker_name,
                checkpoint_data=data,
                created_at=datetime.utcnow()
            )
            session.add(checkpoint)
            await session.commit()

    async def _complete_checkpoint(self, task_id: str):
        """Mark checkpoint as complete"""
        async with self.session_manager.get_session() as session:
            from sqlalchemy import select, update

            stmt = (
                update(WorkerCheckpoint)
                .where(WorkerCheckpoint.task_id == task_id)
                .where(WorkerCheckpoint.completed_at.is_(None))
                .values(completed_at=datetime.utcnow())
            )
            await session.execute(stmt)
            await session.commit()

    async def _cleanup_current_task(self, worker_name: str):
        """Cleanup current task on shutdown"""
        if self._current_task_id:
            logger.info(f"Cleaning up current task: {self._current_task_id}")
            await self._checkpoint(
                self._current_task_id,
                worker_name,
                {"stage": "interrupted", "can_resume": True}
            )

    async def _sleep_with_shutdown_check(self, seconds: int):
        """Sleep but wake up immediately if shutdown requested"""
        for _ in range(seconds):
            if self._shutdown_event.is_set():
                break
            await asyncio.sleep(1)

    async def _judgment_worker(self):
        """
        Background worker for judging trajectories with checkpoint support.

        Periodically checks for unjudged trajectories and judges them.
        """
        logger.info("Judgment worker started")

        while not self._shutdown_event.is_set():
            try:
                # Get unjudged trajectories with dedicated session
                async with self.session_manager.get_read_only_session() as session:
                    trajectory_service = TrajectoryService(session)
                    unjudged = await trajectory_service.get_unjudged_trajectories(limit=10)

                if unjudged:
                    logger.info(f"Processing {len(unjudged)} unjudged trajectories")

                    for trajectory in unjudged:
                        # Check shutdown before processing
                        if self._shutdown_event.is_set():
                            logger.info("Shutdown requested, stopping judgment worker gracefully")
                            break

                        try:
                            # Create checkpoint BEFORE processing
                            await self._checkpoint(
                                task_id=f"judge_{trajectory.trajectory_id}",
                                worker_name="JudgmentWorker",
                                data={"trajectory_id": trajectory.trajectory_id, "stage": "started"}
                            )

                            # Process with dedicated session
                            async with self.session_manager.get_session() as session:
                                reasoningbank = ReasoningBankService(
                                    db_session=session,
                                    judgment_service=self._create_judgment_service(session)
                                )
                                await reasoningbank.process_trajectory_for_learning(
                                    trajectory_id=trajectory.trajectory_id,
                                    force_judgment=False,
                                    auto_distill=False  # Distillation worker handles this
                                )

                            # Mark checkpoint complete
                            await self._complete_checkpoint(f"judge_{trajectory.trajectory_id}")

                        except Exception as e:
                            logger.error(f"Error judging trajectory {trajectory.trajectory_id}: {e}")

                # Sleep with shutdown check
                await self._sleep_with_shutdown_check(30)

            except asyncio.CancelledError:
                logger.info("Judgment worker cancelled, cleaning up")
                await self._cleanup_current_task("JudgmentWorker")
                raise
            except Exception as e:
                logger.error(f"Judgment worker error: {e}", exc_info=True)
                await self._sleep_with_shutdown_check(60)

        logger.info("Judgment worker stopped gracefully")

    async def _distillation_worker(self):
        """
        Background worker for distilling patterns with checkpoint support.

        Processes judged trajectories and extracts patterns.
        """
        logger.info("Distillation worker started")

        while not self._shutdown_event.is_set():
            try:
                # Check if AI services configured
                if not (self._anthropic_client and self._openai_client):
                    await self._sleep_with_shutdown_check(300)
                    continue

                # Get undistilled trajectories with dedicated session
                async with self.session_manager.get_read_only_session() as session:
                    trajectory_service = TrajectoryService(session)
                    undistilled = await trajectory_service.get_undistilled_trajectories(limit=5)

                if undistilled:
                    logger.info(f"Distilling {len(undistilled)} trajectories")

                    for trajectory in undistilled:
                        # Check shutdown before processing
                        if self._shutdown_event.is_set():
                            logger.info("Shutdown requested, stopping distillation worker gracefully")
                            break

                        try:
                            # Create checkpoint BEFORE processing
                            await self._checkpoint(
                                task_id=f"distill_{trajectory.trajectory_id}",
                                worker_name="DistillationWorker",
                                data={"trajectory_id": trajectory.trajectory_id, "stage": "started"}
                            )

                            # Process with dedicated session
                            async with self.session_manager.get_session() as session:
                                distillation_service = DistillationService(
                                    db_session=session,
                                    anthropic_client=self._anthropic_client,
                                    openai_client=self._openai_client
                                )
                                await distillation_service.distill_pattern(trajectory)

                            # Mark checkpoint complete
                            await self._complete_checkpoint(f"distill_{trajectory.trajectory_id}")

                        except Exception as e:
                            logger.error(f"Error distilling trajectory {trajectory.trajectory_id}: {e}")

                # Sleep with shutdown check
                await self._sleep_with_shutdown_check(60)

            except asyncio.CancelledError:
                logger.info("Distillation worker cancelled, cleaning up")
                await self._cleanup_current_task("DistillationWorker")
                raise
            except Exception as e:
                logger.error(f"Distillation worker error: {e}", exc_info=True)
                await self._sleep_with_shutdown_check(120)

        logger.info("Distillation worker stopped gracefully")

    async def _consolidation_worker(self):
        """
        Background worker for memory consolidation with checkpoint support.

        Runs periodic consolidation to deduplicate and optimize patterns.
        """
        logger.info("Consolidation worker started")

        while not self._shutdown_event.is_set():
            try:
                # Check if consolidation is due with dedicated session
                async with self.session_manager.get_read_only_session() as session:
                    reasoningbank = ReasoningBankService(
                        db_session=session,
                        judgment_service=self._create_judgment_service(session)
                    )
                    should_run = await reasoningbank.should_run_consolidation()

                if should_run:
                    # Check shutdown before starting expensive operation
                    if self._shutdown_event.is_set():
                        logger.info("Shutdown requested, skipping consolidation")
                        break

                    try:
                        # Create checkpoint BEFORE processing
                        await self._checkpoint(
                            task_id=f"consolidate_{datetime.utcnow().isoformat()}",
                            worker_name="ConsolidationWorker",
                            data={"stage": "started", "batch_size": 100}
                        )

                        logger.info("Running memory consolidation")

                        # Process with dedicated session
                        async with self.session_manager.get_session() as session:
                            consolidation_service = ConsolidationService(session)
                            result = await consolidation_service.consolidate_patterns(
                                batch_size=100,
                                aggressive=False
                            )

                        logger.info(f"Consolidation complete: {result}")

                        # Mark checkpoint complete
                        await self._complete_checkpoint(f"consolidate_{datetime.utcnow().isoformat()}")

                    except Exception as e:
                        logger.error(f"Consolidation error: {e}")

                # Sleep for 1 hour with shutdown check
                await self._sleep_with_shutdown_check(3600)

            except asyncio.CancelledError:
                logger.info("Consolidation worker cancelled, cleaning up")
                await self._cleanup_current_task("ConsolidationWorker")
                raise
            except Exception as e:
                logger.error(f"Consolidation worker error: {e}", exc_info=True)
                await self._sleep_with_shutdown_check(1800)

        logger.info("Consolidation worker stopped gracefully")

    # ==================== Agent Integration Helpers ====================

    @asynccontextmanager
    async def agent_execution_context(
        self,
        agent_type: str,
        task_description: str,
        context_data: Dict[str, Any],
        tenant_id: Optional[str] = None,
    ):
        """
        Context manager for agent execution with automatic trajectory tracking.

        Usage:
            async with orchestrator.agent_execution_context(...) as ctx:
                # Retrieve patterns
                patterns = await ctx.get_patterns()

                # Execute agent
                result = await agent.execute(...)

                # Record actions
                await ctx.record_action("generated_tests", "Generated 10 test cases")

                # Complete trajectory
                await ctx.complete(result)
        """
        class ExecutionContext:
            def __init__(self, orchestrator, trajectory_id):
                self.orchestrator = orchestrator
                self.trajectory_id = trajectory_id

            async def get_patterns(self, limit: int = 5) -> List[Dict[str, Any]]:
                """Retrieve relevant patterns for this task"""
                return await self.orchestrator.get_relevant_patterns(
                    task_description=task_description,
                    agent_type=agent_type,
                    limit=limit,
                    tenant_id=tenant_id
                )

            async def record_action(self, action_type: str, description: str, data: Optional[Dict] = None):
                """Record an action in the trajectory"""
                await self.orchestrator.record_action(
                    trajectory_id=self.trajectory_id,
                    action_type=action_type,
                    action_description=description,
                    action_data=data
                )

            async def complete(self, final_output: Dict[str, Any], **kwargs):
                """Complete the trajectory"""
                return await self.orchestrator.complete_trajectory(
                    trajectory_id=self.trajectory_id,
                    final_output=final_output,
                    **kwargs
                )

        # Start trajectory
        trajectory_id = await self.start_trajectory(
            agent_type=agent_type,
            task_description=task_description,
            context_data=context_data,
            tenant_id=tenant_id
        )

        ctx = ExecutionContext(self, trajectory_id)

        try:
            yield ctx
        except Exception as e:
            # Mark trajectory as failed
            await self.trajectory_service.update_judgment(
                trajectory_id=trajectory_id,
                outcome="FAILURE",
                confidence=1.0,
                reasoning=f"Execution failed: {str(e)}"
            )
            raise

    # ==================== Health & Status ====================

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on ReasoningBank system.

        Returns:
            Health status dictionary
        """
        return await self.reasoningbank.health_check()

    async def get_statistics(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive statistics about learning.

        Args:
            tenant_id: Optional tenant filter

        Returns:
            Statistics dictionary
        """
        return await self.reasoningbank.get_learning_statistics(
            tenant_id=tenant_id,
            use_cache=True
        )


# Global orchestrator instance
_orchestrator_instance: Optional[ReasoningBankOrchestrator] = None


def get_reasoningbank_orchestrator() -> Optional[ReasoningBankOrchestrator]:
    """Get global ReasoningBank orchestrator instance"""
    return _orchestrator_instance


def initialize_reasoningbank_orchestrator(
    db_session: AsyncSession,
    anthropic_api_key: Optional[str] = None,
    openai_api_key: Optional[str] = None,
    enable_background_tasks: bool = True,
) -> ReasoningBankOrchestrator:
    """
    Initialize global ReasoningBank orchestrator.

    Args:
        db_session: Database session
        anthropic_api_key: Anthropic API key
        openai_api_key: OpenAI API key
        enable_background_tasks: Whether to enable background processing

    Returns:
        Initialized orchestrator
    """
    global _orchestrator_instance

    _orchestrator_instance = ReasoningBankOrchestrator(
        db_session=db_session,
        anthropic_api_key=anthropic_api_key,
        openai_api_key=openai_api_key,
        enable_background_tasks=enable_background_tasks
    )

    logger.info("Global ReasoningBank orchestrator initialized")
    return _orchestrator_instance
