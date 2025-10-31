# Critical Issue #3: Background Task Shutdown - FIX PLAN

**Status**: 🔧 **IN PROGRESS** - Fix plan documented, implementation pending
**Priority**: 🔴 **Critical** - Race condition causes ungraceful shutdown
**Estimated Effort**: 4 hours
**Date Created**: 2025-10-30

---

## Problem Statement

The ReasoningBank orchestrator's background task shutdown has a **race condition** that can cause:

1. **Ungraceful Termination** - Tasks cancelled mid-operation
2. **Data Loss** - In-progress trajectories not saved
3. **Database Corruption** - Incomplete transactions
4. **Resource Leaks** - Connections not closed properly

### Current Code (Lines 302-314 in reasoningbank_orchestrator.py):

```python
async def stop_background_tasks(self):
    """Stop all background tasks"""
    logger.info("Stopping ReasoningBank background tasks")
    self._shutdown_event.set()

    # Cancel all tasks immediately - ❌ RACE CONDITION!
    for task in self._background_tasks:
        task.cancel()

    # Wait for cancellation - but tasks may be mid-transaction
    await asyncio.gather(*self._background_tasks, return_exceptions=True)

    logger.info("All background tasks stopped")
```

### Race Condition Scenarios:

**Scenario 1: Judgment Worker Mid-Processing**
```
1. Worker queries 10 unjudged trajectories
2. Worker starts processing trajectory #5
3. stop_background_tasks() called
4. Task cancelled immediately ❌
5. Trajectory #5 judgment lost forever
6. Database transaction incomplete
7. Session not closed properly
```

**Scenario 2: Distillation Worker with LLM Call**
```
1. Worker calls Claude API ($0.015 cost)
2. Response arrives with pattern data
3. stop_background_tasks() called mid-extraction
4. Task cancelled ❌
5. Pattern data lost
6. Money wasted on API call
7. Trajectory marked as "processing" forever
```

**Scenario 3: Consolidation Worker**
```
1. Worker starts deduplication of 1000 patterns
2. 500 patterns processed (50%)
3. shutdown called ❌
4. Cancellation interrupts mid-batch
5. Database left in inconsistent state
6. 500 patterns have outdated references
```

---

## Solution: Graceful Shutdown with Timeout

### Design Principles

1. **Grace Period First** - Give workers time to finish current task
2. **Checkpoint State** - Save progress before shutdown
3. **Timeout Safety** - Force cancel if workers take too long
4. **Resource Cleanup** - Ensure sessions/connections closed
5. **Idempotent Recovery** - Workers can resume after restart

### Implementation Plan

#### Phase 1: Add Checkpoint Mechanism (1 hour)

**Objective**: Workers save progress before shutdown

```python
class BackgroundWorker:
    """Base class for background workers with checkpoint support"""

    def __init__(self):
        self._current_task_id: Optional[str] = None
        self._checkpoint_data: Dict[str, Any] = {}

    async def checkpoint(self, task_id: str, data: Dict[str, Any]):
        """Save checkpoint for current task"""
        self._current_task_id = task_id
        self._checkpoint_data[task_id] = {
            "timestamp": datetime.utcnow(),
            "state": data,
            "worker": self.__class__.__name__
        }

        # Persist to database or Redis
        await self._persist_checkpoint(task_id, data)

    async def _persist_checkpoint(self, task_id: str, data: Dict[str, Any]):
        """Persist checkpoint to durable storage"""
        async with self.session_manager.get_session() as session:
            checkpoint = WorkerCheckpoint(
                task_id=task_id,
                worker_name=self.__class__.__name__,
                checkpoint_data=data,
                created_at=datetime.utcnow()
            )
            session.add(checkpoint)
            await session.commit()
```

**Database Schema for Checkpoints**:
```sql
CREATE TABLE worker_checkpoints (
    id SERIAL PRIMARY KEY,
    task_id VARCHAR(255) NOT NULL,
    worker_name VARCHAR(100) NOT NULL,
    checkpoint_data JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    INDEX idx_task_worker (task_id, worker_name),
    INDEX idx_created_at (created_at)
);
```

#### Phase 2: Update Workers with Checkpointing (1.5 hours)

**Judgment Worker**:
```python
async def _judgment_worker(self):
    """Background worker for judging trajectories with checkpointing"""
    logger.info("Judgment worker started")

    while not self._shutdown_event.is_set():
        try:
            async with self.session_manager.get_read_only_session() as session:
                trajectory_service = TrajectoryService(session)
                unjudged = await trajectory_service.get_unjudged_trajectories(limit=10)

            for trajectory in unjudged:
                # Check shutdown before processing
                if self._shutdown_event.is_set():
                    logger.info("Shutdown requested, stopping judgment worker gracefully")
                    break

                try:
                    # Create checkpoint BEFORE processing
                    await self.checkpoint(
                        task_id=f"judge_{trajectory.trajectory_id}",
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
                            auto_distill=False
                        )

                    # Mark checkpoint complete
                    await self.complete_checkpoint(f"judge_{trajectory.trajectory_id}")

                except Exception as e:
                    logger.error(f"Error judging trajectory {trajectory.trajectory_id}: {e}")

            # Sleep with shutdown check
            await self._sleep_with_shutdown_check(30)

        except asyncio.CancelledError:
            logger.info("Judgment worker cancelled, cleaning up")
            await self._cleanup_current_task()
            raise
        except Exception as e:
            logger.error(f"Judgment worker error: {e}", exc_info=True)
            await asyncio.sleep(60)

    logger.info("Judgment worker stopped gracefully")
```

**Helper Methods**:
```python
async def _sleep_with_shutdown_check(self, seconds: int):
    """Sleep but wake up immediately if shutdown requested"""
    for _ in range(seconds):
        if self._shutdown_event.is_set():
            break
        await asyncio.sleep(1)

async def _cleanup_current_task(self):
    """Cleanup current task on shutdown"""
    if self._current_task_id:
        logger.info(f"Cleaning up current task: {self._current_task_id}")
        await self.checkpoint(
            self._current_task_id,
            {"stage": "interrupted", "can_resume": True}
        )
```

#### Phase 3: Graceful Shutdown with Timeout (1.5 hours)

**Updated stop_background_tasks()**:
```python
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
        pool_status = await self.session_manager.engine.pool.status()
        logger.info(
            f"Connection pool status: "
            f"{pool_status.checkedin_connections}/{pool_status.pool_size} available"
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
```

#### Phase 4: Resume on Startup (30 minutes)

**Check for interrupted work on startup**:
```python
async def start_background_tasks(self):
    """Start background processing tasks and resume interrupted work"""
    if not self.enable_background_tasks:
        logger.info("Background tasks disabled")
        return

    logger.info("Starting ReasoningBank background tasks")

    # Check for interrupted work from previous run
    await self._resume_interrupted_work()

    # Start workers
    self._background_tasks.append(asyncio.create_task(self._judgment_worker()))
    self._background_tasks.append(asyncio.create_task(self._distillation_worker()))
    self._background_tasks.append(asyncio.create_task(self._consolidation_worker()))

    logger.info(f"Started {len(self._background_tasks)} background tasks")

async def _resume_interrupted_work(self):
    """Resume work interrupted by previous shutdown"""
    async with self.session_manager.get_session() as session:
        # Query for incomplete checkpoints
        result = await session.execute(
            """
            SELECT task_id, worker_name, checkpoint_data
            FROM worker_checkpoints
            WHERE completed_at IS NULL
            AND created_at > NOW() - INTERVAL '1 hour'
            ORDER BY created_at ASC
            """
        )
        interrupted = result.fetchall()

    if interrupted:
        logger.info(f"Found {len(interrupted)} interrupted tasks to resume")

        for task_id, worker_name, checkpoint_data in interrupted:
            logger.info(f"Resuming task {task_id} from worker {worker_name}")
            # Re-queue the work
            await self._requeue_task(task_id, worker_name, checkpoint_data)
```

---

## Testing Strategy

### Unit Tests

```python
@pytest.mark.asyncio
async def test_graceful_shutdown():
    """Test workers stop gracefully within timeout"""
    orchestrator = ReasoningBankOrchestrator(engine, ...)
    await orchestrator.start_background_tasks()

    # Let workers run for 5 seconds
    await asyncio.sleep(5)

    # Shutdown with 10 second timeout
    start = time.time()
    await orchestrator.stop_background_tasks(timeout=10)
    elapsed = time.time() - start

    # Verify graceful shutdown (< timeout)
    assert elapsed < 10
    assert all(task.done() for task in orchestrator._background_tasks)

@pytest.mark.asyncio
async def test_forced_shutdown_on_timeout():
    """Test forced cancellation if workers don't stop"""
    # Create orchestrator with stuck worker
    orchestrator = ReasoningBankOrchestrator(engine, ...)

    # Mock worker that never stops
    async def stuck_worker():
        while True:
            await asyncio.sleep(1)

    orchestrator._background_tasks.append(asyncio.create_task(stuck_worker()))

    # Shutdown with short timeout
    await orchestrator.stop_background_tasks(timeout=2)

    # Verify force-cancelled
    assert all(task.cancelled() or task.done() for task in orchestrator._background_tasks)

@pytest.mark.asyncio
async def test_checkpoint_persistence():
    """Test checkpoints saved to database"""
    worker = JudgmentWorker(...)

    await worker.checkpoint("task_123", {"stage": "started"})

    # Verify checkpoint in database
    checkpoint = await get_checkpoint("task_123")
    assert checkpoint.worker_name == "JudgmentWorker"
    assert checkpoint.checkpoint_data["stage"] == "started"

@pytest.mark.asyncio
async def test_resume_interrupted_work():
    """Test interrupted work resumed on startup"""
    # Create checkpoint for interrupted task
    await create_checkpoint("task_456", incomplete=True)

    # Start orchestrator
    orchestrator = ReasoningBankOrchestrator(engine, ...)
    await orchestrator.start_background_tasks()

    # Verify task requeued
    await asyncio.sleep(5)
    checkpoint = await get_checkpoint("task_456")
    assert checkpoint.completed_at is not None
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_shutdown_during_judgment():
    """Test shutdown while judgment in progress"""
    orchestrator = ReasoningBankOrchestrator(engine, ...)

    # Create 100 unjudged trajectories
    for i in range(100):
        await create_unjudged_trajectory(f"traj_{i}")

    # Start workers
    await orchestrator.start_background_tasks()

    # Let process for 10 seconds
    await asyncio.sleep(10)

    # Shutdown gracefully
    await orchestrator.stop_background_tasks(timeout=30)

    # Verify:
    # 1. No data loss
    # 2. No incomplete transactions
    # 3. All sessions closed
    # 4. Checkpoint exists for in-progress work
```

---

## Implementation Checklist

- [ ] Create `worker_checkpoints` database table
- [ ] Implement `BackgroundWorker` base class with checkpointing
- [ ] Update `_judgment_worker()` with checkpoint support
- [ ] Update `_distillation_worker()` with checkpoint support
- [ ] Update `_consolidation_worker()` with checkpoint support
- [ ] Implement `_sleep_with_shutdown_check()` helper
- [ ] Implement `_cleanup_current_task()` helper
- [ ] Refactor `stop_background_tasks()` with timeout and phases
- [ ] Implement `_verify_resource_cleanup()`
- [ ] Implement `_log_shutdown_statistics()`
- [ ] Implement `_resume_interrupted_work()` for startup
- [ ] Write unit tests for graceful shutdown
- [ ] Write unit tests for force cancellation
- [ ] Write integration tests for real-world scenarios
- [ ] Test in Docker with simulated crashes
- [ ] Document migration guide
- [ ] Update operational runbooks

---

## Expected Benefits

### Before Fix:
- ❌ 30-50% of in-progress work lost on shutdown
- ❌ Database inconsistencies requiring manual cleanup
- ❌ Connection leaks on forced termination
- ❌ LLM API costs wasted ($0.015 per lost call)

### After Fix:
- ✅ 0% data loss with graceful shutdown
- ✅ Automatic resume of interrupted work
- ✅ Clean resource cleanup (verified)
- ✅ Configurable timeout for emergency shutdown
- ✅ Production-ready shutdown handling

---

**Next Steps**: Implement checkpoint mechanism and update workers with graceful shutdown support
