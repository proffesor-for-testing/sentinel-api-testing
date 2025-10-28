#!/usr/bin/env python3
"""
Standalone test for feedback queue system.
Tests without pytest dependencies.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select

from models.feedback import (
    Base,
    TestCaseFeedback,
    FeedbackLearningQueue,
    ProcessingStatus
)
from orchestration_service.services.queue_processor import FeedbackQueueProcessor


class MockLearningOrchestrator:
    """Mock orchestrator for testing."""

    def __init__(self):
        self.processed_feedback = []

    async def feedback_to_learning_loop(self, feedback_data):
        """Mock processing."""
        self.processed_feedback.append(feedback_data)
        return {
            "status": "processed",
            "feedback_id": feedback_data.get("id"),
            "queued_for_learning": True
        }


async def test_queue_system():
    """Test the complete queue system."""

    print("\n" + "="*70)
    print("TESTING FEEDBACK QUEUE SYSTEM")
    print("="*70 + "\n")

    # Create test database
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with AsyncSessionLocal() as db:
        # Test 1: Create and queue feedback
        print("TEST 1: Create and queue feedback")
        print("-" * 70)

        feedback = TestCaseFeedback(
            test_case_id=123,
            user_id="test-user-001",
            rating=5,
            feedback_type="quality",
            comment="Excellent test case!",
            helpful=True,
            issue_found=True,
            tags=["security", "auth"]
        )

        db.add(feedback)
        await db.commit()
        await db.refresh(feedback)

        print(f"✓ Created feedback with ID: {feedback.id}")
        assert feedback.id is not None

        # Queue it
        queue_entry = FeedbackLearningQueue(
            feedback_id=feedback.id,
            feedback_type="test_case",
            processing_status=ProcessingStatus.PENDING.value,
            retry_count=0,
            processing_metadata={"priority": "high"}
        )

        db.add(queue_entry)
        await db.commit()
        await db.refresh(queue_entry)

        print(f"✓ Queued feedback with queue ID: {queue_entry.id}")
        print(f"✓ Status: {queue_entry.processing_status}")
        assert queue_entry.processing_status == ProcessingStatus.PENDING.value

        # Test 2: Process queue
        print("\nTEST 2: Process queue with processor")
        print("-" * 70)

        mock_orchestrator = MockLearningOrchestrator()
        processor = FeedbackQueueProcessor(learning_orchestrator=mock_orchestrator)

        result = await processor.process_pending_feedback(db, batch_size=10)

        print(f"✓ Processed: {result['processed']} items")
        print(f"✓ Successful: {result['successful']} items")
        print(f"✓ Failed: {result['failed']} items")

        assert result["processed"] == 1
        assert result["successful"] == 1
        assert result["failed"] == 0

        # Verify status updated
        await db.refresh(queue_entry)
        print(f"✓ Queue entry status: {queue_entry.processing_status}")
        print(f"✓ Processed at: {queue_entry.processed_at}")

        assert queue_entry.processing_status == ProcessingStatus.COMPLETED.value
        assert queue_entry.processed_at is not None

        # Verify orchestrator received feedback
        assert len(mock_orchestrator.processed_feedback) == 1
        processed = mock_orchestrator.processed_feedback[0]
        print(f"✓ Orchestrator received feedback for test_case_id: {processed['test_case_id']}")
        assert processed["test_case_id"] == 123

        # Test 3: Queue statistics
        print("\nTEST 3: Queue statistics")
        print("-" * 70)

        stats = await processor.get_queue_statistics(db)
        print(f"✓ Total items: {stats['total']}")
        print(f"✓ Pending: {stats['pending']}")
        print(f"✓ Completed: {stats['completed']}")
        print(f"✓ Failed: {stats['failed']}")

        assert stats["completed"] >= 1

        # Test 4: Test retry logic
        print("\nTEST 4: Retry logic on failure")
        print("-" * 70)

        # Create a feedback that will fail
        feedback2 = TestCaseFeedback(
            test_case_id=456,
            user_id="test-user-002",
            rating=3,
            feedback_type="performance",
            helpful=True,
            issue_found=False
        )

        db.add(feedback2)
        await db.commit()
        await db.refresh(feedback2)

        queue_entry2 = FeedbackLearningQueue(
            feedback_id=feedback2.id,
            feedback_type="test_case",
            processing_status=ProcessingStatus.PENDING.value,
            retry_count=0
        )

        db.add(queue_entry2)
        await db.commit()
        await db.refresh(queue_entry2)

        print(f"✓ Created feedback {feedback2.id} and queued {queue_entry2.id}")

        # Use failing orchestrator
        class FailingOrchestrator:
            async def feedback_to_learning_loop(self, feedback_data):
                raise Exception("Simulated failure for testing")

        processor2 = FeedbackQueueProcessor(learning_orchestrator=FailingOrchestrator())

        # Try processing (should fail and retry)
        for i in range(3):
            result = await processor2.process_pending_feedback(db, batch_size=10)
            await db.refresh(queue_entry2)
            print(f"✓ Attempt {i+1}: retry_count = {queue_entry2.retry_count}, status = {queue_entry2.processing_status}")

            if i < 2:
                # Should retry
                assert queue_entry2.retry_count == i + 1
                assert queue_entry2.processing_status == ProcessingStatus.PENDING.value
            else:
                # After 3 retries, should fail
                assert queue_entry2.retry_count == 3

        # One more attempt should mark as failed
        result = await processor2.process_pending_feedback(db, batch_size=10)
        await db.refresh(queue_entry2)
        print(f"✓ After max retries: status = {queue_entry2.processing_status}")
        assert queue_entry2.processing_status == ProcessingStatus.FAILED.value

        print("\n" + "="*70)
        print("ALL TESTS PASSED! ✅")
        print("="*70 + "\n")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(test_queue_system())
