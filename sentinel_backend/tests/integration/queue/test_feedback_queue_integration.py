"""
Integration tests for feedback queue system.

Tests the complete flow:
1. Feedback submission -> database storage -> queue entry
2. Queue processor retrieves and processes items
3. Learning orchestrator receives feedback
4. Failed items retry up to 3 times
5. Completed items marked correctly
"""

import pytest
import asyncio
from datetime import datetime
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select

from sentinel_backend.models.feedback import (
    Base,
    TestCaseFeedback,
    TestSuiteFeedback,
    FeedbackLearningQueue,
    ProcessingStatus
)
from sentinel_backend.orchestration_service.services.queue_processor import FeedbackQueueProcessor
from sentinel_backend.orchestration_service.services.learning_orchestrator import LearningOrchestrator


@pytest.fixture
async def test_db():
    """Create a test database with tables."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with AsyncSessionLocal() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def mock_learning_orchestrator():
    """Mock learning orchestrator for testing."""
    class MockOrchestrator:
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

    return MockOrchestrator()


@pytest.mark.asyncio
async def test_queue_feedback_and_process(test_db, mock_learning_orchestrator):
    """Test complete flow: queue feedback and process it."""

    # Step 1: Create test case feedback
    feedback = TestCaseFeedback(
        test_case_id=123,
        user_id="user-test-001",
        rating=5,
        feedback_type="quality",
        comment="Excellent test!",
        helpful=True,
        issue_found=True,
        tags=["security", "auth"]
    )

    test_db.add(feedback)
    await test_db.commit()
    await test_db.refresh(feedback)

    assert feedback.id is not None
    print(f"✓ Created feedback with ID: {feedback.id}")

    # Step 2: Queue for learning
    queue_entry = FeedbackLearningQueue(
        feedback_id=feedback.id,
        feedback_type="test_case",
        processing_status=ProcessingStatus.PENDING.value,
        retry_count=0,
        processing_metadata={"priority": "high"}
    )

    test_db.add(queue_entry)
    await test_db.commit()
    await test_db.refresh(queue_entry)

    assert queue_entry.id is not None
    assert queue_entry.processing_status == ProcessingStatus.PENDING.value
    print(f"✓ Queued feedback with queue ID: {queue_entry.id}")

    # Step 3: Process queue
    processor = FeedbackQueueProcessor(learning_orchestrator=mock_learning_orchestrator)
    result = await processor.process_pending_feedback(test_db, batch_size=10)

    assert result["processed"] == 1
    assert result["successful"] == 1
    assert result["failed"] == 0
    print(f"✓ Processed {result['processed']} items successfully")

    # Step 4: Verify queue status updated
    await test_db.refresh(queue_entry)
    assert queue_entry.processing_status == ProcessingStatus.COMPLETED.value
    assert queue_entry.processed_at is not None
    print(f"✓ Queue entry marked as completed")

    # Step 5: Verify learning orchestrator received feedback
    assert len(mock_learning_orchestrator.processed_feedback) == 1
    processed = mock_learning_orchestrator.processed_feedback[0]
    assert processed["test_case_id"] == 123
    assert processed["rating"] == 5
    print(f"✓ Learning orchestrator received feedback")


@pytest.mark.asyncio
async def test_queue_retry_on_failure(test_db):
    """Test that failed items are retried up to 3 times."""

    # Create feedback
    feedback = TestCaseFeedback(
        test_case_id=456,
        user_id="user-test-002",
        rating=3,
        feedback_type="coverage",
        helpful=True,
        issue_found=False
    )

    test_db.add(feedback)
    await test_db.commit()
    await test_db.refresh(feedback)

    # Queue it
    queue_entry = FeedbackLearningQueue(
        feedback_id=feedback.id,
        feedback_type="test_case",
        processing_status=ProcessingStatus.PENDING.value,
        retry_count=0
    )

    test_db.add(queue_entry)
    await test_db.commit()
    await test_db.refresh(queue_entry)

    # Mock orchestrator that always fails
    class FailingOrchestrator:
        async def feedback_to_learning_loop(self, feedback_data):
            raise Exception("Simulated failure")

    processor = FeedbackQueueProcessor(learning_orchestrator=FailingOrchestrator())

    # Process 3 times (should retry)
    for i in range(3):
        result = await processor.process_pending_feedback(test_db, batch_size=10)
        await test_db.refresh(queue_entry)

        assert queue_entry.retry_count == i + 1
        print(f"✓ Retry {i + 1}: retry_count = {queue_entry.retry_count}")

    # After 3 retries, should be marked as failed
    result = await processor.process_pending_feedback(test_db, batch_size=10)
    await test_db.refresh(queue_entry)

    assert queue_entry.processing_status == ProcessingStatus.FAILED.value
    assert queue_entry.error_message is not None
    print(f"✓ After max retries, marked as failed")


@pytest.mark.asyncio
async def test_queue_statistics(test_db, mock_learning_orchestrator):
    """Test queue statistics retrieval."""

    # Create multiple feedbacks with different statuses
    statuses = [
        ProcessingStatus.PENDING,
        ProcessingStatus.PENDING,
        ProcessingStatus.PROCESSING,
        ProcessingStatus.COMPLETED,
        ProcessingStatus.COMPLETED,
        ProcessingStatus.COMPLETED,
        ProcessingStatus.FAILED
    ]

    for i, status in enumerate(statuses):
        feedback = TestCaseFeedback(
            test_case_id=1000 + i,
            user_id=f"user-{i}",
            rating=4,
            feedback_type="quality",
            helpful=True,
            issue_found=False
        )
        test_db.add(feedback)
        await test_db.flush()

        queue_entry = FeedbackLearningQueue(
            feedback_id=feedback.id,
            feedback_type="test_case",
            processing_status=status.value,
            retry_count=0
        )
        test_db.add(queue_entry)

    await test_db.commit()

    # Get statistics
    processor = FeedbackQueueProcessor(learning_orchestrator=mock_learning_orchestrator)
    stats = await processor.get_queue_statistics(test_db)

    assert stats["pending"] == 2
    assert stats["processing"] == 1
    assert stats["completed"] == 3
    assert stats["failed"] == 1
    assert stats["total"] == 7

    print(f"✓ Queue statistics: {stats}")


@pytest.mark.asyncio
async def test_suite_feedback_processing(test_db, mock_learning_orchestrator):
    """Test processing of test suite feedback."""

    # Create suite feedback
    suite_feedback = TestSuiteFeedback(
        test_suite_id=789,
        user_id="user-suite-001",
        rating=4,
        coverage_rating=5,
        quality_rating=4,
        comment="Good suite with minor gaps"
    )

    test_db.add(suite_feedback)
    await test_db.commit()
    await test_db.refresh(suite_feedback)

    # Queue it
    queue_entry = FeedbackLearningQueue(
        feedback_id=suite_feedback.id,
        feedback_type="test_suite",
        processing_status=ProcessingStatus.PENDING.value,
        retry_count=0
    )

    test_db.add(queue_entry)
    await test_db.commit()

    # Process
    processor = FeedbackQueueProcessor(learning_orchestrator=mock_learning_orchestrator)
    result = await processor.process_pending_feedback(test_db, batch_size=10)

    assert result["processed"] == 1
    assert result["successful"] == 1

    # Verify suite feedback was processed
    processed = mock_learning_orchestrator.processed_feedback[0]
    assert processed["test_suite_id"] == 789
    assert processed["rating"] == 4

    print(f"✓ Suite feedback processed successfully")


@pytest.mark.asyncio
async def test_retry_failed_items(test_db, mock_learning_orchestrator):
    """Test retry of failed items."""

    # Create failed queue entries
    for i in range(3):
        feedback = TestCaseFeedback(
            test_case_id=2000 + i,
            user_id=f"user-retry-{i}",
            rating=3,
            feedback_type="performance",
            helpful=True,
            issue_found=False
        )
        test_db.add(feedback)
        await test_db.flush()

        queue_entry = FeedbackLearningQueue(
            feedback_id=feedback.id,
            feedback_type="test_case",
            processing_status=ProcessingStatus.FAILED.value,
            retry_count=1,
            error_message="Test error"
        )
        test_db.add(queue_entry)

    await test_db.commit()

    # Retry failed items
    processor = FeedbackQueueProcessor(learning_orchestrator=mock_learning_orchestrator)
    result = await processor.retry_failed_items(test_db, max_items=10)

    assert result["retried"] == 3

    # Verify they're now pending
    pending_result = await test_db.execute(
        select(FeedbackLearningQueue)
        .where(FeedbackLearningQueue.processing_status == ProcessingStatus.PENDING.value)
    )
    pending_items = pending_result.scalars().all()

    assert len(pending_items) >= 3
    print(f"✓ Reset {result['retried']} failed items for retry")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
