"""
Feedback Queue Processor

Processes feedback items from the database-backed learning queue.
Handles retries, error tracking, and orchestrates learning integration.
"""

import logging
import structlog
from typing import Dict, List, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, update

from sentinel_backend.models.feedback import (
    FeedbackLearningQueue,
    FeedbackQueueType,
    ProcessingStatus,
    TestCaseFeedback,
    TestSuiteFeedback
)

logger = structlog.get_logger(__name__)


class FeedbackQueueProcessor:
    """
    Process feedback from learning queue with retry logic and error handling.

    Responsibilities:
    - Retrieve pending feedback from database queue
    - Process feedback through learning orchestrator
    - Update processing status and retry counts
    - Handle failures with exponential backoff
    """

    # Configuration
    MAX_RETRIES = 3
    BATCH_SIZE = 10

    def __init__(self, learning_orchestrator=None):
        """
        Initialize queue processor.

        Args:
            learning_orchestrator: LearningOrchestrator instance for processing feedback
        """
        self.learning_orchestrator = learning_orchestrator
        self.processing_stats = {
            "total_processed": 0,
            "successful": 0,
            "failed": 0,
            "retried": 0
        }

    async def process_pending_feedback(
        self,
        db: AsyncSession,
        batch_size: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Process all pending feedback items in queue.

        Args:
            db: Database session
            batch_size: Number of items to process (default: BATCH_SIZE)

        Returns:
            Dict with processing statistics
        """
        batch_size = batch_size or self.BATCH_SIZE

        logger.info(
            "starting_feedback_queue_processing",
            batch_size=batch_size
        )

        try:
            # Get pending items ordered by priority and creation time
            result = await db.execute(
                select(FeedbackLearningQueue)
                .where(FeedbackLearningQueue.processing_status == ProcessingStatus.PENDING.value)
                .order_by(
                    FeedbackLearningQueue.created_at.asc()
                )
                .limit(batch_size)
            )
            pending_items = result.scalars().all()

            if not pending_items:
                logger.info("no_pending_feedback_in_queue")
                return {
                    "processed": 0,
                    "successful": 0,
                    "failed": 0,
                    "stats": self.processing_stats
                }

            logger.info(
                "processing_feedback_batch",
                count=len(pending_items)
            )

            processed_count = 0
            successful_count = 0
            failed_count = 0

            # Process each item
            for item in pending_items:
                try:
                    success = await self._process_single_feedback(item, db)
                    processed_count += 1

                    if success:
                        successful_count += 1
                        self.processing_stats["successful"] += 1
                    else:
                        failed_count += 1
                        self.processing_stats["failed"] += 1

                except Exception as e:
                    logger.error(
                        "error_processing_queue_item",
                        queue_id=item.id,
                        feedback_id=item.feedback_id,
                        error=str(e),
                        exc_info=True
                    )

                    # Mark as failed
                    await self._mark_as_failed(
                        item=item,
                        db=db,
                        error_message=str(e)
                    )
                    failed_count += 1
                    self.processing_stats["failed"] += 1

            self.processing_stats["total_processed"] += processed_count

            logger.info(
                "feedback_queue_processing_completed",
                processed=processed_count,
                successful=successful_count,
                failed=failed_count
            )

            return {
                "processed": processed_count,
                "successful": successful_count,
                "failed": failed_count,
                "stats": self.processing_stats
            }

        except Exception as e:
            logger.error(
                "error_processing_feedback_queue",
                error=str(e),
                exc_info=True
            )
            return {
                "processed": 0,
                "successful": 0,
                "failed": 0,
                "error": str(e),
                "stats": self.processing_stats
            }

    async def _process_single_feedback(
        self,
        item: FeedbackLearningQueue,
        db: AsyncSession
    ) -> bool:
        """
        Process a single feedback item through learning orchestrator.

        Args:
            item: Queue item to process
            db: Database session

        Returns:
            bool: True if successful, False if failed
        """
        logger.info(
            "processing_feedback_item",
            queue_id=item.id,
            feedback_id=item.feedback_id,
            feedback_type=item.feedback_type,
            retry_count=item.retry_count
        )

        try:
            # Mark as processing
            item.processing_status = ProcessingStatus.PROCESSING.value
            await db.commit()

            # Retrieve the actual feedback
            feedback_data = await self._retrieve_feedback(
                feedback_id=item.feedback_id,
                feedback_type=item.feedback_type,
                db=db
            )

            if not feedback_data:
                raise ValueError(f"Feedback {item.feedback_id} not found")

            # Process through learning orchestrator
            if self.learning_orchestrator:
                result = await self.learning_orchestrator.feedback_to_learning_loop(
                    feedback_data
                )

                logger.debug(
                    "learning_orchestrator_result",
                    queue_id=item.id,
                    result=result
                )
            else:
                logger.warning(
                    "no_learning_orchestrator",
                    queue_id=item.id
                )

            # Mark as completed
            item.processing_status = ProcessingStatus.COMPLETED.value
            item.processed_at = datetime.utcnow()
            await db.commit()

            logger.info(
                "feedback_item_processed_successfully",
                queue_id=item.id,
                feedback_id=item.feedback_id
            )

            return True

        except Exception as e:
            logger.error(
                "error_processing_feedback_item",
                queue_id=item.id,
                feedback_id=item.feedback_id,
                error=str(e),
                exc_info=True
            )

            # Handle retry logic
            if item.retry_count < self.MAX_RETRIES:
                await self._mark_for_retry(item, db, str(e))
                self.processing_stats["retried"] += 1
            else:
                await self._mark_as_failed(item, db, str(e))

            return False

    async def _retrieve_feedback(
        self,
        feedback_id: int,
        feedback_type: str,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve feedback from database by ID and type.

        Args:
            feedback_id: Feedback ID
            feedback_type: Type (test_case or test_suite)
            db: Database session

        Returns:
            Dict with feedback data or None if not found
        """
        try:
            if feedback_type == FeedbackQueueType.TEST_CASE.value:
                result = await db.execute(
                    select(TestCaseFeedback)
                    .where(TestCaseFeedback.id == feedback_id)
                )
                feedback = result.scalar_one_or_none()

                if feedback:
                    return {
                        "id": feedback.id,
                        "test_case_id": feedback.test_case_id,
                        "user_id": feedback.user_id,
                        "rating": feedback.rating,
                        "feedback_type": feedback.feedback_type,
                        "comment": feedback.comment,
                        "helpful": feedback.helpful,
                        "issue_found": feedback.issue_found,
                        "tags": feedback.tags,
                        "created_at": feedback.created_at
                    }

            elif feedback_type == FeedbackQueueType.TEST_SUITE.value:
                result = await db.execute(
                    select(TestSuiteFeedback)
                    .where(TestSuiteFeedback.id == feedback_id)
                )
                feedback = result.scalar_one_or_none()

                if feedback:
                    return {
                        "id": feedback.id,
                        "test_suite_id": feedback.test_suite_id,
                        "user_id": feedback.user_id,
                        "rating": feedback.rating,
                        "coverage_rating": feedback.coverage_rating,
                        "quality_rating": feedback.quality_rating,
                        "comment": feedback.comment,
                        "created_at": feedback.created_at
                    }

            return None

        except Exception as e:
            logger.error(
                "error_retrieving_feedback",
                feedback_id=feedback_id,
                feedback_type=feedback_type,
                error=str(e)
            )
            return None

    async def _mark_for_retry(
        self,
        item: FeedbackLearningQueue,
        db: AsyncSession,
        error_message: str
    ) -> None:
        """
        Mark feedback item for retry after failure.

        Args:
            item: Queue item that failed
            db: Database session
            error_message: Error details
        """
        item.processing_status = ProcessingStatus.PENDING.value
        item.retry_count += 1
        item.error_message = error_message

        await db.commit()

        logger.info(
            "feedback_item_marked_for_retry",
            queue_id=item.id,
            retry_count=item.retry_count,
            error=error_message
        )

    async def _mark_as_failed(
        self,
        item: FeedbackLearningQueue,
        db: AsyncSession,
        error_message: str
    ) -> None:
        """
        Mark feedback item as permanently failed.

        Args:
            item: Queue item that failed
            db: Database session
            error_message: Error details
        """
        item.processing_status = ProcessingStatus.FAILED.value
        item.processed_at = datetime.utcnow()
        item.error_message = error_message

        await db.commit()

        logger.error(
            "feedback_item_marked_as_failed",
            queue_id=item.id,
            feedback_id=item.feedback_id,
            retry_count=item.retry_count,
            error=error_message
        )

    async def get_queue_statistics(self, db: AsyncSession) -> Dict[str, Any]:
        """
        Get statistics about the learning queue.

        Args:
            db: Database session

        Returns:
            Dict with queue statistics
        """
        try:
            # Count by status
            pending_result = await db.execute(
                select(FeedbackLearningQueue)
                .where(FeedbackLearningQueue.processing_status == ProcessingStatus.PENDING.value)
            )
            pending_count = len(pending_result.scalars().all())

            processing_result = await db.execute(
                select(FeedbackLearningQueue)
                .where(FeedbackLearningQueue.processing_status == ProcessingStatus.PROCESSING.value)
            )
            processing_count = len(processing_result.scalars().all())

            completed_result = await db.execute(
                select(FeedbackLearningQueue)
                .where(FeedbackLearningQueue.processing_status == ProcessingStatus.COMPLETED.value)
            )
            completed_count = len(completed_result.scalars().all())

            failed_result = await db.execute(
                select(FeedbackLearningQueue)
                .where(FeedbackLearningQueue.processing_status == ProcessingStatus.FAILED.value)
            )
            failed_count = len(failed_result.scalars().all())

            return {
                "pending": pending_count,
                "processing": processing_count,
                "completed": completed_count,
                "failed": failed_count,
                "total": pending_count + processing_count + completed_count + failed_count,
                "processor_stats": self.processing_stats
            }

        except Exception as e:
            logger.error(
                "error_getting_queue_statistics",
                error=str(e)
            )
            return {
                "error": str(e),
                "processor_stats": self.processing_stats
            }

    async def retry_failed_items(
        self,
        db: AsyncSession,
        max_items: int = 10
    ) -> Dict[str, Any]:
        """
        Retry failed items that haven't exceeded max retries.

        Args:
            db: Database session
            max_items: Maximum number of items to retry

        Returns:
            Dict with retry statistics
        """
        try:
            # Get failed items that can be retried
            result = await db.execute(
                select(FeedbackLearningQueue)
                .where(
                    and_(
                        FeedbackLearningQueue.processing_status == ProcessingStatus.FAILED.value,
                        FeedbackLearningQueue.retry_count < self.MAX_RETRIES
                    )
                )
                .limit(max_items)
            )
            failed_items = result.scalars().all()

            if not failed_items:
                return {
                    "retried": 0,
                    "message": "No failed items eligible for retry"
                }

            # Reset to pending
            for item in failed_items:
                item.processing_status = ProcessingStatus.PENDING.value
                item.error_message = None

            await db.commit()

            logger.info(
                "failed_items_reset_for_retry",
                count=len(failed_items)
            )

            return {
                "retried": len(failed_items),
                "message": f"Reset {len(failed_items)} failed items for retry"
            }

        except Exception as e:
            logger.error(
                "error_retrying_failed_items",
                error=str(e)
            )
            return {
                "retried": 0,
                "error": str(e)
            }
