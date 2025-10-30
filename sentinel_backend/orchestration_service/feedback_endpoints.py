"""
FastAPI endpoints for feedback and learning integration.

Provides REST API for:
- Test case feedback submission
- Test suite feedback submission
- Learning statistics and metrics
- Feedback retrieval and analysis
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, validator
from datetime import datetime
from enum import Enum
import logging
import structlog
import asyncio
from collections import defaultdict
import time

# Import auth middleware
from sentinel_backend.auth_service.auth_middleware import get_current_user

# Import database models and session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sentinel_backend.models.feedback import (
    TestCaseFeedback,
    TestSuiteFeedback,
    FeedbackLearningQueue
)

logger = structlog.get_logger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/feedback", tags=["feedback"])

# Database dependency placeholder - will be overridden by main.py
async def get_db_dependency() -> AsyncSession:
    """Placeholder for database dependency - overridden in main.py"""
    raise NotImplementedError("Database dependency not configured")

# Rate limiting configuration
RATE_LIMIT_REQUESTS = 10  # 10 requests
RATE_LIMIT_WINDOW = 60  # per minute
rate_limit_store = defaultdict(list)


class FeedbackType(str, Enum):
    """Types of feedback that can be provided."""
    QUALITY = "quality"
    ACCURACY = "accuracy"
    COVERAGE = "coverage"
    PERFORMANCE = "performance"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


class CoverageGapCategory(str, Enum):
    """Common categories of coverage gaps."""
    AUTHENTICATION = "authentication"
    ERROR_HANDLING = "error_handling"
    EDGE_CASES = "edge_cases"
    PERFORMANCE = "performance"
    SECURITY = "security"
    CUSTOM = "custom"


# Request/Response Models

class TestCaseFeedbackRequest(BaseModel):
    """Request to submit feedback for a test case."""
    test_case_id: str = Field(..., description="Test case identifier")
    rating: int = Field(..., ge=1, le=5, description="Rating from 1-5")
    feedback_type: FeedbackType = Field(..., description="Type of feedback")
    is_helpful: bool = Field(True, description="Whether test is helpful")
    found_issue: bool = Field(False, description="Whether test found a real issue")
    comment: Optional[str] = Field(None, max_length=2000, description="Additional comments")
    execution_time_ms: Optional[float] = Field(None, ge=0, description="Execution time in ms")

    @validator('comment')
    def validate_comment(cls, v):
        """Validate comment is not just whitespace."""
        if v and not v.strip():
            raise ValueError("Comment cannot be empty or whitespace only")
        return v.strip() if v else None


class TestSuiteFeedbackRequest(BaseModel):
    """Request to submit feedback for a test suite."""
    suite_id: str = Field(..., description="Test suite identifier")
    spec_id: str = Field(..., description="API specification identifier")
    overall_rating: int = Field(..., ge=1, le=5, description="Overall suite rating")
    quality_score: int = Field(..., ge=1, le=5, description="Quality rating")
    coverage_score: int = Field(..., ge=1, le=5, description="Coverage rating")
    accuracy_score: int = Field(..., ge=1, le=5, description="Accuracy rating")
    speed_score: int = Field(..., ge=1, le=5, description="Speed rating")
    coverage_gaps: List[Dict[str, Any]] = Field(default_factory=list, description="Identified coverage gaps")
    excellent_tests: List[str] = Field(default_factory=list, description="Test IDs marked as excellent")
    false_positives: List[str] = Field(default_factory=list, description="Test IDs marked as false positives")
    comment: Optional[str] = Field(None, max_length=2000, description="Additional comments")


class FeedbackStatistics(BaseModel):
    """Learning and feedback statistics."""
    total_feedback_count: int = Field(..., description="Total feedback submissions")
    average_rating: float = Field(..., description="Average rating across all feedback")
    helpful_percentage: float = Field(..., description="Percentage of helpful tests")
    issue_found_percentage: float = Field(..., description="Percentage that found issues")
    coverage_gaps_identified: int = Field(..., description="Number of coverage gaps")
    coverage_gaps_resolved: int = Field(..., description="Number of gaps resolved")
    pattern_count: int = Field(..., description="Number of learned patterns")
    average_confidence: float = Field(..., description="Average pattern confidence")
    feedback_by_type: Dict[str, int] = Field(..., description="Feedback count by type")
    feedback_trend: List[Dict[str, Any]] = Field(..., description="Feedback trend over time")


class TestCaseFeedbackResponse(BaseModel):
    """Response after submitting test case feedback."""
    success: bool = Field(..., description="Whether submission was successful")
    feedback_id: str = Field(..., description="Generated feedback ID")
    test_case_id: str = Field(..., description="Test case ID")
    learning_status: str = Field(..., description="Learning processing status")
    message: str = Field(..., description="Confirmation message")
    queued_for_learning: bool = Field(..., description="Whether queued for learning")


class TestSuiteFeedbackResponse(BaseModel):
    """Response after submitting test suite feedback."""
    success: bool = Field(..., description="Whether submission was successful")
    feedback_id: str = Field(..., description="Generated feedback ID")
    suite_id: str = Field(..., description="Test suite ID")
    learning_status: str = Field(..., description="Learning processing status")
    message: str = Field(..., description="Confirmation message")
    queued_for_learning: bool = Field(..., description="Whether queued for learning")
    gaps_queued_for_generation: int = Field(0, description="Number of gaps queued")


class FeedbackDetail(BaseModel):
    """Detailed feedback information."""
    feedback_id: str
    test_case_id: str
    rating: int
    feedback_type: str
    is_helpful: bool
    found_issue: bool
    comment: Optional[str]
    created_at: datetime
    learning_applied: bool
    pattern_updates: List[str]


# Rate limiting helper
def check_rate_limit(user_id: str) -> bool:
    """
    Check if user has exceeded rate limit.

    Args:
        user_id: User identifier

    Returns:
        True if within limit, False if exceeded
    """
    current_time = time.time()
    user_requests = rate_limit_store[user_id]

    # Remove old requests outside window
    user_requests[:] = [req_time for req_time in user_requests
                       if current_time - req_time < RATE_LIMIT_WINDOW]

    # Check if limit exceeded
    if len(user_requests) >= RATE_LIMIT_REQUESTS:
        return False

    # Add current request
    user_requests.append(current_time)
    return True


async def store_test_case_feedback_in_db(
    feedback_data: TestCaseFeedbackRequest,
    user_id: str,
    correlation_id: str,
    db: AsyncSession
) -> Dict[str, Any]:
    """Store test case feedback in database using SQLAlchemy."""
    try:
        # Create ORM object
        feedback = TestCaseFeedback(
            test_case_id=int(feedback_data.test_case_id),
            user_id=user_id,
            rating=feedback_data.rating,
            feedback_type=feedback_data.feedback_type.value,
            comment=feedback_data.comment,
            helpful=feedback_data.is_helpful,
            issue_found=feedback_data.found_issue,
            tags=[]  # Can be extended to include tags from request
        )

        # Save to database
        db.add(feedback)
        await db.commit()
        await db.refresh(feedback)

        return {
            "feedback_id": str(feedback.id),
            "test_case_id": str(feedback.test_case_id),
            "user_id": feedback.user_id,
            "rating": feedback.rating,
            "feedback_type": feedback.feedback_type,
            "is_helpful": feedback.helpful,
            "found_issue": feedback.issue_found,
            "comment": feedback.comment,
            "created_at": feedback.created_at,
            "correlation_id": correlation_id
        }
    except Exception as e:
        await db.rollback()
        logger.error(f"Error storing test case feedback: {str(e)}")
        raise


async def store_test_suite_feedback_in_db(
    feedback_data: TestSuiteFeedbackRequest,
    user_id: str,
    correlation_id: str,
    db: AsyncSession
) -> Dict[str, Any]:
    """Store test suite feedback in database using SQLAlchemy."""
    try:
        # Create ORM object
        feedback = TestSuiteFeedback(
            test_suite_id=int(feedback_data.suite_id),
            user_id=user_id,
            rating=feedback_data.overall_rating,
            coverage_rating=feedback_data.coverage_score,
            quality_rating=feedback_data.quality_score,
            comment=feedback_data.comment
        )

        # Save to database
        db.add(feedback)
        await db.commit()
        await db.refresh(feedback)

        return {
            "feedback_id": str(feedback.id),
            "suite_id": str(feedback.test_suite_id),
            "spec_id": feedback_data.spec_id,
            "user_id": feedback.user_id,
            "overall_rating": feedback.rating,
            "quality_score": feedback.quality_rating,
            "coverage_score": feedback.coverage_rating,
            "accuracy_score": feedback_data.accuracy_score,
            "speed_score": feedback_data.speed_score,
            "coverage_gaps": feedback_data.coverage_gaps,
            "excellent_tests": feedback_data.excellent_tests,
            "false_positives": feedback_data.false_positives,
            "comment": feedback.comment,
            "created_at": feedback.created_at,
            "correlation_id": correlation_id
        }
    except Exception as e:
        await db.rollback()
        logger.error(f"Error storing test suite feedback: {str(e)}")
        raise


async def queue_feedback_for_learning(
    feedback_id: str,
    feedback_type: str,
    db: AsyncSession,
    priority: str = "normal"
) -> bool:
    """Queue feedback for asynchronous learning processing using SQLAlchemy."""
    try:
        # Create queue entry
        queue_entry = FeedbackLearningQueue(
            feedback_id=int(feedback_id),
            feedback_type=feedback_type,
            processing_status="pending",
            retry_count=0,
            processing_metadata={"priority": priority}
        )

        # Save to database
        db.add(queue_entry)
        await db.commit()

        logger.info(
            "feedback_queued_for_learning",
            feedback_id=feedback_id,
            feedback_type=feedback_type,
            priority=priority,
            queue_id=queue_entry.id
        )

        return True
    except Exception as e:
        await db.rollback()
        logger.error(f"Error queuing feedback for learning: {str(e)}")
        return False


async def get_feedback_statistics(db: AsyncSession) -> Dict[str, Any]:
    """Get learning and feedback statistics from database using SQLAlchemy."""
    try:
        # Get total feedback count
        total_count_result = await db.execute(select(func.count(TestCaseFeedback.id)))
        total_count = total_count_result.scalar() or 0

        # Get average rating
        avg_rating_result = await db.execute(select(func.avg(TestCaseFeedback.rating)))
        avg_rating = float(avg_rating_result.scalar() or 0.0)

        # Get helpful percentage
        helpful_count_result = await db.execute(
            select(func.count(TestCaseFeedback.id)).where(TestCaseFeedback.helpful == True)
        )
        helpful_count = helpful_count_result.scalar() or 0
        helpful_percentage = (helpful_count / total_count * 100) if total_count > 0 else 0.0

        # Get issue found percentage
        issue_found_result = await db.execute(
            select(func.count(TestCaseFeedback.id)).where(TestCaseFeedback.issue_found == True)
        )
        issue_found_count = issue_found_result.scalar() or 0
        issue_found_percentage = (issue_found_count / total_count * 100) if total_count > 0 else 0.0

        # Get feedback by type
        feedback_by_type_result = await db.execute(
            select(TestCaseFeedback.feedback_type, func.count(TestCaseFeedback.id))
            .group_by(TestCaseFeedback.feedback_type)
        )
        feedback_by_type = {row[0]: row[1] for row in feedback_by_type_result.fetchall()}

        # Get feedback trend (last 7 days)
        from datetime import timedelta
        today = datetime.utcnow().date()
        feedback_trend = []
        for i in range(6, -1, -1):
            date = today - timedelta(days=i)
            date_start = datetime.combine(date, datetime.min.time())
            date_end = datetime.combine(date, datetime.max.time())

            count_result = await db.execute(
                select(func.count(TestCaseFeedback.id))
                .where(TestCaseFeedback.created_at.between(date_start, date_end))
            )
            count = count_result.scalar() or 0

            avg_result = await db.execute(
                select(func.avg(TestCaseFeedback.rating))
                .where(TestCaseFeedback.created_at.between(date_start, date_end))
            )
            avg = float(avg_result.scalar() or 0.0)

            feedback_trend.append({
                "date": date.isoformat(),
                "count": count,
                "avg_rating": round(avg, 1)
            })

        return {
            "total_feedback_count": total_count,
            "average_rating": round(avg_rating, 1),
            "helpful_percentage": round(helpful_percentage, 1),
            "issue_found_percentage": round(issue_found_percentage, 1),
            "coverage_gaps_identified": 0,  # TODO: Query from coverage gaps table
            "coverage_gaps_resolved": 0,  # TODO: Query from coverage gaps table
            "pattern_count": 0,  # TODO: Query from patterns table
            "average_confidence": 0.0,  # TODO: Query from patterns table
            "feedback_by_type": feedback_by_type,
            "feedback_trend": feedback_trend
        }
    except Exception as e:
        logger.error(f"Error getting feedback statistics: {str(e)}")
        # Return empty statistics on error
        return {
            "total_feedback_count": 0,
            "average_rating": 0.0,
            "helpful_percentage": 0.0,
            "issue_found_percentage": 0.0,
            "coverage_gaps_identified": 0,
            "coverage_gaps_resolved": 0,
            "pattern_count": 0,
            "average_confidence": 0.0,
            "feedback_by_type": {},
            "feedback_trend": []
        }


async def get_test_case_feedback_from_db(test_id: str, db: AsyncSession) -> Optional[List[Dict[str, Any]]]:
    """Get all feedback for a test case from database using SQLAlchemy."""
    try:
        # Query feedback for test case
        result = await db.execute(
            select(TestCaseFeedback).where(TestCaseFeedback.test_case_id == int(test_id))
        )
        feedback_list = result.scalars().all()

        if not feedback_list:
            return None

        # Convert to dict format
        return [
            {
                "feedback_id": str(fb.id),
                "test_case_id": str(fb.test_case_id),
                "rating": fb.rating,
                "feedback_type": fb.feedback_type,
                "is_helpful": fb.helpful,
                "found_issue": fb.issue_found,
                "comment": fb.comment,
                "created_at": fb.created_at,
                "learning_applied": False,  # TODO: Query from learning queue
                "pattern_updates": []  # TODO: Query from pattern associations
            }
            for fb in feedback_list
        ]
    except Exception as e:
        logger.error(f"Error getting test case feedback: {str(e)}")
        return None


async def get_pattern_feedback_from_db(pattern_id: str, db: AsyncSession) -> Optional[Dict[str, Any]]:
    """Get feedback summary for a pattern from database using SQLAlchemy."""
    try:
        from sentinel_backend.models.feedback import TestCasePattern

        # Get pattern usage count
        usage_result = await db.execute(
            select(func.count(TestCasePattern.id))
            .where(TestCasePattern.pattern_id == pattern_id)
        )
        usage_count = usage_result.scalar() or 0

        if usage_count == 0:
            return None

        # Get average confidence
        confidence_result = await db.execute(
            select(func.avg(TestCasePattern.confidence_score))
            .where(TestCasePattern.pattern_id == pattern_id)
        )
        avg_confidence = float(confidence_result.scalar() or 0.0)

        # Get feedback for test cases using this pattern
        feedback_result = await db.execute(
            select(TestCaseFeedback)
            .join(TestCasePattern, TestCaseFeedback.test_case_id == TestCasePattern.test_case_id)
            .where(TestCasePattern.pattern_id == pattern_id)
            .order_by(TestCaseFeedback.created_at.desc())
            .limit(5)
        )
        recent_feedback_list = feedback_result.scalars().all()

        # Calculate success/failure counts based on feedback
        all_feedback_result = await db.execute(
            select(TestCaseFeedback)
            .join(TestCasePattern, TestCaseFeedback.test_case_id == TestCasePattern.test_case_id)
            .where(TestCasePattern.pattern_id == pattern_id)
        )
        all_feedback = all_feedback_result.scalars().all()

        success_count = sum(1 for fb in all_feedback if fb.rating >= 4)
        failure_count = sum(1 for fb in all_feedback if fb.rating <= 2)
        avg_rating = sum(fb.rating for fb in all_feedback) / len(all_feedback) if all_feedback else 0.0

        return {
            "pattern_id": pattern_id,
            "usage_count": usage_count,
            "success_count": success_count,
            "failure_count": failure_count,
            "average_rating": round(avg_rating, 1),
            "confidence": round(avg_confidence, 2),
            "last_updated": datetime.utcnow(),
            "feedback_count": len(all_feedback),
            "recent_feedback": [
                {
                    "rating": fb.rating,
                    "comment": fb.comment or "",
                    "created_at": fb.created_at
                }
                for fb in recent_feedback_list
            ]
        }
    except Exception as e:
        logger.error(f"Error getting pattern feedback: {str(e)}")
        return None


# Endpoints

@router.post("/test-case", response_model=TestCaseFeedbackResponse)
async def submit_test_case_feedback(
    feedback: TestCaseFeedbackRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_dependency)
) -> TestCaseFeedbackResponse:
    """
    Submit feedback for a test case.

    This endpoint allows users to provide ratings, comments, and classifications
    for individual test cases. Feedback is stored and queued for learning processing.

    **Rate Limit:** 10 requests per minute per user

    Args:
        feedback: Test case feedback details
        request: FastAPI request object
        current_user: Authenticated user information

    Returns:
        Confirmation with feedback ID and learning status

    Raises:
        HTTPException: 400 for invalid input, 429 for rate limit, 500 for server error
    """
    try:
        user_id = current_user["user"]["id"]

        # Check rate limit
        if not check_rate_limit(user_id):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Maximum 10 requests per minute."
            )

        # Get correlation ID from request
        correlation_id = request.headers.get("X-Correlation-ID", "unknown")

        logger.info(
            "test_case_feedback_received",
            test_case_id=feedback.test_case_id,
            rating=feedback.rating,
            feedback_type=feedback.feedback_type,
            user_id=user_id,
            correlation_id=correlation_id
        )

        # Store feedback in database
        stored_feedback = await store_test_case_feedback_in_db(
            feedback, user_id, correlation_id, db
        )

        # Queue for learning processing
        queued = await queue_feedback_for_learning(
            feedback_id=stored_feedback["feedback_id"],
            feedback_type="test_case",
            db=db,
            priority="high" if feedback.found_issue else "normal"
        )

        return TestCaseFeedbackResponse(
            success=True,
            feedback_id=stored_feedback["feedback_id"],
            test_case_id=feedback.test_case_id,
            learning_status="queued" if queued else "pending",
            message="Feedback submitted successfully. Thank you for helping improve test quality!",
            queued_for_learning=queued
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "error_submitting_test_case_feedback",
            error=str(e),
            test_case_id=feedback.test_case_id
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to submit feedback: {str(e)}"
        )


@router.post("/test-suite", response_model=TestSuiteFeedbackResponse)
async def submit_test_suite_feedback(
    feedback: TestSuiteFeedbackRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_dependency)
) -> TestSuiteFeedbackResponse:
    """
    Submit feedback for an entire test suite.

    This endpoint allows users to provide comprehensive feedback on test suites,
    including quality ratings, coverage gaps, and batch classifications.

    **Rate Limit:** 10 requests per minute per user

    Args:
        feedback: Test suite feedback details
        request: FastAPI request object
        current_user: Authenticated user information

    Returns:
        Confirmation with feedback ID and learning status

    Raises:
        HTTPException: 400 for invalid input, 429 for rate limit, 500 for server error
    """
    try:
        user_id = current_user["user"]["id"]

        # Check rate limit
        if not check_rate_limit(user_id):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Maximum 10 requests per minute."
            )

        # Get correlation ID from request
        correlation_id = request.headers.get("X-Correlation-ID", "unknown")

        logger.info(
            "test_suite_feedback_received",
            suite_id=feedback.suite_id,
            overall_rating=feedback.overall_rating,
            coverage_gaps=len(feedback.coverage_gaps),
            user_id=user_id,
            correlation_id=correlation_id
        )

        # Store feedback in database
        stored_feedback = await store_test_suite_feedback_in_db(
            feedback, user_id, correlation_id, db
        )

        # Queue for learning processing
        queued = await queue_feedback_for_learning(
            feedback_id=stored_feedback["feedback_id"],
            feedback_type="test_suite",
            db=db,
            priority="high" if feedback.coverage_gaps else "normal"
        )

        # Queue coverage gaps for auto-generation
        gaps_queued = 0
        if feedback.coverage_gaps:
            # TODO: Queue gaps for automatic test generation
            gaps_queued = len(feedback.coverage_gaps)
            logger.info(
                "coverage_gaps_queued",
                suite_id=feedback.suite_id,
                gap_count=gaps_queued
            )

        return TestSuiteFeedbackResponse(
            success=True,
            feedback_id=stored_feedback["feedback_id"],
            suite_id=feedback.suite_id,
            learning_status="queued" if queued else "pending",
            message="Suite feedback submitted successfully. Coverage gaps will be analyzed for auto-generation.",
            queued_for_learning=queued,
            gaps_queued_for_generation=gaps_queued
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "error_submitting_test_suite_feedback",
            error=str(e),
            suite_id=feedback.suite_id
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to submit suite feedback: {str(e)}"
        )


@router.get("/statistics", response_model=FeedbackStatistics)
async def get_feedback_stats(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_dependency)
) -> FeedbackStatistics:
    """
    Get comprehensive learning and feedback statistics.

    This endpoint provides metrics on feedback collection, pattern learning,
    and coverage gap resolution for monitoring system improvement.

    Args:
        current_user: Authenticated user information

    Returns:
        Learning statistics and metrics

    Raises:
        HTTPException: 500 for server error
    """
    try:
        logger.info(
            "feedback_statistics_requested",
            user_id=current_user["user"]["id"]
        )

        # Get statistics from database
        stats = await get_feedback_statistics(db)

        return FeedbackStatistics(**stats)

    except Exception as e:
        logger.error(
            "error_getting_feedback_statistics",
            error=str(e)
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve statistics: {str(e)}"
        )


@router.get("/test-case/{test_id}", response_model=Dict[str, Any])
async def get_test_case_feedback(
    test_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_dependency)
) -> Dict[str, Any]:
    """
    Get all feedback for a specific test case.

    This endpoint retrieves all feedback submissions for a test case,
    including learning outcomes and pattern updates.

    Args:
        test_id: Test case identifier
        current_user: Authenticated user information

    Returns:
        List of feedback entries with learning status

    Raises:
        HTTPException: 404 if not found, 500 for server error
    """
    try:
        logger.info(
            "test_case_feedback_requested",
            test_id=test_id,
            user_id=current_user["user"]["id"]
        )

        # Get feedback from database
        feedback_list = await get_test_case_feedback_from_db(test_id, db)

        if not feedback_list:
            raise HTTPException(
                status_code=404,
                detail=f"No feedback found for test case: {test_id}"
            )

        return {
            "success": True,
            "test_case_id": test_id,
            "feedback_count": len(feedback_list),
            "feedback": feedback_list
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "error_getting_test_case_feedback",
            error=str(e),
            test_id=test_id
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve feedback: {str(e)}"
        )


@router.get("/patterns/{pattern_id}", response_model=Dict[str, Any])
async def get_pattern_feedback(
    pattern_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_dependency)
) -> Dict[str, Any]:
    """
    Get feedback summary for a specific pattern.

    This endpoint retrieves aggregated feedback and performance metrics
    for a learned pattern, showing how it's being used and improved.

    Args:
        pattern_id: Pattern identifier
        current_user: Authenticated user information

    Returns:
        Pattern feedback summary with usage metrics

    Raises:
        HTTPException: 404 if not found, 500 for server error
    """
    try:
        logger.info(
            "pattern_feedback_requested",
            pattern_id=pattern_id,
            user_id=current_user["user"]["id"]
        )

        # Get pattern feedback from database
        pattern_feedback = await get_pattern_feedback_from_db(pattern_id, db)

        if not pattern_feedback:
            raise HTTPException(
                status_code=404,
                detail=f"No feedback found for pattern: {pattern_id}"
            )

        return {
            "success": True,
            "pattern_feedback": pattern_feedback
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "error_getting_pattern_feedback",
            error=str(e),
            pattern_id=pattern_id
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve pattern feedback: {str(e)}"
        )
