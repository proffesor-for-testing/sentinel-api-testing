"""
Feedback Schemas

Pydantic schemas for request validation and response serialization
for the feedback learning system.
"""

from datetime import datetime
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field, validator, root_validator


class FeedbackTypeEnum(str, Enum):
    """Types of feedback that can be provided."""
    QUALITY = "quality"
    COVERAGE = "coverage"
    ACCURACY = "accuracy"
    RELEVANCE = "relevance"
    PERFORMANCE = "performance"


class ProcessingStatusEnum(str, Enum):
    """Processing status for feedback in the learning queue."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================================================
# TEST CASE FEEDBACK SCHEMAS
# ============================================================================

class TestCaseFeedbackRequest(BaseModel):
    """Request schema for submitting test case feedback."""

    rating: int = Field(
        ...,
        ge=1,
        le=5,
        description="Rating from 1-5 stars"
    )
    feedback_type: FeedbackTypeEnum = Field(
        ...,
        description="Type of feedback: quality, coverage, accuracy, relevance, performance"
    )
    comment: Optional[str] = Field(
        None,
        max_length=2000,
        description="Free-form feedback comment (max 2000 characters)"
    )
    helpful: bool = Field(
        True,
        description="Was this test case helpful?"
    )
    issue_found: bool = Field(
        False,
        description="Did this test find a real issue?"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization"
    )

    @validator('comment')
    def validate_comment_length(cls, v):
        """Ensure comment doesn't exceed 2000 characters."""
        if v and len(v) > 2000:
            raise ValueError('Comment must not exceed 2000 characters')
        return v

    @validator('tags')
    def validate_tags(cls, v):
        """Ensure tags are non-empty strings."""
        if v:
            for tag in v:
                if not tag or not isinstance(tag, str):
                    raise ValueError('Tags must be non-empty strings')
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "rating": 5,
                "feedback_type": "quality",
                "comment": "Excellent test case! Found a critical edge case.",
                "helpful": True,
                "issue_found": True,
                "tags": ["edge-case", "critical"]
            }
        }


class TestCaseFeedbackResponse(BaseModel):
    """Response schema for test case feedback."""

    id: int
    test_case_id: int
    user_id: str
    rating: int
    feedback_type: str
    comment: Optional[str]
    helpful: bool
    issue_found: bool
    tags: List[str]
    created_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 123,
                "test_case_id": 456,
                "user_id": "user-789",
                "rating": 5,
                "feedback_type": "quality",
                "comment": "Excellent test case!",
                "helpful": True,
                "issue_found": True,
                "tags": ["edge-case", "critical"],
                "created_at": "2025-10-28T12:00:00Z"
            }
        }


# ============================================================================
# TEST SUITE FEEDBACK SCHEMAS
# ============================================================================

class TestSuiteFeedbackRequest(BaseModel):
    """Request schema for submitting test suite feedback."""

    rating: int = Field(
        ...,
        ge=1,
        le=5,
        description="Overall rating from 1-5 stars"
    )
    coverage_rating: Optional[int] = Field(
        None,
        ge=1,
        le=5,
        description="Coverage quality rating 1-5"
    )
    quality_rating: Optional[int] = Field(
        None,
        ge=1,
        le=5,
        description="Test quality rating 1-5"
    )
    comment: Optional[str] = Field(
        None,
        max_length=2000,
        description="Free-form feedback comment (max 2000 characters)"
    )

    @validator('comment')
    def validate_comment_length(cls, v):
        """Ensure comment doesn't exceed 2000 characters."""
        if v and len(v) > 2000:
            raise ValueError('Comment must not exceed 2000 characters')
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "rating": 4,
                "coverage_rating": 5,
                "quality_rating": 4,
                "comment": "Good test suite with comprehensive coverage."
            }
        }


class TestSuiteFeedbackResponse(BaseModel):
    """Response schema for test suite feedback."""

    id: int
    test_suite_id: int
    user_id: str
    rating: int
    coverage_rating: Optional[int]
    quality_rating: Optional[int]
    comment: Optional[str]
    overall_score: float
    created_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 123,
                "test_suite_id": 456,
                "user_id": "user-789",
                "rating": 4,
                "coverage_rating": 5,
                "quality_rating": 4,
                "comment": "Good test suite!",
                "overall_score": 4.33,
                "created_at": "2025-10-28T12:00:00Z"
            }
        }


# ============================================================================
# FEEDBACK STATISTICS SCHEMAS
# ============================================================================

class FeedbackStatistics(BaseModel):
    """Statistics aggregated from feedback data."""

    total_feedback_count: int = Field(
        ...,
        description="Total number of feedback submissions"
    )
    average_rating: float = Field(
        ...,
        description="Average rating across all feedback"
    )
    rating_distribution: dict = Field(
        ...,
        description="Distribution of ratings (1-5)"
    )
    helpful_count: int = Field(
        ...,
        description="Number of feedback marked as helpful"
    )
    issue_found_count: int = Field(
        ...,
        description="Number of feedback that found issues"
    )
    feedback_by_type: dict = Field(
        ...,
        description="Count of feedback by type"
    )
    recent_feedback_count: int = Field(
        ...,
        description="Number of feedback in last 24 hours"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "total_feedback_count": 150,
                "average_rating": 4.2,
                "rating_distribution": {
                    "1": 5,
                    "2": 10,
                    "3": 20,
                    "4": 55,
                    "5": 60
                },
                "helpful_count": 130,
                "issue_found_count": 45,
                "feedback_by_type": {
                    "quality": 60,
                    "coverage": 40,
                    "accuracy": 30,
                    "relevance": 15,
                    "performance": 5
                },
                "recent_feedback_count": 12
            }
        }


class TestCaseWithFeedback(BaseModel):
    """Test case with aggregated feedback metrics."""

    test_case_id: int
    feedback_count: int
    avg_rating: Optional[float]
    positive_feedback_count: int
    negative_feedback_count: int
    issue_found_count: int
    helpful_count: int
    top_tags: List[str]

    class Config:
        json_schema_extra = {
            "example": {
                "test_case_id": 456,
                "feedback_count": 15,
                "avg_rating": 4.5,
                "positive_feedback_count": 12,
                "negative_feedback_count": 1,
                "issue_found_count": 8,
                "helpful_count": 14,
                "top_tags": ["edge-case", "critical", "security"]
            }
        }


# ============================================================================
# LEARNING QUEUE SCHEMAS
# ============================================================================

class FeedbackLearningQueueResponse(BaseModel):
    """Response schema for feedback learning queue entries."""

    id: int
    feedback_id: int
    feedback_type: str
    processing_status: ProcessingStatusEnum
    created_at: datetime
    processed_at: Optional[datetime]
    error_message: Optional[str]
    retry_count: int
    metadata: dict

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 789,
                "feedback_id": 123,
                "feedback_type": "test_case",
                "processing_status": "completed",
                "created_at": "2025-10-28T12:00:00Z",
                "processed_at": "2025-10-28T12:05:00Z",
                "error_message": None,
                "retry_count": 0,
                "metadata": {"pattern_count": 3}
            }
        }


class QueueStatistics(BaseModel):
    """Statistics for the feedback learning queue."""

    total_pending: int
    total_processing: int
    total_completed: int
    total_failed: int
    avg_processing_time_seconds: float
    oldest_pending_age_seconds: float

    class Config:
        json_schema_extra = {
            "example": {
                "total_pending": 5,
                "total_processing": 2,
                "total_completed": 143,
                "total_failed": 3,
                "avg_processing_time_seconds": 2.5,
                "oldest_pending_age_seconds": 120.0
            }
        }


# ============================================================================
# PATTERN LINKAGE SCHEMAS
# ============================================================================

class TestCasePatternResponse(BaseModel):
    """Response schema for test case pattern linkage."""

    id: int
    test_case_id: int
    pattern_id: str
    confidence_score: float
    created_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 111,
                "test_case_id": 456,
                "pattern_id": "pattern-edge-case-001",
                "confidence_score": 0.92,
                "created_at": "2025-10-28T12:00:00Z"
            }
        }


class PatternStatistics(BaseModel):
    """Statistics for pattern usage."""

    pattern_id: str
    usage_count: int
    avg_confidence: float
    avg_test_rating: float
    high_confidence_count: int

    class Config:
        json_schema_extra = {
            "example": {
                "pattern_id": "pattern-edge-case-001",
                "usage_count": 45,
                "avg_confidence": 0.87,
                "avg_test_rating": 4.6,
                "high_confidence_count": 38
            }
        }


# ============================================================================
# BULK OPERATIONS
# ============================================================================

class BulkFeedbackRequest(BaseModel):
    """Request schema for submitting multiple feedback items."""

    feedback_items: List[TestCaseFeedbackRequest] = Field(
        ...,
        min_items=1,
        max_items=100,
        description="List of feedback items (max 100)"
    )

    @validator('feedback_items')
    def validate_feedback_items(cls, v):
        """Ensure feedback items list is not empty."""
        if not v or len(v) == 0:
            raise ValueError('At least one feedback item is required')
        if len(v) > 100:
            raise ValueError('Maximum 100 feedback items allowed per request')
        return v


class BulkFeedbackResponse(BaseModel):
    """Response schema for bulk feedback submission."""

    success_count: int
    failure_count: int
    created_ids: List[int]
    errors: List[dict]

    class Config:
        json_schema_extra = {
            "example": {
                "success_count": 45,
                "failure_count": 2,
                "created_ids": [1, 2, 3, 4, 5],
                "errors": [
                    {"index": 10, "error": "Invalid rating value"},
                    {"index": 23, "error": "Test case not found"}
                ]
            }
        }
