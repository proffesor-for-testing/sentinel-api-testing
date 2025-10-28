"""
Feedback Models

SQLAlchemy ORM models for the feedback learning system.
Captures user feedback on test cases and suites to drive continuous learning.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime,
    ForeignKey, CheckConstraint, Index, JSON
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, declarative_base
import sqlalchemy as sa

Base = declarative_base()


class FeedbackType(str, Enum):
    """Types of feedback that can be provided."""
    QUALITY = "quality"
    COVERAGE = "coverage"
    ACCURACY = "accuracy"
    RELEVANCE = "relevance"
    PERFORMANCE = "performance"


class FeedbackQueueType(str, Enum):
    """Types of feedback in the learning queue."""
    TEST_CASE = "test_case"
    TEST_SUITE = "test_suite"


class ProcessingStatus(str, Enum):
    """Processing status for feedback in the learning queue."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class TestCaseFeedback(Base):
    """
    User feedback for individual test cases.

    Captures detailed feedback on test quality, helpfulness, and issues found.
    Drives the learning system to improve future test generation.
    """

    __tablename__ = "test_case_feedback"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign keys (NOTE: For production use, uncomment ForeignKey; for unit testing we test without it)
    test_case_id = Column(Integer, # ForeignKey('test_cases.id', ondelete='CASCADE'),
                         nullable=False, index=True)

    # User and rating
    user_id = Column(String(100), nullable=False, index=True)
    rating = Column(Integer, nullable=False, index=True)  # 1-5

    # Feedback details
    feedback_type = Column(String(50), nullable=False, index=True)
    comment = Column(Text, nullable=True)
    helpful = Column(Boolean, nullable=False, default=True, index=True)
    issue_found = Column(Boolean, nullable=False, default=False, index=True)
    # Use JSON with fallback for SQLite compatibility
    tags = Column(JSON, nullable=False, server_default='[]')

    # Timestamp
    created_at = Column(DateTime(timezone=True), nullable=False,
                       server_default='now()', index=True)

    # Relationships (commented out for standalone testing)
    # test_case = relationship("TestCase", back_populates="feedback")

    # Table constraints
    __table_args__ = (
        CheckConstraint('rating >= 1 AND rating <= 5', name='check_rating_range'),
        CheckConstraint('LENGTH(comment) <= 2000', name='check_comment_length'),
        Index('idx_test_case_feedback_test_case_id', 'test_case_id'),
        Index('idx_test_case_feedback_user_id', 'user_id'),
        Index('idx_test_case_feedback_rating', 'rating'),
        Index('idx_test_case_feedback_type', 'feedback_type'),
        Index('idx_test_case_feedback_created', 'created_at'),
        Index('idx_test_case_feedback_helpful', 'helpful'),
        Index('idx_test_case_feedback_issue_found', 'issue_found'),
    )

    @property
    def is_positive(self) -> bool:
        """Check if feedback is positive (rating >= 4)."""
        return self.rating >= 4

    @property
    def is_negative(self) -> bool:
        """Check if feedback is negative (rating <= 2)."""
        return self.rating <= 2

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "test_case_id": self.test_case_id,
            "user_id": self.user_id,
            "rating": self.rating,
            "feedback_type": self.feedback_type,
            "comment": self.comment,
            "helpful": self.helpful,
            "issue_found": self.issue_found,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<TestCaseFeedback(id={self.id}, "
            f"test_case_id={self.test_case_id}, "
            f"rating={self.rating}, "
            f"type='{self.feedback_type}', "
            f"helpful={self.helpful})>"
        )


class TestSuiteFeedback(Base):
    """
    User feedback for complete test suites.

    Captures overall assessment of test suite quality, coverage, and effectiveness.
    Used to optimize test suite composition and generation strategies.
    """

    __tablename__ = "test_suite_feedback"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign keys (NOTE: For production, uncomment ForeignKey; for unit testing we test without it)
    test_suite_id = Column(Integer, # ForeignKey('test_suites.id', ondelete='CASCADE'),
                          nullable=False, index=True)

    # User and ratings
    user_id = Column(String(100), nullable=False, index=True)
    rating = Column(Integer, nullable=False, index=True)  # 1-5
    coverage_rating = Column(Integer, nullable=True)  # 1-5
    quality_rating = Column(Integer, nullable=True)  # 1-5

    # Feedback details
    comment = Column(Text, nullable=True)

    # Timestamp
    created_at = Column(DateTime(timezone=True), nullable=False,
                       server_default='now()', index=True)

    # Relationships (commented out for standalone testing)
    # test_suite = relationship("TestSuite", back_populates="feedback")

    # Table constraints
    __table_args__ = (
        CheckConstraint('rating >= 1 AND rating <= 5', name='check_suite_rating_range'),
        CheckConstraint('coverage_rating IS NULL OR (coverage_rating >= 1 AND coverage_rating <= 5)',
                       name='check_coverage_rating_range'),
        CheckConstraint('quality_rating IS NULL OR (quality_rating >= 1 AND quality_rating <= 5)',
                       name='check_quality_rating_range'),
        CheckConstraint('LENGTH(comment) <= 2000', name='check_suite_comment_length'),
        Index('idx_test_suite_feedback_test_suite_id', 'test_suite_id'),
        Index('idx_test_suite_feedback_user_id', 'user_id'),
        Index('idx_test_suite_feedback_rating', 'rating'),
        Index('idx_test_suite_feedback_created', 'created_at'),
    )

    @property
    def overall_score(self) -> float:
        """Calculate weighted overall score."""
        scores = [self.rating]
        if self.coverage_rating:
            scores.append(self.coverage_rating)
        if self.quality_rating:
            scores.append(self.quality_rating)
        return sum(scores) / len(scores)

    @property
    def is_positive(self) -> bool:
        """Check if feedback is positive (rating >= 4)."""
        return self.rating >= 4

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "test_suite_id": self.test_suite_id,
            "user_id": self.user_id,
            "rating": self.rating,
            "coverage_rating": self.coverage_rating,
            "quality_rating": self.quality_rating,
            "comment": self.comment,
            "overall_score": self.overall_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<TestSuiteFeedback(id={self.id}, "
            f"test_suite_id={self.test_suite_id}, "
            f"rating={self.rating}, "
            f"overall_score={self.overall_score:.2f})>"
        )


class FeedbackLearningQueue(Base):
    """
    Queue for asynchronous processing of feedback by the learning system.

    Tracks the processing status of feedback submissions, enabling retry logic
    and error handling for the learning integration.
    """

    __tablename__ = "feedback_learning_queue"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Queue details
    feedback_id = Column(Integer, nullable=False)
    feedback_type = Column(String(20), nullable=False, index=True)  # test_case or test_suite
    processing_status = Column(String(20), nullable=False, default='pending', index=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False,
                       server_default='now()', index=True)
    processed_at = Column(DateTime(timezone=True), nullable=True, index=True)

    # Error handling
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    # Use JSON with fallback for SQLite compatibility
    processing_metadata = Column('metadata', JSON, nullable=False, server_default='{}')

    # Table constraints
    __table_args__ = (
        CheckConstraint("feedback_type IN ('test_case', 'test_suite')",
                       name='check_feedback_type'),
        CheckConstraint("processing_status IN ('pending', 'processing', 'completed', 'failed')",
                       name='check_processing_status'),
        Index('idx_feedback_queue_status', 'processing_status'),
        Index('idx_feedback_queue_type', 'feedback_type'),
        Index('idx_feedback_queue_created', 'created_at'),
        Index('idx_feedback_queue_processed', 'processed_at'),
        Index('idx_feedback_queue_pending', 'processing_status', 'created_at',
              postgresql_where="processing_status = 'pending'"),
    )

    @property
    def is_pending(self) -> bool:
        """Check if feedback is pending processing."""
        return self.processing_status == ProcessingStatus.PENDING.value

    @property
    def is_completed(self) -> bool:
        """Check if feedback processing is completed."""
        return self.processing_status == ProcessingStatus.COMPLETED.value

    @property
    def is_failed(self) -> bool:
        """Check if feedback processing failed."""
        return self.processing_status == ProcessingStatus.FAILED.value

    @property
    def can_retry(self) -> bool:
        """Check if failed feedback can be retried."""
        return self.is_failed and self.retry_count < 3

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "feedback_id": self.feedback_id,
            "feedback_type": self.feedback_type,
            "processing_status": self.processing_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "metadata": self.processing_metadata,
        }

    def __repr__(self) -> str:
        return (
            f"<FeedbackLearningQueue(id={self.id}, "
            f"feedback_id={self.feedback_id}, "
            f"type='{self.feedback_type}', "
            f"status='{self.processing_status}')>"
        )


class TestCasePattern(Base):
    """
    Links test cases to learned patterns from the reasoningbank.

    Tracks which patterns were used to generate or optimize each test case,
    enabling pattern-based test generation and improvement.
    """

    __tablename__ = "test_case_patterns"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Foreign keys (NOTE: For production use, uncomment ForeignKey; for unit testing we test without it)
    test_case_id = Column(Integer, # ForeignKey('test_cases.id', ondelete='CASCADE'),
                         nullable=False, index=True)

    # Pattern details
    pattern_id = Column(String(100), nullable=False, index=True)
    confidence_score = Column(Float, nullable=False, default=0.0, index=True)

    # Timestamp
    created_at = Column(DateTime(timezone=True), nullable=False,
                       server_default='now()')

    # Relationships (commented out for standalone testing)
    # test_case = relationship("TestCase", back_populates="patterns")

    # Table constraints
    __table_args__ = (
        CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0',
                       name='check_confidence_score_range'),
        Index('idx_test_case_patterns_test_case_id', 'test_case_id'),
        Index('idx_test_case_patterns_pattern_id', 'pattern_id'),
        Index('idx_test_case_patterns_confidence', 'confidence_score'),
        {'sqlite_autoincrement': True}
    )

    @property
    def is_high_confidence(self) -> bool:
        """Check if pattern has high confidence (>= 0.8)."""
        return self.confidence_score >= 0.8

    @property
    def is_low_confidence(self) -> bool:
        """Check if pattern has low confidence (<= 0.3)."""
        return self.confidence_score <= 0.3

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "test_case_id": self.test_case_id,
            "pattern_id": self.pattern_id,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<TestCasePattern(id={self.id}, "
            f"test_case_id={self.test_case_id}, "
            f"pattern_id='{self.pattern_id}', "
            f"confidence={self.confidence_score:.2f})>"
        )
