"""
Unit Tests for Feedback Models

Comprehensive tests for SQLAlchemy ORM models in the feedback learning system.
Tests model creation, validation, relationships, and constraints.
"""

import pytest
from datetime import datetime
import sqlalchemy as sa
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from sentinel_backend.models.feedback import (
    Base,
    TestCaseFeedback,
    TestSuiteFeedback,
    FeedbackLearningQueue,
    TestCasePattern,
    FeedbackType,
    FeedbackQueueType,
    ProcessingStatus,
)


@pytest.fixture(scope='function')
def db_session():
    """Create an in-memory SQLite database session for testing."""
    # Use SQLite without foreign key enforcement for unit testing
    engine = create_engine('sqlite:///:memory:', echo=False,
                          connect_args={'check_same_thread': False})

    # Disable foreign key constraints for testing
    @sa.event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=OFF")
        cursor.close()

    # Create all tables
    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    yield session

    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture
def sample_test_case_feedback():
    """Sample test case feedback data."""
    return {
        'test_case_id': 123,
        'user_id': 'user-456',
        'rating': 4,
        'feedback_type': FeedbackType.QUALITY.value,
        'comment': 'Great test case!',
        'helpful': True,
        'issue_found': False,
        'tags': ['edge-case', 'api']
    }


@pytest.fixture
def sample_test_suite_feedback():
    """Sample test suite feedback data."""
    return {
        'test_suite_id': 789,
        'user_id': 'user-456',
        'rating': 5,
        'coverage_rating': 4,
        'quality_rating': 5,
        'comment': 'Excellent test suite!'
    }


# ============================================================================
# TEST CASE FEEDBACK MODEL TESTS
# ============================================================================

class TestTestCaseFeedbackModel:
    """Tests for TestCaseFeedback model."""

    def test_create_test_case_feedback(self, db_session, sample_test_case_feedback):
        """Test creating a test case feedback entry."""
        feedback = TestCaseFeedback(**sample_test_case_feedback)
        db_session.add(feedback)
        db_session.commit()

        assert feedback.id is not None
        assert feedback.test_case_id == 123
        assert feedback.user_id == 'user-456'
        assert feedback.rating == 4
        assert feedback.feedback_type == FeedbackType.QUALITY.value
        assert feedback.helpful is True
        assert feedback.issue_found is False
        assert feedback.created_at is not None

    def test_test_case_feedback_rating_constraint(self, db_session):
        """Test rating constraint (must be 1-5)."""
        # Test rating too low
        feedback_low = TestCaseFeedback(
            test_case_id=123,
            user_id='user-456',
            rating=0,  # Invalid
            feedback_type=FeedbackType.QUALITY.value
        )
        db_session.add(feedback_low)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Test rating too high
        feedback_high = TestCaseFeedback(
            test_case_id=123,
            user_id='user-456',
            rating=6,  # Invalid
            feedback_type=FeedbackType.QUALITY.value
        )
        db_session.add(feedback_high)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_test_case_feedback_is_positive(self, db_session, sample_test_case_feedback):
        """Test is_positive property."""
        # Positive feedback (rating >= 4)
        positive_feedback = TestCaseFeedback(**sample_test_case_feedback)
        positive_feedback.rating = 4
        assert positive_feedback.is_positive is True

        positive_feedback.rating = 5
        assert positive_feedback.is_positive is True

        # Not positive feedback
        positive_feedback.rating = 3
        assert positive_feedback.is_positive is False

    def test_test_case_feedback_is_negative(self, db_session, sample_test_case_feedback):
        """Test is_negative property."""
        negative_feedback = TestCaseFeedback(**sample_test_case_feedback)

        # Negative feedback (rating <= 2)
        negative_feedback.rating = 1
        assert negative_feedback.is_negative is True

        negative_feedback.rating = 2
        assert negative_feedback.is_negative is True

        # Not negative feedback
        negative_feedback.rating = 3
        assert negative_feedback.is_negative is False

    def test_test_case_feedback_to_dict(self, db_session, sample_test_case_feedback):
        """Test to_dict serialization."""
        feedback = TestCaseFeedback(**sample_test_case_feedback)
        db_session.add(feedback)
        db_session.commit()

        feedback_dict = feedback.to_dict()

        assert feedback_dict['id'] == feedback.id
        assert feedback_dict['test_case_id'] == 123
        assert feedback_dict['user_id'] == 'user-456'
        assert feedback_dict['rating'] == 4
        assert feedback_dict['helpful'] is True
        assert 'created_at' in feedback_dict

    def test_test_case_feedback_all_feedback_types(self, db_session):
        """Test all valid feedback types."""
        feedback_types = [
            FeedbackType.QUALITY,
            FeedbackType.COVERAGE,
            FeedbackType.ACCURACY,
            FeedbackType.RELEVANCE,
            FeedbackType.PERFORMANCE
        ]

        for feedback_type in feedback_types:
            feedback = TestCaseFeedback(
                test_case_id=123,
                user_id='user-456',
                rating=4,
                feedback_type=feedback_type.value
            )
            db_session.add(feedback)
            db_session.commit()

            assert feedback.id is not None
            assert feedback.feedback_type == feedback_type.value

            db_session.delete(feedback)
            db_session.commit()


# ============================================================================
# TEST SUITE FEEDBACK MODEL TESTS
# ============================================================================

class TestTestSuiteFeedbackModel:
    """Tests for TestSuiteFeedback model."""

    def test_create_test_suite_feedback(self, db_session, sample_test_suite_feedback):
        """Test creating a test suite feedback entry."""
        feedback = TestSuiteFeedback(**sample_test_suite_feedback)
        db_session.add(feedback)
        db_session.commit()

        assert feedback.id is not None
        assert feedback.test_suite_id == 789
        assert feedback.rating == 5
        assert feedback.coverage_rating == 4
        assert feedback.quality_rating == 5
        assert feedback.created_at is not None

    def test_test_suite_feedback_rating_constraint(self, db_session):
        """Test rating constraints for suite feedback."""
        # Test invalid main rating
        feedback = TestSuiteFeedback(
            test_suite_id=789,
            user_id='user-456',
            rating=0  # Invalid
        )
        db_session.add(feedback)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_test_suite_feedback_overall_score(self, db_session, sample_test_suite_feedback):
        """Test overall_score calculation."""
        feedback = TestSuiteFeedback(**sample_test_suite_feedback)

        # With all ratings
        expected_score = (5 + 4 + 5) / 3
        assert feedback.overall_score == pytest.approx(expected_score, 0.01)

        # With only main rating
        feedback.coverage_rating = None
        feedback.quality_rating = None
        assert feedback.overall_score == 5.0

        # With main + coverage rating
        feedback.coverage_rating = 4
        expected_score = (5 + 4) / 2
        assert feedback.overall_score == pytest.approx(expected_score, 0.01)

    def test_test_suite_feedback_is_positive(self, db_session, sample_test_suite_feedback):
        """Test is_positive property."""
        feedback = TestSuiteFeedback(**sample_test_suite_feedback)

        feedback.rating = 4
        assert feedback.is_positive is True

        feedback.rating = 5
        assert feedback.is_positive is True

        feedback.rating = 3
        assert feedback.is_positive is False

    def test_test_suite_feedback_to_dict(self, db_session, sample_test_suite_feedback):
        """Test to_dict serialization."""
        feedback = TestSuiteFeedback(**sample_test_suite_feedback)
        db_session.add(feedback)
        db_session.commit()

        feedback_dict = feedback.to_dict()

        assert feedback_dict['id'] == feedback.id
        assert feedback_dict['test_suite_id'] == 789
        assert feedback_dict['rating'] == 5
        assert 'overall_score' in feedback_dict
        assert 'created_at' in feedback_dict

    def test_test_suite_feedback_optional_ratings(self, db_session):
        """Test that coverage and quality ratings are optional."""
        feedback = TestSuiteFeedback(
            test_suite_id=789,
            user_id='user-456',
            rating=4,
            coverage_rating=None,
            quality_rating=None
        )
        db_session.add(feedback)
        db_session.commit()

        assert feedback.id is not None
        assert feedback.coverage_rating is None
        assert feedback.quality_rating is None


# ============================================================================
# FEEDBACK LEARNING QUEUE MODEL TESTS
# ============================================================================

class TestFeedbackLearningQueueModel:
    """Tests for FeedbackLearningQueue model."""

    def test_create_feedback_learning_queue(self, db_session):
        """Test creating a feedback learning queue entry."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.PENDING.value
        )
        db_session.add(queue_entry)
        db_session.commit()

        assert queue_entry.id is not None
        assert queue_entry.feedback_id == 123
        assert queue_entry.feedback_type == FeedbackQueueType.TEST_CASE.value
        assert queue_entry.processing_status == ProcessingStatus.PENDING.value
        assert queue_entry.retry_count == 0
        assert queue_entry.created_at is not None

    def test_feedback_queue_type_constraint(self, db_session):
        """Test feedback type constraint."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type='invalid_type',  # Invalid
            processing_status=ProcessingStatus.PENDING.value
        )
        db_session.add(queue_entry)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_feedback_queue_status_constraint(self, db_session):
        """Test processing status constraint."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status='invalid_status'  # Invalid
        )
        db_session.add(queue_entry)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_feedback_queue_is_pending(self, db_session):
        """Test is_pending property."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.PENDING.value
        )
        assert queue_entry.is_pending is True

        queue_entry.processing_status = ProcessingStatus.COMPLETED.value
        assert queue_entry.is_pending is False

    def test_feedback_queue_is_completed(self, db_session):
        """Test is_completed property."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.COMPLETED.value
        )
        assert queue_entry.is_completed is True

    def test_feedback_queue_is_failed(self, db_session):
        """Test is_failed property."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.FAILED.value
        )
        assert queue_entry.is_failed is True

    def test_feedback_queue_can_retry(self, db_session):
        """Test can_retry property."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.FAILED.value,
            retry_count=0
        )
        assert queue_entry.can_retry is True

        # After 3 retries, cannot retry
        queue_entry.retry_count = 3
        assert queue_entry.can_retry is False

        # Non-failed entries cannot retry
        queue_entry.processing_status = ProcessingStatus.PENDING.value
        assert queue_entry.can_retry is False

    def test_feedback_queue_to_dict(self, db_session):
        """Test to_dict serialization."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.PENDING.value,
            processing_metadata={'key': 'value'}
        )
        db_session.add(queue_entry)
        db_session.commit()

        entry_dict = queue_entry.to_dict()

        assert entry_dict['id'] == queue_entry.id
        assert entry_dict['feedback_id'] == 123
        assert entry_dict['feedback_type'] == FeedbackQueueType.TEST_CASE.value
        assert entry_dict['processing_status'] == ProcessingStatus.PENDING.value
        assert entry_dict['metadata'] == {'key': 'value'}

    def test_feedback_queue_all_statuses(self, db_session):
        """Test all valid processing statuses."""
        statuses = [
            ProcessingStatus.PENDING,
            ProcessingStatus.PROCESSING,
            ProcessingStatus.COMPLETED,
            ProcessingStatus.FAILED
        ]

        for status in statuses:
            queue_entry = FeedbackLearningQueue(
                feedback_id=123,
                feedback_type=FeedbackQueueType.TEST_CASE.value,
                processing_status=status.value
            )
            db_session.add(queue_entry)
            db_session.commit()

            assert queue_entry.id is not None
            assert queue_entry.processing_status == status.value

            db_session.delete(queue_entry)
            db_session.commit()


# ============================================================================
# TEST CASE PATTERN MODEL TESTS
# ============================================================================

class TestTestCasePatternModel:
    """Tests for TestCasePattern model."""

    def test_create_test_case_pattern(self, db_session):
        """Test creating a test case pattern linkage."""
        pattern = TestCasePattern(
            test_case_id=123,
            pattern_id='pattern-edge-case-001',
            confidence_score=0.85
        )
        db_session.add(pattern)
        db_session.commit()

        assert pattern.id is not None
        assert pattern.test_case_id == 123
        assert pattern.pattern_id == 'pattern-edge-case-001'
        assert pattern.confidence_score == 0.85
        assert pattern.created_at is not None

    def test_test_case_pattern_confidence_constraint(self, db_session):
        """Test confidence score constraint (0.0-1.0)."""
        # Test confidence too low
        pattern_low = TestCasePattern(
            test_case_id=123,
            pattern_id='pattern-001',
            confidence_score=-0.1  # Invalid
        )
        db_session.add(pattern_low)
        with pytest.raises(IntegrityError):
            db_session.commit()
        db_session.rollback()

        # Test confidence too high
        pattern_high = TestCasePattern(
            test_case_id=123,
            pattern_id='pattern-001',
            confidence_score=1.1  # Invalid
        )
        db_session.add(pattern_high)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_test_case_pattern_is_high_confidence(self, db_session):
        """Test is_high_confidence property."""
        pattern = TestCasePattern(
            test_case_id=123,
            pattern_id='pattern-001',
            confidence_score=0.85
        )

        pattern.confidence_score = 0.8
        assert pattern.is_high_confidence is True

        pattern.confidence_score = 0.9
        assert pattern.is_high_confidence is True

        pattern.confidence_score = 0.75
        assert pattern.is_high_confidence is False

    def test_test_case_pattern_is_low_confidence(self, db_session):
        """Test is_low_confidence property."""
        pattern = TestCasePattern(
            test_case_id=123,
            pattern_id='pattern-001',
            confidence_score=0.2
        )

        pattern.confidence_score = 0.3
        assert pattern.is_low_confidence is True

        pattern.confidence_score = 0.1
        assert pattern.is_low_confidence is True

        pattern.confidence_score = 0.4
        assert pattern.is_low_confidence is False

    def test_test_case_pattern_to_dict(self, db_session):
        """Test to_dict serialization."""
        pattern = TestCasePattern(
            test_case_id=123,
            pattern_id='pattern-edge-case-001',
            confidence_score=0.92
        )
        db_session.add(pattern)
        db_session.commit()

        pattern_dict = pattern.to_dict()

        assert pattern_dict['id'] == pattern.id
        assert pattern_dict['test_case_id'] == 123
        assert pattern_dict['pattern_id'] == 'pattern-edge-case-001'
        assert pattern_dict['confidence_score'] == 0.92
        assert 'created_at' in pattern_dict

    def test_test_case_pattern_boundary_values(self, db_session):
        """Test boundary values for confidence score."""
        # Test minimum confidence (0.0)
        pattern_min = TestCasePattern(
            test_case_id=123,
            pattern_id='pattern-001',
            confidence_score=0.0
        )
        db_session.add(pattern_min)
        db_session.commit()
        assert pattern_min.id is not None

        # Test maximum confidence (1.0)
        pattern_max = TestCasePattern(
            test_case_id=124,
            pattern_id='pattern-002',
            confidence_score=1.0
        )
        db_session.add(pattern_max)
        db_session.commit()
        assert pattern_max.id is not None


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestFeedbackModelsIntegration:
    """Integration tests for feedback models."""

    def test_multiple_feedback_for_same_test_case(self, db_session, sample_test_case_feedback):
        """Test multiple users can provide feedback for the same test case."""
        feedback1 = TestCaseFeedback(**sample_test_case_feedback)
        feedback1.user_id = 'user-1'

        feedback2 = TestCaseFeedback(**sample_test_case_feedback)
        feedback2.user_id = 'user-2'

        db_session.add_all([feedback1, feedback2])
        db_session.commit()

        assert feedback1.id != feedback2.id
        assert feedback1.test_case_id == feedback2.test_case_id

    def test_feedback_queue_with_metadata(self, db_session):
        """Test feedback queue with complex metadata."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.COMPLETED.value,
            processing_metadata={
                'pattern_count': 5,
                'processing_time_ms': 234,
                'learning_algo': 'q-learning'
            }
        )
        db_session.add(queue_entry)
        db_session.commit()

        retrieved = db_session.query(FeedbackLearningQueue).filter_by(id=queue_entry.id).first()
        assert retrieved.processing_metadata['pattern_count'] == 5
        assert retrieved.processing_metadata['processing_time_ms'] == 234

    def test_multiple_patterns_for_test_case(self, db_session):
        """Test linking multiple patterns to a single test case."""
        patterns = [
            TestCasePattern(
                test_case_id=123,
                pattern_id='pattern-001',
                confidence_score=0.9
            ),
            TestCasePattern(
                test_case_id=123,
                pattern_id='pattern-002',
                confidence_score=0.85
            ),
            TestCasePattern(
                test_case_id=123,
                pattern_id='pattern-003',
                confidence_score=0.75
            )
        ]

        db_session.add_all(patterns)
        db_session.commit()

        retrieved_patterns = db_session.query(TestCasePattern).filter_by(
            test_case_id=123
        ).all()

        assert len(retrieved_patterns) == 3
        confidence_scores = [p.confidence_score for p in retrieved_patterns]
        assert 0.9 in confidence_scores
        assert 0.85 in confidence_scores
        assert 0.75 in confidence_scores


# ============================================================================
# EDGE CASES AND ERROR HANDLING
# ============================================================================

class TestFeedbackModelsEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_comment(self, db_session, sample_test_case_feedback):
        """Test feedback with empty comment."""
        sample_test_case_feedback['comment'] = ''
        feedback = TestCaseFeedback(**sample_test_case_feedback)
        db_session.add(feedback)
        db_session.commit()

        assert feedback.id is not None
        assert feedback.comment == ''

    def test_none_comment(self, db_session, sample_test_case_feedback):
        """Test feedback with None comment."""
        sample_test_case_feedback['comment'] = None
        feedback = TestCaseFeedback(**sample_test_case_feedback)
        db_session.add(feedback)
        db_session.commit()

        assert feedback.id is not None
        assert feedback.comment is None

    def test_empty_tags_list(self, db_session, sample_test_case_feedback):
        """Test feedback with empty tags list."""
        sample_test_case_feedback['tags'] = []
        feedback = TestCaseFeedback(**sample_test_case_feedback)
        db_session.add(feedback)
        db_session.commit()

        assert feedback.id is not None
        assert feedback.tags == []

    def test_queue_entry_with_error_message(self, db_session):
        """Test queue entry with error message."""
        queue_entry = FeedbackLearningQueue(
            feedback_id=123,
            feedback_type=FeedbackQueueType.TEST_CASE.value,
            processing_status=ProcessingStatus.FAILED.value,
            error_message='Failed to process: Invalid pattern format',
            retry_count=2
        )
        db_session.add(queue_entry)
        db_session.commit()

        assert queue_entry.error_message is not None
        assert 'Invalid pattern format' in queue_entry.error_message
        assert queue_entry.retry_count == 2


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=sentinel_backend.models.feedback', '--cov-report=term-missing'])
