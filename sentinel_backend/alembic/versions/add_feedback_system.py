"""Add feedback system for learning integration

Revision ID: feedback_system_v1
Revises: rl_learning_v1
Create Date: 2025-10-28 12:00:00.000000

Implements Phase 1 Week 1 (Days 1-4) of feedback learning integration:
- Test case feedback collection
- Test suite feedback collection
- Feedback learning queue for async processing
- Pattern linkage for test cases
- Enhanced existing tables with feedback metrics
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'feedback_system_v1'
down_revision = 'rl_learning_v1'
branch_labels = None
depends_on = None


def upgrade():
    """Create feedback system tables and enhance existing tables."""

    # ========================================================================
    # 1. TEST CASE FEEDBACK TABLE
    # ========================================================================
    op.create_table(
        'test_case_feedback',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('test_case_id', sa.Integer(), nullable=False,
                  comment='Reference to test_cases.id'),
        sa.Column('user_id', sa.String(100), nullable=False,
                  comment='User who provided feedback'),
        sa.Column('rating', sa.Integer(), nullable=False,
                  comment='Rating from 1-5 stars'),
        sa.Column('feedback_type', sa.String(50), nullable=False,
                  comment='Type: quality, coverage, accuracy, relevance, performance'),
        sa.Column('comment', sa.Text(), nullable=True,
                  comment='Free-form feedback comment (max 2000 chars)'),
        sa.Column('helpful', sa.Boolean(), nullable=False, default=True,
                  comment='Was this test case helpful?'),
        sa.Column('issue_found', sa.Boolean(), nullable=False, default=False,
                  comment='Did this test find a real issue?'),
        sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()),
                  server_default='[]', nullable=False,
                  comment='Tags for categorization'),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False,
                  comment='Feedback submission timestamp'),

        # Constraints
        sa.ForeignKeyConstraint(['test_case_id'], ['test_cases.id'],
                               ondelete='CASCADE',
                               name='fk_test_case_feedback_test_case'),
        sa.CheckConstraint('rating >= 1 AND rating <= 5',
                          name='check_rating_range'),
        sa.CheckConstraint('LENGTH(comment) <= 2000',
                          name='check_comment_length'),

        comment='User feedback for individual test cases - drives learning system'
    )

    # Indexes for test_case_feedback
    op.create_index('idx_test_case_feedback_test_case_id',
                   'test_case_feedback', ['test_case_id'])
    op.create_index('idx_test_case_feedback_user_id',
                   'test_case_feedback', ['user_id'])
    op.create_index('idx_test_case_feedback_rating',
                   'test_case_feedback', ['rating'],
                   postgresql_ops={'rating': 'DESC'})
    op.create_index('idx_test_case_feedback_type',
                   'test_case_feedback', ['feedback_type'])
    op.create_index('idx_test_case_feedback_created',
                   'test_case_feedback', ['created_at'],
                   postgresql_ops={'created_at': 'DESC'})
    op.create_index('idx_test_case_feedback_helpful',
                   'test_case_feedback', ['helpful'])
    op.create_index('idx_test_case_feedback_issue_found',
                   'test_case_feedback', ['issue_found'])

    # ========================================================================
    # 2. TEST SUITE FEEDBACK TABLE
    # ========================================================================
    op.create_table(
        'test_suite_feedback',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('test_suite_id', sa.Integer(), nullable=False,
                  comment='Reference to test_suites.id'),
        sa.Column('user_id', sa.String(100), nullable=False,
                  comment='User who provided feedback'),
        sa.Column('rating', sa.Integer(), nullable=False,
                  comment='Overall rating from 1-5 stars'),
        sa.Column('coverage_rating', sa.Integer(), nullable=True,
                  comment='Coverage quality rating 1-5'),
        sa.Column('quality_rating', sa.Integer(), nullable=True,
                  comment='Test quality rating 1-5'),
        sa.Column('comment', sa.Text(), nullable=True,
                  comment='Free-form feedback comment (max 2000 chars)'),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False,
                  comment='Feedback submission timestamp'),

        # Constraints
        sa.ForeignKeyConstraint(['test_suite_id'], ['test_suites.id'],
                               ondelete='CASCADE',
                               name='fk_test_suite_feedback_test_suite'),
        sa.CheckConstraint('rating >= 1 AND rating <= 5',
                          name='check_suite_rating_range'),
        sa.CheckConstraint('coverage_rating IS NULL OR (coverage_rating >= 1 AND coverage_rating <= 5)',
                          name='check_coverage_rating_range'),
        sa.CheckConstraint('quality_rating IS NULL OR (quality_rating >= 1 AND quality_rating <= 5)',
                          name='check_quality_rating_range'),
        sa.CheckConstraint('LENGTH(comment) <= 2000',
                          name='check_suite_comment_length'),

        comment='User feedback for complete test suites - drives suite optimization'
    )

    # Indexes for test_suite_feedback
    op.create_index('idx_test_suite_feedback_test_suite_id',
                   'test_suite_feedback', ['test_suite_id'])
    op.create_index('idx_test_suite_feedback_user_id',
                   'test_suite_feedback', ['user_id'])
    op.create_index('idx_test_suite_feedback_rating',
                   'test_suite_feedback', ['rating'],
                   postgresql_ops={'rating': 'DESC'})
    op.create_index('idx_test_suite_feedback_created',
                   'test_suite_feedback', ['created_at'],
                   postgresql_ops={'created_at': 'DESC'})

    # ========================================================================
    # 3. FEEDBACK LEARNING QUEUE
    # ========================================================================
    op.create_table(
        'feedback_learning_queue',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('feedback_id', sa.Integer(), nullable=False,
                  comment='ID of feedback (from either feedback table)'),
        sa.Column('feedback_type', sa.String(20), nullable=False,
                  comment='Type: test_case or test_suite'),
        sa.Column('processing_status', sa.String(20), nullable=False,
                  default='pending',
                  comment='Status: pending, processing, completed, failed'),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False,
                  comment='Queue entry creation time'),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True,
                  comment='When feedback was processed by learning system'),
        sa.Column('error_message', sa.Text(), nullable=True,
                  comment='Error message if processing failed'),
        sa.Column('retry_count', sa.Integer(), nullable=False, default=0,
                  comment='Number of processing retry attempts'),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()),
                  server_default='{}', nullable=False,
                  comment='Additional processing metadata'),

        # Constraints
        sa.CheckConstraint("feedback_type IN ('test_case', 'test_suite')",
                          name='check_feedback_type'),
        sa.CheckConstraint("processing_status IN ('pending', 'processing', 'completed', 'failed')",
                          name='check_processing_status'),

        comment='Queue for async processing of feedback by learning system'
    )

    # Indexes for feedback_learning_queue
    op.create_index('idx_feedback_queue_status',
                   'feedback_learning_queue', ['processing_status'])
    op.create_index('idx_feedback_queue_type',
                   'feedback_learning_queue', ['feedback_type'])
    op.create_index('idx_feedback_queue_created',
                   'feedback_learning_queue', ['created_at'],
                   postgresql_ops={'created_at': 'DESC'})
    op.create_index('idx_feedback_queue_processed',
                   'feedback_learning_queue', ['processed_at'],
                   postgresql_ops={'processed_at': 'DESC'})
    op.create_index('idx_feedback_queue_pending',
                   'feedback_learning_queue', ['processing_status', 'created_at'],
                   postgresql_where=sa.text("processing_status = 'pending'"))

    # ========================================================================
    # 4. TEST CASE PATTERNS LINKAGE
    # ========================================================================
    op.create_table(
        'test_case_patterns',
        sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
        sa.Column('test_case_id', sa.Integer(), nullable=False,
                  comment='Reference to test_cases.id'),
        sa.Column('pattern_id', sa.String(100), nullable=False,
                  comment='Pattern ID from reasoningbank'),
        sa.Column('confidence_score', sa.Float(), nullable=False, default=0.0,
                  comment='Confidence that this pattern applies (0.0-1.0)'),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False,
                  comment='Pattern linkage creation time'),

        # Constraints
        sa.ForeignKeyConstraint(['test_case_id'], ['test_cases.id'],
                               ondelete='CASCADE',
                               name='fk_test_case_patterns_test_case'),
        sa.CheckConstraint('confidence_score >= 0.0 AND confidence_score <= 1.0',
                          name='check_confidence_score_range'),
        sa.UniqueConstraint('test_case_id', 'pattern_id',
                           name='uq_test_case_pattern'),

        comment='Links test cases to learned patterns from reasoningbank'
    )

    # Indexes for test_case_patterns
    op.create_index('idx_test_case_patterns_test_case_id',
                   'test_case_patterns', ['test_case_id'])
    op.create_index('idx_test_case_patterns_pattern_id',
                   'test_case_patterns', ['pattern_id'])
    op.create_index('idx_test_case_patterns_confidence',
                   'test_case_patterns', ['confidence_score'],
                   postgresql_ops={'confidence_score': 'DESC'})

    # ========================================================================
    # 5. ENHANCE EXISTING TABLES WITH FEEDBACK COLUMNS
    # ========================================================================

    # Add feedback metrics to test_cases table
    op.add_column('test_cases',
                  sa.Column('feedback_count', sa.Integer(), nullable=False,
                           default=0, server_default='0',
                           comment='Total number of feedback submissions'))
    op.add_column('test_cases',
                  sa.Column('avg_rating', sa.Float(), nullable=True,
                           comment='Average rating from all feedback'))

    # Create indexes for new test_cases columns
    op.create_index('idx_test_cases_feedback_count',
                   'test_cases', ['feedback_count'],
                   postgresql_ops={'feedback_count': 'DESC'})
    op.create_index('idx_test_cases_avg_rating',
                   'test_cases', ['avg_rating'],
                   postgresql_ops={'avg_rating': 'DESC'})

    # Add trajectory linkage to test_results table
    op.add_column('test_results',
                  sa.Column('trajectory_id', sa.String(100), nullable=True,
                           comment='Link to task_trajectories for learning'))

    # Create index for trajectory linkage
    op.create_index('idx_test_results_trajectory_id',
                   'test_results', ['trajectory_id'])


def downgrade():
    """Remove feedback system tables and columns."""

    # Drop indexes on enhanced columns
    op.drop_index('idx_test_results_trajectory_id', table_name='test_results')
    op.drop_index('idx_test_cases_avg_rating', table_name='test_cases')
    op.drop_index('idx_test_cases_feedback_count', table_name='test_cases')

    # Drop columns from existing tables
    op.drop_column('test_results', 'trajectory_id')
    op.drop_column('test_cases', 'avg_rating')
    op.drop_column('test_cases', 'feedback_count')

    # Drop test_case_patterns indexes and table
    op.drop_index('idx_test_case_patterns_confidence', table_name='test_case_patterns')
    op.drop_index('idx_test_case_patterns_pattern_id', table_name='test_case_patterns')
    op.drop_index('idx_test_case_patterns_test_case_id', table_name='test_case_patterns')
    op.drop_table('test_case_patterns')

    # Drop feedback_learning_queue indexes and table
    op.drop_index('idx_feedback_queue_pending', table_name='feedback_learning_queue')
    op.drop_index('idx_feedback_queue_processed', table_name='feedback_learning_queue')
    op.drop_index('idx_feedback_queue_created', table_name='feedback_learning_queue')
    op.drop_index('idx_feedback_queue_type', table_name='feedback_learning_queue')
    op.drop_index('idx_feedback_queue_status', table_name='feedback_learning_queue')
    op.drop_table('feedback_learning_queue')

    # Drop test_suite_feedback indexes and table
    op.drop_index('idx_test_suite_feedback_created', table_name='test_suite_feedback')
    op.drop_index('idx_test_suite_feedback_rating', table_name='test_suite_feedback')
    op.drop_index('idx_test_suite_feedback_user_id', table_name='test_suite_feedback')
    op.drop_index('idx_test_suite_feedback_test_suite_id', table_name='test_suite_feedback')
    op.drop_table('test_suite_feedback')

    # Drop test_case_feedback indexes and table
    op.drop_index('idx_test_case_feedback_issue_found', table_name='test_case_feedback')
    op.drop_index('idx_test_case_feedback_helpful', table_name='test_case_feedback')
    op.drop_index('idx_test_case_feedback_created', table_name='test_case_feedback')
    op.drop_index('idx_test_case_feedback_type', table_name='test_case_feedback')
    op.drop_index('idx_test_case_feedback_rating', table_name='test_case_feedback')
    op.drop_index('idx_test_case_feedback_user_id', table_name='test_case_feedback')
    op.drop_index('idx_test_case_feedback_test_case_id', table_name='test_case_feedback')
    op.drop_table('test_case_feedback')
