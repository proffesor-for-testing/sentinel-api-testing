"""Create RL learning tables for Q-Learning with 9 algorithms

Revision ID: rl_learning_v1
Revises: 00bf195867b2
Create Date: 2025-10-27 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'rl_learning_v1'
down_revision = '00bf195867b2'
branch_labels = None
depends_on = None


def upgrade():
    """Create reinforcement learning tables."""

    # Q-Table for storing learned Q-values
    op.create_table(
        'rl_q_table',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('state_hash', sa.String(64), nullable=False,
                  comment='Hash of state vector for efficient lookup'),
        sa.Column('action_id', sa.Integer(), nullable=False,
                  comment='Action identifier'),
        sa.Column('q_value', sa.Float(), nullable=False, default=0.0,
                  comment='Learned Q-value for state-action pair'),
        sa.Column('visit_count', sa.Integer(), nullable=False, default=0,
                  comment='Number of times this state-action was visited'),
        sa.Column('last_updated', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'),
                  comment='Last time Q-value was updated'),
        sa.Column('algorithm', sa.String(50), nullable=False,
                  comment='RL algorithm (Q-Learning, SARSA, DQN, etc.)'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('state_hash', 'action_id', 'algorithm',
                           name='uq_state_action_algo'),
        comment='Q-table storing learned state-action values for all RL algorithms'
    )

    # Create indexes for Q-table
    op.create_index('idx_q_table_lookup', 'rl_q_table', ['state_hash', 'algorithm'])
    op.create_index('idx_q_table_value', 'rl_q_table', ['q_value'], postgresql_ops={'q_value': 'DESC'})
    op.create_index('idx_q_table_algorithm', 'rl_q_table', ['algorithm'])

    # Experience replay buffer
    op.create_table(
        'rl_experiences',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(64), nullable=False,
                  comment='Learning session identifier'),
        sa.Column('state_vector', postgresql.JSONB(astext_type=sa.Text()), nullable=False,
                  comment='Complete state representation'),
        sa.Column('action_vector', postgresql.JSONB(astext_type=sa.Text()), nullable=False,
                  comment='Action taken in this state'),
        sa.Column('reward', sa.Float(), nullable=False,
                  comment='Reward received after action'),
        sa.Column('next_state_vector', postgresql.JSONB(astext_type=sa.Text()), nullable=False,
                  comment='Next state after action'),
        sa.Column('done', sa.Boolean(), nullable=False, default=False,
                  comment='Whether episode terminated after this step'),
        sa.Column('algorithm', sa.String(50), nullable=False,
                  comment='RL algorithm used'),
        sa.Column('created_at', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'),
                  comment='Timestamp of experience'),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()),
                  server_default='{}', nullable=False,
                  comment='Additional metadata (episode, step, etc.)'),
        sa.PrimaryKeyConstraint('id'),
        comment='Experience replay buffer storing (s, a, r, s\') tuples for training'
    )

    # Create indexes for experiences
    op.create_index('idx_experiences_session', 'rl_experiences', ['session_id'])
    op.create_index('idx_experiences_algorithm', 'rl_experiences', ['algorithm'])
    op.create_index('idx_experiences_created', 'rl_experiences', ['created_at'],
                   postgresql_ops={'created_at': 'DESC'})
    op.create_index('idx_experiences_reward', 'rl_experiences', ['reward'],
                   postgresql_ops={'reward': 'DESC'})

    # Learning sessions
    op.create_table(
        'rl_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(64), unique=True, nullable=False,
                  comment='Unique session identifier'),
        sa.Column('campaign_id', sa.Integer(), nullable=True,
                  comment='Associated test campaign'),
        sa.Column('algorithm', sa.String(50), nullable=False,
                  comment='RL algorithm used in this session'),
        sa.Column('task_type', sa.String(50), nullable=False,
                  comment='Task type: test_selection, agent_coordination, etc.'),
        sa.Column('start_time', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'),
                  comment='Session start time'),
        sa.Column('end_time', sa.TIMESTAMP(), nullable=True,
                  comment='Session end time'),
        sa.Column('total_episodes', sa.Integer(), default=0, nullable=False,
                  comment='Total number of episodes completed'),
        sa.Column('total_reward', sa.Float(), default=0.0, nullable=False,
                  comment='Cumulative reward across all episodes'),
        sa.Column('avg_reward', sa.Float(), default=0.0, nullable=False,
                  comment='Average reward per episode'),
        sa.Column('best_reward', sa.Float(), default=-999999.0, nullable=False,
                  comment='Best reward achieved in any episode'),
        sa.Column('epsilon', sa.Float(), default=1.0, nullable=False,
                  comment='Current exploration rate (epsilon-greedy)'),
        sa.Column('learning_rate', sa.Float(), default=0.1, nullable=False,
                  comment='Learning rate (alpha)'),
        sa.Column('discount_factor', sa.Float(), default=0.95, nullable=False,
                  comment='Discount factor (gamma)'),
        sa.Column('config', postgresql.JSONB(astext_type=sa.Text()),
                  server_default='{}', nullable=False,
                  comment='Additional configuration parameters'),
        sa.Column('metrics', postgresql.JSONB(astext_type=sa.Text()),
                  server_default='{}', nullable=False,
                  comment='Learning progress metrics'),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['campaign_id'], ['test_campaigns.id'],
                               ondelete='CASCADE'),
        comment='RL learning sessions tracking training progress'
    )

    # Create indexes for sessions
    op.create_index('idx_sessions_campaign', 'rl_sessions', ['campaign_id'])
    op.create_index('idx_sessions_algorithm', 'rl_sessions', ['algorithm'])
    op.create_index('idx_sessions_task_type', 'rl_sessions', ['task_type'])
    op.create_index('idx_sessions_start_time', 'rl_sessions', ['start_time'],
                   postgresql_ops={'start_time': 'DESC'})

    # Algorithm performance metrics
    op.create_table(
        'rl_algorithm_metrics',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('algorithm', sa.String(50), nullable=False,
                  comment='RL algorithm name'),
        sa.Column('task_type', sa.String(50), nullable=False,
                  comment='Task type this metric applies to'),
        sa.Column('avg_reward', sa.Float(), nullable=False,
                  comment='Average reward across all episodes'),
        sa.Column('convergence_speed', sa.Float(), nullable=True,
                  comment='Average episodes to convergence'),
        sa.Column('stability_score', sa.Float(), nullable=True,
                  comment='Reward variance (lower is more stable)'),
        sa.Column('sample_efficiency', sa.Float(), nullable=True,
                  comment='Reward per episode (higher is more efficient)'),
        sa.Column('total_episodes', sa.Integer(), nullable=False,
                  comment='Total episodes trained'),
        sa.Column('success_rate', sa.Float(), nullable=False,
                  comment='Percentage of successful episodes'),
        sa.Column('last_updated', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'),
                  comment='Last time metrics were updated'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('algorithm', 'task_type', name='uq_algo_task'),
        comment='Performance metrics for each RL algorithm by task type'
    )

    # Create indexes for algorithm metrics
    op.create_index('idx_algorithm_performance', 'rl_algorithm_metrics',
                   ['algorithm', 'task_type'])
    op.create_index('idx_algorithm_reward', 'rl_algorithm_metrics', ['avg_reward'],
                   postgresql_ops={'avg_reward': 'DESC'})
    op.create_index('idx_algorithm_efficiency', 'rl_algorithm_metrics',
                   ['sample_efficiency'],
                   postgresql_ops={'sample_efficiency': 'DESC'})

    # Action statistics
    op.create_table(
        'rl_action_stats',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('action_id', sa.Integer(), nullable=False,
                  comment='Action identifier'),
        sa.Column('action_name', sa.String(100), nullable=False,
                  comment='Human-readable action name'),
        sa.Column('task_type', sa.String(50), nullable=False,
                  comment='Task type this action applies to'),
        sa.Column('execution_count', sa.Integer(), nullable=False, default=0,
                  comment='Number of times action was executed'),
        sa.Column('success_count', sa.Integer(), nullable=False, default=0,
                  comment='Number of successful executions'),
        sa.Column('avg_reward', sa.Float(), nullable=False, default=0.0,
                  comment='Average reward when this action is taken'),
        sa.Column('avg_execution_time', sa.Float(), nullable=True,
                  comment='Average execution time in seconds'),
        sa.Column('avg_cost', sa.Float(), nullable=True,
                  comment='Average cost in USD'),
        sa.Column('last_used', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'),
                  comment='Last time action was used'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('action_id', 'task_type', name='uq_action_task'),
        comment='Statistics for each action by task type'
    )

    # Create indexes for action stats
    op.create_index('idx_action_stats_type', 'rl_action_stats', ['task_type'])
    op.create_index('idx_action_stats_reward', 'rl_action_stats', ['avg_reward'],
                   postgresql_ops={'avg_reward': 'DESC'})
    op.create_index('idx_action_stats_success', 'rl_action_stats',
                   ['success_count'], postgresql_ops={'success_count': 'DESC'})

    # State space statistics
    op.create_table(
        'rl_state_stats',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('state_hash', sa.String(64), nullable=False,
                  comment='Hash of state vector'),
        sa.Column('task_type', sa.String(50), nullable=False,
                  comment='Task type'),
        sa.Column('visit_count', sa.Integer(), nullable=False, default=0,
                  comment='Number of times state was visited'),
        sa.Column('avg_reward', sa.Float(), nullable=False, default=0.0,
                  comment='Average reward from this state'),
        sa.Column('best_action', sa.Integer(), nullable=True,
                  comment='Best action to take in this state'),
        sa.Column('state_features', postgresql.JSONB(astext_type=sa.Text()),
                  server_default='{}', nullable=False,
                  comment='State feature summary for analysis'),
        sa.Column('last_visited', sa.TIMESTAMP(), server_default=sa.text('CURRENT_TIMESTAMP'),
                  comment='Last time state was visited'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('state_hash', 'task_type', name='uq_state_task'),
        comment='Statistics for each state by task type'
    )

    # Create indexes for state stats
    op.create_index('idx_state_stats_type', 'rl_state_stats', ['task_type'])
    op.create_index('idx_state_stats_reward', 'rl_state_stats', ['avg_reward'],
                   postgresql_ops={'avg_reward': 'DESC'})
    op.create_index('idx_state_stats_visits', 'rl_state_stats', ['visit_count'],
                   postgresql_ops={'visit_count': 'DESC'})


def downgrade():
    """Drop reinforcement learning tables."""

    # Drop indexes first
    op.drop_index('idx_state_stats_visits', table_name='rl_state_stats')
    op.drop_index('idx_state_stats_reward', table_name='rl_state_stats')
    op.drop_index('idx_state_stats_type', table_name='rl_state_stats')

    op.drop_index('idx_action_stats_success', table_name='rl_action_stats')
    op.drop_index('idx_action_stats_reward', table_name='rl_action_stats')
    op.drop_index('idx_action_stats_type', table_name='rl_action_stats')

    op.drop_index('idx_algorithm_efficiency', table_name='rl_algorithm_metrics')
    op.drop_index('idx_algorithm_reward', table_name='rl_algorithm_metrics')
    op.drop_index('idx_algorithm_performance', table_name='rl_algorithm_metrics')

    op.drop_index('idx_sessions_start_time', table_name='rl_sessions')
    op.drop_index('idx_sessions_task_type', table_name='rl_sessions')
    op.drop_index('idx_sessions_algorithm', table_name='rl_sessions')
    op.drop_index('idx_sessions_campaign', table_name='rl_sessions')

    op.drop_index('idx_experiences_reward', table_name='rl_experiences')
    op.drop_index('idx_experiences_created', table_name='rl_experiences')
    op.drop_index('idx_experiences_algorithm', table_name='rl_experiences')
    op.drop_index('idx_experiences_session', table_name='rl_experiences')

    op.drop_index('idx_q_table_algorithm', table_name='rl_q_table')
    op.drop_index('idx_q_table_value', table_name='rl_q_table')
    op.drop_index('idx_q_table_lookup', table_name='rl_q_table')

    # Drop tables
    op.drop_table('rl_state_stats')
    op.drop_table('rl_action_stats')
    op.drop_table('rl_algorithm_metrics')
    op.drop_table('rl_sessions')
    op.drop_table('rl_experiences')
    op.drop_table('rl_q_table')
