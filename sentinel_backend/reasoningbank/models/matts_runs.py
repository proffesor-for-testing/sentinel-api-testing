"""
MaTTS Runs Model

Memory-aware Test-Time Scaling bookkeeping.
Tracks parallel and sequential exploration modes.

MaTTS converts inference compute into persistent memory capital
by running multiple variations and distilling unified learnings.
"""

from datetime import datetime
from enum import Enum
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Index, JSON, Enum as SQLEnum
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class MattsMode(str, Enum):
    """MaTTS execution modes."""
    PARALLEL = "parallel"  # Launch k independent rollouts with diversity seeds
    SEQUENTIAL = "sequential"  # Iterative refinement across r iterations


class MattsRun(Base):
    """
    Test-time scaling bookkeeping for MaTTS experiments.

    Parallel Mode (k=6):
    1. Launch 6 independent test generation attempts with diversity
    2. Judge each trajectory independently
    3. Self-contrast aggregation to identify common patterns
    4. Extract higher-quality unified memories

    Sequential Mode (r=3):
    1. Iterative refinement across 3 rounds
    2. Collect intermediate signals at each step
    3. Single consolidated memory extraction from all iterations
    """

    __tablename__ = "matts_runs"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Run identification
    run_id = Column(String(100), nullable=False, unique=True, index=True)
    mode = Column(SQLEnum(MattsMode), nullable=False, index=True)

    # Task context
    task_type = Column(String(50), nullable=False)
    task_description = Column(Text, nullable=False)
    base_trajectory_id = Column(String(100), nullable=True)  # Original trajectory that triggered MaTTS

    # Parallel mode (k rollouts)
    parallel_k = Column(Integer, default=6, nullable=True)
    trajectory_ids = Column(JSON, nullable=True)  # List of k trajectory IDs
    diversity_seeds = Column(JSON, nullable=True)  # Seeds used for each rollout

    # Sequential mode (r iterations)
    sequential_r = Column(Integer, default=3, nullable=True)
    iteration_trajectory_ids = Column(JSON, nullable=True)  # List of r trajectory IDs

    # Results
    success_count = Column(Integer, default=0, nullable=False)
    failure_count = Column(Integer, default=0, nullable=False)

    # Pattern extraction
    extracted_pattern_ids = Column(JSON, nullable=True)  # Unified patterns from all trajectories
    aggregation_method = Column(String(50), nullable=True)  # "self_contrast", "majority_vote", etc.

    # Metrics
    total_execution_time_ms = Column(Integer, nullable=True)
    total_token_count = Column(Integer, nullable=True)
    improvement_over_baseline = Column(Float, nullable=True)  # % improvement

    # Status
    is_completed = Column(Integer, default=0, nullable=False)  # Boolean: 0=False, 1=True

    # Temporal tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Tenant scoping
    tenant_id = Column(String(100), nullable=True, index=True)

    # Indexes for performance
    __table_args__ = (
        Index("idx_matts_mode", "mode"),
        Index("idx_matts_completed", "is_completed"),
        Index("idx_matts_created", "created_at"),
    )

    @property
    def success_rate(self) -> float:
        """Calculate success rate across all trajectories."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

    @property
    def rollout_count(self) -> int:
        """Get number of rollouts/iterations."""
        if self.mode == MattsMode.PARALLEL:
            return self.parallel_k or 0
        else:
            return self.sequential_r or 0

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "run_id": self.run_id,
            "mode": self.mode.value,
            "task_type": self.task_type,
            "task_description": self.task_description,
            "base_trajectory_id": self.base_trajectory_id,
            "parallel_k": self.parallel_k,
            "sequential_r": self.sequential_r,
            "trajectory_ids": self.trajectory_ids,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_rate,
            "extracted_pattern_ids": self.extracted_pattern_ids,
            "aggregation_method": self.aggregation_method,
            "total_execution_time_ms": self.total_execution_time_ms,
            "total_token_count": self.total_token_count,
            "improvement_over_baseline": self.improvement_over_baseline,
            "is_completed": bool(self.is_completed),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<MattsRun(id={self.id}, "
            f"run_id='{self.run_id}', "
            f"mode='{self.mode.value}', "
            f"rollouts={self.rollout_count}, "
            f"success_rate={self.success_rate:.2f})>"
        )
