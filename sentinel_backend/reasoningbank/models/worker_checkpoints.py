"""
Worker Checkpoints Model

Tracks background worker progress for graceful shutdown and resumability.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Index
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class WorkerCheckpoint(Base):
    """
    Checkpoint for background worker progress.

    Enables:
    - Graceful shutdown (workers save state before stopping)
    - Resumable work (interrupted tasks can be resumed)
    - Progress tracking (monitor worker activity)
    - Debugging (see what workers were doing)
    """

    __tablename__ = "worker_checkpoints"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Checkpoint identification
    task_id = Column(String(255), nullable=False, index=True)
    worker_name = Column(String(100), nullable=False, index=True)

    # Checkpoint data
    checkpoint_data = Column(JSON, nullable=False)

    # Status
    completed_at = Column(DateTime, nullable=True)

    # Temporal tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Indexes for performance
    __table_args__ = (
        Index("idx_checkpoint_task_worker", "task_id", "worker_name"),
        Index("idx_checkpoint_created", "created_at"),
        Index("idx_checkpoint_incomplete", "completed_at"),
    )

    @property
    def is_complete(self) -> bool:
        """Check if checkpoint is complete."""
        return self.completed_at is not None

    @property
    def can_resume(self) -> bool:
        """Check if checkpoint can be resumed."""
        return not self.is_complete and self.checkpoint_data.get("can_resume", True)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "task_id": self.task_id,
            "worker_name": self.worker_name,
            "checkpoint_data": self.checkpoint_data,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        status = "complete" if self.is_complete else "incomplete"
        return (
            f"<WorkerCheckpoint(id={self.id}, "
            f"task_id='{self.task_id}', "
            f"worker='{self.worker_name}', "
            f"status='{status}')>"
        )
