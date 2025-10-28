"""
Pattern Embeddings Model

Stores vector representations of learned patterns for semantic retrieval.
Integrates with PostgreSQL pgvector for efficient similarity search.
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Index, JSON
from sqlalchemy.orm import declarative_base
from pgvector.sqlalchemy import Vector

Base = declarative_base()


class PatternEmbedding(Base):
    """
    Vector representations of learned patterns for semantic retrieval.

    Scoring Formula:
    score = α·similarity + β·recency + γ·reliability - δ·diversity

    Default Weights:
    - α (similarity): 0.65
    - β (recency): 0.15
    - γ (reliability): 0.20
    - δ (diversity): 0.10
    """

    __tablename__ = "pattern_embeddings"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Pattern identification
    pattern_id = Column(String(100), nullable=False, unique=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)

    # Procedural content (3-8 numbered steps)
    content = Column(Text, nullable=False)

    # Vector embedding (1536 dimensions for text-embedding-3-large)
    embedding = Column(Vector(1536), nullable=False)

    # Confidence and reliability
    confidence = Column(Float, default=0.75, nullable=False)  # 0.0-1.0
    usage_count = Column(Integer, default=0, nullable=False)
    success_count = Column(Integer, default=0, nullable=False)
    failure_count = Column(Integer, default=0, nullable=False)

    # Metadata
    domain_tags = Column(JSON, nullable=True)  # ["api_testing", "security", etc.]
    source_trajectory_id = Column(String(100), nullable=True)

    # Temporal tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    # Tenant scoping
    tenant_id = Column(String(100), nullable=True, index=True)

    # Indexes for performance
    __table_args__ = (
        Index("idx_pattern_confidence", "confidence"),
        Index("idx_pattern_usage", "usage_count"),
        Index("idx_pattern_created", "created_at"),
        Index("idx_pattern_domain", "domain_tags", postgresql_using="gin"),
    )

    @property
    def reliability_score(self) -> float:
        """
        Calculate reliability based on success/failure ratio.
        Uses sigmoid function to prevent extreme values.

        Returns:
            float: Reliability score between 0 and 1
        """
        total = self.success_count + self.failure_count
        if total == 0:
            return self.confidence

        success_rate = self.success_count / total
        # Sigmoid function: sigmoid(log(1 + usage_count))
        usage_boost = 1 / (1 + 2.718 ** (-1 * (1 + self.usage_count)))

        return min(1.0, success_rate * 0.7 + usage_boost * 0.3)

    @property
    def recency_score(self) -> float:
        """
        Calculate recency score based on last usage time.
        Exponential decay with 90-day half-life.

        Returns:
            float: Recency score between 0 and 1
        """
        if not self.last_used_at:
            # Use creation date if never used
            days_old = (datetime.utcnow() - self.created_at).days
        else:
            days_old = (datetime.utcnow() - self.last_used_at).days

        # Exponential decay: e^(-days/half_life)
        half_life = 90
        return 2.718 ** (-days_old / half_life)

    def update_confidence(self, success: bool, learning_rate: float = 0.05) -> None:
        """
        Update confidence based on usage outcome.

        Update Rule:
        confidence ← clamp(confidence + η·success_delta, 0, 1)

        Args:
            success: Whether the pattern was used successfully
            learning_rate: Learning rate (η), default 0.05
        """
        success_delta = 1.0 if success else -1.0
        new_confidence = self.confidence + learning_rate * success_delta
        self.confidence = max(0.0, min(1.0, new_confidence))

        # Update counts
        self.usage_count += 1
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1

        self.last_used_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "pattern_id": self.pattern_id,
            "title": self.title,
            "description": self.description,
            "content": self.content,
            "confidence": self.confidence,
            "reliability_score": self.reliability_score,
            "recency_score": self.recency_score,
            "usage_count": self.usage_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "domain_tags": self.domain_tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
        }

    def to_prompt_format(self) -> str:
        """
        Format pattern for system prompt injection.

        Returns:
            str: Formatted pattern with title and steps
        """
        return f"[{self.title}]\n{self.content}"

    def __repr__(self) -> str:
        return (
            f"<PatternEmbedding(id={self.id}, pattern_id='{self.pattern_id}', "
            f"title='{self.title}', confidence={self.confidence:.2f}, "
            f"usage_count={self.usage_count})>"
        )
