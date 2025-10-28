"""
Pattern Links Model

Tracks relationships between patterns for memory quality control:
- Deduplication (similar patterns)
- Contradictions (conflicting guidance)
- Refinements (improved versions)
"""

from datetime import datetime
from enum import Enum
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Index, Enum as SQLEnum
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class LinkType(str, Enum):
    """Types of relationships between patterns."""
    DUPLICATE = "duplicate"  # Near-identical patterns (similarity >= 0.87)
    CONTRADICTION = "contradiction"  # Conflicting guidance (NLI score >= 0.60)
    REFINEMENT = "refinement"  # Improved version of pattern
    RELATED = "related"  # Semantically related patterns
    SUPERSEDES = "supersedes"  # New pattern replaces old one


class PatternLink(Base):
    """
    Relationships between patterns for memory quality control.

    Supports:
    - Deduplication: Detect near-identical patterns (cosine similarity >= 0.87)
    - Contradiction: Detect conflicting guidance (NLI-based, threshold >= 0.60)
    - Refinement: Track pattern evolution over time
    """

    __tablename__ = "pattern_links"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Pattern relationships
    source_pattern_id = Column(String(100), nullable=False, index=True)
    target_pattern_id = Column(String(100), nullable=False, index=True)

    # Link type and strength
    link_type = Column(SQLEnum(LinkType), nullable=False, index=True)
    similarity_score = Column(Float, nullable=False)  # 0.0-1.0

    # Consolidation metadata
    is_resolved = Column(Integer, default=0, nullable=False)  # Boolean: 0=False, 1=True
    resolution_action = Column(String(50), nullable=True)  # "merge", "quarantine", "keep_both"

    # Temporal tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)

    # Tenant scoping
    tenant_id = Column(String(100), nullable=True, index=True)

    # Indexes for performance
    __table_args__ = (
        Index("idx_link_source_target", "source_pattern_id", "target_pattern_id"),
        Index("idx_link_type_resolved", "link_type", "is_resolved"),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "source_pattern_id": self.source_pattern_id,
            "target_pattern_id": self.target_pattern_id,
            "link_type": self.link_type.value,
            "similarity_score": self.similarity_score,
            "is_resolved": bool(self.is_resolved),
            "resolution_action": self.resolution_action,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<PatternLink(id={self.id}, "
            f"source='{self.source_pattern_id}', "
            f"target='{self.target_pattern_id}', "
            f"type='{self.link_type.value}', "
            f"similarity={self.similarity_score:.2f})>"
        )
