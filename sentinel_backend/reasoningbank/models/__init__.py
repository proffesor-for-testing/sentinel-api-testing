"""
ReasoningBank Database Models

Implements the 4 core tables for ReasoningBank:
1. pattern_embeddings - Vector representations for semantic retrieval
2. pattern_links - Relationships between memories (deduplication, contradictions)
3. task_trajectories - Complete execution paths with labels
4. matts_runs - Test-time scaling bookkeeping
"""

from .pattern_embeddings import PatternEmbedding
from .pattern_links import PatternLink, LinkType
from .task_trajectories import TaskTrajectory, TrajectoryOutcome
from .matts_runs import MattsRun, MattsMode

__all__ = [
    "PatternEmbedding",
    "PatternLink",
    "LinkType",
    "TaskTrajectory",
    "TrajectoryOutcome",
    "MattsRun",
    "MattsMode",
]
