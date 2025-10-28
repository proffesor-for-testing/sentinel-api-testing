"""
ReasoningBank: Self-Improving Memory System for Sentinel

Implements closed-loop learning from test execution trajectories.
Learns from both successes and failures to continuously improve test generation.

Architecture:
- Trajectory tracking: Capture complete test generation processes
- Verdict judgment: LLM-based success/failure analysis
- Pattern distillation: Extract reusable strategic principles
- Semantic retrieval: Vector-based similarity search with MMR
- Memory consolidation: Deduplication, contradiction detection, aging
- Confidence dynamics: Usage-based reinforcement learning

Based on: https://gist.github.com/ruvnet/0670d2070a4a75bb70949d7d55d26cd1
"""

__version__ = "1.0.0"
__author__ = "Sentinel Team"

from .services.trajectory_service import TrajectoryService
from .services.judgment_service import JudgmentService
from .services.retrieval_service import RetrievalService
from .services.distillation_service import DistillationService
from .services.consolidation_service import ConsolidationService
from .services.reasoningbank_service import ReasoningBankService

__all__ = [
    "TrajectoryService",
    "JudgmentService",
    "RetrievalService",
    "DistillationService",
    "ConsolidationService",
    "ReasoningBankService",
]
