"""
Task Trajectories Model

Archives complete execution paths for learning:
- Input: Task description and context
- Actions: Step-by-step execution trace
- Outcome: Success/failure with confidence
- Extracted patterns: Distilled learnings
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Literal
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Index, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Outcome type as Literal for type hints
TrajectoryOutcome = Literal["SUCCESS", "PARTIAL_SUCCESS", "FAILURE", "ERROR", "UNKNOWN"]


class TaskTrajectory(Base):
    """
    Complete execution path for learning from experience.

    Captures:
    - Input: Task description, context, API spec
    - Process: Step-by-step actions taken
    - Output: Test cases generated, errors encountered
    - Judgment: Success/failure verdict with reasoning
    - Learnings: Extracted patterns for future use
    """

    __tablename__ = "task_trajectories"

    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)

    # Trajectory identification
    trajectory_id = Column(String(100), nullable=False, unique=True, index=True)
    task_type = Column(String(50), nullable=False, index=True)  # "test_generation", "security_scan", etc.

    # Input
    task_description = Column(Text, nullable=False)
    context_data = Column(JSON, nullable=True)  # API spec, requirements, constraints
    agent_type = Column(String(50), nullable=True)  # Which agent executed this

    # Process trace
    actions = Column(JSON, nullable=False)  # List of steps taken
    intermediate_outputs = Column(JSON, nullable=True)  # Intermediate results

    # Output
    final_output = Column(JSON, nullable=False)  # Final result (test cases, etc.)
    execution_time_ms = Column(Integer, nullable=True)
    token_count = Column(Integer, nullable=True)

    # Judgment (LLM-as-judge)
    outcome = Column(String(20), default='UNKNOWN', nullable=False, index=True)
    outcome_confidence = Column(Float, default=0.0, nullable=False)  # 0.0-1.0
    judgment_reasoning = Column(Text, nullable=True)

    # Extracted patterns
    extracted_pattern_ids = Column(JSON, nullable=True)  # List of pattern IDs learned from this trajectory
    distillation_performed = Column(Integer, default=0, nullable=False)  # Boolean: 0=False, 1=True

    # Metrics
    test_success_rate = Column(Float, nullable=True)  # For test generation tasks
    coverage_score = Column(Float, nullable=True)  # Code coverage achieved

    # Temporal tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    judged_at = Column(DateTime, nullable=True)
    distilled_at = Column(DateTime, nullable=True)

    # Tenant scoping
    tenant_id = Column(String(100), nullable=True, index=True)

    # Indexes for performance
    __table_args__ = (
        Index("idx_trajectory_task_type", "task_type"),
        Index("idx_trajectory_outcome", "outcome"),
        Index("idx_trajectory_created", "created_at"),
        Index("idx_trajectory_distilled", "distillation_performed"),
    )

    @property
    def is_success(self) -> bool:
        """Check if trajectory was successful."""
        outcome_upper = str(self.outcome).upper() if self.outcome else ""
        return outcome_upper == "SUCCESS"

    @property
    def is_failure(self) -> bool:
        """Check if trajectory was a failure."""
        outcome_upper = str(self.outcome).upper() if self.outcome else ""
        return outcome_upper == "FAILURE"

    @property
    def needs_judgment(self) -> bool:
        """Check if trajectory needs to be judged."""
        outcome_upper = str(self.outcome).upper() if self.outcome else ""
        return outcome_upper == "UNKNOWN"

    @property
    def needs_distillation(self) -> bool:
        """Check if trajectory needs pattern distillation."""
        outcome_upper = str(self.outcome).upper() if self.outcome else ""
        return not self.distillation_performed and outcome_upper not in ("UNKNOWN", "")

    def to_dict(self) -> dict:
        """Convert to dictionary for API responses."""
        outcome_str = str(self.outcome).upper() if self.outcome else "UNKNOWN"

        return {
            "id": self.id,
            "trajectory_id": self.trajectory_id,
            "task_type": self.task_type,
            "task_description": self.task_description,
            "context_data": self.context_data,
            "agent_type": self.agent_type,
            "actions": self.actions,
            "final_output": self.final_output,
            "outcome": outcome_str,
            "outcome_confidence": self.outcome_confidence,
            "judgment_reasoning": self.judgment_reasoning,
            "extracted_pattern_ids": self.extracted_pattern_ids,
            "distillation_performed": bool(self.distillation_performed),
            "execution_time_ms": self.execution_time_ms,
            "token_count": self.token_count,
            "test_success_rate": self.test_success_rate,
            "coverage_score": self.coverage_score,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "judged_at": self.judged_at.isoformat() if self.judged_at else None,
            "distilled_at": self.distilled_at.isoformat() if self.distilled_at else None,
        }

    def to_judgment_prompt(self) -> str:
        """
        Format trajectory for LLM judgment.

        Returns:
            str: Formatted prompt for Claude Sonnet 4.5
        """
        actions_str = "\n".join([f"  {i+1}. {action}" for i, action in enumerate(self.actions)])

        return f"""
Evaluate this test generation trajectory:

Task: {self.task_description}

Actions Taken:
{actions_str}

Final Output:
{self.final_output}

Analyze:
1. Was the task completed successfully?
2. Were the generated tests comprehensive and correct?
3. Were there any errors or issues?
4. What was the quality of the output?

Provide:
- Verdict: SUCCESS, FAILURE, or PARTIAL
- Confidence: 0.0-1.0
- Reasoning: Brief explanation (2-3 sentences)
"""

    def __repr__(self) -> str:
        return (
            f"<TaskTrajectory(id={self.id}, "
            f"trajectory_id='{self.trajectory_id}', "
            f"task_type='{self.task_type}', "
            f"outcome='{self.outcome}', "
            f"confidence={self.outcome_confidence:.2f})>"
        )
