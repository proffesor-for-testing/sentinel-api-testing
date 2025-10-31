"""
Judgment Service

LLM-as-judge evaluation of task trajectories.
Uses Claude Sonnet 4.5 at temperature=0 for deterministic judgments.

Evaluates:
- Task completion success
- Output quality
- Error handling
- Overall effectiveness

Returns:
- Verdict: SUCCESS, FAILURE, or PARTIAL
- Confidence: 0.0-1.0
- Reasoning: Brief explanation
"""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import json

from anthropic import AsyncAnthropic

from ..models.task_trajectories import TaskTrajectory, TrajectoryOutcome


class JudgmentService:
    """Service for judging trajectory outcomes using LLM."""

    # Judgment prompt template
    JUDGMENT_PROMPT = """You are an expert evaluator for AI-generated test cases and API testing workflows.

Evaluate this test generation trajectory:

**Task Type:** {task_type}

**Task Description:**
{task_description}

**Context:**
{context_data}

**Actions Taken:**
{actions}

**Final Output:**
{final_output}

**Metrics:**
- Execution Time: {execution_time_ms}ms
- Test Success Rate: {test_success_rate}%
- Coverage Score: {coverage_score}%

Analyze:
1. Was the task completed successfully?
2. Were the generated tests comprehensive and correct?
3. Were there any errors or critical issues?
4. What was the quality of the output?

Provide your judgment in this exact JSON format:
{{
    "verdict": "SUCCESS" | "FAILURE" | "PARTIAL",
    "confidence": <float between 0.0 and 1.0>,
    "reasoning": "<brief explanation in 2-3 sentences>",
    "quality_score": <float between 0.0 and 1.0>,
    "key_issues": ["<issue 1>", "<issue 2>", ...]
}}

Be strict in your evaluation. Only mark as SUCCESS if the output is high-quality and fit for purpose."""

    def __init__(self, anthropic_client: Optional[AsyncAnthropic] = None, api_key: Optional[str] = None):
        """
        Initialize judgment service.

        Args:
            anthropic_client: Optional pre-configured Anthropic client
            api_key: Anthropic API key if client not provided
        """
        if anthropic_client:
            self.client = anthropic_client
        elif api_key:
            self.client = AsyncAnthropic(api_key=api_key)
        else:
            # Try to use environment variable
            self.client = AsyncAnthropic()

        self.model = "claude-sonnet-4-20250514"  # Claude Sonnet 4.5
        self.temperature = 0.0  # Deterministic judgments
        self.max_tokens = 1024

    async def judge_trajectory(
        self,
        trajectory: TaskTrajectory,
    ) -> Tuple[str, float, str, Dict[str, Any]]:
        """
        Judge a trajectory using Claude Sonnet 4.5.

        Args:
            trajectory: Trajectory to judge

        Returns:
            Tuple of (outcome, confidence, reasoning, additional_data)
        """
        # Format trajectory for judgment
        prompt = self._format_judgment_prompt(trajectory)

        try:
            # Call Claude Sonnet 4.5 for judgment
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            )

            # Extract judgment from response
            judgment_text = response.content[0].text
            judgment = self._parse_judgment(judgment_text)

            outcome = TrajectoryOutcome[judgment["verdict"].upper()]
            confidence = float(judgment["confidence"])
            reasoning = judgment["reasoning"]

            additional_data = {
                "quality_score": judgment.get("quality_score", 0.0),
                "key_issues": judgment.get("key_issues", []),
                "model_used": self.model,
                "temperature": self.temperature,
            }

            return outcome, confidence, reasoning, additional_data

        except Exception as e:
            # Fallback to UNKNOWN if judgment fails
            return (
                "UNKNOWN",
                0.0,
                f"Judgment failed: {str(e)}",
                {"error": str(e)},
            )

    def _format_judgment_prompt(self, trajectory: TaskTrajectory) -> str:
        """Format trajectory data for judgment prompt."""
        actions_str = "\n".join([
            f"{i+1}. {action.get('description', 'No description')}"
            for i, action in enumerate(trajectory.actions or [])
        ])

        context_str = json.dumps(trajectory.context_data or {}, indent=2)
        output_str = json.dumps(trajectory.final_output or {}, indent=2)

        return self.JUDGMENT_PROMPT.format(
            task_type=trajectory.task_type,
            task_description=trajectory.task_description,
            context_data=context_str,
            actions=actions_str or "No actions recorded",
            final_output=output_str,
            execution_time_ms=trajectory.execution_time_ms or "N/A",
            test_success_rate=f"{trajectory.test_success_rate * 100:.1f}" if trajectory.test_success_rate else "N/A",
            coverage_score=f"{trajectory.coverage_score * 100:.1f}" if trajectory.coverage_score else "N/A",
        )

    def _parse_judgment(self, judgment_text: str) -> Dict[str, Any]:
        """
        Parse Claude's judgment response.

        Args:
            judgment_text: Raw text from Claude

        Returns:
            Dict with verdict, confidence, reasoning, etc.
        """
        try:
            # Try to extract JSON from response
            # Claude might include explanation before/after JSON
            start_idx = judgment_text.find("{")
            end_idx = judgment_text.rfind("}") + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = judgment_text[start_idx:end_idx]
                judgment = json.loads(json_str)
            else:
                # Fallback: try to parse entire response
                judgment = json.loads(judgment_text)

            # Validate required fields
            if "verdict" not in judgment:
                raise ValueError("Missing 'verdict' field")
            if "confidence" not in judgment:
                raise ValueError("Missing 'confidence' field")
            if "reasoning" not in judgment:
                judgment["reasoning"] = "No reasoning provided"

            # Normalize verdict
            judgment["verdict"] = judgment["verdict"].upper()
            if judgment["verdict"] not in ["SUCCESS", "FAILURE", "PARTIAL"]:
                raise ValueError(f"Invalid verdict: {judgment['verdict']}")

            # Validate confidence
            confidence = float(judgment["confidence"])
            if not 0.0 <= confidence <= 1.0:
                raise ValueError(f"Invalid confidence: {confidence}")
            judgment["confidence"] = confidence

            return judgment

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # Fallback parsing using heuristics
            return self._fallback_parse(judgment_text, str(e))

    def _fallback_parse(self, text: str, error: str) -> Dict[str, Any]:
        """
        Fallback parsing if JSON extraction fails.

        Uses heuristics to extract verdict from text.
        """
        text_upper = text.upper()

        # Determine verdict based on keywords
        if "SUCCESS" in text_upper and "FAILURE" not in text_upper:
            verdict = "SUCCESS"
            confidence = 0.7
        elif "FAILURE" in text_upper or "FAILED" in text_upper or "ERROR" in text_upper:
            verdict = "FAILURE"
            confidence = 0.7
        elif "PARTIAL" in text_upper:
            verdict = "PARTIAL"
            confidence = 0.6
        else:
            verdict = "PARTIAL"
            confidence = 0.5

        return {
            "verdict": verdict,
            "confidence": confidence,
            "reasoning": f"Fallback parsing due to: {error}. Original response: {text[:200]}",
            "quality_score": 0.5,
            "key_issues": [f"Judgment parsing error: {error}"],
        }

    async def batch_judge_trajectories(
        self,
        trajectories: list[TaskTrajectory],
    ) -> list[Tuple[TaskTrajectory, str, float, str, Dict[str, Any]]]:
        """
        Judge multiple trajectories in batch.

        Args:
            trajectories: List of trajectories to judge

        Returns:
            List of tuples: (trajectory, outcome, confidence, reasoning, additional_data)
        """
        results = []

        for trajectory in trajectories:
            outcome, confidence, reasoning, additional_data = await self.judge_trajectory(trajectory)
            results.append((trajectory, outcome, confidence, reasoning, additional_data))

        return results

    def get_judgment_summary(self, judgments: list[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics from judgments.

        Args:
            judgments: List of judgment dictionaries

        Returns:
            Dict with summary statistics
        """
        if not judgments:
            return {
                "total": 0,
                "success_count": 0,
                "failure_count": 0,
                "partial_count": 0,
                "avg_confidence": 0.0,
                "avg_quality": 0.0,
            }

        total = len(judgments)
        success_count = sum(1 for j in judgments if j["verdict"] == "SUCCESS")
        failure_count = sum(1 for j in judgments if j["verdict"] == "FAILURE")
        partial_count = sum(1 for j in judgments if j["verdict"] == "PARTIAL")

        avg_confidence = sum(j["confidence"] for j in judgments) / total
        avg_quality = sum(j.get("quality_score", 0.0) for j in judgments) / total

        return {
            "total": total,
            "success_count": success_count,
            "failure_count": failure_count,
            "partial_count": partial_count,
            "success_rate": success_count / total,
            "avg_confidence": avg_confidence,
            "avg_quality": avg_quality,
        }
