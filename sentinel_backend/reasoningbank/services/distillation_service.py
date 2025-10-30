"""
Distillation Service

Extracts reusable strategic patterns from successful trajectories.
Uses Claude Sonnet 4.5 for intelligent pattern extraction with structured output.

Core Capabilities:
- Pattern extraction from successful trajectories
- LLM-based principle identification
- Vector embedding generation
- Pattern storage with semantic indexing
- Batch distillation for efficiency

Pattern Quality Requirements:
- 3-8 numbered procedural steps
- Clear, actionable guidance
- Domain-specific expertise
- Success-validated principles
"""

from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from uuid import uuid4
import json
import logging

from anthropic import AsyncAnthropic
from openai import AsyncOpenAI
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..models.task_trajectories import TaskTrajectory, TrajectoryOutcome
from ..models.pattern_embeddings import PatternEmbedding
from .trajectory_service import TrajectoryService

logger = logging.getLogger(__name__)


class DistillationService:
    """Service for extracting reusable patterns from trajectories."""

    # Pattern extraction prompt template
    DISTILLATION_PROMPT = """You are an expert AI system that learns from experience by extracting reusable strategic patterns.

Analyze this successful test generation trajectory and extract key strategic principles:

**Task Type:** {task_type}

**Task Description:**
{task_description}

**Context:**
{context_data}

**Actions Taken (Step-by-Step):**
{actions}

**Final Output:**
{final_output}

**Metrics:**
- Execution Time: {execution_time_ms}ms
- Test Success Rate: {test_success_rate}%
- Coverage Score: {coverage_score}%

**Judgment:**
- Outcome: {outcome}
- Confidence: {confidence}
- Reasoning: {reasoning}

Extract strategic patterns that made this trajectory successful. Focus on:
1. Key decision points and reasoning
2. Effective techniques or approaches
3. Domain-specific best practices
4. Reusable problem-solving strategies

Provide your analysis in this exact JSON format:
{{
    "patterns": [
        {{
            "title": "<clear, concise pattern name>",
            "description": "<1-2 sentence summary>",
            "content": "<3-8 numbered procedural steps>",
            "domain_tags": ["<tag1>", "<tag2>", ...],
            "confidence": <float 0.0-1.0>,
            "applicability": "<when to use this pattern>"
        }}
    ],
    "key_insights": ["<insight 1>", "<insight 2>", ...],
    "risk_factors": ["<risk 1>", "<risk 2>", ...]
}}

Requirements:
- Extract 1-3 high-quality patterns
- Each pattern must have 3-8 clear, actionable steps
- Steps should be numbered and procedural
- Focus on generalizable principles, not task-specific details
- Include relevant domain tags (e.g., "api_testing", "security", "performance")
- Confidence should reflect how broadly applicable the pattern is
"""

    def __init__(
        self,
        db_session: AsyncSession,
        anthropic_client: Optional[AsyncAnthropic] = None,
        openai_client: Optional[AsyncOpenAI] = None,
        anthropic_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
    ):
        """
        Initialize distillation service.

        Args:
            db_session: AsyncSession for database operations
            anthropic_client: Optional pre-configured Anthropic client
            openai_client: Optional pre-configured OpenAI client
            anthropic_api_key: Anthropic API key if client not provided
            openai_api_key: OpenAI API key if client not provided
        """
        self.db = db_session
        self.trajectory_service = TrajectoryService(db_session)

        # Initialize Anthropic client for pattern extraction
        if anthropic_client:
            self.anthropic_client = anthropic_client
        elif anthropic_api_key:
            self.anthropic_client = AsyncAnthropic(api_key=anthropic_api_key)
        else:
            # Try to use environment variable
            self.anthropic_client = AsyncAnthropic()

        # Initialize OpenAI client for embeddings
        if openai_client:
            self.openai_client = openai_client
        elif openai_api_key:
            self.openai_client = AsyncOpenAI(api_key=openai_api_key)
        else:
            # Try to use environment variable
            self.openai_client = AsyncOpenAI()

        self.model = "claude-sonnet-4-20250514"  # Claude Sonnet 4.5
        self.temperature = 0.0  # Deterministic extraction
        self.max_tokens = 4096
        self.embedding_model = "text-embedding-3-large"
        self.embedding_dimensions = 1536

    async def distill_pattern(
        self,
        trajectory: TaskTrajectory,
    ) -> List[PatternEmbedding]:
        """
        Extract reusable patterns from a single trajectory.

        Args:
            trajectory: Trajectory to distill patterns from

        Returns:
            List[PatternEmbedding]: List of extracted patterns with embeddings

        Raises:
            ValueError: If trajectory is not ready for distillation
        """
        # Validate trajectory is ready for distillation
        if trajectory.outcome == TrajectoryOutcome.UNKNOWN:
            raise ValueError(f"Trajectory {trajectory.trajectory_id} has not been judged yet")

        if trajectory.distillation_performed:
            logger.warning(
                f"Trajectory {trajectory.trajectory_id} has already been distilled"
            )
            return []

        # Only distill from successful trajectories (or high-confidence partial)
        if trajectory.outcome == TrajectoryOutcome.FAILURE:
            logger.info(
                f"Skipping distillation for failed trajectory {trajectory.trajectory_id}"
            )
            await self.trajectory_service.mark_distilled(trajectory.trajectory_id, [])
            return []

        if (
            trajectory.outcome == TrajectoryOutcome.PARTIAL
            and trajectory.outcome_confidence < 0.7
        ):
            logger.info(
                f"Skipping distillation for low-confidence partial trajectory {trajectory.trajectory_id}"
            )
            await self.trajectory_service.mark_distilled(trajectory.trajectory_id, [])
            return []

        try:
            # Extract patterns using Claude
            patterns_data = await self.extract_principles(trajectory)

            if not patterns_data or not patterns_data.get("patterns"):
                logger.warning(
                    f"No patterns extracted from trajectory {trajectory.trajectory_id}"
                )
                await self.trajectory_service.mark_distilled(trajectory.trajectory_id, [])
                return []

            # Create pattern embeddings
            pattern_embeddings = []
            pattern_ids = []

            for pattern_dict in patterns_data["patterns"]:
                try:
                    # Generate embedding for semantic search
                    embedding = await self.generate_embedding(
                        f"{pattern_dict['title']}\n{pattern_dict['description']}\n{pattern_dict['content']}"
                    )

                    # Create pattern embedding object
                    pattern_id = f"pat_{uuid4().hex[:16]}"
                    pattern = PatternEmbedding(
                        pattern_id=pattern_id,
                        title=pattern_dict["title"],
                        description=pattern_dict["description"],
                        content=pattern_dict["content"],
                        embedding=embedding,
                        confidence=float(pattern_dict.get("confidence", 0.75)),
                        domain_tags=pattern_dict.get("domain_tags", []),
                        source_trajectory_id=trajectory.trajectory_id,
                        tenant_id=trajectory.tenant_id,
                    )

                    self.db.add(pattern)
                    pattern_embeddings.append(pattern)
                    pattern_ids.append(pattern_id)

                    logger.info(
                        f"Created pattern {pattern_id} from trajectory {trajectory.trajectory_id}"
                    )

                except Exception as e:
                    logger.error(
                        f"Failed to create pattern from trajectory {trajectory.trajectory_id}: {e}"
                    )
                    continue

            # Commit patterns to database
            await self.db.commit()

            # Refresh pattern objects
            for pattern in pattern_embeddings:
                await self.db.refresh(pattern)

            # Mark trajectory as distilled
            await self.trajectory_service.mark_distilled(
                trajectory.trajectory_id, pattern_ids
            )

            logger.info(
                f"Distilled {len(pattern_embeddings)} patterns from trajectory {trajectory.trajectory_id}"
            )

            return pattern_embeddings

        except Exception as e:
            logger.error(
                f"Distillation failed for trajectory {trajectory.trajectory_id}: {e}",
                exc_info=True,
            )
            # Mark as distilled even if failed to avoid retry loops
            await self.trajectory_service.mark_distilled(trajectory.trajectory_id, [])
            raise

    async def extract_principles(
        self,
        trajectory: TaskTrajectory,
    ) -> Dict[str, Any]:
        """
        Use LLM to extract strategic principles from trajectory.

        Args:
            trajectory: Trajectory to analyze

        Returns:
            Dict with extracted patterns, insights, and risk factors
        """
        # Format trajectory for distillation prompt
        prompt = self._format_distillation_prompt(trajectory)

        try:
            # Call Claude Sonnet 4.5 for pattern extraction
            response = await self.anthropic_client.messages.create(
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

            # Extract patterns from response
            extraction_text = response.content[0].text
            patterns_data = self._parse_patterns(extraction_text)

            return patterns_data

        except Exception as e:
            logger.error(
                f"Pattern extraction failed for trajectory {trajectory.trajectory_id}: {e}",
                exc_info=True,
            )
            return {
                "patterns": [],
                "key_insights": [],
                "risk_factors": [f"Extraction failed: {str(e)}"],
            }

    async def generate_embedding(
        self,
        text: str,
    ) -> List[float]:
        """
        Generate vector embedding for semantic search.

        Uses OpenAI text-embedding-3-large model (1536 dimensions).

        Args:
            text: Text to embed

        Returns:
            List[float]: 1536-dimensional embedding vector
        """
        try:
            response = await self.openai_client.embeddings.create(
                model=self.embedding_model,
                input=text,
                dimensions=self.embedding_dimensions,
            )

            embedding = response.data[0].embedding
            return embedding

        except Exception as e:
            logger.error(f"Embedding generation failed: {e}", exc_info=True)
            # Return zero vector as fallback
            return [0.0] * self.embedding_dimensions

    async def batch_distill_trajectories(
        self,
        trajectories: List[TaskTrajectory],
    ) -> List[Tuple[TaskTrajectory, List[PatternEmbedding]]]:
        """
        Distill patterns from multiple trajectories in batch.

        Args:
            trajectories: List of trajectories to process

        Returns:
            List of tuples: (trajectory, extracted_patterns)
        """
        results = []

        for trajectory in trajectories:
            try:
                patterns = await self.distill_pattern(trajectory)
                results.append((trajectory, patterns))
            except Exception as e:
                logger.error(
                    f"Batch distillation failed for trajectory {trajectory.trajectory_id}: {e}"
                )
                results.append((trajectory, []))

        return results

    async def distill_undistilled_trajectories(
        self,
        task_type: Optional[str] = None,
        limit: int = 10,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Automatically distill patterns from undistilled trajectories.

        Args:
            task_type: Filter by task type
            limit: Maximum number of trajectories to process
            tenant_id: Filter by tenant

        Returns:
            Dict with distillation summary
        """
        # Get undistilled trajectories
        trajectories = await self.trajectory_service.get_undistilled_trajectories(
            task_type=task_type,
            limit=limit,
            tenant_id=tenant_id,
        )

        if not trajectories:
            return {
                "trajectories_processed": 0,
                "patterns_extracted": 0,
                "success_count": 0,
                "failure_count": 0,
            }

        # Batch distill
        results = await self.batch_distill_trajectories(trajectories)

        # Calculate summary
        success_count = sum(1 for _, patterns in results if patterns)
        failure_count = len(results) - success_count
        total_patterns = sum(len(patterns) for _, patterns in results)

        summary = {
            "trajectories_processed": len(trajectories),
            "patterns_extracted": total_patterns,
            "success_count": success_count,
            "failure_count": failure_count,
            "avg_patterns_per_trajectory": total_patterns / len(trajectories)
            if trajectories
            else 0.0,
        }

        logger.info(f"Distillation summary: {summary}")

        return summary

    async def get_pattern_by_id(
        self,
        pattern_id: str,
    ) -> Optional[PatternEmbedding]:
        """
        Retrieve pattern by ID.

        Args:
            pattern_id: Pattern identifier

        Returns:
            Optional[PatternEmbedding]: Pattern if found
        """
        result = await self.db.execute(
            select(PatternEmbedding).where(PatternEmbedding.pattern_id == pattern_id)
        )
        return result.scalar_one_or_none()

    async def get_patterns_by_domain(
        self,
        domain_tag: str,
        limit: int = 10,
        tenant_id: Optional[str] = None,
    ) -> List[PatternEmbedding]:
        """
        Get patterns filtered by domain tag.

        Args:
            domain_tag: Domain tag to filter by
            limit: Maximum number of patterns to return
            tenant_id: Filter by tenant

        Returns:
            List[PatternEmbedding]: List of patterns
        """
        query = select(PatternEmbedding).where(
            PatternEmbedding.domain_tags.contains([domain_tag])
        )

        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        query = query.order_by(PatternEmbedding.confidence.desc()).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    def _format_distillation_prompt(self, trajectory: TaskTrajectory) -> str:
        """Format trajectory data for distillation prompt."""
        actions_str = "\n".join(
            [
                f"{i+1}. {action.get('description', 'No description')}"
                for i, action in enumerate(trajectory.actions or [])
            ]
        )

        context_str = json.dumps(trajectory.context_data or {}, indent=2)
        output_str = json.dumps(trajectory.final_output or {}, indent=2)

        return self.DISTILLATION_PROMPT.format(
            task_type=trajectory.task_type,
            task_description=trajectory.task_description,
            context_data=context_str,
            actions=actions_str or "No actions recorded",
            final_output=output_str,
            execution_time_ms=trajectory.execution_time_ms or "N/A",
            test_success_rate=f"{trajectory.test_success_rate * 100:.1f}"
            if trajectory.test_success_rate
            else "N/A",
            coverage_score=f"{trajectory.coverage_score * 100:.1f}"
            if trajectory.coverage_score
            else "N/A",
            outcome=trajectory.outcome.value if trajectory.outcome else "UNKNOWN",
            confidence=f"{trajectory.outcome_confidence:.2f}"
            if trajectory.outcome_confidence
            else "N/A",
            reasoning=trajectory.judgment_reasoning or "No reasoning provided",
        )

    def _parse_patterns(self, extraction_text: str) -> Dict[str, Any]:
        """
        Parse Claude's pattern extraction response.

        Args:
            extraction_text: Raw text from Claude

        Returns:
            Dict with patterns, insights, and risk factors
        """
        try:
            # Try to extract JSON from response
            start_idx = extraction_text.find("{")
            end_idx = extraction_text.rfind("}") + 1

            if start_idx >= 0 and end_idx > start_idx:
                json_str = extraction_text[start_idx:end_idx]
                patterns_data = json.loads(json_str)
            else:
                # Fallback: try to parse entire response
                patterns_data = json.loads(extraction_text)

            # Validate structure
            if "patterns" not in patterns_data:
                patterns_data["patterns"] = []

            # Validate each pattern
            valid_patterns = []
            for pattern in patterns_data.get("patterns", []):
                if self._validate_pattern(pattern):
                    valid_patterns.append(pattern)
                else:
                    logger.warning(f"Invalid pattern skipped: {pattern.get('title', 'Unknown')}")

            patterns_data["patterns"] = valid_patterns

            # Ensure required fields
            patterns_data.setdefault("key_insights", [])
            patterns_data.setdefault("risk_factors", [])

            return patterns_data

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.error(f"Pattern parsing failed: {e}")
            return {
                "patterns": [],
                "key_insights": [],
                "risk_factors": [f"Parsing error: {str(e)}"],
            }

    def _validate_pattern(self, pattern: Dict[str, Any]) -> bool:
        """
        Validate pattern structure and quality.

        Args:
            pattern: Pattern dictionary

        Returns:
            bool: True if valid
        """
        required_fields = ["title", "description", "content"]

        # Check required fields
        for field in required_fields:
            if field not in pattern or not pattern[field]:
                return False

        # Validate content has procedural steps (3-8 numbered steps)
        content = pattern["content"]
        if not isinstance(content, str):
            return False

        # Count numbered steps (look for patterns like "1.", "2.", etc.)
        lines = content.strip().split("\n")
        numbered_steps = sum(1 for line in lines if line.strip() and line.strip()[0].isdigit())

        if not (3 <= numbered_steps <= 8):
            logger.warning(
                f"Pattern '{pattern['title']}' has {numbered_steps} steps (expected 3-8)"
            )
            return False

        # Validate confidence if present
        if "confidence" in pattern:
            try:
                confidence = float(pattern["confidence"])
                if not (0.0 <= confidence <= 1.0):
                    return False
            except (ValueError, TypeError):
                return False

        return True

    async def get_distillation_statistics(
        self,
        task_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get statistics about pattern distillation.

        Args:
            task_type: Filter by task type
            tenant_id: Filter by tenant

        Returns:
            Dict with distillation statistics
        """
        # Get trajectory statistics
        trajectory_stats = await self.trajectory_service.get_trajectory_statistics(
            task_type=task_type,
            tenant_id=tenant_id,
        )

        # Get pattern counts
        query = select(PatternEmbedding)
        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(query)
        patterns = list(result.scalars().all())

        total_patterns = len(patterns)
        avg_confidence = (
            sum(p.confidence for p in patterns) / total_patterns if total_patterns > 0 else 0.0
        )
        avg_usage = (
            sum(p.usage_count for p in patterns) / total_patterns if total_patterns > 0 else 0.0
        )

        return {
            "total_patterns": total_patterns,
            "avg_confidence": avg_confidence,
            "avg_usage_count": avg_usage,
            "trajectories_distilled": trajectory_stats.get("distilled_count", 0),
            "distillation_rate": trajectory_stats.get("distillation_rate", 0.0),
            "patterns_per_trajectory": total_patterns / max(trajectory_stats.get("distilled_count", 1), 1),
        }
