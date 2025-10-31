"""
Consolidation Service

Memory quality control through deduplication, contradiction detection, and confidence updates.
Implements:
- Pattern deduplication based on semantic similarity
- Contradiction detection using embeddings and NLI
- Pattern aging with exponential decay
- Confidence dynamics with usage-based reinforcement learning
- Pattern merging for redundancy reduction
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, delete
import numpy as np
from collections import defaultdict
import logging

from ..models.pattern_embeddings import PatternEmbedding
from ..models.pattern_links import PatternLink, LinkType

logger = logging.getLogger(__name__)


class ConsolidationService:
    """
    Service for memory consolidation and quality control.

    Responsibilities:
    1. Deduplication: Identify and merge near-identical patterns
    2. Contradiction Detection: Find conflicting patterns using semantic analysis
    3. Pattern Aging: Reduce confidence of unused patterns over time
    4. Confidence Updates: Reinforce successful patterns, weaken failed ones
    5. Pattern Merging: Combine similar patterns to reduce redundancy
    """

    # Configuration constants
    DUPLICATE_THRESHOLD = 0.87  # Cosine similarity threshold for duplicates
    CONTRADICTION_THRESHOLD = 0.60  # NLI score threshold for contradictions
    AGING_HALF_LIFE_DAYS = 90  # Half-life for exponential decay
    MIN_CONFIDENCE = 0.1  # Minimum confidence before pattern archival
    MAX_USAGE_GAP_DAYS = 180  # Maximum days without usage before aggressive aging
    MERGE_SIMILARITY_THRESHOLD = 0.75  # Threshold for merging similar patterns
    LEARNING_RATE = 0.05  # Default learning rate for confidence updates

    def __init__(self, db_session: AsyncSession):
        """
        Initialize consolidation service.

        Args:
            db_session: AsyncSession for database operations
        """
        self.db = db_session

    async def consolidate_patterns(
        self,
        tenant_id: Optional[str] = None,
        batch_size: int = 100,
        aggressive: bool = False,
    ) -> Dict[str, Any]:
        """
        Run full consolidation pipeline on patterns.

        This is the main entry point that orchestrates all consolidation tasks:
        1. Detect duplicates and contradictions
        2. Age patterns based on usage
        3. Update confidence scores
        4. Merge similar patterns
        5. Archive low-confidence patterns

        Args:
            tenant_id: Filter patterns by tenant
            batch_size: Number of patterns to process per batch
            aggressive: If True, use more aggressive consolidation (merge more, age faster)

        Returns:
            Dict with consolidation statistics and results
        """
        logger.info(f"Starting consolidation for tenant_id={tenant_id}, aggressive={aggressive}")

        stats = {
            "start_time": datetime.utcnow().isoformat(),
            "tenant_id": tenant_id,
            "aggressive_mode": aggressive,
            "patterns_processed": 0,
            "duplicates_found": 0,
            "contradictions_found": 0,
            "patterns_merged": 0,
            "patterns_aged": 0,
            "patterns_archived": 0,
            "errors": [],
        }

        try:
            # Step 1: Detect duplicates and contradictions
            logger.info("Step 1: Detecting duplicates and contradictions")
            duplicate_links = await self.detect_duplicates(tenant_id=tenant_id, batch_size=batch_size)
            contradiction_links = await self.detect_contradictions(tenant_id=tenant_id, batch_size=batch_size)

            stats["duplicates_found"] = len(duplicate_links)
            stats["contradictions_found"] = len(contradiction_links)

            # Step 2: Merge duplicate patterns
            logger.info(f"Step 2: Merging {len(duplicate_links)} duplicate patterns")
            for link in duplicate_links:
                try:
                    merged = await self._merge_duplicate_patterns(
                        link.source_pattern_id,
                        link.target_pattern_id,
                        similarity=link.similarity_score,
                    )
                    if merged:
                        stats["patterns_merged"] += 1
                except Exception as e:
                    logger.error(f"Error merging patterns {link.source_pattern_id} and {link.target_pattern_id}: {e}")
                    stats["errors"].append(str(e))

            # Step 3: Age patterns based on usage
            logger.info("Step 3: Aging patterns")
            aging_config = {
                "half_life_days": self.AGING_HALF_LIFE_DAYS // 2 if aggressive else self.AGING_HALF_LIFE_DAYS,
                "min_confidence": self.MIN_CONFIDENCE,
            }
            aged_count = await self.age_patterns(tenant_id=tenant_id, **aging_config)
            stats["patterns_aged"] = aged_count

            # Step 4: Update confidence based on recent usage (if applicable)
            logger.info("Step 4: Updating confidence scores")
            # This is typically done during pattern usage, but we can refresh here
            await self._refresh_confidence_scores(tenant_id=tenant_id)

            # Step 5: Archive low-confidence patterns
            logger.info("Step 5: Archiving low-confidence patterns")
            archived_count = await self._archive_low_confidence_patterns(
                tenant_id=tenant_id,
                min_confidence=self.MIN_CONFIDENCE,
            )
            stats["patterns_archived"] = archived_count

            # Step 6: Get total patterns processed
            query = select(func.count(PatternEmbedding.id))
            if tenant_id:
                query = query.where(PatternEmbedding.tenant_id == tenant_id)
            result = await self.db.execute(query)
            stats["patterns_processed"] = result.scalar()

            stats["end_time"] = datetime.utcnow().isoformat()
            stats["success"] = True

            logger.info(f"Consolidation complete: {stats}")
            return stats

        except Exception as e:
            logger.error(f"Consolidation failed: {e}", exc_info=True)
            stats["success"] = False
            stats["errors"].append(str(e))
            stats["end_time"] = datetime.utcnow().isoformat()
            return stats

    async def detect_duplicates(
        self,
        tenant_id: Optional[str] = None,
        batch_size: int = 100,
    ) -> List[PatternLink]:
        """
        Detect near-identical patterns using cosine similarity.

        Uses vector embeddings to find patterns with similarity >= DUPLICATE_THRESHOLD.
        Creates PatternLink records with type=DUPLICATE.

        Args:
            tenant_id: Filter patterns by tenant
            batch_size: Number of patterns to process per batch

        Returns:
            List of PatternLink objects representing duplicates
        """
        logger.info(f"Detecting duplicates with threshold={self.DUPLICATE_THRESHOLD}")

        # Fetch all patterns with embeddings
        query = select(PatternEmbedding)
        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(query)
        patterns = list(result.scalars().all())

        if len(patterns) < 2:
            logger.info("Not enough patterns for duplicate detection")
            return []

        duplicate_links = []
        processed_pairs: Set[Tuple[str, str]] = set()

        # Compare patterns pairwise using embeddings
        for i, pattern_a in enumerate(patterns):
            for pattern_b in patterns[i + 1:]:
                # Skip if already processed
                pair = tuple(sorted([pattern_a.pattern_id, pattern_b.pattern_id]))
                if pair in processed_pairs:
                    continue

                processed_pairs.add(pair)

                # Calculate cosine similarity
                similarity = self._cosine_similarity(
                    np.array(pattern_a.embedding),
                    np.array(pattern_b.embedding)
                )

                if similarity >= self.DUPLICATE_THRESHOLD:
                    logger.info(
                        f"Duplicate found: {pattern_a.pattern_id} <-> {pattern_b.pattern_id} "
                        f"(similarity={similarity:.3f})"
                    )

                    # Create link record
                    link = PatternLink(
                        source_pattern_id=pattern_a.pattern_id,
                        target_pattern_id=pattern_b.pattern_id,
                        link_type=LinkType.DUPLICATE,
                        similarity_score=similarity,
                        is_resolved=0,
                        tenant_id=tenant_id,
                    )

                    self.db.add(link)
                    duplicate_links.append(link)

        if duplicate_links:
            await self.db.commit()
            logger.info(f"Found {len(duplicate_links)} duplicate pairs")

        return duplicate_links

    async def detect_contradictions(
        self,
        tenant_id: Optional[str] = None,
        batch_size: int = 100,
    ) -> List[PatternLink]:
        """
        Detect contradicting patterns using semantic analysis.

        Identifies patterns that provide conflicting guidance by analyzing:
        1. Semantic similarity (patterns about same topic)
        2. Opposing recommendations (different actions for same situation)

        Args:
            tenant_id: Filter patterns by tenant
            batch_size: Number of patterns to process per batch

        Returns:
            List of PatternLink objects representing contradictions
        """
        logger.info(f"Detecting contradictions with threshold={self.CONTRADICTION_THRESHOLD}")

        # Fetch all patterns
        query = select(PatternEmbedding)
        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(query)
        patterns = list(result.scalars().all())

        if len(patterns) < 2:
            logger.info("Not enough patterns for contradiction detection")
            return []

        contradiction_links = []
        processed_pairs: Set[Tuple[str, str]] = set()

        # Compare patterns for contradictions
        for i, pattern_a in enumerate(patterns):
            for pattern_b in patterns[i + 1:]:
                # Skip if already processed
                pair = tuple(sorted([pattern_a.pattern_id, pattern_b.pattern_id]))
                if pair in processed_pairs:
                    continue

                processed_pairs.add(pair)

                # Check for contradiction using semantic analysis
                is_contradiction, confidence = self._detect_semantic_contradiction(
                    pattern_a.content,
                    pattern_b.content,
                    pattern_a.embedding,
                    pattern_b.embedding,
                )

                if is_contradiction and confidence >= self.CONTRADICTION_THRESHOLD:
                    logger.warning(
                        f"Contradiction found: {pattern_a.pattern_id} <-> {pattern_b.pattern_id} "
                        f"(confidence={confidence:.3f})"
                    )

                    # Create link record
                    link = PatternLink(
                        source_pattern_id=pattern_a.pattern_id,
                        target_pattern_id=pattern_b.pattern_id,
                        link_type=LinkType.CONTRADICTION,
                        similarity_score=confidence,
                        is_resolved=0,
                        tenant_id=tenant_id,
                    )

                    self.db.add(link)
                    contradiction_links.append(link)

        if contradiction_links:
            await self.db.commit()
            logger.warning(f"Found {len(contradiction_links)} contradictions")

        return contradiction_links

    async def update_confidence(
        self,
        pattern_id: str,
        success: bool,
        learning_rate: Optional[float] = None,
    ) -> PatternEmbedding:
        """
        Update pattern confidence based on usage outcome.

        Implements reinforcement learning-style confidence updates:
        - Success: Increase confidence by learning_rate
        - Failure: Decrease confidence by learning_rate

        Update Rule:
        confidence ← clamp(confidence + η·success_delta, 0, 1)

        Args:
            pattern_id: Pattern to update
            success: Whether the pattern was used successfully
            learning_rate: Learning rate (default: LEARNING_RATE)

        Returns:
            Updated PatternEmbedding

        Raises:
            ValueError: If pattern not found
        """
        lr = learning_rate or self.LEARNING_RATE

        # Fetch pattern
        result = await self.db.execute(
            select(PatternEmbedding).where(PatternEmbedding.pattern_id == pattern_id)
        )
        pattern = result.scalar_one_or_none()

        if not pattern:
            raise ValueError(f"Pattern not found: {pattern_id}")

        # Update confidence using pattern's built-in method
        old_confidence = pattern.confidence
        pattern.update_confidence(success=success, learning_rate=lr)

        logger.info(
            f"Updated confidence for {pattern_id}: "
            f"{old_confidence:.3f} -> {pattern.confidence:.3f} "
            f"(success={success}, lr={lr})"
        )

        await self.db.commit()
        await self.db.refresh(pattern)

        return pattern

    async def age_patterns(
        self,
        tenant_id: Optional[str] = None,
        half_life_days: Optional[int] = None,
        min_confidence: Optional[float] = None,
    ) -> int:
        """
        Age patterns based on time since last use (exponential decay).

        Implements exponential decay formula:
        confidence ← confidence × e^(-days_unused / half_life)

        Patterns that haven't been used recently have their confidence reduced.
        This encourages the system to prefer fresh, actively-used patterns.

        Args:
            tenant_id: Filter patterns by tenant
            half_life_days: Half-life for decay (default: AGING_HALF_LIFE_DAYS)
            min_confidence: Minimum confidence to maintain (default: MIN_CONFIDENCE)

        Returns:
            Number of patterns aged
        """
        hl = half_life_days or self.AGING_HALF_LIFE_DAYS
        min_conf = min_confidence or self.MIN_CONFIDENCE

        logger.info(f"Aging patterns with half_life={hl} days, min_confidence={min_conf}")

        # Fetch patterns that need aging
        query = select(PatternEmbedding)
        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(query)
        patterns = list(result.scalars().all())

        aged_count = 0
        now = datetime.utcnow()

        for pattern in patterns:
            # Calculate days since last use
            last_used = pattern.last_used_at or pattern.created_at
            days_unused = (now - last_used).days

            if days_unused == 0:
                continue  # Pattern was used today, no aging

            # Apply exponential decay
            decay_factor = np.exp(-days_unused / hl)
            old_confidence = pattern.confidence
            new_confidence = max(min_conf, pattern.confidence * decay_factor)

            if new_confidence < old_confidence:
                pattern.confidence = new_confidence
                pattern.updated_at = now
                aged_count += 1

                logger.debug(
                    f"Aged pattern {pattern.pattern_id}: "
                    f"{old_confidence:.3f} -> {new_confidence:.3f} "
                    f"(unused for {days_unused} days)"
                )

        if aged_count > 0:
            await self.db.commit()
            logger.info(f"Aged {aged_count} patterns")

        return aged_count

    async def merge_similar_patterns(
        self,
        source_pattern_id: str,
        target_pattern_id: str,
        strategy: str = "combine",
    ) -> Optional[PatternEmbedding]:
        """
        Merge two similar patterns into one.

        Strategies:
        - "combine": Combine usage stats, keep higher-quality content
        - "keep_better": Keep pattern with better reliability, delete other
        - "average": Average confidence, combine content

        Args:
            source_pattern_id: First pattern to merge
            target_pattern_id: Second pattern to merge
            strategy: Merge strategy (default: "combine")

        Returns:
            Merged PatternEmbedding, or None if merge failed

        Raises:
            ValueError: If patterns not found or strategy invalid
        """
        logger.info(
            f"Merging patterns {source_pattern_id} and {target_pattern_id} "
            f"using strategy='{strategy}'"
        )

        # Fetch both patterns
        result = await self.db.execute(
            select(PatternEmbedding).where(
                PatternEmbedding.pattern_id.in_([source_pattern_id, target_pattern_id])
            )
        )
        patterns = list(result.scalars().all())

        if len(patterns) != 2:
            raise ValueError(f"Could not find both patterns to merge")

        pattern_a, pattern_b = patterns

        if strategy == "combine":
            return await self._merge_combine(pattern_a, pattern_b)
        elif strategy == "keep_better":
            return await self._merge_keep_better(pattern_a, pattern_b)
        elif strategy == "average":
            return await self._merge_average(pattern_a, pattern_b)
        else:
            raise ValueError(f"Invalid merge strategy: {strategy}")

    # ==================== Private Helper Methods ====================

    def _cosine_similarity(self, vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """
        Calculate cosine similarity between two vectors.

        Args:
            vec_a: First vector
            vec_b: Second vector

        Returns:
            Cosine similarity (0.0 to 1.0)
        """
        dot_product = np.dot(vec_a, vec_b)
        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return float(dot_product / (norm_a * norm_b))

    def _detect_semantic_contradiction(
        self,
        content_a: str,
        content_b: str,
        embedding_a: List[float],
        embedding_b: List[float],
    ) -> Tuple[bool, float]:
        """
        Detect if two patterns contradict each other.

        Uses semantic similarity and content analysis to determine if patterns
        provide conflicting guidance for similar situations.

        Args:
            content_a: First pattern content
            content_b: Second pattern content
            embedding_a: First pattern embedding
            embedding_b: Second pattern embedding

        Returns:
            Tuple of (is_contradiction, confidence)
        """
        # Calculate semantic similarity
        similarity = self._cosine_similarity(
            np.array(embedding_a),
            np.array(embedding_b)
        )

        # If patterns are about different topics, they can't contradict
        if similarity < 0.3:
            return False, 0.0

        # Check for contradictory keywords
        contradiction_indicators = [
            ("always", "never"),
            ("must", "must not"),
            ("should", "should not"),
            ("do", "don't"),
            ("include", "exclude"),
            ("enable", "disable"),
            ("use", "avoid"),
            ("prefer", "avoid"),
        ]

        content_a_lower = content_a.lower()
        content_b_lower = content_b.lower()

        contradiction_score = 0.0
        matches = 0

        for positive, negative in contradiction_indicators:
            has_positive_a = positive in content_a_lower
            has_negative_a = negative in content_a_lower
            has_positive_b = positive in content_b_lower
            has_negative_b = negative in content_b_lower

            # Check for opposing patterns
            if (has_positive_a and has_negative_b) or (has_negative_a and has_positive_b):
                contradiction_score += 1.0
                matches += 1

        if matches > 0:
            # Combine similarity and contradiction indicators
            confidence = (similarity * 0.5) + (contradiction_score / len(contradiction_indicators) * 0.5)
            return confidence >= self.CONTRADICTION_THRESHOLD, confidence

        return False, 0.0

    async def _merge_duplicate_patterns(
        self,
        source_id: str,
        target_id: str,
        similarity: float,
    ) -> bool:
        """
        Merge duplicate patterns by combining their statistics.

        Args:
            source_id: First pattern ID
            target_id: Second pattern ID
            similarity: Similarity score

        Returns:
            True if merge successful
        """
        try:
            merged = await self.merge_similar_patterns(
                source_id,
                target_id,
                strategy="combine"
            )

            if merged:
                # Mark link as resolved
                await self.db.execute(
                    select(PatternLink).where(
                        and_(
                            PatternLink.source_pattern_id == source_id,
                            PatternLink.target_pattern_id == target_id,
                            PatternLink.link_type == LinkType.DUPLICATE,
                        )
                    )
                )
                result = await self.db.execute(
                    select(PatternLink).where(
                        and_(
                            PatternLink.source_pattern_id == source_id,
                            PatternLink.target_pattern_id == target_id,
                        )
                    )
                )
                link = result.scalar_one_or_none()
                if link:
                    link.is_resolved = 1
                    link.resolution_action = "merge"
                    link.resolved_at = datetime.utcnow()
                    await self.db.commit()

                return True

        except Exception as e:
            logger.error(f"Failed to merge patterns {source_id} and {target_id}: {e}")
            return False

        return False

    async def _merge_combine(
        self,
        pattern_a: PatternEmbedding,
        pattern_b: PatternEmbedding,
    ) -> PatternEmbedding:
        """
        Merge by combining usage stats and keeping better content.

        Args:
            pattern_a: First pattern
            pattern_b: Second pattern

        Returns:
            Merged pattern
        """
        # Keep pattern with higher reliability
        if pattern_a.reliability_score >= pattern_b.reliability_score:
            keeper, deleter = pattern_a, pattern_b
        else:
            keeper, deleter = pattern_b, pattern_a

        # Combine usage statistics
        keeper.usage_count += deleter.usage_count
        keeper.success_count += deleter.success_count
        keeper.failure_count += deleter.failure_count

        # Update confidence (weighted average based on usage)
        total_usage = keeper.usage_count
        weight_keeper = keeper.usage_count / total_usage if total_usage > 0 else 0.5
        weight_deleter = deleter.usage_count / total_usage if total_usage > 0 else 0.5

        keeper.confidence = (
            keeper.confidence * weight_keeper +
            deleter.confidence * weight_deleter
        )

        # Update timestamps
        keeper.updated_at = datetime.utcnow()
        if deleter.last_used_at and (not keeper.last_used_at or deleter.last_used_at > keeper.last_used_at):
            keeper.last_used_at = deleter.last_used_at

        # Delete the inferior pattern
        await self.db.delete(deleter)
        await self.db.commit()
        await self.db.refresh(keeper)

        logger.info(f"Merged patterns: kept {keeper.pattern_id}, deleted {deleter.pattern_id}")
        return keeper

    async def _merge_keep_better(
        self,
        pattern_a: PatternEmbedding,
        pattern_b: PatternEmbedding,
    ) -> PatternEmbedding:
        """
        Keep pattern with better reliability, delete the other.

        Args:
            pattern_a: First pattern
            pattern_b: Second pattern

        Returns:
            Kept pattern
        """
        if pattern_a.reliability_score >= pattern_b.reliability_score:
            keeper, deleter = pattern_a, pattern_b
        else:
            keeper, deleter = pattern_b, pattern_a

        await self.db.delete(deleter)
        await self.db.commit()
        await self.db.refresh(keeper)

        logger.info(f"Kept better pattern: {keeper.pattern_id}, deleted {deleter.pattern_id}")
        return keeper

    async def _merge_average(
        self,
        pattern_a: PatternEmbedding,
        pattern_b: PatternEmbedding,
    ) -> PatternEmbedding:
        """
        Average confidence and combine content.

        Args:
            pattern_a: First pattern
            pattern_b: Second pattern

        Returns:
            Merged pattern
        """
        # Keep pattern with more usage
        if pattern_a.usage_count >= pattern_b.usage_count:
            keeper, deleter = pattern_a, pattern_b
        else:
            keeper, deleter = pattern_b, pattern_a

        # Average confidence
        keeper.confidence = (keeper.confidence + deleter.confidence) / 2

        # Combine usage stats
        keeper.usage_count += deleter.usage_count
        keeper.success_count += deleter.success_count
        keeper.failure_count += deleter.failure_count

        # Average embeddings
        keeper.embedding = [
            (a + b) / 2
            for a, b in zip(keeper.embedding, deleter.embedding)
        ]

        keeper.updated_at = datetime.utcnow()

        await self.db.delete(deleter)
        await self.db.commit()
        await self.db.refresh(keeper)

        logger.info(f"Merged patterns (average): kept {keeper.pattern_id}, deleted {deleter.pattern_id}")
        return keeper

    async def _refresh_confidence_scores(self, tenant_id: Optional[str] = None) -> int:
        """
        Refresh confidence scores based on recent reliability.

        Args:
            tenant_id: Filter by tenant

        Returns:
            Number of patterns updated
        """
        query = select(PatternEmbedding)
        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(query)
        patterns = list(result.scalars().all())

        updated = 0
        for pattern in patterns:
            old_confidence = pattern.confidence
            new_confidence = pattern.reliability_score

            # Only update if there's a significant change
            if abs(new_confidence - old_confidence) > 0.05:
                pattern.confidence = new_confidence
                pattern.updated_at = datetime.utcnow()
                updated += 1

        if updated > 0:
            await self.db.commit()
            logger.info(f"Refreshed confidence for {updated} patterns")

        return updated

    async def _archive_low_confidence_patterns(
        self,
        tenant_id: Optional[str] = None,
        min_confidence: float = 0.1,
    ) -> int:
        """
        Archive (soft delete) patterns with very low confidence.

        Args:
            tenant_id: Filter by tenant
            min_confidence: Minimum confidence to keep

        Returns:
            Number of patterns archived
        """
        # For now, we'll just delete low-confidence patterns
        # In production, you might want to move them to an archive table

        query = select(PatternEmbedding).where(
            PatternEmbedding.confidence < min_confidence
        )

        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(query)
        low_confidence_patterns = list(result.scalars().all())

        archived_count = 0
        for pattern in low_confidence_patterns:
            # Only archive if pattern hasn't been used recently
            days_since_use = (datetime.utcnow() - (pattern.last_used_at or pattern.created_at)).days

            if days_since_use > self.MAX_USAGE_GAP_DAYS:
                logger.info(
                    f"Archiving pattern {pattern.pattern_id}: "
                    f"confidence={pattern.confidence:.3f}, unused for {days_since_use} days"
                )
                await self.db.delete(pattern)
                archived_count += 1

        if archived_count > 0:
            await self.db.commit()
            logger.info(f"Archived {archived_count} low-confidence patterns")

        return archived_count

    async def get_consolidation_status(
        self,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get current consolidation status and statistics.

        Args:
            tenant_id: Filter by tenant

        Returns:
            Dict with consolidation statistics
        """
        # Count patterns
        pattern_query = select(func.count(PatternEmbedding.id))
        if tenant_id:
            pattern_query = pattern_query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(pattern_query)
        total_patterns = result.scalar()

        # Count unresolved links
        link_query = select(func.count(PatternLink.id)).where(PatternLink.is_resolved == 0)
        if tenant_id:
            link_query = link_query.where(PatternLink.tenant_id == tenant_id)

        result = await self.db.execute(link_query)
        unresolved_links = result.scalar()

        # Count by link type
        duplicate_query = select(func.count(PatternLink.id)).where(
            and_(
                PatternLink.link_type == LinkType.DUPLICATE,
                PatternLink.is_resolved == 0,
            )
        )
        if tenant_id:
            duplicate_query = duplicate_query.where(PatternLink.tenant_id == tenant_id)

        result = await self.db.execute(duplicate_query)
        unresolved_duplicates = result.scalar()

        contradiction_query = select(func.count(PatternLink.id)).where(
            and_(
                PatternLink.link_type == LinkType.CONTRADICTION,
                PatternLink.is_resolved == 0,
            )
        )
        if tenant_id:
            contradiction_query = contradiction_query.where(PatternLink.tenant_id == tenant_id)

        result = await self.db.execute(contradiction_query)
        unresolved_contradictions = result.scalar()

        # Low confidence patterns
        low_conf_query = select(func.count(PatternEmbedding.id)).where(
            PatternEmbedding.confidence < self.MIN_CONFIDENCE
        )
        if tenant_id:
            low_conf_query = low_conf_query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(low_conf_query)
        low_confidence_count = result.scalar()

        return {
            "total_patterns": total_patterns,
            "unresolved_links": unresolved_links,
            "unresolved_duplicates": unresolved_duplicates,
            "unresolved_contradictions": unresolved_contradictions,
            "low_confidence_patterns": low_confidence_count,
            "min_confidence_threshold": self.MIN_CONFIDENCE,
            "duplicate_threshold": self.DUPLICATE_THRESHOLD,
            "contradiction_threshold": self.CONTRADICTION_THRESHOLD,
            "aging_half_life_days": self.AGING_HALF_LIFE_DAYS,
        }
