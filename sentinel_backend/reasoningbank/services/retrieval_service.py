"""
Retrieval Service

Semantic retrieval of learned patterns using vector similarity search.
Implements Maximum Marginal Relevance (MMR) for diverse results.

Architecture:
- Vector-based similarity search with pgvector
- MMR algorithm: balance relevance vs diversity
- Weighted scoring: similarity + recency + reliability
- Pattern matching with domain filtering
"""

from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, text
import numpy as np

from ..models.pattern_embeddings import PatternEmbedding


class RetrievalService:
    """
    Service for semantic retrieval of learned patterns.

    Uses pgvector for efficient similarity search and implements
    Maximum Marginal Relevance (MMR) for diverse, relevant results.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        embedding_service: Optional[Any] = None,
    ):
        """
        Initialize retrieval service.

        Args:
            db_session: AsyncSession for database operations
            embedding_service: Service for generating embeddings (optional)
        """
        self.db = db_session
        self.embedding_service = embedding_service

        # Default scoring weights (α, β, γ, δ)
        self.similarity_weight = 0.65  # α - Vector similarity
        self.recency_weight = 0.15  # β - Temporal recency
        self.reliability_weight = 0.20  # γ - Success/usage-based reliability
        self.diversity_penalty = 0.10  # δ - Penalty for similarity to selected items

    async def retrieve_relevant_patterns(
        self,
        query_text: str,
        query_embedding: Optional[List[float]] = None,
        limit: int = 10,
        domain_tags: Optional[List[str]] = None,
        min_confidence: float = 0.5,
        tenant_id: Optional[str] = None,
        use_mmr: bool = True,
        mmr_lambda: float = 0.7,
    ) -> List[PatternEmbedding]:
        """
        Retrieve relevant patterns for a given query.

        Args:
            query_text: Natural language query describing the task
            query_embedding: Pre-computed embedding vector (1536-dim)
            limit: Maximum number of patterns to return
            domain_tags: Filter by domain tags (e.g., ["api_testing", "security"])
            min_confidence: Minimum confidence threshold (0.0-1.0)
            tenant_id: Filter by tenant for multi-tenancy
            use_mmr: Whether to use MMR for diversity
            mmr_lambda: MMR balance parameter (0=diversity, 1=relevance)

        Returns:
            List[PatternEmbedding]: Ranked list of relevant patterns
        """
        # Generate embedding if not provided
        if query_embedding is None:
            if self.embedding_service is None:
                raise ValueError("embedding_service is required if query_embedding not provided")
            query_embedding = await self._generate_embedding(query_text)

        if use_mmr:
            # Use MMR for diverse results
            return await self.mmr_search(
                query_embedding=query_embedding,
                limit=limit,
                domain_tags=domain_tags,
                min_confidence=min_confidence,
                tenant_id=tenant_id,
                lambda_param=mmr_lambda,
            )
        else:
            # Standard similarity search
            return await self.similarity_search(
                query_embedding=query_embedding,
                limit=limit,
                domain_tags=domain_tags,
                min_confidence=min_confidence,
                tenant_id=tenant_id,
            )

    async def similarity_search(
        self,
        query_embedding: List[float],
        limit: int = 10,
        domain_tags: Optional[List[str]] = None,
        min_confidence: float = 0.5,
        tenant_id: Optional[str] = None,
    ) -> List[PatternEmbedding]:
        """
        Vector similarity search with weighted scoring.

        Scoring Formula:
        score = α·similarity + β·recency + γ·reliability

        Args:
            query_embedding: Query vector (1536-dim)
            limit: Maximum results to return
            domain_tags: Domain filter
            min_confidence: Confidence threshold
            tenant_id: Tenant filter

        Returns:
            List[PatternEmbedding]: Patterns ranked by weighted score
        """
        # Build query with filters
        query = select(PatternEmbedding).where(
            PatternEmbedding.confidence >= min_confidence
        )

        if domain_tags:
            # Filter by domain tags (PostgreSQL JSONB contains operator)
            query = query.where(
                or_(*[
                    func.jsonb_exists(PatternEmbedding.domain_tags, tag)
                    for tag in domain_tags
                ])
            )

        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        # Fetch candidates (we'll score them in Python)
        result = await self.db.execute(query)
        candidates = list(result.scalars().all())

        if not candidates:
            return []

        # Calculate weighted scores for each candidate
        scored_patterns = []
        query_vector = np.array(query_embedding, dtype=np.float32)

        for pattern in candidates:
            # 1. Similarity score (cosine similarity)
            pattern_vector = np.array(pattern.embedding, dtype=np.float32)
            similarity = float(self._cosine_similarity(query_vector, pattern_vector))

            # 2. Recency score (exponential decay)
            recency = pattern.recency_score

            # 3. Reliability score (success rate + usage)
            reliability = pattern.reliability_score

            # Weighted combination
            weighted_score = (
                self.similarity_weight * similarity
                + self.recency_weight * recency
                + self.reliability_weight * reliability
            )

            scored_patterns.append((weighted_score, pattern, similarity))

        # Sort by weighted score (descending)
        scored_patterns.sort(key=lambda x: x[0], reverse=True)

        # Return top-k patterns
        return [pattern for _, pattern, _ in scored_patterns[:limit]]

    async def mmr_search(
        self,
        query_embedding: List[float],
        limit: int = 10,
        domain_tags: Optional[List[str]] = None,
        min_confidence: float = 0.5,
        tenant_id: Optional[str] = None,
        lambda_param: float = 0.7,
        candidate_multiplier: int = 3,
    ) -> List[PatternEmbedding]:
        """
        Maximum Marginal Relevance (MMR) search for diverse results.

        MMR Formula:
        MMR = argmax[D\\S] [λ·sim(q,d) - (1-λ)·max[d'∈S] sim(d,d')]

        Balances relevance (similarity to query) with diversity (dissimilarity
        from already-selected documents).

        Args:
            query_embedding: Query vector (1536-dim)
            limit: Number of patterns to return
            domain_tags: Domain filter
            min_confidence: Confidence threshold
            tenant_id: Tenant filter
            lambda_param: Balance parameter (0=diversity, 1=relevance)
            candidate_multiplier: Fetch this many more candidates for diversity

        Returns:
            List[PatternEmbedding]: Diverse, relevant patterns
        """
        # Fetch more candidates than needed for better diversity
        candidate_limit = limit * candidate_multiplier

        # Get initial candidate set using similarity search
        candidates = await self.similarity_search(
            query_embedding=query_embedding,
            limit=candidate_limit,
            domain_tags=domain_tags,
            min_confidence=min_confidence,
            tenant_id=tenant_id,
        )

        if len(candidates) <= limit:
            # Not enough candidates for MMR, return as-is
            return candidates

        # Convert to numpy arrays for efficient computation
        query_vector = np.array(query_embedding, dtype=np.float32)
        candidate_vectors = np.array(
            [np.array(p.embedding, dtype=np.float32) for p in candidates]
        )

        # Calculate query-document similarities
        query_similarities = np.array([
            self._cosine_similarity(query_vector, vec)
            for vec in candidate_vectors
        ])

        # MMR selection
        selected_indices = []
        remaining_indices = list(range(len(candidates)))

        for _ in range(limit):
            if not remaining_indices:
                break

            mmr_scores = []

            for i in remaining_indices:
                # Relevance term: similarity to query
                relevance = query_similarities[i]

                # Diversity term: max similarity to already-selected documents
                if selected_indices:
                    diversity_penalty = max(
                        self._cosine_similarity(
                            candidate_vectors[i],
                            candidate_vectors[j]
                        )
                        for j in selected_indices
                    )
                else:
                    diversity_penalty = 0.0

                # MMR score
                mmr_score = (
                    lambda_param * relevance
                    - (1 - lambda_param) * diversity_penalty
                )

                mmr_scores.append((mmr_score, i))

            # Select best MMR score
            mmr_scores.sort(key=lambda x: x[0], reverse=True)
            best_score, best_idx = mmr_scores[0]

            selected_indices.append(best_idx)
            remaining_indices.remove(best_idx)

        # Return selected patterns in order
        return [candidates[i] for i in selected_indices]

    async def find_similar_patterns(
        self,
        pattern_id: str,
        limit: int = 5,
        min_similarity: float = 0.7,
        exclude_self: bool = True,
    ) -> List[Tuple[PatternEmbedding, float]]:
        """
        Find patterns similar to a given pattern.

        Useful for:
        - Deduplication (finding near-duplicates)
        - Pattern clustering
        - Related pattern recommendations

        Args:
            pattern_id: Pattern to find similar patterns for
            limit: Maximum results
            min_similarity: Minimum cosine similarity threshold
            exclude_self: Exclude the pattern itself from results

        Returns:
            List[Tuple[PatternEmbedding, float]]: (pattern, similarity_score) pairs
        """
        # Get source pattern
        result = await self.db.execute(
            select(PatternEmbedding).where(PatternEmbedding.pattern_id == pattern_id)
        )
        source_pattern = result.scalar_one_or_none()

        if not source_pattern:
            raise ValueError(f"Pattern not found: {pattern_id}")

        # Get all patterns (excluding self if requested)
        query = select(PatternEmbedding)
        if exclude_self:
            query = query.where(PatternEmbedding.pattern_id != pattern_id)

        result = await self.db.execute(query)
        candidates = list(result.scalars().all())

        if not candidates:
            return []

        # Calculate similarities
        source_vector = np.array(source_pattern.embedding, dtype=np.float32)
        similar_patterns = []

        for candidate in candidates:
            candidate_vector = np.array(candidate.embedding, dtype=np.float32)
            similarity = self._cosine_similarity(source_vector, candidate_vector)

            if similarity >= min_similarity:
                similar_patterns.append((candidate, float(similarity)))

        # Sort by similarity (descending)
        similar_patterns.sort(key=lambda x: x[1], reverse=True)

        return similar_patterns[:limit]

    async def search_by_domain(
        self,
        domain_tags: List[str],
        limit: int = 20,
        min_confidence: float = 0.5,
        tenant_id: Optional[str] = None,
    ) -> List[PatternEmbedding]:
        """
        Retrieve patterns filtered by domain tags.

        Args:
            domain_tags: Domain tags to filter by
            limit: Maximum results
            min_confidence: Confidence threshold
            tenant_id: Tenant filter

        Returns:
            List[PatternEmbedding]: Patterns sorted by reliability
        """
        query = select(PatternEmbedding).where(
            and_(
                PatternEmbedding.confidence >= min_confidence,
                or_(*[
                    func.jsonb_exists(PatternEmbedding.domain_tags, tag)
                    for tag in domain_tags
                ])
            )
        )

        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        # Order by reliability (descending)
        query = query.order_by(
            (PatternEmbedding.success_count * 1.0 /
             func.greatest(PatternEmbedding.usage_count, 1)).desc()
        ).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_top_patterns(
        self,
        limit: int = 10,
        tenant_id: Optional[str] = None,
    ) -> List[PatternEmbedding]:
        """
        Get top patterns by reliability and usage.

        Args:
            limit: Maximum results
            tenant_id: Tenant filter

        Returns:
            List[PatternEmbedding]: Top-performing patterns
        """
        query = select(PatternEmbedding)

        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        # Order by combined score: reliability * log(1 + usage_count)
        query = query.order_by(
            (
                (PatternEmbedding.confidence * PatternEmbedding.success_count) /
                func.greatest(PatternEmbedding.usage_count, 1) *
                func.log(1 + PatternEmbedding.usage_count)
            ).desc()
        ).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def update_pattern_usage(
        self,
        pattern_id: str,
        success: bool,
        learning_rate: float = 0.05,
    ) -> PatternEmbedding:
        """
        Update pattern confidence based on usage outcome.

        Args:
            pattern_id: Pattern to update
            success: Whether pattern was used successfully
            learning_rate: Learning rate for confidence update

        Returns:
            PatternEmbedding: Updated pattern
        """
        result = await self.db.execute(
            select(PatternEmbedding).where(PatternEmbedding.pattern_id == pattern_id)
        )
        pattern = result.scalar_one_or_none()

        if not pattern:
            raise ValueError(f"Pattern not found: {pattern_id}")

        # Update confidence using pattern's built-in method
        pattern.update_confidence(success=success, learning_rate=learning_rate)

        await self.db.commit()
        await self.db.refresh(pattern)

        return pattern

    async def get_retrieval_statistics(
        self,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get statistics about pattern retrieval and usage.

        Args:
            tenant_id: Filter by tenant

        Returns:
            Dict[str, Any]: Statistics including total patterns, avg confidence, etc.
        """
        query = select(PatternEmbedding)
        if tenant_id:
            query = query.where(PatternEmbedding.tenant_id == tenant_id)

        result = await self.db.execute(query)
        patterns = list(result.scalars().all())

        if not patterns:
            return {
                "total_patterns": 0,
                "avg_confidence": 0.0,
                "avg_reliability": 0.0,
                "avg_usage_count": 0.0,
                "success_rate": 0.0,
            }

        total = len(patterns)
        total_usage = sum(p.usage_count for p in patterns)
        total_success = sum(p.success_count for p in patterns)

        return {
            "total_patterns": total,
            "avg_confidence": sum(p.confidence for p in patterns) / total,
            "avg_reliability": sum(p.reliability_score for p in patterns) / total,
            "avg_usage_count": total_usage / total,
            "success_rate": total_success / total_usage if total_usage > 0 else 0.0,
            "total_usage": total_usage,
            "total_success": total_success,
        }

    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        Calculate cosine similarity between two vectors.

        Args:
            vec1: First vector
            vec2: Second vector

        Returns:
            float: Cosine similarity [-1, 1] (typically [0, 1] for embeddings)
        """
        # Normalize vectors
        vec1_norm = vec1 / (np.linalg.norm(vec1) + 1e-10)
        vec2_norm = vec2 / (np.linalg.norm(vec2) + 1e-10)

        # Dot product of normalized vectors
        similarity = float(np.dot(vec1_norm, vec2_norm))

        return similarity

    async def _generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for text using embedding service.

        Args:
            text: Text to embed

        Returns:
            List[float]: 1536-dimensional embedding vector

        Raises:
            ValueError: If embedding service is not configured
        """
        if self.embedding_service is None:
            raise ValueError("Embedding service not configured")

        # Assuming embedding service has an embed_text method
        # Adjust based on actual embedding service interface
        if hasattr(self.embedding_service, 'embed_text'):
            embedding = await self.embedding_service.embed_text(text)
        elif hasattr(self.embedding_service, 'embed'):
            embedding = await self.embedding_service.embed(text)
        else:
            raise ValueError("Embedding service does not have embed_text or embed method")

        return embedding.tolist() if isinstance(embedding, np.ndarray) else embedding

    def set_scoring_weights(
        self,
        similarity: float = 0.65,
        recency: float = 0.15,
        reliability: float = 0.20,
    ) -> None:
        """
        Configure scoring weights for retrieval.

        Args:
            similarity: Weight for vector similarity (α)
            recency: Weight for temporal recency (β)
            reliability: Weight for success-based reliability (γ)

        Note:
            Weights should sum to approximately 1.0 for interpretability
        """
        total = similarity + recency + reliability
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"Weights should sum to 1.0, got {total}. "
                f"Consider normalizing: sim={similarity/total:.2f}, "
                f"rec={recency/total:.2f}, rel={reliability/total:.2f}"
            )

        self.similarity_weight = similarity
        self.recency_weight = recency
        self.reliability_weight = reliability
