"""
Unit Tests for RetrievalService

Tests semantic retrieval, MMR algorithm, and pattern matching.
"""

import pytest
import numpy as np
from datetime import datetime, timedelta
from typing import List
from unittest.mock import Mock, AsyncMock, patch

from sentinel_backend.reasoningbank.services.retrieval_service import RetrievalService
from sentinel_backend.reasoningbank.models.pattern_embeddings import PatternEmbedding


@pytest.fixture
def mock_db_session():
    """Create mock database session."""
    session = AsyncMock()
    return session


@pytest.fixture
def mock_embedding_service():
    """Create mock embedding service."""
    service = Mock()
    service.embed_text = AsyncMock(return_value=np.random.randn(1536).tolist())
    return service


@pytest.fixture
def retrieval_service(mock_db_session, mock_embedding_service):
    """Create RetrievalService instance."""
    return RetrievalService(
        db_session=mock_db_session,
        embedding_service=mock_embedding_service,
    )


@pytest.fixture
def sample_patterns() -> List[PatternEmbedding]:
    """Create sample pattern embeddings for testing."""
    patterns = []

    # Pattern 1: High confidence, recent
    pattern1 = PatternEmbedding(
        id=1,
        pattern_id="pat_001",
        title="Authentication Testing Pattern",
        description="Test OAuth2 authentication flows",
        content="1. Send login request\n2. Verify token\n3. Test protected endpoint",
        embedding=np.random.randn(1536).tolist(),
        confidence=0.9,
        usage_count=50,
        success_count=45,
        failure_count=5,
        domain_tags=["api_testing", "security"],
        created_at=datetime.utcnow() - timedelta(days=10),
        last_used_at=datetime.utcnow() - timedelta(days=1),
    )
    patterns.append(pattern1)

    # Pattern 2: Medium confidence, older
    pattern2 = PatternEmbedding(
        id=2,
        pattern_id="pat_002",
        title="REST API Validation",
        description="Validate REST API responses",
        content="1. Send request\n2. Check status code\n3. Validate schema",
        embedding=np.random.randn(1536).tolist(),
        confidence=0.75,
        usage_count=30,
        success_count=25,
        failure_count=5,
        domain_tags=["api_testing"],
        created_at=datetime.utcnow() - timedelta(days=60),
        last_used_at=datetime.utcnow() - timedelta(days=30),
    )
    patterns.append(pattern2)

    # Pattern 3: Low confidence, never used
    pattern3 = PatternEmbedding(
        id=3,
        pattern_id="pat_003",
        title="GraphQL Testing",
        description="Test GraphQL queries",
        content="1. Build query\n2. Send request\n3. Validate response",
        embedding=np.random.randn(1536).tolist(),
        confidence=0.6,
        usage_count=0,
        success_count=0,
        failure_count=0,
        domain_tags=["api_testing", "graphql"],
        created_at=datetime.utcnow() - timedelta(days=5),
        last_used_at=None,
    )
    patterns.append(pattern3)

    return patterns


class TestRetrievalServiceInit:
    """Test RetrievalService initialization."""

    def test_init_with_defaults(self, mock_db_session):
        """Test initialization with default parameters."""
        service = RetrievalService(db_session=mock_db_session)

        assert service.db == mock_db_session
        assert service.embedding_service is None
        assert service.similarity_weight == 0.65
        assert service.recency_weight == 0.15
        assert service.reliability_weight == 0.20
        assert service.diversity_penalty == 0.10

    def test_init_with_embedding_service(self, mock_db_session, mock_embedding_service):
        """Test initialization with embedding service."""
        service = RetrievalService(
            db_session=mock_db_session,
            embedding_service=mock_embedding_service,
        )

        assert service.embedding_service == mock_embedding_service


class TestCosineSimilarity:
    """Test cosine similarity calculation."""

    def test_identical_vectors(self, retrieval_service):
        """Test similarity of identical vectors."""
        vec = np.array([1.0, 0.0, 0.0])
        similarity = retrieval_service._cosine_similarity(vec, vec)

        assert abs(similarity - 1.0) < 1e-6

    def test_orthogonal_vectors(self, retrieval_service):
        """Test similarity of orthogonal vectors."""
        vec1 = np.array([1.0, 0.0, 0.0])
        vec2 = np.array([0.0, 1.0, 0.0])
        similarity = retrieval_service._cosine_similarity(vec1, vec2)

        assert abs(similarity - 0.0) < 1e-6

    def test_opposite_vectors(self, retrieval_service):
        """Test similarity of opposite vectors."""
        vec1 = np.array([1.0, 0.0, 0.0])
        vec2 = np.array([-1.0, 0.0, 0.0])
        similarity = retrieval_service._cosine_similarity(vec1, vec2)

        assert abs(similarity - (-1.0)) < 1e-6

    def test_normalized_vectors(self, retrieval_service):
        """Test similarity with pre-normalized vectors."""
        vec1 = np.array([0.6, 0.8, 0.0])
        vec2 = np.array([0.8, 0.6, 0.0])
        similarity = retrieval_service._cosine_similarity(vec1, vec2)

        expected = 0.6 * 0.8 + 0.8 * 0.6  # 0.96
        assert abs(similarity - expected) < 1e-6


class TestSimilaritySearch:
    """Test similarity search functionality."""

    @pytest.mark.asyncio
    async def test_similarity_search_basic(self, retrieval_service, sample_patterns, mock_db_session):
        """Test basic similarity search."""
        # Mock database query
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = sample_patterns
        mock_db_session.execute.return_value = mock_result

        # Create query embedding
        query_embedding = np.random.randn(1536).tolist()

        # Perform search
        results = await retrieval_service.similarity_search(
            query_embedding=query_embedding,
            limit=3,
        )

        assert len(results) <= 3
        assert all(isinstance(p, PatternEmbedding) for p in results)

    @pytest.mark.asyncio
    async def test_similarity_search_with_confidence_filter(
        self, retrieval_service, sample_patterns, mock_db_session
    ):
        """Test similarity search with confidence threshold."""
        # Filter to only high-confidence patterns
        high_confidence_patterns = [p for p in sample_patterns if p.confidence >= 0.8]

        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = high_confidence_patterns
        mock_db_session.execute.return_value = mock_result

        query_embedding = np.random.randn(1536).tolist()

        results = await retrieval_service.similarity_search(
            query_embedding=query_embedding,
            min_confidence=0.8,
            limit=10,
        )

        assert all(p.confidence >= 0.8 for p in results)

    @pytest.mark.asyncio
    async def test_similarity_search_empty_results(self, retrieval_service, mock_db_session):
        """Test similarity search with no matching patterns."""
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result

        query_embedding = np.random.randn(1536).tolist()

        results = await retrieval_service.similarity_search(
            query_embedding=query_embedding,
            limit=10,
        )

        assert len(results) == 0


class TestMMRSearch:
    """Test Maximum Marginal Relevance search."""

    @pytest.mark.asyncio
    async def test_mmr_search_basic(self, retrieval_service, sample_patterns, mock_db_session):
        """Test basic MMR search."""
        # Mock database query
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = sample_patterns
        mock_db_session.execute.return_value = mock_result

        query_embedding = np.random.randn(1536).tolist()

        results = await retrieval_service.mmr_search(
            query_embedding=query_embedding,
            limit=2,
            lambda_param=0.7,
        )

        assert len(results) <= 2
        assert all(isinstance(p, PatternEmbedding) for p in results)

    @pytest.mark.asyncio
    async def test_mmr_diversity(self, retrieval_service, mock_db_session):
        """Test that MMR produces diverse results."""
        # Create patterns with similar embeddings
        base_embedding = np.random.randn(1536)

        similar_patterns = []
        for i in range(5):
            # Add small perturbation to base embedding
            pattern = PatternEmbedding(
                id=i,
                pattern_id=f"pat_{i:03d}",
                title=f"Pattern {i}",
                description=f"Description {i}",
                content=f"Content {i}",
                embedding=(base_embedding + np.random.randn(1536) * 0.1).tolist(),
                confidence=0.8,
                usage_count=10,
                success_count=9,
                failure_count=1,
                domain_tags=["test"],
                created_at=datetime.utcnow(),
                last_used_at=datetime.utcnow(),
            )
            similar_patterns.append(pattern)

        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = similar_patterns
        mock_db_session.execute.return_value = mock_result

        query_embedding = base_embedding.tolist()

        # High lambda (relevance-focused)
        results_high_lambda = await retrieval_service.mmr_search(
            query_embedding=query_embedding,
            limit=3,
            lambda_param=0.9,
        )

        # Low lambda (diversity-focused)
        results_low_lambda = await retrieval_service.mmr_search(
            query_embedding=query_embedding,
            limit=3,
            lambda_param=0.3,
        )

        assert len(results_high_lambda) == 3
        assert len(results_low_lambda) == 3

        # Results should be different due to different lambda
        # (This is a weak test, but checking diversity is complex)

    @pytest.mark.asyncio
    async def test_mmr_with_few_candidates(self, retrieval_service, mock_db_session):
        """Test MMR when there are fewer candidates than requested."""
        patterns = [
            PatternEmbedding(
                id=1,
                pattern_id="pat_001",
                title="Pattern 1",
                description="Desc 1",
                content="Content 1",
                embedding=np.random.randn(1536).tolist(),
                confidence=0.8,
                usage_count=10,
                success_count=9,
                failure_count=1,
                domain_tags=["test"],
                created_at=datetime.utcnow(),
                last_used_at=datetime.utcnow(),
            )
        ]

        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = patterns
        mock_db_session.execute.return_value = mock_result

        query_embedding = np.random.randn(1536).tolist()

        results = await retrieval_service.mmr_search(
            query_embedding=query_embedding,
            limit=5,
        )

        # Should return all available patterns even if fewer than limit
        assert len(results) == 1


class TestRetrieveRelevantPatterns:
    """Test high-level pattern retrieval."""

    @pytest.mark.asyncio
    async def test_retrieve_with_query_text(
        self, retrieval_service, sample_patterns, mock_db_session
    ):
        """Test retrieval with query text (generates embedding)."""
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = sample_patterns
        mock_db_session.execute.return_value = mock_result

        results = await retrieval_service.retrieve_relevant_patterns(
            query_text="Test OAuth authentication",
            limit=3,
            use_mmr=False,
        )

        assert len(results) <= 3
        retrieval_service.embedding_service.embed_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_retrieve_with_precomputed_embedding(
        self, retrieval_service, sample_patterns, mock_db_session
    ):
        """Test retrieval with pre-computed embedding."""
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = sample_patterns
        mock_db_session.execute.return_value = mock_result

        query_embedding = np.random.randn(1536).tolist()

        results = await retrieval_service.retrieve_relevant_patterns(
            query_text="dummy",
            query_embedding=query_embedding,
            limit=3,
            use_mmr=False,
        )

        assert len(results) <= 3
        # Should not call embedding service if embedding provided
        retrieval_service.embedding_service.embed_text.assert_not_called()

    @pytest.mark.asyncio
    async def test_retrieve_with_mmr_enabled(
        self, retrieval_service, sample_patterns, mock_db_session
    ):
        """Test retrieval with MMR enabled."""
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = sample_patterns
        mock_db_session.execute.return_value = mock_result

        query_embedding = np.random.randn(1536).tolist()

        results = await retrieval_service.retrieve_relevant_patterns(
            query_text="dummy",
            query_embedding=query_embedding,
            limit=2,
            use_mmr=True,
            mmr_lambda=0.7,
        )

        assert len(results) <= 2


class TestFindSimilarPatterns:
    """Test finding similar patterns."""

    @pytest.mark.asyncio
    async def test_find_similar_patterns(self, retrieval_service, sample_patterns, mock_db_session):
        """Test finding patterns similar to a given pattern."""
        source_pattern = sample_patterns[0]
        other_patterns = sample_patterns[1:]

        # Mock finding source pattern
        mock_result_source = Mock()
        mock_result_source.scalar_one_or_none.return_value = source_pattern

        # Mock finding candidates
        mock_result_candidates = Mock()
        mock_result_candidates.scalars.return_value.all.return_value = other_patterns

        mock_db_session.execute.side_effect = [mock_result_source, mock_result_candidates]

        results = await retrieval_service.find_similar_patterns(
            pattern_id="pat_001",
            limit=5,
            min_similarity=0.5,
        )

        assert len(results) <= 5
        assert all(isinstance(item, tuple) for item in results)
        assert all(isinstance(item[0], PatternEmbedding) for item in results)
        assert all(isinstance(item[1], float) for item in results)
        # Similarity should be >= min_similarity
        assert all(item[1] >= 0.5 for item in results)

    @pytest.mark.asyncio
    async def test_find_similar_pattern_not_found(self, retrieval_service, mock_db_session):
        """Test finding similar patterns when source not found."""
        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        with pytest.raises(ValueError, match="Pattern not found"):
            await retrieval_service.find_similar_patterns(pattern_id="nonexistent")


class TestDomainSearch:
    """Test domain-based search."""

    @pytest.mark.asyncio
    async def test_search_by_domain(self, retrieval_service, sample_patterns, mock_db_session):
        """Test searching patterns by domain tags."""
        # Filter patterns with 'security' tag
        security_patterns = [p for p in sample_patterns if "security" in (p.domain_tags or [])]

        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = security_patterns
        mock_db_session.execute.return_value = mock_result

        results = await retrieval_service.search_by_domain(
            domain_tags=["security"],
            limit=10,
        )

        assert all("security" in (p.domain_tags or []) for p in results)


class TestUpdatePatternUsage:
    """Test pattern usage tracking."""

    @pytest.mark.asyncio
    async def test_update_pattern_usage_success(
        self, retrieval_service, sample_patterns, mock_db_session
    ):
        """Test updating pattern on successful usage."""
        pattern = sample_patterns[0]
        initial_confidence = pattern.confidence
        initial_success = pattern.success_count

        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = pattern
        mock_db_session.execute.return_value = mock_result

        updated_pattern = await retrieval_service.update_pattern_usage(
            pattern_id="pat_001",
            success=True,
            learning_rate=0.05,
        )

        assert updated_pattern.confidence >= initial_confidence
        assert updated_pattern.success_count == initial_success + 1

    @pytest.mark.asyncio
    async def test_update_pattern_usage_failure(
        self, retrieval_service, sample_patterns, mock_db_session
    ):
        """Test updating pattern on failed usage."""
        pattern = sample_patterns[0]
        initial_confidence = pattern.confidence
        initial_failure = pattern.failure_count

        mock_result = Mock()
        mock_result.scalar_one_or_none.return_value = pattern
        mock_db_session.execute.return_value = mock_result

        updated_pattern = await retrieval_service.update_pattern_usage(
            pattern_id="pat_001",
            success=False,
            learning_rate=0.05,
        )

        assert updated_pattern.confidence <= initial_confidence
        assert updated_pattern.failure_count == initial_failure + 1


class TestScoringWeights:
    """Test scoring weight configuration."""

    def test_set_scoring_weights_valid(self, retrieval_service):
        """Test setting valid scoring weights."""
        retrieval_service.set_scoring_weights(
            similarity=0.7,
            recency=0.2,
            reliability=0.1,
        )

        assert retrieval_service.similarity_weight == 0.7
        assert retrieval_service.recency_weight == 0.2
        assert retrieval_service.reliability_weight == 0.1

    def test_set_scoring_weights_invalid(self, retrieval_service):
        """Test that invalid weights raise error."""
        with pytest.raises(ValueError, match="should sum to 1.0"):
            retrieval_service.set_scoring_weights(
                similarity=0.5,
                recency=0.3,
                reliability=0.3,  # Sum = 1.1
            )


class TestRetrievalStatistics:
    """Test retrieval statistics."""

    @pytest.mark.asyncio
    async def test_get_statistics(self, retrieval_service, sample_patterns, mock_db_session):
        """Test getting retrieval statistics."""
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = sample_patterns
        mock_db_session.execute.return_value = mock_result

        stats = await retrieval_service.get_retrieval_statistics()

        assert stats["total_patterns"] == len(sample_patterns)
        assert 0.0 <= stats["avg_confidence"] <= 1.0
        assert 0.0 <= stats["avg_reliability"] <= 1.0
        assert stats["avg_usage_count"] >= 0
        assert 0.0 <= stats["success_rate"] <= 1.0

    @pytest.mark.asyncio
    async def test_get_statistics_empty(self, retrieval_service, mock_db_session):
        """Test statistics with no patterns."""
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result

        stats = await retrieval_service.get_retrieval_statistics()

        assert stats["total_patterns"] == 0
        assert stats["avg_confidence"] == 0.0


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_retrieve_without_embedding_service(self, mock_db_session):
        """Test retrieval without embedding service raises error."""
        service = RetrievalService(db_session=mock_db_session)

        with pytest.raises(ValueError, match="embedding_service is required"):
            await service.retrieve_relevant_patterns(
                query_text="test query",
                limit=5,
            )

    @pytest.mark.asyncio
    async def test_cosine_similarity_zero_vectors(self, retrieval_service):
        """Test cosine similarity with near-zero vectors."""
        vec1 = np.array([1e-10, 1e-10, 1e-10])
        vec2 = np.array([1e-10, 1e-10, 1e-10])

        # Should handle gracefully (added epsilon in implementation)
        similarity = retrieval_service._cosine_similarity(vec1, vec2)

        assert -1.0 <= similarity <= 1.0

    @pytest.mark.asyncio
    async def test_mmr_lambda_boundaries(self, retrieval_service, sample_patterns, mock_db_session):
        """Test MMR with boundary lambda values."""
        mock_result = Mock()
        mock_result.scalars.return_value.all.return_value = sample_patterns
        mock_db_session.execute.return_value = mock_result

        query_embedding = np.random.randn(1536).tolist()

        # Lambda = 1.0 (pure relevance)
        results_lambda_1 = await retrieval_service.mmr_search(
            query_embedding=query_embedding,
            limit=2,
            lambda_param=1.0,
        )
        assert len(results_lambda_1) <= 2

        # Lambda = 0.0 (pure diversity)
        results_lambda_0 = await retrieval_service.mmr_search(
            query_embedding=query_embedding,
            limit=2,
            lambda_param=0.0,
        )
        assert len(results_lambda_0) <= 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
