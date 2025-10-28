"""
Embedding Service

Generate vector embeddings for test patterns, execution results,
and agent behaviors using sentence-transformers.
"""

import logging
import json
from typing import List, Dict, Union, Optional
import numpy as np

logger = logging.getLogger(__name__)


class EmbeddingService:
    """Generate embeddings for semantic search."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize embedding service.

        Args:
            model_name: Sentence transformer model name
        """
        self.model_name = model_name
        self.dimension = 384  # Dimension for all-MiniLM-L6-v2
        self.model = None
        self._load_model()

    def _load_model(self):
        """Load sentence transformer model."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            logger.info(f"Loaded embedding model: {self.model_name}")
        except ImportError:
            logger.warning(
                "sentence-transformers not installed. Using mock embeddings. "
                "Install with: pip install sentence-transformers"
            )
            self.model = None
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            self.model = None

    def embed_test_pattern(self, pattern: Dict) -> np.ndarray:
        """
        Generate embedding for test pattern.

        Args:
            pattern: Test pattern dictionary with endpoint, method, parameters

        Returns:
            384-dimensional embedding vector
        """
        text = self._pattern_to_text(pattern)

        if self.model:
            return self.model.encode(text, convert_to_numpy=True)
        else:
            # Mock embedding for development
            return self._mock_embedding(text)

    def embed_execution_result(self, result: Dict) -> np.ndarray:
        """
        Generate embedding for execution result.

        Args:
            result: Execution result with status, response, etc.

        Returns:
            384-dimensional embedding vector
        """
        text = self._result_to_text(result)

        if self.model:
            return self.model.encode(text, convert_to_numpy=True)
        else:
            return self._mock_embedding(text)

    def embed_agent_behavior(self, behavior: Dict) -> np.ndarray:
        """
        Generate embedding for agent behavior pattern.

        Args:
            behavior: Agent behavior with strategy, metrics, etc.

        Returns:
            384-dimensional embedding vector
        """
        text = self._behavior_to_text(behavior)

        if self.model:
            return self.model.encode(text, convert_to_numpy=True)
        else:
            return self._mock_embedding(text)

    def batch_embed(
        self,
        items: List[Dict],
        item_type: str = "pattern"
    ) -> np.ndarray:
        """
        Batch embedding for performance.

        Args:
            items: List of items to embed
            item_type: Type of items (pattern, result, behavior)

        Returns:
            Array of embeddings [N, 384]
        """
        if item_type == "pattern":
            texts = [self._pattern_to_text(item) for item in items]
        elif item_type == "result":
            texts = [self._result_to_text(item) for item in items]
        elif item_type == "behavior":
            texts = [self._behavior_to_text(item) for item in items]
        else:
            raise ValueError(f"Unknown item type: {item_type}")

        if self.model:
            return self.model.encode(
                texts,
                convert_to_numpy=True,
                show_progress_bar=len(texts) > 100
            )
        else:
            return np.array([self._mock_embedding(text) for text in texts])

    def _pattern_to_text(self, pattern: Dict) -> str:
        """
        Convert test pattern to text for embedding.

        Args:
            pattern: Test pattern dictionary

        Returns:
            Text representation
        """
        parts = []

        # HTTP method and endpoint
        method = pattern.get('method', 'GET')
        endpoint = pattern.get('endpoint', '')
        parts.append(f"HTTP {method} {endpoint}")

        # Parameters
        if 'parameters' in pattern:
            params = pattern['parameters']
            if params:
                param_str = json.dumps(params, sort_keys=True)
                parts.append(f"parameters: {param_str}")

        # Response codes
        if 'response_codes' in pattern:
            codes = pattern['response_codes']
            parts.append(f"response codes: {codes}")

        # Agent type
        if 'agent_type' in pattern:
            parts.append(f"agent: {pattern['agent_type']}")

        # Tags
        if 'tags' in pattern:
            tags = ' '.join(pattern['tags'])
            parts.append(f"tags: {tags}")

        # Success metrics
        if 'success_rate' in pattern:
            parts.append(f"success rate: {pattern['success_rate']}")

        return " | ".join(parts)

    def _result_to_text(self, result: Dict) -> str:
        """
        Convert execution result to text for embedding.

        Args:
            result: Execution result dictionary

        Returns:
            Text representation
        """
        parts = []

        # Request details
        method = result.get('method', 'GET')
        endpoint = result.get('endpoint', '')
        parts.append(f"HTTP {method} {endpoint}")

        # Result status
        status = result.get('status', 'unknown')
        response_code = result.get('response_code', 0)
        parts.append(f"status: {status} code: {response_code}")

        # Performance
        if 'latency_ms' in result:
            parts.append(f"latency: {result['latency_ms']}ms")

        # Assertions
        if 'assertions' in result:
            assertions = result['assertions']
            passed = assertions.get('passed', 0)
            failed = assertions.get('failed', 0)
            parts.append(f"assertions: {passed} passed, {failed} failed")

        # Error pattern
        if 'error_pattern' in result and result['error_pattern']:
            parts.append(f"error: {result['error_pattern']}")

        # Learned patterns
        if 'learned_patterns' in result:
            patterns = ' '.join(result['learned_patterns'])
            parts.append(f"patterns: {patterns}")

        return " | ".join(parts)

    def _behavior_to_text(self, behavior: Dict) -> str:
        """
        Convert agent behavior to text for embedding.

        Args:
            behavior: Agent behavior dictionary

        Returns:
            Text representation
        """
        parts = []

        # Agent and strategy
        agent_type = behavior.get('agent_type', 'unknown')
        strategy = behavior.get('strategy', 'unknown')
        parts.append(f"agent: {agent_type} strategy: {strategy}")

        # Contexts
        if 'contexts' in behavior:
            contexts = ' '.join(behavior['contexts'])
            parts.append(f"contexts: {contexts}")

        # Patterns
        if 'patterns' in behavior:
            patterns = ' '.join(behavior['patterns'])
            parts.append(f"patterns: {patterns}")

        # Performance metrics
        if 'performance_metrics' in behavior:
            metrics = behavior['performance_metrics']
            if 'success_rate' in metrics:
                parts.append(f"success rate: {metrics['success_rate']}")
            if 'test_quality_score' in metrics:
                parts.append(f"quality: {metrics['test_quality_score']}")

        return " | ".join(parts)

    def _mock_embedding(self, text: str) -> np.ndarray:
        """
        Generate mock embedding for development.

        Args:
            text: Text to embed

        Returns:
            Mock 384-dimensional embedding
        """
        # Use hash of text to generate deterministic mock embedding
        import hashlib
        hash_value = int(hashlib.md5(text.encode()).hexdigest(), 16)

        # Set random seed for reproducibility
        np.random.seed(hash_value % (2**32))

        # Generate random normalized vector
        embedding = np.random.randn(self.dimension)
        embedding = embedding / np.linalg.norm(embedding)

        return embedding.astype(np.float32)

    def cosine_similarity(
        self,
        vec1: np.ndarray,
        vec2: np.ndarray
    ) -> float:
        """
        Calculate cosine similarity between two vectors.

        Args:
            vec1: First vector
            vec2: Second vector

        Returns:
            Similarity score [0, 1]
        """
        return float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))

    def batch_similarity(
        self,
        query_vector: np.ndarray,
        vectors: np.ndarray
    ) -> np.ndarray:
        """
        Calculate similarity between query and multiple vectors.

        Args:
            query_vector: Query embedding [384]
            vectors: Matrix of embeddings [N, 384]

        Returns:
            Similarity scores [N]
        """
        # Normalize vectors
        query_norm = query_vector / np.linalg.norm(query_vector)
        vectors_norm = vectors / np.linalg.norm(vectors, axis=1, keepdims=True)

        # Compute dot products
        similarities = np.dot(vectors_norm, query_norm)

        return similarities
