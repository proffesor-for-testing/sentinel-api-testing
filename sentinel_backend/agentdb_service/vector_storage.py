"""
Vector Storage

High-level operations for storing and retrieving test patterns,
execution results, and agent behaviors as vectors.
"""

import logging
import uuid
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import numpy as np

from .agentdb_client import AgentDBClient
from .embedding_service import EmbeddingService

logger = logging.getLogger(__name__)


class VectorStorage:
    """High-level vector storage operations."""

    def __init__(
        self,
        agentdb_client: AgentDBClient,
        embedding_service: EmbeddingService
    ):
        """
        Initialize vector storage.

        Args:
            agentdb_client: AgentDB client instance
            embedding_service: Embedding service instance
        """
        self.client = agentdb_client
        self.embedder = embedding_service
        self.collections = agentdb_client.collections

    async def initialize(self):
        """Initialize all collections."""
        await self.client.initialize_collections()
        logger.info("Vector storage initialized")

    # ==================== Test Patterns ====================

    async def store_test_pattern(
        self,
        endpoint: str,
        method: str,
        parameters: Dict,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store test pattern with vector embedding.

        Args:
            endpoint: API endpoint path
            method: HTTP method
            parameters: Request parameters
            metadata: Additional metadata

        Returns:
            Pattern ID
        """
        pattern = {
            "endpoint": endpoint,
            "method": method,
            "parameters": parameters,
            **(metadata or {})
        }

        # Generate embedding
        vector = self.embedder.embed_test_pattern(pattern)

        # Store in AgentDB
        pattern_id = str(uuid.uuid4())
        pattern["pattern_id"] = pattern_id
        pattern["created_at"] = datetime.utcnow().isoformat()

        await self.client.vector_insert(
            collection=self.collections["test_patterns"],
            vectors=[vector.tolist()],
            metadata=[pattern],
            ids=[pattern_id]
        )

        logger.info(f"Stored test pattern {pattern_id}: {method} {endpoint}")
        return pattern_id

    async def find_similar_patterns(
        self,
        query_pattern: Dict,
        top_k: int = 10,
        min_similarity: float = 0.7,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Find similar test patterns using semantic search.

        Args:
            query_pattern: Pattern to search for
            top_k: Number of results
            min_similarity: Minimum similarity threshold [0, 1]
            filters: Optional metadata filters

        Returns:
            List of similar patterns with scores
        """
        # Generate query embedding
        query_vector = self.embedder.embed_test_pattern(query_pattern)

        # Search AgentDB
        results = await self.client.vector_search(
            collection=self.collections["test_patterns"],
            query_vector=query_vector.tolist(),
            top_k=top_k * 2,  # Get extra to filter
            filters=filters
        )

        # Filter by similarity threshold
        filtered_results = [
            r for r in results
            if r["score"] >= min_similarity
        ][:top_k]

        logger.info(
            f"Found {len(filtered_results)} similar patterns "
            f"(threshold: {min_similarity})"
        )

        return filtered_results

    async def batch_store_patterns(
        self,
        patterns: List[Dict]
    ) -> List[str]:
        """
        Batch store test patterns for performance.

        Args:
            patterns: List of test patterns

        Returns:
            List of pattern IDs
        """
        if not patterns:
            return []

        # Generate embeddings in batch
        vectors = self.embedder.batch_embed(patterns, item_type="pattern")

        # Generate IDs and add timestamps
        pattern_ids = [str(uuid.uuid4()) for _ in patterns]
        timestamp = datetime.utcnow().isoformat()

        for pattern, pattern_id in zip(patterns, pattern_ids):
            pattern["pattern_id"] = pattern_id
            pattern["created_at"] = timestamp

        # Batch insert
        await self.client.vector_insert(
            collection=self.collections["test_patterns"],
            vectors=vectors.tolist(),
            metadata=patterns,
            ids=pattern_ids
        )

        logger.info(f"Batch stored {len(patterns)} test patterns")
        return pattern_ids

    async def update_pattern_metrics(
        self,
        pattern_id: str,
        metrics: Dict
    ):
        """
        Update test pattern metrics (success rate, test count, etc.).

        Args:
            pattern_id: Pattern ID
            metrics: Metrics to update
        """
        metadata_update = {
            "success_rate": metrics.get("success_rate"),
            "test_count": metrics.get("test_count"),
            "avg_latency_ms": metrics.get("avg_latency_ms"),
            "updated_at": datetime.utcnow().isoformat()
        }

        # Remove None values
        metadata_update = {k: v for k, v in metadata_update.items() if v is not None}

        await self.client.update_metadata(
            collection=self.collections["test_patterns"],
            id=pattern_id,
            metadata=metadata_update
        )

        logger.info(f"Updated pattern {pattern_id} metrics")

    # ==================== Execution Results ====================

    async def store_execution_result(
        self,
        test_id: str,
        result: Dict
    ) -> str:
        """
        Store test execution result with vector.

        Args:
            test_id: Test case ID
            result: Execution result data

        Returns:
            Result ID
        """
        result_data = {
            "test_id": test_id,
            **result,
            "result_id": str(uuid.uuid4()),
            "recorded_at": datetime.utcnow().isoformat()
        }

        # Generate embedding
        vector = self.embedder.embed_execution_result(result_data)

        # Store in AgentDB
        result_id = result_data["result_id"]

        await self.client.vector_insert(
            collection=self.collections["execution_results"],
            vectors=[vector.tolist()],
            metadata=[result_data],
            ids=[result_id]
        )

        logger.info(
            f"Stored execution result {result_id} "
            f"(status: {result.get('status')})"
        )

        return result_id

    async def find_similar_executions(
        self,
        query_result: Dict,
        top_k: int = 20,
        status_filter: Optional[str] = None
    ) -> List[Dict]:
        """
        Find similar execution results.

        Args:
            query_result: Result to search for
            top_k: Number of results
            status_filter: Filter by status (pass, fail, error)

        Returns:
            List of similar execution results
        """
        # Generate query embedding
        query_vector = self.embedder.embed_execution_result(query_result)

        # Build filters
        filters = {}
        if status_filter:
            filters["status"] = status_filter

        # Search
        results = await self.client.vector_search(
            collection=self.collections["execution_results"],
            query_vector=query_vector.tolist(),
            top_k=top_k,
            filters=filters
        )

        logger.info(f"Found {len(results)} similar execution results")
        return results

    async def analyze_failure_patterns(
        self,
        endpoint: str,
        method: str,
        top_k: int = 50
    ) -> List[Dict]:
        """
        Analyze failure patterns for an endpoint.

        Args:
            endpoint: API endpoint
            method: HTTP method
            top_k: Number of failures to analyze

        Returns:
            Clustered failure patterns
        """
        # Query for failed executions
        query = {
            "endpoint": endpoint,
            "method": method,
            "status": "fail"
        }

        query_vector = self.embedder.embed_execution_result(query)

        # Search failures
        failures = await self.client.vector_search(
            collection=self.collections["execution_results"],
            query_vector=query_vector.tolist(),
            top_k=top_k,
            filters={"status": "fail"}
        )

        # Group similar failures
        failure_patterns = self._cluster_failures(failures)

        logger.info(
            f"Analyzed {len(failures)} failures into "
            f"{len(failure_patterns)} patterns"
        )

        return failure_patterns

    def _cluster_failures(
        self,
        failures: List[Dict],
        similarity_threshold: float = 0.85
    ) -> List[Dict]:
        """
        Cluster similar failures together.

        Args:
            failures: List of failure results
            similarity_threshold: Clustering threshold

        Returns:
            List of failure pattern clusters
        """
        if not failures:
            return []

        # Simple clustering by response code and error message similarity
        clusters = []
        used_indices = set()

        for i, failure in enumerate(failures):
            if i in used_indices:
                continue

            cluster = {
                "pattern": {
                    "response_code": failure["metadata"].get("response_code"),
                    "error_pattern": failure["metadata"].get("error_pattern")
                },
                "occurrences": 1,
                "examples": [failure["metadata"]]
            }

            # Find similar failures
            for j, other in enumerate(failures[i+1:], start=i+1):
                if j in used_indices:
                    continue

                # Check similarity based on score
                if failure["score"] > similarity_threshold:
                    cluster["occurrences"] += 1
                    cluster["examples"].append(other["metadata"])
                    used_indices.add(j)

            clusters.append(cluster)
            used_indices.add(i)

        # Sort by occurrence count
        clusters.sort(key=lambda x: x["occurrences"], reverse=True)

        return clusters

    # ==================== Agent Behaviors ====================

    async def store_agent_behavior(
        self,
        agent_type: str,
        behavior: Dict
    ) -> str:
        """
        Store agent behavior pattern.

        Args:
            agent_type: Type of agent
            behavior: Behavior data

        Returns:
            Behavior ID
        """
        behavior_data = {
            "agent_type": agent_type,
            **behavior,
            "behavior_id": str(uuid.uuid4()),
            "learned_at": datetime.utcnow().isoformat()
        }

        # Generate embedding
        vector = self.embedder.embed_agent_behavior(behavior_data)

        # Store in AgentDB
        behavior_id = behavior_data["behavior_id"]

        await self.client.vector_insert(
            collection=self.collections["agent_behaviors"],
            vectors=[vector.tolist()],
            metadata=[behavior_data],
            ids=[behavior_id]
        )

        logger.info(
            f"Stored agent behavior {behavior_id} "
            f"(agent: {agent_type}, strategy: {behavior.get('strategy')})"
        )

        return behavior_id

    async def find_successful_behaviors(
        self,
        agent_type: str,
        context: Dict,
        top_k: int = 10,
        min_success_rate: float = 0.8
    ) -> List[Dict]:
        """
        Find successful agent behaviors for a context.

        Args:
            agent_type: Type of agent
            context: Execution context
            top_k: Number of results
            min_success_rate: Minimum success rate

        Returns:
            List of successful behaviors
        """
        # Build query
        query = {
            "agent_type": agent_type,
            **context
        }

        query_vector = self.embedder.embed_agent_behavior(query)

        # Search
        results = await self.client.vector_search(
            collection=self.collections["agent_behaviors"],
            query_vector=query_vector.tolist(),
            top_k=top_k * 2
        )

        # Filter by success rate
        filtered = [
            r for r in results
            if r["metadata"].get("performance_metrics", {}).get("success_rate", 0)
            >= min_success_rate
        ][:top_k]

        logger.info(
            f"Found {len(filtered)} successful behaviors for {agent_type}"
        )

        return filtered

    # ==================== Statistics ====================

    async def get_collection_stats(self) -> Dict:
        """
        Get statistics for all collections.

        Returns:
            Statistics dictionary
        """
        stats = {}

        for name, collection in self.collections.items():
            stats[name] = await self.client.get_stats(collection)

        total_vectors = sum(s.get("vector_count", 0) for s in stats.values())
        total_memory = sum(s.get("memory_mb", 0) for s in stats.values())

        return {
            "collections": stats,
            "total_vectors": total_vectors,
            "total_memory_mb": total_memory,
            "embedding_dimension": self.embedder.dimension
        }
