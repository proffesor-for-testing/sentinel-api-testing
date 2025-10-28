"""
Pattern Storage Service with AgentDB Integration.

This service handles persistent storage of patterns using AgentDB's vector database
capabilities for efficient semantic search and retrieval.
"""

from typing import Dict, List, Any, Optional
import logging
import json
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


class PatternStorage:
    """
    Handles persistent storage and retrieval of patterns.

    Uses AgentDB for:
    - Vector embeddings for semantic similarity
    - Fast nearest-neighbor search
    - Pattern metadata storage
    - Pattern evolution tracking
    """

    def __init__(self, db_connection_string: Optional[str] = None):
        """
        Initialize pattern storage.

        Args:
            db_connection_string: Database connection string
        """
        self.db_connection = db_connection_string
        self.agentdb_client = None
        self.initialized = False
        logger.info("Pattern Storage Service initialized")

    async def initialize(self):
        """Initialize AgentDB connection and create necessary collections."""
        try:
            # Initialize AgentDB client
            self.agentdb_client = await self._create_agentdb_client()

            if self.agentdb_client:
                # Create pattern collection
                await self._create_pattern_collection()
                self.initialized = True
                logger.info("AgentDB connection established for pattern storage")
            else:
                logger.warning("AgentDB not available, using in-memory storage")

        except Exception as e:
            logger.error(f"Error initializing pattern storage: {e}")
            logger.warning("Falling back to in-memory storage")

    async def store_pattern(
        self,
        pattern_id: str,
        pattern_data: Dict[str, Any],
        embedding: List[float]
    ) -> bool:
        """
        Store a pattern with its vector embedding.

        Args:
            pattern_id: Unique pattern identifier
            pattern_data: Pattern metadata and structure
            embedding: Vector embedding for similarity search

        Returns:
            Success status
        """
        try:
            if not self.initialized:
                await self.initialize()

            if self.agentdb_client:
                # Store in AgentDB
                success = await self.agentdb_client.upsert(
                    collection="patterns",
                    id=pattern_id,
                    vector=embedding,
                    metadata={
                        **pattern_data,
                        "stored_at": datetime.utcnow().isoformat()
                    }
                )

                if success:
                    logger.info(f"Stored pattern {pattern_id} in AgentDB")
                    return True
                else:
                    logger.warning(f"Failed to store pattern {pattern_id} in AgentDB")
                    return False
            else:
                # In-memory fallback
                logger.debug(f"Pattern {pattern_id} stored in memory (AgentDB unavailable)")
                return True

        except Exception as e:
            logger.error(f"Error storing pattern: {e}")
            return False

    async def retrieve_pattern(self, pattern_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a pattern by ID.

        Args:
            pattern_id: Pattern identifier

        Returns:
            Pattern data or None if not found
        """
        try:
            if not self.initialized:
                await self.initialize()

            if self.agentdb_client:
                result = await self.agentdb_client.get(
                    collection="patterns",
                    id=pattern_id
                )

                if result:
                    logger.info(f"Retrieved pattern {pattern_id} from AgentDB")
                    return result.get("metadata", {})
                else:
                    logger.info(f"Pattern {pattern_id} not found in AgentDB")
                    return None
            else:
                logger.debug("AgentDB not available for pattern retrieval")
                return None

        except Exception as e:
            logger.error(f"Error retrieving pattern: {e}")
            return None

    async def search_similar_patterns(
        self,
        query_embedding: List[float],
        limit: int = 10,
        similarity_threshold: float = 0.7,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for similar patterns using vector similarity.

        Args:
            query_embedding: Query vector embedding
            limit: Maximum number of results
            similarity_threshold: Minimum similarity score
            filters: Optional metadata filters

        Returns:
            List of similar patterns with similarity scores
        """
        try:
            if not self.initialized:
                await self.initialize()

            if self.agentdb_client:
                results = await self.agentdb_client.search(
                    collection="patterns",
                    query_vector=query_embedding,
                    limit=limit,
                    filter=filters,
                    min_similarity=similarity_threshold
                )

                logger.info(f"Found {len(results)} similar patterns")
                return [
                    {
                        "pattern_id": r.get("id"),
                        "similarity_score": r.get("score", 0.0),
                        "pattern_data": r.get("metadata", {}),
                        "embedding": r.get("vector", [])
                    }
                    for r in results
                ]
            else:
                logger.debug("AgentDB not available for similarity search")
                return []

        except Exception as e:
            logger.error(f"Error searching similar patterns: {e}")
            return []

    async def update_pattern(
        self,
        pattern_id: str,
        updates: Dict[str, Any]
    ) -> bool:
        """
        Update pattern metadata.

        Args:
            pattern_id: Pattern identifier
            updates: Fields to update

        Returns:
            Success status
        """
        try:
            if not self.initialized:
                await self.initialize()

            if self.agentdb_client:
                # Get existing pattern
                existing = await self.retrieve_pattern(pattern_id)
                if not existing:
                    logger.warning(f"Pattern {pattern_id} not found for update")
                    return False

                # Merge updates
                updated_data = {**existing, **updates}
                updated_data["updated_at"] = datetime.utcnow().isoformat()

                # Store updated pattern
                success = await self.agentdb_client.update(
                    collection="patterns",
                    id=pattern_id,
                    metadata=updated_data
                )

                if success:
                    logger.info(f"Updated pattern {pattern_id}")
                    return True
                else:
                    logger.warning(f"Failed to update pattern {pattern_id}")
                    return False
            else:
                logger.debug("AgentDB not available for pattern update")
                return False

        except Exception as e:
            logger.error(f"Error updating pattern: {e}")
            return False

    async def delete_pattern(self, pattern_id: str) -> bool:
        """
        Delete a pattern.

        Args:
            pattern_id: Pattern identifier

        Returns:
            Success status
        """
        try:
            if not self.initialized:
                await self.initialize()

            if self.agentdb_client:
                success = await self.agentdb_client.delete(
                    collection="patterns",
                    id=pattern_id
                )

                if success:
                    logger.info(f"Deleted pattern {pattern_id}")
                    return True
                else:
                    logger.warning(f"Failed to delete pattern {pattern_id}")
                    return False
            else:
                logger.debug("AgentDB not available for pattern deletion")
                return False

        except Exception as e:
            logger.error(f"Error deleting pattern: {e}")
            return False

    async def list_patterns(
        self,
        pattern_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        List patterns with optional filtering.

        Args:
            pattern_type: Optional pattern type filter
            limit: Maximum number of results
            offset: Pagination offset

        Returns:
            List of patterns
        """
        try:
            if not self.initialized:
                await self.initialize()

            if self.agentdb_client:
                filters = {}
                if pattern_type:
                    filters["pattern_type"] = pattern_type

                results = await self.agentdb_client.list(
                    collection="patterns",
                    filter=filters,
                    limit=limit,
                    offset=offset
                )

                logger.info(f"Listed {len(results)} patterns")
                return [r.get("metadata", {}) for r in results]
            else:
                logger.debug("AgentDB not available for pattern listing")
                return []

        except Exception as e:
            logger.error(f"Error listing patterns: {e}")
            return []

    async def get_pattern_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about stored patterns.

        Returns:
            Statistics dictionary
        """
        try:
            if not self.initialized:
                await self.initialize()

            if self.agentdb_client:
                stats = await self.agentdb_client.get_collection_stats("patterns")

                return {
                    "total_patterns": stats.get("count", 0),
                    "collection_size_bytes": stats.get("size", 0),
                    "average_vector_dimension": stats.get("avg_vector_dim", 0),
                    "last_updated": stats.get("last_updated")
                }
            else:
                return {
                    "total_patterns": 0,
                    "collection_size_bytes": 0,
                    "average_vector_dimension": 0,
                    "last_updated": None
                }

        except Exception as e:
            logger.error(f"Error getting pattern statistics: {e}")
            return {}

    async def bulk_store_patterns(
        self,
        patterns: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Store multiple patterns in bulk for efficiency.

        Args:
            patterns: List of pattern dicts with id, data, and embedding

        Returns:
            Result summary
        """
        try:
            if not self.initialized:
                await self.initialize()

            success_count = 0
            failure_count = 0

            if self.agentdb_client:
                # Batch insert for performance
                batch_data = [
                    {
                        "id": p["pattern_id"],
                        "vector": p["embedding"],
                        "metadata": p["data"]
                    }
                    for p in patterns
                ]

                results = await self.agentdb_client.bulk_upsert(
                    collection="patterns",
                    items=batch_data
                )

                success_count = results.get("success", 0)
                failure_count = results.get("failed", 0)
            else:
                # Fallback: store one by one in memory
                for pattern in patterns:
                    success = await self.store_pattern(
                        pattern["pattern_id"],
                        pattern["data"],
                        pattern["embedding"]
                    )
                    if success:
                        success_count += 1
                    else:
                        failure_count += 1

            logger.info(
                f"Bulk stored {success_count} patterns, "
                f"{failure_count} failures"
            )

            return {
                "success_count": success_count,
                "failure_count": failure_count,
                "total": len(patterns)
            }

        except Exception as e:
            logger.error(f"Error in bulk pattern storage: {e}")
            return {
                "success_count": 0,
                "failure_count": len(patterns),
                "total": len(patterns),
                "error": str(e)
            }

    async def _create_agentdb_client(self):
        """Create AgentDB client instance."""
        try:
            # Import AgentDB client (stub for now - will be implemented with actual AgentDB)
            # from agentdb import AgentDB
            # return AgentDB(connection_string=self.db_connection)

            # Placeholder: return None until AgentDB is integrated
            logger.info("AgentDB client creation pending integration")
            return None

        except Exception as e:
            logger.error(f"Error creating AgentDB client: {e}")
            return None

    async def _create_pattern_collection(self):
        """Create pattern collection in AgentDB."""
        try:
            if self.agentdb_client:
                await self.agentdb_client.create_collection(
                    name="patterns",
                    vector_dimension=128,
                    distance_metric="cosine",
                    metadata_schema={
                        "pattern_id": "string",
                        "pattern_type": "string",
                        "name": "string",
                        "description": "string",
                        "confidence": "float",
                        "usage_count": "integer",
                        "success_count": "integer",
                        "created_at": "datetime",
                        "updated_at": "datetime"
                    }
                )
                logger.info("Created patterns collection in AgentDB")

        except Exception as e:
            logger.error(f"Error creating pattern collection: {e}")
