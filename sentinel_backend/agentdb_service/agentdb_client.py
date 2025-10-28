"""
AgentDB Client

Wrapper for AgentDB MCP tools via claude-flow for vector operations.
Provides high-level interface for semantic search and pattern storage.
"""

import subprocess
import json
import logging
from typing import List, Dict, Optional, Any
import numpy as np

logger = logging.getLogger(__name__)


class AgentDBClient:
    """Client for AgentDB vector database via MCP tools."""

    def __init__(self, collection_prefix: str = "sentinel"):
        """
        Initialize AgentDB client.

        Args:
            collection_prefix: Prefix for collection names
        """
        self.collection_prefix = collection_prefix
        self.collections = {
            "test_patterns": f"{collection_prefix}_test_patterns",
            "execution_results": f"{collection_prefix}_executions",
            "agent_behaviors": f"{collection_prefix}_behaviors"
        }
        logger.info(f"Initialized AgentDB client with prefix: {collection_prefix}")

    async def initialize_collections(self):
        """Initialize all required collections."""
        for name, collection in self.collections.items():
            try:
                await self._create_collection(collection)
                logger.info(f"Initialized collection: {collection}")
            except Exception as e:
                logger.warning(f"Collection {collection} may already exist: {e}")

    async def _create_collection(self, name: str):
        """Create a collection via MCP tool."""
        # Note: AgentDB MCP tools handle collection creation automatically
        # This is a placeholder for explicit creation if needed
        pass

    async def vector_insert(
        self,
        collection: str,
        vectors: List[List[float]],
        metadata: List[Dict],
        ids: Optional[List[str]] = None
    ) -> Dict:
        """
        Insert vectors into collection.

        Args:
            collection: Collection name
            vectors: List of vector embeddings
            metadata: List of metadata dicts (one per vector)
            ids: Optional list of IDs

        Returns:
            Result dictionary with status and inserted IDs
        """
        if not ids:
            import uuid
            ids = [str(uuid.uuid4()) for _ in range(len(vectors))]

        if len(vectors) != len(metadata) or len(vectors) != len(ids):
            raise ValueError("vectors, metadata, and ids must have same length")

        try:
            # Prepare data for AgentDB
            items = []
            for i, (vector, meta, item_id) in enumerate(zip(vectors, metadata, ids)):
                items.append({
                    "id": item_id,
                    "vector": vector,
                    "metadata": {
                        **meta,
                        "collection": collection,
                        "inserted_at": self._get_timestamp()
                    }
                })

            # Use AgentDB MCP tool via subprocess
            # In production, this would use the MCP server directly
            result = await self._execute_mcp_tool(
                "vector_insert",
                {
                    "collection": collection,
                    "items": items
                }
            )

            logger.info(f"Inserted {len(vectors)} vectors into {collection}")
            return {
                "status": "success",
                "inserted": len(vectors),
                "ids": ids
            }

        except Exception as e:
            logger.error(f"Failed to insert vectors: {e}")
            raise

    async def vector_search(
        self,
        collection: str,
        query_vector: List[float],
        top_k: int = 10,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Search for similar vectors using HNSW index.

        Args:
            collection: Collection name
            query_vector: Query embedding
            top_k: Number of results to return
            filters: Optional metadata filters

        Returns:
            List of results with scores and metadata
        """
        try:
            # Execute semantic search via MCP
            result = await self._execute_mcp_tool(
                "vector_search",
                {
                    "collection": collection,
                    "query_vector": query_vector,
                    "top_k": top_k,
                    "filters": filters or {}
                }
            )

            # Parse and return results
            results = result.get("results", [])
            logger.info(f"Found {len(results)} similar vectors in {collection}")

            return [
                {
                    "id": item["id"],
                    "score": item["score"],
                    "metadata": item["metadata"]
                }
                for item in results
            ]

        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            raise

    async def batch_search(
        self,
        collection: str,
        query_vectors: List[List[float]],
        top_k: int = 10
    ) -> List[List[Dict]]:
        """
        Batch semantic search for multiple queries.

        Args:
            collection: Collection name
            query_vectors: List of query embeddings
            top_k: Number of results per query

        Returns:
            List of result lists
        """
        results = []
        for query_vector in query_vectors:
            result = await self.vector_search(collection, query_vector, top_k)
            results.append(result)

        return results

    async def get_stats(self, collection: str) -> Dict:
        """
        Get collection statistics.

        Args:
            collection: Collection name

        Returns:
            Statistics dictionary
        """
        try:
            result = await self._execute_mcp_tool(
                "collection_stats",
                {"collection": collection}
            )

            return {
                "collection": collection,
                "vector_count": result.get("count", 0),
                "dimension": result.get("dimension", 384),
                "index_type": "HNSW",
                "memory_mb": result.get("memory_mb", 0)
            }

        except Exception as e:
            logger.error(f"Failed to get stats for {collection}: {e}")
            return {
                "collection": collection,
                "vector_count": 0,
                "error": str(e)
            }

    async def delete_vectors(
        self,
        collection: str,
        ids: List[str]
    ) -> Dict:
        """
        Delete vectors by ID.

        Args:
            collection: Collection name
            ids: List of vector IDs to delete

        Returns:
            Result dictionary
        """
        try:
            result = await self._execute_mcp_tool(
                "vector_delete",
                {
                    "collection": collection,
                    "ids": ids
                }
            )

            logger.info(f"Deleted {len(ids)} vectors from {collection}")
            return {
                "status": "success",
                "deleted": len(ids)
            }

        except Exception as e:
            logger.error(f"Failed to delete vectors: {e}")
            raise

    async def update_metadata(
        self,
        collection: str,
        id: str,
        metadata: Dict
    ) -> Dict:
        """
        Update metadata for a vector.

        Args:
            collection: Collection name
            id: Vector ID
            metadata: New metadata

        Returns:
            Result dictionary
        """
        try:
            result = await self._execute_mcp_tool(
                "metadata_update",
                {
                    "collection": collection,
                    "id": id,
                    "metadata": metadata
                }
            )

            return {
                "status": "success",
                "updated": id
            }

        except Exception as e:
            logger.error(f"Failed to update metadata: {e}")
            raise

    async def _execute_mcp_tool(
        self,
        tool_name: str,
        params: Dict
    ) -> Dict:
        """
        Execute AgentDB MCP tool via claude-flow.

        Args:
            tool_name: MCP tool name
            params: Tool parameters

        Returns:
            Tool execution result

        Note:
            In production, this would connect to the MCP server.
            For now, we simulate with in-memory storage.
        """
        # Placeholder implementation
        # In production, this would call:
        # npx claude-flow@alpha mcp agentdb {tool_name} --params {json_params}

        logger.debug(f"MCP tool call: {tool_name} with params: {params}")

        # Simulated response for development
        if tool_name == "vector_insert":
            return {"status": "success", "inserted": len(params.get("items", []))}
        elif tool_name == "vector_search":
            return {"status": "success", "results": []}
        elif tool_name == "collection_stats":
            return {"count": 0, "dimension": 384, "memory_mb": 0}
        else:
            return {"status": "success"}

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat()


class AgentDBError(Exception):
    """Base exception for AgentDB operations."""
    pass


class CollectionNotFoundError(AgentDBError):
    """Collection does not exist."""
    pass


class VectorInsertError(AgentDBError):
    """Failed to insert vectors."""
    pass


class VectorSearchError(AgentDBError):
    """Failed to search vectors."""
    pass
