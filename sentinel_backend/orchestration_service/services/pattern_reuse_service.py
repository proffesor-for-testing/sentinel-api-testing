"""
Pattern Reuse Service - Phase 2 AgentDB Integration

Semantic search for similar test patterns and intelligent pattern adaptation.
Enables agents to reuse proven patterns for new API specs, reducing generation
time by 30-50%.
"""

import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import numpy as np
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class PatternMatch(BaseModel):
    """Represents a pattern match result with confidence scoring."""
    pattern_id: str
    pattern_type: str
    endpoint_pattern: str
    http_method: str
    similarity_score: float  # Cosine similarity (0-1)
    confidence_score: float  # Pattern's historical confidence
    combined_score: float  # similarity * confidence
    match_reason: str
    test_structure: Dict[str, Any]
    api_characteristics: Dict[str, Any]
    usage_statistics: Dict[str, Any]


class AdaptedPattern(BaseModel):
    """Pattern adapted for a new context."""
    original_pattern_id: str
    adapted_test_case: Dict[str, Any]
    adaptation_notes: List[str]
    confidence: float


class PatternReuseService:
    """
    Service for semantic search and intelligent pattern reuse.

    Core responsibilities:
    1. Semantic search for similar API patterns using vector embeddings
    2. Score patterns by similarity + confidence + success rate
    3. Adapt patterns to new API contexts
    4. Generate test cases from patterns
    5. Track pattern versioning and evolution
    """

    def __init__(
        self,
        agentdb_client,
        embedding_service,
        similarity_threshold: float = 0.7
    ):
        """
        Initialize Pattern Reuse Service.

        Args:
            agentdb_client: AgentDB client for vector search
            embedding_service: Service for generating embeddings
            similarity_threshold: Minimum similarity for pattern matching (0-1)
        """
        self.agentdb = agentdb_client
        self.embedding_service = embedding_service
        self.similarity_threshold = similarity_threshold
        self.collection = "sentinel_test_patterns"

        logger.info(
            f"PatternReuseService initialized with threshold={similarity_threshold}"
        )

    async def find_similar_patterns(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        pattern_type: Optional[str] = None,
        top_k: int = 5
    ) -> List[PatternMatch]:
        """
        Find patterns similar to the given API endpoint using semantic search.

        Args:
            api_spec: API specification for context
            endpoint: Target endpoint to match
            method: HTTP method (GET, POST, etc.)
            pattern_type: Filter by pattern type (optional)
            top_k: Number of results to return

        Returns:
            List of PatternMatch results sorted by combined score
        """
        try:
            # Normalize endpoint
            endpoint_pattern = self._normalize_endpoint(endpoint)

            # Extract API characteristics for richer search
            api_characteristics = self._extract_api_characteristics(
                endpoint,
                method,
                api_spec
            )

            # Generate query embedding
            query_dict = {
                "method": method,
                "endpoint": endpoint_pattern,
                "characteristics": api_characteristics
            }
            query_embedding = await self._generate_query_embedding(query_dict)

            # Perform vector search in AgentDB
            search_filters = {}
            if pattern_type:
                search_filters["pattern_type"] = pattern_type

            results = await self.agentdb.vector_search(
                collection=self.collection,
                query_vector=query_embedding,
                top_k=top_k * 2,  # Get more, then filter
                filters=search_filters
            )

            # Convert to PatternMatch objects with scoring
            matches = []
            for result in results:
                metadata = result.get("metadata", {})
                similarity = result.get("score", 0.0)

                # Only consider matches above threshold
                if similarity < self.similarity_threshold:
                    continue

                # Calculate combined score
                confidence = metadata.get("confidence_score", 1.0)
                success_rate = metadata.get("success_metrics", {}).get("success_rate", 1.0)
                combined_score = similarity * confidence * success_rate

                # Build match reason
                match_reason = self._generate_match_reason(
                    similarity,
                    metadata,
                    api_characteristics
                )

                match = PatternMatch(
                    pattern_id=metadata.get("pattern_id", result.get("id")),
                    pattern_type=metadata.get("pattern_type", "unknown"),
                    endpoint_pattern=metadata.get("endpoint_pattern", ""),
                    http_method=metadata.get("http_method", ""),
                    similarity_score=similarity,
                    confidence_score=confidence,
                    combined_score=combined_score,
                    match_reason=match_reason,
                    test_structure=metadata.get("test_structure", {}),
                    api_characteristics=metadata.get("api_characteristics", {}),
                    usage_statistics={
                        "usage_count": metadata.get("usage_count", 0),
                        "success_count": metadata.get("success_count", 0),
                        "failure_count": metadata.get("failure_count", 0),
                        "success_rate": success_rate
                    }
                )

                matches.append(match)

            # Sort by combined score
            matches.sort(key=lambda m: m.combined_score, reverse=True)

            # Return top_k results
            matches = matches[:top_k]

            logger.info(
                f"Found {len(matches)} matching patterns for {method} {endpoint} "
                f"(top score: {matches[0].combined_score:.3f})" if matches else
                f"Found 0 matching patterns for {method} {endpoint}"
            )

            return matches

        except Exception as e:
            logger.error(f"Failed to find similar patterns: {e}", exc_info=True)
            return []

    async def adapt_pattern_to_context(
        self,
        pattern_match: PatternMatch,
        target_endpoint: str,
        target_method: str,
        api_spec: Dict[str, Any]
    ) -> AdaptedPattern:
        """
        Adapt a pattern to a new API context.

        This is where the magic happens - we take a proven pattern and customize
        it for a new endpoint while preserving the core test logic.

        Args:
            pattern_match: Matched pattern to adapt
            target_endpoint: Target endpoint for adaptation
            target_method: Target HTTP method
            api_spec: Target API specification

        Returns:
            AdaptedPattern with customized test case
        """
        try:
            adaptation_notes = []
            adapted_test = {}

            # Start with pattern structure
            test_structure = pattern_match.test_structure

            # Adapt endpoint and method
            adapted_test["endpoint"] = target_endpoint
            adapted_test["method"] = target_method
            adapted_test["test_type"] = pattern_match.pattern_type
            adapted_test["description"] = (
                f"Pattern-based test (from {pattern_match.pattern_id}): "
                f"{target_method} {target_endpoint}"
            )
            adapted_test["tags"] = ["pattern-generated", pattern_match.pattern_type]
            adapted_test["pattern_id"] = pattern_match.pattern_id

            # Adapt headers
            adapted_test["headers"] = test_structure.get("headers", {
                "Content-Type": "application/json",
                "Accept": "application/json"
            })
            adaptation_notes.append("Applied standard headers from pattern")

            # Adapt query parameters
            if test_structure.get("query_params_structure"):
                adapted_test["query_params"] = self._generate_params_from_structure(
                    test_structure["query_params_structure"],
                    api_spec
                )
                adaptation_notes.append(
                    f"Generated {len(adapted_test['query_params'])} query parameters"
                )

            # Adapt request body
            if test_structure.get("body_structure"):
                adapted_test["body"] = self._generate_body_from_structure(
                    test_structure["body_structure"],
                    api_spec,
                    target_endpoint
                )
                adaptation_notes.append("Generated request body from schema")

            # Adapt assertions
            adapted_test["assertions"] = test_structure.get("assertions", [])
            adapted_test["expected_status"] = test_structure.get("expected_status", 200)
            adaptation_notes.append(
                f"Applied {len(adapted_test['assertions'])} assertions"
            )

            # Adapt authentication
            if test_structure.get("auth_required"):
                adapted_test["auth_required"] = True
                adapted_test["auth_type"] = "bearer"  # Default
                adaptation_notes.append("Authentication required")

            # Calculate confidence
            # Confidence decreases with adaptation distance
            confidence = pattern_match.combined_score * 0.9  # Slight penalty for adaptation

            adapted = AdaptedPattern(
                original_pattern_id=pattern_match.pattern_id,
                adapted_test_case=adapted_test,
                adaptation_notes=adaptation_notes,
                confidence=confidence
            )

            logger.info(
                f"Adapted pattern {pattern_match.pattern_id} to "
                f"{target_method} {target_endpoint} (confidence: {confidence:.3f})"
            )

            return adapted

        except Exception as e:
            logger.error(f"Failed to adapt pattern: {e}", exc_info=True)
            # Return empty adaptation
            return AdaptedPattern(
                original_pattern_id=pattern_match.pattern_id,
                adapted_test_case={},
                adaptation_notes=[f"Adaptation failed: {str(e)}"],
                confidence=0.0
            )

    async def generate_tests_from_patterns(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        pattern_type: str,
        max_tests: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple test cases from patterns.

        This is the high-level interface agents use to get pattern-based tests.

        Args:
            api_spec: API specification
            endpoint: Target endpoint
            method: HTTP method
            pattern_type: Type of tests to generate
            max_tests: Maximum number of tests to generate

        Returns:
            List of generated test cases
        """
        try:
            # Find similar patterns
            matches = await self.find_similar_patterns(
                api_spec=api_spec,
                endpoint=endpoint,
                method=method,
                pattern_type=pattern_type,
                top_k=max_tests
            )

            if not matches:
                logger.info(
                    f"No patterns found for {method} {endpoint}, "
                    "agent will generate from scratch"
                )
                return []

            # Adapt each pattern
            generated_tests = []
            for match in matches:
                adapted = await self.adapt_pattern_to_context(
                    pattern_match=match,
                    target_endpoint=endpoint,
                    target_method=method,
                    api_spec=api_spec
                )

                # Only use adaptations with reasonable confidence
                if adapted.confidence >= 0.5:
                    test_case = adapted.adapted_test_case
                    test_case["metadata"] = {
                        "pattern_id": match.pattern_id,
                        "pattern_confidence": match.confidence_score,
                        "similarity_score": match.similarity_score,
                        "combined_score": match.combined_score,
                        "adaptation_notes": adapted.adaptation_notes,
                        "generated_from_pattern": True
                    }
                    generated_tests.append(test_case)

            logger.info(
                f"Generated {len(generated_tests)} tests from patterns for "
                f"{method} {endpoint}"
            )

            return generated_tests

        except Exception as e:
            logger.error(f"Failed to generate tests from patterns: {e}", exc_info=True)
            return []

    async def get_pattern_by_id(
        self,
        pattern_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve a specific pattern by ID.

        Args:
            pattern_id: Pattern ID

        Returns:
            Pattern metadata dict or None
        """
        try:
            # Search with exact ID filter
            results = await self.agentdb.vector_search(
                collection=self.collection,
                query_vector=[0.0] * 384,  # Dummy vector for ID lookup
                top_k=1,
                filters={"pattern_id": pattern_id}
            )

            if results:
                return results[0].get("metadata")

            return None

        except Exception as e:
            logger.error(f"Failed to get pattern by ID: {e}", exc_info=True)
            return None

    async def get_pattern_versions(
        self,
        pattern_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get version history of a pattern.

        Patterns evolve over time as they're used and refined.

        Args:
            pattern_id: Pattern ID

        Returns:
            List of pattern versions sorted by date
        """
        try:
            # In a full implementation, we'd track versions in a separate table
            # For now, return the current version
            pattern = await self.get_pattern_by_id(pattern_id)

            if pattern:
                return [pattern]

            return []

        except Exception as e:
            logger.error(f"Failed to get pattern versions: {e}", exc_info=True)
            return []

    # Private helper methods

    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint by replacing IDs with placeholders."""
        import re
        endpoint = re.sub(r'/\d+', '/{id}', endpoint)
        endpoint = re.sub(
            r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            '/{id}',
            endpoint,
            flags=re.IGNORECASE
        )
        endpoint = re.sub(r'/[a-zA-Z0-9_-]{10,}', '/{id}', endpoint)
        return endpoint

    def _extract_api_characteristics(
        self,
        endpoint: str,
        method: str,
        api_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract API characteristics for semantic matching."""
        return {
            "has_path_params": "{" in endpoint or "/:" in endpoint,
            "method": method,
            "resource_type": self._identify_resource_type(endpoint),
            "endpoint_depth": len([p for p in endpoint.split("/") if p]),
            "is_collection": not self._has_id_in_path(endpoint),
            "is_singular": self._has_id_in_path(endpoint)
        }

    def _identify_resource_type(self, endpoint: str) -> str:
        """Identify resource type from endpoint."""
        parts = [p for p in endpoint.split("/") if p and "{" not in p and ":" not in p]
        if parts:
            return parts[-1]
        return "unknown"

    def _has_id_in_path(self, endpoint: str) -> bool:
        """Check if endpoint has an ID parameter."""
        return "{id}" in endpoint or "/{id}" in endpoint or "/:" in endpoint

    async def _generate_query_embedding(
        self,
        query_dict: Dict[str, Any]
    ) -> List[float]:
        """Generate embedding for query."""
        try:
            embedding = self.embedding_service.embed_test_pattern(query_dict)

            if isinstance(embedding, np.ndarray):
                embedding = embedding.tolist()

            return embedding

        except Exception as e:
            logger.error(f"Failed to generate query embedding: {e}", exc_info=True)
            return [0.0] * 384

    def _generate_match_reason(
        self,
        similarity: float,
        pattern_metadata: Dict[str, Any],
        query_characteristics: Dict[str, Any]
    ) -> str:
        """Generate human-readable match reason."""
        reasons = []

        # Similarity level
        if similarity >= 0.9:
            reasons.append("Very high semantic similarity")
        elif similarity >= 0.8:
            reasons.append("High semantic similarity")
        else:
            reasons.append("Moderate semantic similarity")

        # Same resource type
        pattern_resource = pattern_metadata.get("api_characteristics", {}).get("resource_type")
        query_resource = query_characteristics.get("resource_type")
        if pattern_resource == query_resource:
            reasons.append(f"Same resource type ({pattern_resource})")

        # Same characteristics
        pattern_chars = pattern_metadata.get("api_characteristics", {})
        if pattern_chars.get("has_path_params") == query_characteristics.get("has_path_params"):
            reasons.append("Similar path structure")

        # High success rate
        success_rate = pattern_metadata.get("success_metrics", {}).get("success_rate", 0)
        if success_rate >= 0.9:
            reasons.append(f"High success rate ({success_rate:.1%})")

        # Frequently used
        usage_count = pattern_metadata.get("usage_count", 0)
        if usage_count >= 10:
            reasons.append(f"Frequently used ({usage_count} times)")

        return " | ".join(reasons)

    def _generate_params_from_structure(
        self,
        param_structure: Dict[str, str],
        api_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate query parameters from structure."""
        params = {}

        for param_name, param_type in param_structure.items():
            # Generate appropriate values based on type and name
            if param_type == "int":
                if "limit" in param_name.lower():
                    params[param_name] = 10
                elif "offset" in param_name.lower() or "page" in param_name.lower():
                    params[param_name] = 0
                else:
                    params[param_name] = 1
            elif param_type == "bool":
                params[param_name] = True
            elif param_type == "list":
                params[param_name] = []
            else:  # string
                if "sort" in param_name.lower():
                    params[param_name] = "asc"
                elif "filter" in param_name.lower():
                    params[param_name] = "active"
                else:
                    params[param_name] = "test_value"

        return params

    def _generate_body_from_structure(
        self,
        body_structure: Dict[str, Any],
        api_spec: Dict[str, Any],
        endpoint: str
    ) -> Dict[str, Any]:
        """Generate request body from structure."""
        def generate_value(field_name: str, field_type: str) -> Any:
            """Generate appropriate value for field."""
            field_lower = field_name.lower()

            if field_type == "int":
                if "age" in field_lower:
                    return 25
                elif "count" in field_lower:
                    return 10
                else:
                    return 1
            elif field_type == "bool":
                return True
            elif field_type == "list":
                return []
            elif field_type == "dict":
                return {}
            else:  # string
                if "email" in field_lower:
                    return "test@example.com"
                elif "name" in field_lower:
                    return "Test Name"
                elif "url" in field_lower:
                    return "https://example.com"
                elif "date" in field_lower:
                    return "2024-01-01"
                elif "id" in field_lower:
                    return "test_id_123"
                else:
                    return f"test_{field_name}"

        def process_structure(structure: Dict[str, Any]) -> Dict[str, Any]:
            """Recursively process structure."""
            result = {}
            for key, value in structure.items():
                if isinstance(value, dict):
                    result[key] = process_structure(value)
                elif isinstance(value, str):
                    result[key] = generate_value(key, value)
                else:
                    result[key] = value
            return result

        return process_structure(body_structure)
