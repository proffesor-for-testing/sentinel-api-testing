"""
Pattern Recognition Service for learning from test execution history.

This service analyzes successful and failed tests to extract reusable patterns,
reducing duplicate test generation and improving test quality over time.
"""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from enum import Enum
import logging
import json
import hashlib
from pydantic import BaseModel
import numpy as np

logger = logging.getLogger(__name__)


class PatternType(str, Enum):
    """Types of patterns that can be recognized."""
    API_PATTERN = "api_pattern"              # API structure patterns (REST, paths)
    PARAMETER_PATTERN = "parameter_pattern"  # Parameter usage patterns
    ASSERTION_PATTERN = "assertion_pattern"  # Common assertion patterns
    ERROR_PATTERN = "error_pattern"          # Failure patterns
    AUTH_PATTERN = "auth_pattern"            # Authentication patterns
    WORKFLOW_PATTERN = "workflow_pattern"    # Multi-step workflow patterns


class PatternContext(BaseModel):
    """Context information for a pattern."""
    api_spec_id: Optional[int] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    test_type: Optional[str] = None
    tags: List[str] = []


class Pattern(BaseModel):
    """Represents a learned pattern."""
    pattern_id: str
    pattern_type: PatternType
    name: str
    description: str
    structure: Dict[str, Any]
    context: PatternContext
    confidence: float = 1.0
    usage_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    created_at: datetime = datetime.utcnow()
    updated_at: datetime = datetime.utcnow()
    embedding: Optional[List[float]] = None

    class Config:
        use_enum_values = True


class PatternMatch(BaseModel):
    """Represents a pattern match result."""
    pattern: Pattern
    similarity_score: float
    match_reason: str
    confidence: float


class PatternRecognitionService:
    """
    Service for recognizing and learning from test patterns.

    Responsibilities:
    - Extract patterns from test execution history
    - Store patterns with vector embeddings
    - Match new API specs to existing patterns
    - Suggest test templates based on patterns
    - Learn from pattern reuse success/failure
    """

    def __init__(self, vector_db_client=None, reasoning_bank_client=None):
        """
        Initialize the pattern recognition service.

        Args:
            vector_db_client: AgentDB client for vector storage
            reasoning_bank_client: ReasoningBank client for learning
        """
        self.vector_db = vector_db_client
        self.reasoning_bank = reasoning_bank_client
        self.patterns: Dict[str, Pattern] = {}
        self.pattern_cache: Dict[str, List[Pattern]] = {}
        logger.info("Pattern Recognition Service initialized")

    async def extract_pattern_from_test(
        self,
        test_case: Dict[str, Any],
        execution_result: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Pattern]:
        """
        Extract patterns from a test case and its execution result.

        Args:
            test_case: The test case definition
            execution_result: The execution result (success/failure)
            api_spec: The API specification

        Returns:
            List of extracted patterns
        """
        patterns = []

        try:
            # Extract different types of patterns
            api_patterns = self._extract_api_patterns(test_case, api_spec)
            param_patterns = self._extract_parameter_patterns(test_case)
            assertion_patterns = self._extract_assertion_patterns(test_case)

            # If test failed, extract error patterns
            if execution_result.get("status") == "failed":
                error_patterns = self._extract_error_patterns(test_case, execution_result)
                patterns.extend(error_patterns)

            # If test succeeded, strengthen success patterns
            if execution_result.get("status") == "success":
                patterns.extend(api_patterns)
                patterns.extend(param_patterns)
                patterns.extend(assertion_patterns)

            # Generate embeddings for patterns
            for pattern in patterns:
                pattern.embedding = await self._generate_pattern_embedding(pattern)

            logger.info(f"Extracted {len(patterns)} patterns from test case")
            return patterns

        except Exception as e:
            logger.error(f"Error extracting patterns: {e}")
            return []

    def _extract_api_patterns(
        self,
        test_case: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Pattern]:
        """Extract API structure patterns."""
        patterns = []

        endpoint = test_case.get("endpoint", "")
        method = test_case.get("method", "")

        # Extract path pattern (e.g., /api/v1/users/{id})
        path_pattern = self._normalize_path(endpoint)

        # Create API structure pattern
        pattern = Pattern(
            pattern_id=self._generate_pattern_id(f"api_{method}_{path_pattern}"),
            pattern_type=PatternType.API_PATTERN,
            name=f"{method} {path_pattern}",
            description=f"API pattern for {method} requests to {path_pattern}",
            structure={
                "method": method,
                "path_pattern": path_pattern,
                "path_segments": len(path_pattern.split("/")),
                "has_path_params": "{" in endpoint,
                "resource_type": self._identify_resource_type(path_pattern)
            },
            context=PatternContext(
                endpoint=endpoint,
                method=method,
                test_type=test_case.get("test_type"),
                tags=test_case.get("tags", [])
            )
        )

        patterns.append(pattern)
        return patterns

    def _extract_parameter_patterns(self, test_case: Dict[str, Any]) -> List[Pattern]:
        """Extract parameter usage patterns."""
        patterns = []

        # Analyze query parameters
        query_params = test_case.get("query_params", {})
        if query_params:
            param_structure = {
                "param_count": len(query_params),
                "param_names": sorted(query_params.keys()),
                "param_types": {
                    k: type(v).__name__ for k, v in query_params.items()
                }
            }

            pattern = Pattern(
                pattern_id=self._generate_pattern_id(
                    f"params_{','.join(sorted(query_params.keys()))}"
                ),
                pattern_type=PatternType.PARAMETER_PATTERN,
                name=f"Query params: {', '.join(sorted(query_params.keys()))}",
                description="Common query parameter combination",
                structure=param_structure,
                context=PatternContext(
                    method=test_case.get("method"),
                    test_type=test_case.get("test_type")
                )
            )
            patterns.append(pattern)

        # Analyze request body structure
        body = test_case.get("body", {})
        if body:
            body_structure = {
                "field_count": len(body),
                "field_names": sorted(body.keys()),
                "field_types": {k: type(v).__name__ for k, v in body.items()},
                "nested_objects": self._count_nested_objects(body)
            }

            pattern = Pattern(
                pattern_id=self._generate_pattern_id(
                    f"body_{','.join(sorted(body.keys()))}"
                ),
                pattern_type=PatternType.PARAMETER_PATTERN,
                name=f"Request body: {', '.join(sorted(body.keys()))}",
                description="Common request body structure",
                structure=body_structure,
                context=PatternContext(
                    method=test_case.get("method"),
                    test_type=test_case.get("test_type")
                )
            )
            patterns.append(pattern)

        return patterns

    def _extract_assertion_patterns(self, test_case: Dict[str, Any]) -> List[Pattern]:
        """Extract assertion patterns."""
        patterns = []

        assertions = test_case.get("assertions", [])
        if assertions:
            assertion_structure = {
                "assertion_count": len(assertions),
                "assertion_types": [a.get("type") for a in assertions],
                "expected_status": test_case.get("expected_status"),
                "has_schema_validation": any(
                    a.get("type") == "response_schema" for a in assertions
                )
            }

            pattern = Pattern(
                pattern_id=self._generate_pattern_id(
                    f"assertions_{len(assertions)}"
                ),
                pattern_type=PatternType.ASSERTION_PATTERN,
                name=f"Assertions: {', '.join(assertion_structure['assertion_types'])}",
                description="Common assertion pattern",
                structure=assertion_structure,
                context=PatternContext(
                    method=test_case.get("method"),
                    test_type=test_case.get("test_type")
                )
            )
            patterns.append(pattern)

        return patterns

    def _extract_error_patterns(
        self,
        test_case: Dict[str, Any],
        execution_result: Dict[str, Any]
    ) -> List[Pattern]:
        """Extract patterns from failed tests."""
        patterns = []

        error_info = {
            "error_type": execution_result.get("error_type"),
            "status_code": execution_result.get("status_code"),
            "error_message": execution_result.get("error_message", ""),
            "test_type": test_case.get("test_type"),
            "endpoint": test_case.get("endpoint"),
            "method": test_case.get("method")
        }

        pattern = Pattern(
            pattern_id=self._generate_pattern_id(
                f"error_{error_info['error_type']}_{error_info['status_code']}"
            ),
            pattern_type=PatternType.ERROR_PATTERN,
            name=f"Error: {error_info['error_type']}",
            description=f"Common error pattern: {error_info['error_message'][:100]}",
            structure=error_info,
            context=PatternContext(
                endpoint=test_case.get("endpoint"),
                method=test_case.get("method"),
                test_type=test_case.get("test_type")
            )
        )

        patterns.append(pattern)
        return patterns

    async def find_matching_patterns(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        similarity_threshold: float = 0.7
    ) -> List[PatternMatch]:
        """
        Find patterns that match the given API specification.

        Args:
            api_spec: The API specification
            endpoint: The endpoint path
            method: The HTTP method
            similarity_threshold: Minimum similarity score (0-1)

        Returns:
            List of matching patterns sorted by similarity
        """
        try:
            # Generate query embedding
            query_data = {
                "method": method,
                "endpoint": endpoint,
                "path_pattern": self._normalize_path(endpoint)
            }
            query_embedding = await self._generate_embedding(json.dumps(query_data))

            # Search for similar patterns
            matches = []

            # Check cached patterns first
            cache_key = f"{method}_{self._normalize_path(endpoint)}"
            if cache_key in self.pattern_cache:
                cached_patterns = self.pattern_cache[cache_key]
                for pattern in cached_patterns:
                    similarity = self._calculate_similarity(
                        query_embedding,
                        pattern.embedding or []
                    )
                    if similarity >= similarity_threshold:
                        matches.append(PatternMatch(
                            pattern=pattern,
                            similarity_score=similarity,
                            match_reason="Semantic similarity",
                            confidence=pattern.confidence
                        ))

            # Also check rule-based matching
            rule_matches = self._rule_based_matching(endpoint, method)
            matches.extend(rule_matches)

            # Sort by combined score (similarity * confidence)
            matches.sort(
                key=lambda x: x.similarity_score * x.confidence,
                reverse=True
            )

            logger.info(f"Found {len(matches)} matching patterns for {method} {endpoint}")
            return matches

        except Exception as e:
            logger.error(f"Error finding matching patterns: {e}")
            return []

    def _rule_based_matching(self, endpoint: str, method: str) -> List[PatternMatch]:
        """Perform rule-based pattern matching."""
        matches = []

        path_pattern = self._normalize_path(endpoint)
        resource_type = self._identify_resource_type(path_pattern)

        # Match patterns with same resource type and method
        for pattern in self.patterns.values():
            if pattern.pattern_type == PatternType.API_PATTERN:
                pattern_method = pattern.structure.get("method")
                pattern_resource = pattern.structure.get("resource_type")

                if pattern_method == method and pattern_resource == resource_type:
                    matches.append(PatternMatch(
                        pattern=pattern,
                        similarity_score=0.85,
                        match_reason=f"Same resource type: {resource_type}",
                        confidence=pattern.confidence
                    ))

        return matches

    async def generate_test_from_pattern(
        self,
        pattern: Pattern,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str
    ) -> Dict[str, Any]:
        """
        Generate a test case based on a pattern.

        Args:
            pattern: The pattern to use as template
            api_spec: The API specification
            endpoint: The target endpoint
            method: The HTTP method

        Returns:
            Generated test case
        """
        try:
            # Start with pattern structure
            test_case = {
                "method": method,
                "endpoint": endpoint,
                "test_type": pattern.context.test_type or "functional-positive",
                "description": f"Pattern-based test: {pattern.name}",
                "tags": pattern.context.tags + ["pattern-generated"],
                "pattern_id": pattern.pattern_id
            }

            # Apply parameter patterns
            if pattern.pattern_type == PatternType.PARAMETER_PATTERN:
                if "param_names" in pattern.structure:
                    test_case["query_params"] = self._generate_params_from_pattern(
                        pattern.structure,
                        api_spec
                    )
                if "field_names" in pattern.structure:
                    test_case["body"] = self._generate_body_from_pattern(
                        pattern.structure,
                        api_spec
                    )

            # Apply assertion patterns
            if pattern.pattern_type == PatternType.ASSERTION_PATTERN:
                test_case["assertions"] = self._generate_assertions_from_pattern(
                    pattern.structure
                )
                test_case["expected_status"] = pattern.structure.get(
                    "expected_status",
                    200
                )

            # Apply API patterns
            if pattern.pattern_type == PatternType.API_PATTERN:
                test_case["headers"] = {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }

            logger.info(f"Generated test case from pattern: {pattern.pattern_id}")
            return test_case

        except Exception as e:
            logger.error(f"Error generating test from pattern: {e}")
            return {}

    async def update_pattern_feedback(
        self,
        pattern_id: str,
        success: bool,
        execution_time: Optional[float] = None
    ):
        """
        Update pattern statistics based on usage feedback.

        Args:
            pattern_id: The pattern ID
            success: Whether the pattern usage was successful
            execution_time: Optional execution time for performance tracking
        """
        try:
            pattern = self.patterns.get(pattern_id)
            if not pattern:
                logger.warning(f"Pattern not found: {pattern_id}")
                return

            # Update statistics
            pattern.usage_count += 1
            if success:
                pattern.success_count += 1
            else:
                pattern.failure_count += 1

            # Update confidence based on success rate
            if pattern.usage_count > 0:
                success_rate = pattern.success_count / pattern.usage_count
                # Confidence grows with successful usage
                pattern.confidence = min(
                    1.0,
                    pattern.confidence * 0.9 + success_rate * 0.1
                )

            pattern.updated_at = datetime.utcnow()

            # Store updated pattern
            await self._store_pattern(pattern)

            # Feed back to ReasoningBank for learning
            if self.reasoning_bank:
                await self._update_reasoning_bank(pattern, success, execution_time)

            logger.info(
                f"Updated pattern {pattern_id}: "
                f"confidence={pattern.confidence:.2f}, "
                f"success_rate={pattern.success_count}/{pattern.usage_count}"
            )

        except Exception as e:
            logger.error(f"Error updating pattern feedback: {e}")

    async def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get statistics about pattern usage and effectiveness."""
        try:
            total_patterns = len(self.patterns)
            if total_patterns == 0:
                return {
                    "total_patterns": 0,
                    "patterns_by_type": {},
                    "average_confidence": 0,
                    "total_usage": 0,
                    "success_rate": 0
                }

            patterns_by_type = {}
            total_usage = 0
            total_success = 0
            total_confidence = 0

            for pattern in self.patterns.values():
                # Count by type
                pattern_type = pattern.pattern_type
                patterns_by_type[pattern_type] = patterns_by_type.get(pattern_type, 0) + 1

                # Accumulate statistics
                total_usage += pattern.usage_count
                total_success += pattern.success_count
                total_confidence += pattern.confidence

            success_rate = total_success / total_usage if total_usage > 0 else 0
            average_confidence = total_confidence / total_patterns

            return {
                "total_patterns": total_patterns,
                "patterns_by_type": patterns_by_type,
                "average_confidence": average_confidence,
                "total_usage": total_usage,
                "total_success": total_success,
                "success_rate": success_rate,
                "most_used_patterns": self._get_most_used_patterns(5),
                "highest_confidence_patterns": self._get_highest_confidence_patterns(5)
            }

        except Exception as e:
            logger.error(f"Error getting pattern statistics: {e}")
            return {}

    # Helper methods

    def _normalize_path(self, path: str) -> str:
        """Normalize path by replacing IDs with placeholders."""
        import re
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        # Replace UUID-like strings
        path = re.sub(
            r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
            '/{id}',
            path
        )
        return path

    def _identify_resource_type(self, path: str) -> str:
        """Identify the resource type from the path."""
        parts = [p for p in path.split("/") if p and p != "{id}"]
        if parts:
            # Return the last resource in the path
            return parts[-1]
        return "unknown"

    def _count_nested_objects(self, data: Any, depth: int = 0) -> int:
        """Count nested objects in data structure."""
        if depth > 10:  # Prevent infinite recursion
            return 0

        count = 0
        if isinstance(data, dict):
            count += 1
            for value in data.values():
                count += self._count_nested_objects(value, depth + 1)
        elif isinstance(data, list):
            for item in data:
                count += self._count_nested_objects(item, depth + 1)

        return count

    def _generate_pattern_id(self, identifier: str) -> str:
        """Generate a unique pattern ID."""
        return hashlib.md5(identifier.encode()).hexdigest()[:16]

    async def _generate_pattern_embedding(self, pattern: Pattern) -> List[float]:
        """Generate vector embedding for a pattern."""
        try:
            # Create text representation of pattern
            pattern_text = json.dumps({
                "type": pattern.pattern_type,
                "name": pattern.name,
                "structure": pattern.structure,
                "context": pattern.context.dict()
            })

            return await self._generate_embedding(pattern_text)

        except Exception as e:
            logger.error(f"Error generating pattern embedding: {e}")
            return []

    async def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for text using vector DB or simple hash."""
        if self.vector_db:
            try:
                # Use vector DB embedding
                return await self.vector_db.embed(text)
            except Exception as e:
                logger.warning(f"Vector DB embedding failed: {e}")

        # Fallback: simple hash-based embedding
        hash_value = hashlib.md5(text.encode()).digest()
        # Convert to 128-dimensional vector
        embedding = [float(b) / 255.0 for b in hash_value]
        # Pad to 128 dimensions
        embedding.extend([0.0] * (128 - len(embedding)))
        return embedding[:128]

    def _calculate_similarity(
        self,
        embedding1: List[float],
        embedding2: List[float]
    ) -> float:
        """Calculate cosine similarity between embeddings."""
        if not embedding1 or not embedding2:
            return 0.0

        # Ensure same dimensions
        min_len = min(len(embedding1), len(embedding2))
        e1 = np.array(embedding1[:min_len])
        e2 = np.array(embedding2[:min_len])

        # Cosine similarity
        dot_product = np.dot(e1, e2)
        norm1 = np.linalg.norm(e1)
        norm2 = np.linalg.norm(e2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot_product / (norm1 * norm2))

    def _generate_params_from_pattern(
        self,
        pattern_structure: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate query parameters from pattern structure."""
        params = {}
        param_names = pattern_structure.get("param_names", [])

        for param_name in param_names:
            # Generate appropriate value based on name
            if "limit" in param_name.lower():
                params[param_name] = 10
            elif "offset" in param_name.lower() or "page" in param_name.lower():
                params[param_name] = 0
            elif "sort" in param_name.lower():
                params[param_name] = "asc"
            else:
                params[param_name] = "test_value"

        return params

    def _generate_body_from_pattern(
        self,
        pattern_structure: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate request body from pattern structure."""
        body = {}
        field_names = pattern_structure.get("field_names", [])

        for field_name in field_names:
            # Generate appropriate value based on name
            if "name" in field_name.lower():
                body[field_name] = "Test Name"
            elif "email" in field_name.lower():
                body[field_name] = "test@example.com"
            elif "id" in field_name.lower():
                body[field_name] = "test_id_123"
            else:
                body[field_name] = "test_value"

        return body

    def _generate_assertions_from_pattern(
        self,
        pattern_structure: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate assertions from pattern structure."""
        assertions = []

        # Status code assertion
        if "expected_status" in pattern_structure:
            assertions.append({
                "type": "status_code",
                "expected": pattern_structure["expected_status"]
            })

        # Schema validation if pattern used it
        if pattern_structure.get("has_schema_validation"):
            assertions.append({
                "type": "response_schema",
                "validate": True
            })

        return assertions

    async def _store_pattern(self, pattern: Pattern):
        """Store pattern in vector database."""
        try:
            if self.vector_db:
                await self.vector_db.store(
                    id=pattern.pattern_id,
                    embedding=pattern.embedding or [],
                    metadata=pattern.dict()
                )

            # Also keep in memory
            self.patterns[pattern.pattern_id] = pattern

            # Update cache
            cache_key = f"{pattern.context.method}_{self._normalize_path(pattern.context.endpoint or '')}"
            if cache_key not in self.pattern_cache:
                self.pattern_cache[cache_key] = []
            self.pattern_cache[cache_key].append(pattern)

        except Exception as e:
            logger.error(f"Error storing pattern: {e}")

    async def _update_reasoning_bank(
        self,
        pattern: Pattern,
        success: bool,
        execution_time: Optional[float]
    ):
        """Update ReasoningBank with pattern learning data."""
        try:
            if not self.reasoning_bank:
                return

            learning_data = {
                "pattern_id": pattern.pattern_id,
                "pattern_type": pattern.pattern_type,
                "success": success,
                "confidence": pattern.confidence,
                "execution_time": execution_time,
                "context": pattern.context.dict()
            }

            await self.reasoning_bank.record_experience(learning_data)

        except Exception as e:
            logger.error(f"Error updating ReasoningBank: {e}")

    def _get_most_used_patterns(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get the most frequently used patterns."""
        sorted_patterns = sorted(
            self.patterns.values(),
            key=lambda p: p.usage_count,
            reverse=True
        )

        return [
            {
                "pattern_id": p.pattern_id,
                "name": p.name,
                "usage_count": p.usage_count,
                "success_rate": p.success_count / p.usage_count if p.usage_count > 0 else 0
            }
            for p in sorted_patterns[:limit]
        ]

    def _get_highest_confidence_patterns(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get patterns with highest confidence."""
        sorted_patterns = sorted(
            self.patterns.values(),
            key=lambda p: p.confidence,
            reverse=True
        )

        return [
            {
                "pattern_id": p.pattern_id,
                "name": p.name,
                "confidence": p.confidence,
                "usage_count": p.usage_count
            }
            for p in sorted_patterns[:limit]
        ]
