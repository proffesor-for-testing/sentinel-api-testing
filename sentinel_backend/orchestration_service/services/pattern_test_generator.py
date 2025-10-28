"""
Pattern-Based Test Generator.

This service generates tests by reusing patterns from successful test history,
reducing duplicate generation and improving test quality.
"""

from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

from .pattern_recognition_service import (
    PatternRecognitionService,
    Pattern,
    PatternMatch,
    PatternType
)

logger = logging.getLogger(__name__)


class PatternTestGenerator:
    """
    Generates tests using learned patterns.

    Workflow:
    1. Query patterns matching the API spec
    2. Rank patterns by similarity and confidence
    3. Adapt patterns to new context
    4. Generate tests from top patterns
    5. Validate and deduplicate tests
    """

    def __init__(self, pattern_service: PatternRecognitionService):
        """
        Initialize pattern-based test generator.

        Args:
            pattern_service: Pattern recognition service instance
        """
        self.pattern_service = pattern_service
        self.generated_tests_cache: Dict[str, List[Dict[str, Any]]] = {}
        logger.info("Pattern Test Generator initialized")

    async def generate_tests_from_patterns(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        max_patterns: int = 5,
        similarity_threshold: float = 0.7
    ) -> List[Dict[str, Any]]:
        """
        Generate test cases using matched patterns.

        Args:
            api_spec: The API specification
            endpoint: Target endpoint
            method: HTTP method
            max_patterns: Maximum number of patterns to use
            similarity_threshold: Minimum pattern similarity

        Returns:
            List of generated test cases
        """
        try:
            # Find matching patterns
            pattern_matches = await self.pattern_service.find_matching_patterns(
                api_spec=api_spec,
                endpoint=endpoint,
                method=method,
                similarity_threshold=similarity_threshold
            )

            if not pattern_matches:
                logger.info(f"No patterns found for {method} {endpoint}")
                return []

            # Limit to top patterns
            pattern_matches = pattern_matches[:max_patterns]

            logger.info(
                f"Found {len(pattern_matches)} patterns for {method} {endpoint}, "
                f"using top {max_patterns}"
            )

            # Generate tests from each pattern
            test_cases = []
            for match in pattern_matches:
                test = await self._generate_test_from_match(
                    match=match,
                    api_spec=api_spec,
                    endpoint=endpoint,
                    method=method
                )

                if test:
                    # Add pattern metadata
                    test["_pattern_metadata"] = {
                        "pattern_id": match.pattern.pattern_id,
                        "pattern_name": match.pattern.name,
                        "similarity_score": match.similarity_score,
                        "confidence": match.confidence,
                        "match_reason": match.match_reason
                    }
                    test_cases.append(test)

            # Deduplicate tests
            unique_tests = self._deduplicate_tests(test_cases)

            logger.info(
                f"Generated {len(test_cases)} tests from patterns, "
                f"{len(unique_tests)} after deduplication"
            )

            # Cache generated tests
            cache_key = f"{method}_{endpoint}"
            self.generated_tests_cache[cache_key] = unique_tests

            return unique_tests

        except Exception as e:
            logger.error(f"Error generating tests from patterns: {e}")
            return []

    async def generate_test_suite_from_patterns(
        self,
        api_spec: Dict[str, Any],
        test_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate a complete test suite using patterns.

        Args:
            api_spec: The full API specification
            test_types: Optional list of test types to generate

        Returns:
            Test suite with tests grouped by endpoint
        """
        try:
            test_suite = {
                "generated_at": datetime.utcnow().isoformat(),
                "api_spec_id": api_spec.get("info", {}).get("title", "unknown"),
                "pattern_based": True,
                "endpoints": {}
            }

            # Extract endpoints
            paths = api_spec.get("paths", {})

            for path, path_item in paths.items():
                for method in ["get", "post", "put", "patch", "delete"]:
                    if method not in path_item:
                        continue

                    # Generate tests for this endpoint
                    tests = await self.generate_tests_from_patterns(
                        api_spec=api_spec,
                        endpoint=path,
                        method=method.upper()
                    )

                    if tests:
                        endpoint_key = f"{method.upper()} {path}"
                        test_suite["endpoints"][endpoint_key] = {
                            "path": path,
                            "method": method.upper(),
                            "test_count": len(tests),
                            "tests": tests,
                            "pattern_coverage": self._calculate_pattern_coverage(tests)
                        }

            test_suite["total_endpoints"] = len(test_suite["endpoints"])
            test_suite["total_tests"] = sum(
                ep["test_count"] for ep in test_suite["endpoints"].values()
            )

            logger.info(
                f"Generated test suite with {test_suite['total_tests']} tests "
                f"for {test_suite['total_endpoints']} endpoints"
            )

            return test_suite

        except Exception as e:
            logger.error(f"Error generating test suite from patterns: {e}")
            return {}

    async def hybrid_generation(
        self,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str,
        traditional_generator: Any
    ) -> List[Dict[str, Any]]:
        """
        Hybrid approach: use patterns first, fall back to traditional generation.

        Args:
            api_spec: API specification
            endpoint: Target endpoint
            method: HTTP method
            traditional_generator: Fallback generator instance

        Returns:
            Combined test cases
        """
        try:
            # Try pattern-based generation first
            pattern_tests = await self.generate_tests_from_patterns(
                api_spec=api_spec,
                endpoint=endpoint,
                method=method
            )

            if pattern_tests:
                logger.info(
                    f"Generated {len(pattern_tests)} tests from patterns "
                    f"for {method} {endpoint}"
                )

                # Mark tests as pattern-based
                for test in pattern_tests:
                    test["generation_method"] = "pattern_based"

                return pattern_tests
            else:
                # Fall back to traditional generation
                logger.info(
                    f"No patterns found for {method} {endpoint}, "
                    f"using traditional generation"
                )

                traditional_tests = await traditional_generator.generate_tests(
                    api_spec=api_spec,
                    endpoint=endpoint,
                    method=method
                )

                # Mark tests as traditional
                for test in traditional_tests:
                    test["generation_method"] = "traditional"

                return traditional_tests

        except Exception as e:
            logger.error(f"Error in hybrid generation: {e}")
            return []

    async def suggest_test_improvements(
        self,
        test_case: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """
        Suggest improvements to a test case based on patterns.

        Args:
            test_case: Test case to improve
            api_spec: API specification

        Returns:
            List of improvement suggestions
        """
        try:
            suggestions = []

            endpoint = test_case.get("endpoint", "")
            method = test_case.get("method", "")

            # Find similar patterns
            pattern_matches = await self.pattern_service.find_matching_patterns(
                api_spec=api_spec,
                endpoint=endpoint,
                method=method,
                similarity_threshold=0.6
            )

            if not pattern_matches:
                return suggestions

            # Analyze differences between test and patterns
            for match in pattern_matches[:3]:  # Top 3 patterns
                pattern = match.pattern

                # Check for missing assertions
                if pattern.pattern_type == PatternType.ASSERTION_PATTERN:
                    test_assertions = set(
                        a.get("type") for a in test_case.get("assertions", [])
                    )
                    pattern_assertions = set(pattern.structure.get("assertion_types", []))

                    missing_assertions = pattern_assertions - test_assertions
                    if missing_assertions:
                        suggestions.append({
                            "type": "missing_assertion",
                            "description": f"Consider adding {', '.join(missing_assertions)} assertions",
                            "pattern_id": pattern.pattern_id,
                            "confidence": match.confidence
                        })

                # Check for missing parameters
                if pattern.pattern_type == PatternType.PARAMETER_PATTERN:
                    test_params = set(test_case.get("query_params", {}).keys())
                    pattern_params = set(pattern.structure.get("param_names", []))

                    missing_params = pattern_params - test_params
                    if missing_params:
                        suggestions.append({
                            "type": "missing_parameter",
                            "description": f"Consider adding parameters: {', '.join(missing_params)}",
                            "pattern_id": pattern.pattern_id,
                            "confidence": match.confidence
                        })

            logger.info(f"Generated {len(suggestions)} improvement suggestions")
            return suggestions

        except Exception as e:
            logger.error(f"Error suggesting improvements: {e}")
            return []

    async def get_generation_statistics(self) -> Dict[str, Any]:
        """Get statistics about pattern-based test generation."""
        try:
            total_generated = sum(
                len(tests) for tests in self.generated_tests_cache.values()
            )

            pattern_stats = await self.pattern_service.get_pattern_statistics()

            return {
                "total_tests_generated": total_generated,
                "cached_endpoints": len(self.generated_tests_cache),
                "pattern_statistics": pattern_stats,
                "average_tests_per_endpoint": (
                    total_generated / len(self.generated_tests_cache)
                    if self.generated_tests_cache else 0
                )
            }

        except Exception as e:
            logger.error(f"Error getting generation statistics: {e}")
            return {}

    # Helper methods

    async def _generate_test_from_match(
        self,
        match: PatternMatch,
        api_spec: Dict[str, Any],
        endpoint: str,
        method: str
    ) -> Optional[Dict[str, Any]]:
        """Generate a test case from a pattern match."""
        try:
            # Use pattern service to generate base test
            test = await self.pattern_service.generate_test_from_pattern(
                pattern=match.pattern,
                api_spec=api_spec,
                endpoint=endpoint,
                method=method
            )

            if not test:
                return None

            # Enhance test with additional metadata
            test["confidence"] = match.confidence
            test["similarity_score"] = match.similarity_score
            test["generation_timestamp"] = datetime.utcnow().isoformat()

            return test

        except Exception as e:
            logger.error(f"Error generating test from match: {e}")
            return None

    def _deduplicate_tests(self, tests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate tests based on test structure."""
        seen = set()
        unique_tests = []

        for test in tests:
            # Create signature based on key test components
            signature = self._create_test_signature(test)

            if signature not in seen:
                seen.add(signature)
                unique_tests.append(test)

        return unique_tests

    def _create_test_signature(self, test: Dict[str, Any]) -> str:
        """Create a unique signature for a test case."""
        import json

        # Use key components for signature
        signature_data = {
            "endpoint": test.get("endpoint"),
            "method": test.get("method"),
            "query_params": sorted(test.get("query_params", {}).keys()),
            "body_fields": sorted(test.get("body", {}).keys()),
            "expected_status": test.get("expected_status")
        }

        return json.dumps(signature_data, sort_keys=True)

    def _calculate_pattern_coverage(self, tests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate pattern coverage metrics."""
        if not tests:
            return {"pattern_count": 0, "coverage_percentage": 0}

        pattern_ids = set()
        for test in tests:
            pattern_meta = test.get("_pattern_metadata", {})
            if pattern_meta:
                pattern_ids.add(pattern_meta.get("pattern_id"))

        return {
            "pattern_count": len(pattern_ids),
            "unique_patterns": list(pattern_ids),
            "coverage_percentage": (len(pattern_ids) / len(tests) * 100)
        }
