"""
Comprehensive TDD Tests for Consolidated Functional Agent

This test suite ensures:
1. UNIQUE test case generation across different strategies
2. NO DUPLICATION between positive, negative, boundary, and edge case strategies
3. Proper categorization and coverage
4. Meaningful assertions (NO assert True!)
5. Tests FAIL before implementation (TDD approach)
"""

import pytest
import asyncio
from typing import Dict, List, Any, Set
from unittest.mock import Mock, patch, AsyncMock
import hashlib

from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


def create_test_signature(test_case: Dict[str, Any]) -> str:
    """Create unique signature for test case to detect duplicates"""
    components = [
        test_case.get('endpoint', ''),
        test_case.get('method', ''),
        str(test_case.get('body', '')),
        str(test_case.get('query_params', '')),
        str(test_case.get('path_params', ''))
    ]
    signature = '|'.join(components)
    return hashlib.md5(signature.encode()).hexdigest()


class TestConsolidatedFunctionalAgent:
    """Test suite for consolidated functional testing agents"""

    @pytest.fixture
    def positive_agent(self):
        """Create Functional Positive Agent instance"""
        return FunctionalPositiveAgent()

    @pytest.fixture
    def negative_agent(self):
        """Create Functional Negative Agent instance"""
        return FunctionalNegativeAgent()

    @pytest.fixture
    def agent_task(self):
        """Standard agent task for testing"""
        return AgentTask(
            task_id="test-functional-001",
            spec_id=1,
            agent_type="Functional-Agent",
            parameters={},
            enable_llm=False
        )

    @pytest.fixture
    def comprehensive_api_spec(self):
        """Comprehensive API spec for testing all strategies"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "E-commerce API", "version": "1.0.0"},
            "paths": {
                "/products": {
                    "get": {
                        "summary": "List products",
                        "parameters": [
                            {
                                "name": "category",
                                "in": "query",
                                "schema": {"type": "string", "enum": ["electronics", "books", "clothing"]}
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                            },
                            {
                                "name": "price_min",
                                "in": "query",
                                "schema": {"type": "number", "minimum": 0}
                            }
                        ],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "post": {
                        "summary": "Create product",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string", "minLength": 3, "maxLength": 100},
                                            "price": {"type": "number", "minimum": 0, "exclusiveMinimum": True},
                                            "quantity": {"type": "integer", "minimum": 0, "maximum": 10000},
                                            "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 10}
                                        },
                                        "required": ["name", "price"]
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Created"},
                            "400": {"description": "Bad Request"}
                        }
                    }
                },
                "/products/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer", "minimum": 1}}
                        ],
                        "responses": {
                            "200": {"description": "Success"},
                            "404": {"description": "Not Found"}
                        }
                    },
                    "put": {
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string", "minLength": 1},
                                            "price": {"type": "number", "minimum": 0}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }

    # ==================== POSITIVE STRATEGY TESTS ====================

    @pytest.mark.asyncio
    async def test_positive_strategy_generates_valid_cases(self, positive_agent, agent_task, comprehensive_api_spec):
        """MUST generate test cases with valid data expecting 2xx status codes"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        # Specific count assertion
        assert len(result.test_cases) >= 5, f"Expected at least 5 positive tests, got {len(result.test_cases)}"

        # All positive tests must expect success
        for test_case in result.test_cases:
            expected_statuses = test_case.get('expected_status_codes', [test_case.get('expected_status', 0)])
            success_codes = [s for s in expected_statuses if 200 <= s < 300]
            assert len(success_codes) > 0, f"Positive test must expect 2xx status: {test_case}"

    @pytest.mark.asyncio
    async def test_positive_strategy_uses_valid_data(self, positive_agent, agent_task, comprehensive_api_spec):
        """MUST use data that conforms to schema constraints"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        post_tests = [tc for tc in result.test_cases if tc.get('method') == 'POST' and '/products' in tc.get('endpoint', '')]
        assert len(post_tests) > 0, "Must have POST /products tests"

        for test_case in post_tests:
            body = test_case.get('body', {})
            if body:
                # SPECIFIC assertions - no vague checks!
                assert 'name' in body, "Required field 'name' missing"
                assert 'price' in body, "Required field 'price' missing"

                if 'name' in body:
                    assert len(body['name']) >= 3, f"Name too short: {body['name']}"
                    assert len(body['name']) <= 100, f"Name too long: {body['name']}"

                if 'price' in body:
                    assert body['price'] > 0, f"Price must be positive: {body['price']}"

    @pytest.mark.asyncio
    async def test_positive_strategy_covers_all_methods(self, positive_agent, agent_task, comprehensive_api_spec):
        """MUST generate tests for ALL HTTP methods in spec"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        methods_tested = set(tc.get('method', '').upper() for tc in result.test_cases)

        # Specific method requirements
        assert 'GET' in methods_tested, "Missing GET method tests"
        assert 'POST' in methods_tested, "Missing POST method tests"
        assert 'PUT' in methods_tested, "Missing PUT method tests"

        # Count assertion per method
        get_tests = [tc for tc in result.test_cases if tc.get('method', '').upper() == 'GET']
        assert len(get_tests) >= 2, f"Expected at least 2 GET tests, got {len(get_tests)}"

    # ==================== NEGATIVE STRATEGY TESTS ====================

    @pytest.mark.asyncio
    async def test_negative_strategy_generates_invalid_cases(self, negative_agent, agent_task, comprehensive_api_spec):
        """MUST generate test cases with invalid data expecting 4xx status codes"""
        result = await negative_agent.execute(agent_task, comprehensive_api_spec)

        assert len(result.test_cases) >= 5, f"Expected at least 5 negative tests, got {len(result.test_cases)}"

        # All negative tests must expect errors
        for test_case in result.test_cases:
            expected_statuses = test_case.get('expected_status_codes', [test_case.get('expected_status', 0)])
            error_codes = [s for s in expected_statuses if 400 <= s < 500]
            assert len(error_codes) > 0, f"Negative test must expect 4xx status: {test_case}"

    @pytest.mark.asyncio
    async def test_negative_strategy_violates_constraints(self, negative_agent, agent_task, comprehensive_api_spec):
        """MUST intentionally violate schema constraints"""
        result = await negative_agent.execute(agent_task, comprehensive_api_spec)

        post_tests = [tc for tc in result.test_cases if tc.get('method') == 'POST']
        assert len(post_tests) > 0, "Must have POST tests with violations"

        # Find constraint violations
        violations_found = {
            'missing_required': False,
            'invalid_type': False,
            'out_of_range': False,
            'too_short': False,
            'too_long': False
        }

        for test_case in post_tests:
            body = test_case.get('body', {})

            # Check for missing required fields
            if 'name' not in body or 'price' not in body:
                violations_found['missing_required'] = True

            # Check for constraint violations
            if 'name' in body and isinstance(body['name'], str):
                if len(body['name']) < 3:
                    violations_found['too_short'] = True
                elif len(body['name']) > 100:
                    violations_found['too_long'] = True

            if 'price' in body:
                if not isinstance(body['price'], (int, float)):
                    violations_found['invalid_type'] = True
                elif body['price'] <= 0:
                    violations_found['out_of_range'] = True

        # Must have at least 2 different violation types
        violations_count = sum(violations_found.values())
        assert violations_count >= 2, f"Expected diverse violations, only found: {violations_found}"

    # ==================== NO DUPLICATION TESTS (CRITICAL!) ====================

    @pytest.mark.asyncio
    async def test_no_duplication_between_positive_and_negative(
        self, positive_agent, negative_agent, agent_task, comprehensive_api_spec
    ):
        """CRITICAL: Positive and negative agents MUST NOT generate duplicate tests"""
        pos_result = await positive_agent.execute(agent_task, comprehensive_api_spec)
        neg_result = await negative_agent.execute(agent_task, comprehensive_api_spec)

        # Create signatures for all tests
        pos_signatures = {create_test_signature(tc) for tc in pos_result.test_cases}
        neg_signatures = {create_test_signature(tc) for tc in neg_result.test_cases}

        # Find overlaps
        duplicates = pos_signatures & neg_signatures

        assert len(duplicates) == 0, (
            f"Found {len(duplicates)} duplicate tests between positive and negative strategies! "
            f"Agents MUST generate unique tests."
        )

    @pytest.mark.asyncio
    async def test_no_duplicate_descriptions(self, positive_agent, agent_task, comprehensive_api_spec):
        """MUST NOT generate duplicate test descriptions"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        descriptions = [tc.get('description', tc.get('test_name', '')) for tc in result.test_cases]
        unique_descriptions = set(descriptions)

        assert len(descriptions) == len(unique_descriptions), (
            f"Found {len(descriptions) - len(unique_descriptions)} duplicate descriptions! "
            f"Each test MUST have a unique description."
        )

    @pytest.mark.asyncio
    async def test_no_duplicate_within_strategy(self, positive_agent, agent_task, comprehensive_api_spec):
        """MUST NOT generate duplicate tests within same strategy"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        signatures = [create_test_signature(tc) for tc in result.test_cases]
        unique_signatures = set(signatures)

        assert len(signatures) == len(unique_signatures), (
            f"Found {len(signatures) - len(unique_signatures)} duplicate tests within positive strategy! "
            f"All tests must be unique."
        )

    # ==================== COVERAGE AND CATEGORIZATION TESTS ====================

    @pytest.mark.asyncio
    async def test_positive_tests_properly_categorized(self, positive_agent, agent_task, comprehensive_api_spec):
        """MUST properly categorize positive test subtypes"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        # Count different subtypes
        subtypes = {}
        for tc in result.test_cases:
            subtype = tc.get('test_subtype', 'unknown')
            subtypes[subtype] = subtypes.get(subtype, 0) + 1

        # Must have variety in test subtypes
        assert len(subtypes) >= 2, (
            f"Expected diverse test subtypes, only got: {list(subtypes.keys())}"
        )

        # Check for expected categories
        expected_categories = ['minimal', 'complete', 'valid']
        found_categories = [cat for cat in expected_categories if any(cat in st for st in subtypes.keys())]

        assert len(found_categories) > 0, (
            f"Expected categories like {expected_categories}, but found: {list(subtypes.keys())}"
        )

    @pytest.mark.asyncio
    async def test_negative_tests_properly_categorized(self, negative_agent, agent_task, comprehensive_api_spec):
        """MUST properly categorize negative test subtypes"""
        result = await negative_agent.execute(agent_task, comprehensive_api_spec)

        # Count violation types
        violation_types = set()
        for tc in result.test_cases:
            subtype = tc.get('test_subtype', '')
            if subtype:
                violation_types.add(subtype)

        # Must have multiple violation categories
        assert len(violation_types) >= 2, (
            f"Expected diverse violation types, only got: {violation_types}"
        )

    # ==================== BOUNDARY AND EDGE CASE TESTS ====================

    @pytest.mark.asyncio
    async def test_boundary_values_for_integers(self, positive_agent, negative_agent, agent_task, comprehensive_api_spec):
        """MUST test boundary values for integer constraints"""
        # Positive should test valid boundaries
        pos_result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        # Check for limit parameter tests (min=1, max=100)
        limit_tests = [
            tc for tc in pos_result.test_cases
            if tc.get('query_params', {}).get('limit') is not None
        ]

        if limit_tests:
            limit_values = [tc['query_params']['limit'] for tc in limit_tests]

            # Should test boundary values
            assert 1 in limit_values or any(1 <= v <= 5 for v in limit_values), (
                "Must test minimum boundary value"
            )
            assert 100 in limit_values or any(95 <= v <= 100 for v in limit_values), (
                "Must test maximum boundary value"
            )

        # Negative should test invalid boundaries
        neg_result = await negative_agent.execute(agent_task, comprehensive_api_spec)
        invalid_limit_tests = [
            tc for tc in neg_result.test_cases
            if tc.get('query_params', {}).get('limit') is not None
        ]

        if invalid_limit_tests:
            invalid_limits = [tc['query_params']['limit'] for tc in invalid_limit_tests]

            # Should test out-of-bounds values
            has_too_low = any(v < 1 for v in invalid_limits)
            has_too_high = any(v > 100 for v in invalid_limits)

            assert has_too_low or has_too_high, (
                "Negative tests must include out-of-bounds values"
            )

    # ==================== SPECIFIC ASSERTION TESTS (NO VAGUE CHECKS!) ====================

    @pytest.mark.asyncio
    async def test_all_tests_have_required_fields(self, positive_agent, agent_task, comprehensive_api_spec):
        """ALL tests MUST have endpoint, method, and expected status"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        for i, tc in enumerate(result.test_cases):
            assert 'endpoint' in tc or 'path' in tc, f"Test {i} missing endpoint/path"
            assert 'method' in tc, f"Test {i} missing method"

            # Must have expected status in some form
            has_status = (
                'expected_status' in tc or
                'expected_status_codes' in tc or
                'expected_status_code' in tc
            )
            assert has_status, f"Test {i} missing expected status"

    @pytest.mark.asyncio
    async def test_metadata_contains_specific_metrics(self, positive_agent, agent_task, comprehensive_api_spec):
        """Metadata MUST contain specific, measurable metrics"""
        result = await positive_agent.execute(agent_task, comprehensive_api_spec)

        assert 'total_test_cases' in result.metadata or 'total_tests' in result.metadata, (
            "Metadata missing test count"
        )

        # Get actual count
        metadata_count = result.metadata.get('total_test_cases', result.metadata.get('total_tests', 0))
        actual_count = len(result.test_cases)

        assert metadata_count == actual_count, (
            f"Metadata count ({metadata_count}) doesn't match actual ({actual_count})"
        )

    # ==================== ERROR HANDLING TESTS ====================

    @pytest.mark.asyncio
    async def test_handles_empty_spec_gracefully(self, positive_agent, agent_task):
        """MUST handle empty spec without crashing"""
        empty_spec = {"openapi": "3.0.0", "paths": {}}

        result = await positive_agent.execute(agent_task, empty_spec)

        assert result.status == "success", "Should succeed even with empty spec"
        assert len(result.test_cases) == 0, "Should generate no tests for empty spec"

    @pytest.mark.asyncio
    async def test_handles_invalid_spec_gracefully(self, positive_agent, agent_task):
        """MUST handle invalid spec with proper error"""
        invalid_spec = {"invalid": "structure"}

        result = await positive_agent.execute(agent_task, invalid_spec)

        # Should either succeed with no tests or fail gracefully
        assert result.status in ["success", "failed"], "Must have valid status"

        if result.status == "failed":
            assert result.error_message is not None, "Failed status must have error message"
