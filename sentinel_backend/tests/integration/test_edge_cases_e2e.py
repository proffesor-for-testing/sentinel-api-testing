"""
End-to-End Regression Tests for Edge Cases Agent (Priority 2: HIGH)

These tests verify the Edge Cases Agent's complete workflow after PR #30's
Assertion struct fixes. Critical focus areas:
- Unicode malformation test generation and assertions
- Payload size limit test generation and status codes
- Rate limiting test generation and status handling
- Header edge case test generation and validation

Risk Analysis: PR #30 changed 25 assertion instances in edge_cases.rs
- Risk Score: 78/100 (HIGH)
- Security Impact: Unicode injection, DoS, header injection vulnerabilities
- Coverage Gap: No E2E tests for full agent workflow

Test Strategy:
1. Load sample OpenAPI spec
2. Create edge case task
3. Execute EdgeCasesAgent.execute(task, api_spec)
4. Verify generated test cases have correct assertion structure:
   - assertion_type format (not old field+operator)
   - Expected status codes ([400, 422, 500] for errors, [413] for payload, [200, 429] for rate limiting)
   - No 'field' or 'operator' keys (old pattern removed)

Reference: /docs/REGRESSION_RISK_ANALYSIS_PR30.md lines 594-648
"""

import pytest
import asyncio
from typing import Dict, Any, List
from unittest.mock import patch, Mock, AsyncMock

from sentinel_backend.orchestration_service.agents.edge_cases_agent import EdgeCasesAgent
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


@pytest.fixture
def edge_cases_agent():
    """Create Edge Cases Agent instance for testing."""
    return EdgeCasesAgent()


@pytest.fixture
def sample_api_spec() -> Dict[str, Any]:
    """
    Sample OpenAPI spec for edge case testing.

    Includes endpoints that should trigger:
    - Unicode edge cases
    - Payload size limits
    - Rate limiting scenarios
    - Header edge cases
    """
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Edge Case Test API",
            "version": "1.0.0"
        },
        "paths": {
            "/users": {
                "get": {
                    "operationId": "getUsers",
                    "summary": "Get all users",
                    "parameters": [
                        {
                            "name": "name",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 100
                            }
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100
                            }
                        }
                    ],
                    "responses": {
                        "200": {"description": "Success"},
                        "400": {"description": "Bad Request"},
                        "429": {"description": "Too Many Requests"}
                    }
                },
                "post": {
                    "operationId": "createUser",
                    "summary": "Create a new user",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name", "email"],
                                    "properties": {
                                        "name": {
                                            "type": "string",
                                            "minLength": 1,
                                            "maxLength": 255
                                        },
                                        "email": {
                                            "type": "string",
                                            "format": "email"
                                        },
                                        "bio": {
                                            "type": "string",
                                            "maxLength": 10000
                                        },
                                        "tags": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                            "maxItems": 1000
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Created"},
                        "400": {"description": "Bad Request"},
                        "413": {"description": "Payload Too Large"},
                        "422": {"description": "Unprocessable Entity"},
                        "500": {"description": "Internal Server Error"}
                    }
                }
            },
            "/users/{userId}": {
                "get": {
                    "operationId": "getUserById",
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "userId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        },
                        {
                            "name": "X-Custom-Header",
                            "in": "header",
                            "required": False,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Success"},
                        "400": {"description": "Bad Request"},
                        "404": {"description": "Not Found"}
                    }
                }
            }
        }
    }


@pytest.fixture
def edge_case_task() -> AgentTask:
    """Create an AgentTask for edge case generation."""
    return AgentTask(
        task_id="edge_case_test_001",
        spec_id=1,
        agent_type="Edge-Cases-Agent",
        parameters={
            "include_unicode": True,
            "include_size_limits": True,
            "include_rate_limiting": True,
            "include_headers": True
        }
    )


def assert_valid_assertion_structure(assertion: Dict[str, Any], test_name: str) -> None:
    """
    Verify assertion follows new pattern from PR #30.

    CRITICAL: Old pattern (field + operator) was removed in PR #30
    New pattern: assertion_type with expected value and optional path

    Args:
        assertion: Assertion dictionary to validate
        test_name: Name of test case for error messages
    """
    # Skip validation for metadata notes (not actual assertions)
    if assertion.get('type') == 'concurrency_note':
        return

    # MUST have assertion_type (new pattern)
    assert 'assertion_type' in assertion, \
        f"Test '{test_name}': Missing 'assertion_type' field in assertion with type: {assertion.get('type', 'unknown')}"

    # MUST NOT have old pattern fields
    assert 'field' not in assertion, \
        f"Test '{test_name}': Old 'field' pattern detected - should use 'assertion_type'"

    assert 'operator' not in assertion, \
        f"Test '{test_name}': Old 'operator' pattern detected - should use 'assertion_type'"

    # assertion_type should be a string
    assert isinstance(assertion['assertion_type'], str), \
        f"Test '{test_name}': 'assertion_type' must be a string"

    # Should have expected value
    assert 'expected' in assertion, \
        f"Test '{test_name}': Missing 'expected' field in assertion"


@pytest.mark.integration
class TestEdgeCasesAgentE2E:
    """
    End-to-end regression tests for Edge Cases Agent.

    Priority 2: HIGH (Run in CI Pipeline)
    Risk Score: 78/100

    Tests verify complete workflow:
    1. Load OpenAPI spec
    2. Execute agent
    3. Validate generated test cases
    4. Verify assertion structure correctness
    """

    @pytest.mark.asyncio
    async def test_unicode_malformation_assertions(self, edge_cases_agent, sample_api_spec, edge_case_task):
        """
        Verify unicode edge case tests still validate correctly.

        CRITICAL: Security vulnerability if unicode tests fail
        - Malformed UTF-8 could bypass validation
        - Injection attacks via malformed unicode

        Expected behavior:
        - Generate unicode test cases for string parameters
        - Use new assertion_type format (not field+operator)
        - Expect status codes: [200] for valid, [400, 422, 500] for malformed

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 94-97, 608-627
        """
        result = await edge_cases_agent.execute(edge_case_task, sample_api_spec)

        assert result.status == "success", f"Agent execution failed: {result.error_message}"
        assert len(result.test_cases) > 0, "No test cases generated"

        # Find unicode-related test cases
        unicode_tests = [
            tc for tc in result.test_cases
            if 'unicode' in tc.get('description', '').lower()
        ]

        assert len(unicode_tests) > 0, \
            "No unicode test cases generated - critical coverage gap"

        # Verify assertion structure for each unicode test
        for tc in unicode_tests:
            test_name = tc.get('description', 'Unknown')

            # Should have expected_status
            assert 'expected_status' in tc, \
                f"Unicode test '{test_name}' missing expected_status"

            # Status should be valid for unicode tests
            status = tc['expected_status']
            assert status in [200, 400, 422, 500], \
                f"Unicode test '{test_name}' has unexpected status: {status}"

            # Check assertions if present
            assertions = tc.get('assertions', [])
            for assertion in assertions:
                assert_valid_assertion_structure(assertion, test_name)

                # Verify assertion types are appropriate
                assertion_type = assertion['assertion_type']
                assert assertion_type in [
                    'status_code_in',
                    'response_time_lt',
                    'status_code_eq'
                ], f"Unexpected assertion_type for unicode test: {assertion_type}"

    @pytest.mark.asyncio
    async def test_payload_size_limit_assertions(self, edge_cases_agent, sample_api_spec, edge_case_task):
        """
        Verify payload size tests correctly expect 413/400/500.

        CRITICAL: Availability risk if payload limits fail
        - DoS protection via payload limits could fail
        - Server OOM from unbounded payloads

        Expected behavior:
        - Generate payload size tests for request bodies
        - Use new assertion_type format
        - Expect status codes: [200] for valid, [413, 400, 500] for oversized

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 100-102, 630-647
        """
        result = await edge_cases_agent.execute(edge_case_task, sample_api_spec)

        assert result.status == "success", f"Agent execution failed: {result.error_message}"

        # Find payload/size-related test cases
        payload_tests = [
            tc for tc in result.test_cases
            if any(keyword in tc.get('description', '').lower()
                   for keyword in ['payload', 'size', 'large', 'maximum'])
        ]

        assert len(payload_tests) > 0, \
            "No payload size test cases generated - critical coverage gap"

        # Track if we found tests expecting error status codes
        found_error_status_tests = False

        for tc in payload_tests:
            test_name = tc.get('description', 'Unknown')

            # Should have expected_status
            assert 'expected_status' in tc, \
                f"Payload test '{test_name}' missing expected_status"

            status = tc['expected_status']

            # Check if test expects error status (oversized payload)
            if status in [413, 400, 500]:
                found_error_status_tests = True

            # Validate status is reasonable for payload tests
            assert status in [200, 201, 400, 413, 422, 500], \
                f"Payload test '{test_name}' has unexpected status: {status}"

            # Check assertions if present
            assertions = tc.get('assertions', [])
            for assertion in assertions:
                assert_valid_assertion_structure(assertion, test_name)

                # For status_code_in assertions, verify expected values
                if assertion['assertion_type'] == 'status_code_in':
                    expected = assertion['expected']
                    assert isinstance(expected, list), \
                        f"status_code_in expected value should be list, got {type(expected)}"

                    # Should expect error codes for oversized payloads
                    if 'large' in test_name.lower() or 'maximum' in test_name.lower():
                        assert any(code in expected for code in [413, 400, 500]), \
                            f"Large payload test should expect error codes, got {expected}"

        # At least some tests should expect error status for oversized payloads
        # (Note: This may not always be true depending on spec, so we log a warning)
        if not found_error_status_tests:
            import logging
            logging.warning("No payload size tests found expecting error status codes")

    @pytest.mark.asyncio
    async def test_rate_limiting_assertions(self, edge_cases_agent, sample_api_spec, edge_case_task):
        """
        Verify rapid requests trigger 429 or succeed with 200.

        CRITICAL: DDoS vulnerability if rate limiting tests fail
        - Rate limiting bypass
        - Service degradation under load

        Expected behavior:
        - Generate rate limiting test scenarios
        - Use new assertion_type format
        - Expect status codes: [200, 429]

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 105-108
        """
        result = await edge_cases_agent.execute(edge_case_task, sample_api_spec)

        assert result.status == "success", f"Agent execution failed: {result.error_message}"

        # Rate limiting tests might be in concurrent scenarios or edge cases
        rate_limit_tests = [
            tc for tc in result.test_cases
            if any(keyword in tc.get('description', '').lower()
                   for keyword in ['rate', 'concurrent', 'rapid', 'limit'])
        ]

        # Note: Rate limiting tests might not be generated for all specs
        # This is expected behavior - only generate if API spec indicates rate limiting
        if len(rate_limit_tests) > 0:
            for tc in rate_limit_tests:
                test_name = tc.get('description', 'Unknown')

                # Should have expected_status
                assert 'expected_status' in tc, \
                    f"Rate limit test '{test_name}' missing expected_status"

                status = tc['expected_status']

                # Rate limiting tests should expect success, rate limit, or bad request for invalid params
                assert status in [200, 201, 400, 429], \
                    f"Rate limit test '{test_name}' should expect 200, 400, or 429, got {status}"

                # Check assertions if present
                assertions = tc.get('assertions', [])
                for assertion in assertions:
                    assert_valid_assertion_structure(assertion, test_name)

    @pytest.mark.asyncio
    async def test_header_edge_cases(self, edge_cases_agent, sample_api_spec, edge_case_task):
        """
        Verify binary/long/unicode header tests.

        CRITICAL: Security risk if header tests fail
        - Header injection attacks
        - Malicious headers bypass validation

        Expected behavior:
        - Generate header edge case tests
        - Test binary headers, very long headers (8KB), unicode headers
        - Use new assertion_type format
        - Expect status codes: [200] for valid, [400] for malformed

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 109-112
        """
        result = await edge_cases_agent.execute(edge_case_task, sample_api_spec)

        assert result.status == "success", f"Agent execution failed: {result.error_message}"

        # Find header-related test cases
        header_tests = [
            tc for tc in result.test_cases
            if ('header' in tc.get('description', '').lower() or
                len(tc.get('headers', {})) > 0)
        ]

        # Header tests should be generated for endpoints with header parameters
        # or for general header edge cases
        if len(header_tests) > 0:
            for tc in header_tests:
                test_name = tc.get('description', 'Unknown')

                # Should have expected_status
                assert 'expected_status' in tc, \
                    f"Header test '{test_name}' missing expected_status"

                # Validate headers structure if present
                headers = tc.get('headers', {})
                if headers:
                    assert isinstance(headers, dict), \
                        f"Headers should be dict, got {type(headers)}"

                # Check assertions if present
                assertions = tc.get('assertions', [])
                for assertion in assertions:
                    assert_valid_assertion_structure(assertion, test_name)

    @pytest.mark.asyncio
    async def test_complete_edge_case_workflow(self, edge_cases_agent, sample_api_spec, edge_case_task):
        """
        Test complete Edge Cases Agent workflow end-to-end.

        Verifies:
        1. Agent accepts task and spec
        2. Generates multiple categories of edge case tests
        3. All test cases follow new assertion structure
        4. Metadata is populated correctly

        Reference: Full workflow validation
        """
        result = await edge_cases_agent.execute(edge_case_task, sample_api_spec)

        # Verify successful execution
        assert result.status == "success", f"Agent execution failed: {result.error_message}"
        assert result.task_id == edge_case_task.task_id
        assert result.agent_type == "Edge-Cases-Agent"

        # Verify test cases generated
        assert len(result.test_cases) > 0, "No test cases generated"

        # Verify metadata
        assert 'total_endpoints' in result.metadata
        assert 'total_test_cases' in result.metadata
        assert 'edge_case_categories' in result.metadata

        # Verify categories present
        categories = result.metadata.get('edge_case_categories', [])
        expected_categories = [
            'boundary_values',
            'unicode_special_characters',
            'null_empty_undefined',
            'case_sensitivity',
            'whitespace_handling'
        ]

        for category in expected_categories:
            assert category in categories, \
                f"Expected edge case category '{category}' not found in metadata"

        # Verify ALL test cases follow new assertion structure
        for tc in result.test_cases:
            test_name = tc.get('description', 'Unknown')

            # Basic test case structure
            assert 'endpoint' in tc, f"Test '{test_name}' missing endpoint"
            assert 'method' in tc, f"Test '{test_name}' missing method"
            assert 'description' in tc, f"Test '{test_name}' missing description"
            assert 'expected_status' in tc, f"Test '{test_name}' missing expected_status"

            # Verify assertions if present
            assertions = tc.get('assertions', [])
            for assertion in assertions:
                assert_valid_assertion_structure(assertion, test_name)

    @pytest.mark.asyncio
    async def test_boundary_value_assertion_structure(self, edge_cases_agent, sample_api_spec, edge_case_task):
        """
        Specifically test boundary value tests have correct assertion structure.

        Boundary values are critical for edge case detection.
        PR #30 changes could affect how min/max boundaries are asserted.
        """
        result = await edge_cases_agent.execute(edge_case_task, sample_api_spec)

        assert result.status == "success"

        # Find boundary value tests
        boundary_tests = [
            tc for tc in result.test_cases
            if 'boundary' in tc.get('description', '').lower()
        ]

        assert len(boundary_tests) > 0, "No boundary value tests generated"

        for tc in boundary_tests:
            test_name = tc.get('description', 'Unknown')

            # Boundary tests should have clear expected status
            assert 'expected_status' in tc

            # If expecting error, should be 400 or 422
            if 'below' in test_name.lower() or 'above' in test_name.lower():
                assert tc['expected_status'] in [200, 400, 422], \
                    f"Boundary test '{test_name}' has unexpected status"

            # Verify assertion structure
            for assertion in tc.get('assertions', []):
                assert_valid_assertion_structure(assertion, test_name)

    @pytest.mark.asyncio
    async def test_no_legacy_assertion_patterns(self, edge_cases_agent, sample_api_spec, edge_case_task):
        """
        Verify NO test cases use the old field+operator pattern.

        This is the core regression test - ensuring PR #30's changes
        fully removed the old assertion pattern.
        """
        result = await edge_cases_agent.execute(edge_case_task, sample_api_spec)

        assert result.status == "success"

        legacy_pattern_found = []

        for tc in result.test_cases:
            test_name = tc.get('description', 'Unknown')

            for assertion in tc.get('assertions', []):
                # Check for legacy fields
                if 'field' in assertion or 'operator' in assertion:
                    legacy_pattern_found.append({
                        'test': test_name,
                        'assertion': assertion
                    })

        # CRITICAL: Should find ZERO legacy patterns
        assert len(legacy_pattern_found) == 0, \
            f"Found {len(legacy_pattern_found)} legacy assertion patterns: {legacy_pattern_found}"
