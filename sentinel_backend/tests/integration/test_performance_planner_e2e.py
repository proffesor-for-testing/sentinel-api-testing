"""
End-to-End Regression Tests for Performance Planner Agent

Priority 2 HIGH regression tests to validate PR #30 assertion struct fixes.
These tests verify that performance test generation includes all critical
assertions with correct types and expected values.

Critical Risks Addressed:
- Performance Planner Risk Score: 71/100 (HIGH)
- 22 assertion instances modified in PR #30
- Production risks: P99 SLO violations, memory leaks, capacity planning errors
- Coverage gaps: No E2E tests for performance test generation

Test Scenarios (from REGRESSION_RISK_ANALYSIS_PR30.md lines 652-696):
1. Load test assertions completeness (P95, error_rate, throughput)
2. Endurance test memory leak detection (memory_leak_detection_eq)
3. Stress test breaking point assertions (degradation checks)
4. Spike test traffic handling assertions

Reference: /docs/REGRESSION_RISK_ANALYSIS_PR30.md
"""

import pytest
import asyncio
from typing import Dict, Any, List
from unittest.mock import Mock

from sentinel_backend.orchestration_service.agents.performance_planner_agent import (
    PerformancePlannerAgent
)
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


@pytest.fixture
def performance_planner():
    """Create PerformancePlannerAgent instance for testing"""
    return PerformancePlannerAgent()


@pytest.fixture
def agent_task():
    """Create agent task for performance planning"""
    return AgentTask(
        task_id="perf-e2e-test-001",
        spec_id=1,
        agent_type="Performance-Planner-Agent",
        parameters={},
        enable_llm=False  # Disable LLM for deterministic tests
    )


@pytest.fixture
def api_spec():
    """
    Sample OpenAPI specification with diverse endpoints for performance testing.

    Includes:
    - Read endpoints (GET)
    - Write endpoints (POST, PUT)
    - Critical paths (auth, search)
    - Data-intensive operations (upload, export)
    """
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Performance Test API",
            "version": "1.0.0",
            "description": "API for regression testing performance planner assertions"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "operationId": "listUsers",
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 20}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}}
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "object"}
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name", "email"],
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string", "format": "email"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Created"}
                    }
                }
            },
            "/auth/login": {
                "post": {
                    "summary": "User login - critical path",
                    "operationId": "login",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["username", "password"],
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string", "format": "password"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Success"},
                        "401": {"description": "Unauthorized"}
                    }
                }
            },
            "/search": {
                "get": {
                    "summary": "Search endpoint - critical path",
                    "operationId": "search",
                    "parameters": [
                        {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}},
                        {"name": "filter", "in": "query", "schema": {"type": "string"}}
                    ],
                    "responses": {
                        "200": {"description": "Success"}
                    }
                }
            },
            "/upload": {
                "post": {
                    "summary": "File upload - data intensive",
                    "operationId": "uploadFile",
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Success"},
                        "413": {"description": "Payload too large"}
                    }
                }
            },
            "/reports/export": {
                "get": {
                    "summary": "Export report - data intensive",
                    "operationId": "exportReport",
                    "parameters": [
                        {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["pdf", "csv", "json"]}}
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/pdf": {},
                                "text/csv": {},
                                "application/json": {}
                            }
                        }
                    }
                }
            }
        }
    }


def find_test_cases_by_type(test_cases: List[Dict[str, Any]], test_type_keyword: str) -> List[Dict[str, Any]]:
    """
    Find test cases by type keyword (case-insensitive search).

    Args:
        test_cases: List of test case dictionaries
        test_type_keyword: Keyword to search for in test type/subtype/name

    Returns:
        List of matching test cases
    """
    matching_tests = []
    keyword_lower = test_type_keyword.lower()

    for tc in test_cases:
        test_type = tc.get('test_type', '').lower()
        test_subtype = tc.get('test_subtype', '').lower()
        test_name = tc.get('test_name', '').lower()

        if (keyword_lower in test_type or
            keyword_lower in test_subtype or
            keyword_lower in test_name):
            matching_tests.append(tc)

    return matching_tests


def get_assertion_types(test_case: Dict[str, Any]) -> set:
    """
    Extract assertion types from a test case.

    Args:
        test_case: Test case dictionary

    Returns:
        Set of assertion type strings
    """
    assertions = test_case.get('assertions', [])
    return {a.get('assertion_type', '') for a in assertions if a.get('assertion_type')}


def find_assertion(test_case: Dict[str, Any], assertion_type_substring: str) -> Dict[str, Any]:
    """
    Find assertion by type substring match.

    Args:
        test_case: Test case dictionary
        assertion_type_substring: Substring to match in assertion_type

    Returns:
        First matching assertion or empty dict
    """
    assertions = test_case.get('assertions', [])
    for assertion in assertions:
        if assertion_type_substring in assertion.get('assertion_type', ''):
            return assertion
    return {}


@pytest.mark.integration
@pytest.mark.performance
class TestPerformancePlannerE2ERegression:
    """
    End-to-end regression tests for Performance Planner Agent.

    Validates that PR #30 assertion struct fixes maintain correct semantics
    for performance test generation.
    """

    @pytest.mark.asyncio
    async def test_agent_executes_successfully(self, performance_planner, agent_task, api_spec):
        """
        Verify agent executes successfully and returns valid result structure.

        This is a smoke test to ensure basic functionality works before
        validating specific assertion details.
        """
        result = await performance_planner.execute(agent_task, api_spec)

        assert isinstance(result, AgentResult)
        assert result.task_id == agent_task.task_id
        assert result.agent_type == "Performance-Planner-Agent"
        assert result.status == "success"
        assert len(result.test_cases) > 0, "Should generate at least one test case"
        assert result.metadata is not None
        assert "test_types" in result.metadata

    @pytest.mark.asyncio
    async def test_load_test_assertions_complete(self, performance_planner, agent_task, api_spec):
        """
        Priority 2 HIGH: Verify load tests include all critical assertions.

        Critical assertions to validate:
        - response_time_p95_lt (and other percentiles: P50, P75, P90, P99, P99.9)
        - error_rate_lt
        - throughput_gt

        Risk: If assertions missing, SLO violations could go undetected in production.
        Impact: Production outages due to degraded performance not caught in testing.

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 658-676
        """
        result = await performance_planner.execute(agent_task, api_spec)

        # Find load test cases
        load_tests = find_test_cases_by_type(result.test_cases, 'load')

        assert len(load_tests) > 0, "Should generate at least one load test"

        # Validate each load test has critical assertions
        for tc in load_tests:
            assertion_types = get_assertion_types(tc)

            # Must include response time percentile assertions
            # Note: Different load profiles may use different percentiles
            percentile_assertions = [at for at in assertion_types if 'response_time_p' in at]
            assert len(percentile_assertions) > 0, \
                f"Load test '{tc.get('test_name')}' missing response time percentile assertions. Found: {assertion_types}"

            # Common percentiles to check for
            common_percentiles = ['p50', 'p75', 'p90', 'p95', 'p99']
            has_common_percentile = any(
                any(p in at for p in common_percentiles)
                for at in assertion_types
            )
            assert has_common_percentile, \
                f"Load test should include common percentile (P50/P75/P90/P95/P99). Found: {assertion_types}"

            # Must include error rate assertion
            has_error_rate = any('error_rate' in at for at in assertion_types)
            assert has_error_rate, \
                f"Load test '{tc.get('test_name')}' missing error_rate assertion. Found: {assertion_types}"

            # Must include throughput assertion
            has_throughput = any('throughput' in at for at in assertion_types)
            assert has_throughput, \
                f"Load test '{tc.get('test_name')}' missing throughput assertion. Found: {assertion_types}"

            # Verify assertion structure (PR #30 changes)
            for assertion in tc.get('assertions', []):
                # New pattern: assertion_type field must exist
                assert 'assertion_type' in assertion, \
                    f"Assertion missing 'assertion_type' field: {assertion}"

                # Old pattern: field and operator should NOT exist (removed in PR #30)
                assert 'field' not in assertion, \
                    f"Old assertion pattern detected - 'field' should not exist: {assertion}"
                assert 'operator' not in assertion, \
                    f"Old assertion pattern detected - 'operator' should not exist: {assertion}"

                # Must have expected value
                assert 'expected' in assertion, \
                    f"Assertion missing 'expected' value: {assertion}"

    @pytest.mark.asyncio
    async def test_endurance_test_memory_leak_assertion(self, performance_planner, agent_task, api_spec):
        """
        Priority 2 HIGH: Verify endurance tests check for memory leaks.

        Critical assertion to validate:
        - memory_leak_detection_eq with expected=False

        Risk: If assertion evaluation changed, memory leaks in endurance tests could pass.
        Impact: Production instability - OOM crashes after prolonged operation.
        Duration: 2h/8h/72h soak tests affected.

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 678-695
        """
        result = await performance_planner.execute(agent_task, api_spec)

        # Find endurance/soak test cases
        endurance_tests = find_test_cases_by_type(result.test_cases, 'endurance')
        soak_tests = find_test_cases_by_type(result.test_cases, 'soak')
        long_running_tests = endurance_tests + soak_tests

        # Note: Endurance tests may not always be generated for simple APIs
        # If they exist, they must have proper memory leak detection
        if len(long_running_tests) > 0:
            for tc in long_running_tests:
                assertion_types = get_assertion_types(tc)

                # Must include memory leak detection
                has_memory_leak_check = any('memory_leak' in at for at in assertion_types)
                assert has_memory_leak_check, \
                    f"Endurance test '{tc.get('test_name')}' missing memory_leak_detection assertion. Found: {assertion_types}"

                # Find the memory leak assertion and verify expected value
                leak_assertion = find_assertion(tc, 'memory_leak')
                assert leak_assertion, \
                    f"Could not find memory_leak assertion in test '{tc.get('test_name')}'"

                # Expected value should be False (no leak expected)
                expected_value = leak_assertion.get('expected')
                assert expected_value is False or expected_value == 'false' or expected_value == False, \
                    f"Memory leak assertion should expect False (no leak), got: {expected_value}"

                # Verify assertion type is correct
                assert leak_assertion['assertion_type'] == 'memory_leak_detection_eq', \
                    f"Memory leak assertion type incorrect: {leak_assertion['assertion_type']}"

    @pytest.mark.asyncio
    async def test_stress_test_breaking_point_assertions(self, performance_planner, agent_task, api_spec):
        """
        Priority 2 HIGH: Verify stress tests have breaking point detection assertions.

        Critical assertions to validate:
        - performance_degradation_lt (threshold checking)
        - breaking_point_identified (detection logic)
        - recovery_time validation

        Risk: Breaking point detection logic might not work correctly with new assertion pattern.
        Impact: Capacity planning errors - insufficient resources provisioned.

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 171-188
        """
        result = await performance_planner.execute(agent_task, api_spec)

        # Find stress test cases
        stress_tests = find_test_cases_by_type(result.test_cases, 'stress')

        assert len(stress_tests) > 0, "Should generate at least one stress test"

        for tc in stress_tests:
            assertion_types = get_assertion_types(tc)

            # Should include performance degradation checking
            has_degradation_check = any('degradation' in at or 'breaking' in at for at in assertion_types)

            # Also check performance config for breaking point detection
            perf_config = tc.get('performance_config', {})
            has_breaking_point_config = 'breaking_point_detection' in perf_config

            # Either assertions or config should indicate breaking point detection
            assert has_degradation_check or has_breaking_point_config, \
                f"Stress test '{tc.get('test_name')}' missing breaking point detection. Assertions: {assertion_types}, Config keys: {perf_config.keys()}"

            # Verify stress test has high user count for breaking point detection
            max_users = perf_config.get('max_virtual_users', 0)
            assert max_users > 50, \
                f"Stress test should have significant user load for breaking point detection, got {max_users} users"

    @pytest.mark.asyncio
    async def test_spike_test_assertions(self, performance_planner, agent_task, api_spec):
        """
        Priority 2 HIGH: Verify spike tests handle traffic spikes correctly.

        Critical assertions to validate:
        - error_rate_during_spike_lt
        - recovery_time validation
        - spike_handling metrics

        Risk: Spike handling validation might fail silently with new assertion pattern.
        Impact: Production system can't handle traffic spikes, leading to outages.

        Reference: REGRESSION_RISK_ANALYSIS_PR30.md lines 190-198
        """
        result = await performance_planner.execute(agent_task, api_spec)

        # Find spike test cases
        spike_tests = find_test_cases_by_type(result.test_cases, 'spike')

        assert len(spike_tests) > 0, "Should generate at least one spike test"

        for tc in spike_tests:
            assertion_types = get_assertion_types(tc)

            # Should include error rate checking (critical during spikes)
            has_error_rate = any('error_rate' in at for at in assertion_types)
            assert has_error_rate, \
                f"Spike test '{tc.get('test_name')}' missing error_rate assertion. Found: {assertion_types}"

            # Verify spike configuration
            perf_config = tc.get('performance_config', {})
            assert 'baseline_users' in perf_config, "Spike test missing baseline_users"
            assert 'spike_users' in perf_config, "Spike test missing spike_users"

            baseline = perf_config.get('baseline_users', 0)
            spike = perf_config.get('spike_users', 0)

            # Spike should be significantly higher than baseline
            assert spike > baseline * 3, \
                f"Spike test should have spike_users >> baseline_users. Got baseline={baseline}, spike={spike}"

    @pytest.mark.asyncio
    async def test_percentile_assertions_completeness(self, performance_planner, agent_task, api_spec):
        """
        Verify response time percentile assertions cover full spectrum.

        Expected percentiles: P50, P75, P90, P95, P99, P99.9

        Risk: Missing percentile assertions could miss SLO violations at different levels.
        Impact: Different user segments experience different performance (P99.9 users suffer).
        """
        result = await performance_planner.execute(agent_task, api_spec)

        # Collect all percentile assertions across all tests
        all_percentiles = set()

        for tc in result.test_cases:
            assertion_types = get_assertion_types(tc)
            for at in assertion_types:
                if 'response_time_p' in at:
                    # Extract percentile number (e.g., "response_time_p95_lt" -> "p95")
                    import re
                    match = re.search(r'p(\d+(?:\.\d+)?)', at)
                    if match:
                        all_percentiles.add(match.group(0))

        # Should cover at least common percentiles
        common_percentiles = {'p50', 'p75', 'p90', 'p95', 'p99'}
        found_common = common_percentiles.intersection(all_percentiles)

        assert len(found_common) >= 3, \
            f"Should cover at least 3 common percentiles. Found: {all_percentiles}, Common: {found_common}"

    @pytest.mark.asyncio
    async def test_assertion_structure_post_pr30(self, performance_planner, agent_task, api_spec):
        """
        Verify ALL assertions follow PR #30 structure (assertion_type pattern).

        PR #30 Changes:
        - Old: {field: "status", operator: "in", expected: [...]}
        - New: {assertion_type: "status_code_in", expected: [...], path: None}

        This test ensures complete migration to new pattern.
        """
        result = await performance_planner.execute(agent_task, api_spec)

        assertion_count = 0

        for tc in result.test_cases:
            for assertion in tc.get('assertions', []):
                assertion_count += 1

                # New pattern: Must have assertion_type
                assert 'assertion_type' in assertion, \
                    f"Assertion missing 'assertion_type' field (PR #30 requirement): {assertion}"

                # Old pattern: Must NOT have field/operator
                assert 'field' not in assertion, \
                    f"Old pattern detected - 'field' exists (should be removed per PR #30): {assertion}"
                assert 'operator' not in assertion, \
                    f"Old pattern detected - 'operator' exists (should be removed per PR #30): {assertion}"

                # Must have expected value
                assert 'expected' in assertion, \
                    f"Assertion missing 'expected' value: {assertion}"

                # Assertion type should follow naming convention: {field}_{operator}
                assertion_type = assertion['assertion_type']
                assert '_' in assertion_type or assertion_type.islower(), \
                    f"Assertion type should follow snake_case convention: {assertion_type}"

        # Should have generated some assertions
        assert assertion_count > 0, "No assertions generated - test may not be validating correctly"

        print(f"\n✓ Validated {assertion_count} assertions all follow PR #30 structure")

    @pytest.mark.asyncio
    async def test_critical_path_performance_validation(self, performance_planner, agent_task, api_spec):
        """
        Verify critical paths (auth, search) get comprehensive performance tests.

        Critical paths should have:
        - More aggressive load testing
        - Stricter SLO thresholds
        - Multiple percentile checks
        """
        result = await performance_planner.execute(agent_task, api_spec)

        # Find tests for critical paths
        auth_tests = [tc for tc in result.test_cases if 'auth' in tc.get('endpoint', '').lower() or 'login' in tc.get('endpoint', '').lower()]
        search_tests = [tc for tc in result.test_cases if 'search' in tc.get('endpoint', '').lower()]

        critical_path_tests = auth_tests + search_tests

        # Critical paths should have performance tests
        assert len(critical_path_tests) > 0, \
            "Critical paths (auth, search) should have dedicated performance tests"

        # Critical path tests should have comprehensive assertions
        for tc in critical_path_tests:
            assertion_types = get_assertion_types(tc)

            # Should have multiple types of assertions (not just one)
            assert len(assertion_types) >= 2, \
                f"Critical path test '{tc.get('test_name')}' should have comprehensive assertions. Found: {assertion_types}"

    @pytest.mark.asyncio
    async def test_data_intensive_operations_performance(self, performance_planner, agent_task, api_spec):
        """
        Verify data-intensive operations (upload, export) have appropriate tests.

        Data-intensive operations should consider:
        - Payload size limits
        - Processing time thresholds
        - Memory usage patterns
        """
        result = await performance_planner.execute(agent_task, api_spec)

        # Find tests for data-intensive operations
        upload_tests = [tc for tc in result.test_cases if 'upload' in tc.get('endpoint', '').lower()]
        export_tests = [tc for tc in result.test_cases if 'export' in tc.get('endpoint', '').lower() or 'report' in tc.get('endpoint', '').lower()]

        data_intensive_tests = upload_tests + export_tests

        # Data-intensive operations should have performance tests
        assert len(data_intensive_tests) > 0, \
            "Data-intensive operations (upload, export) should have performance tests"

        # Should include response time checks (data ops may be slower)
        for tc in data_intensive_tests:
            assertion_types = get_assertion_types(tc)
            has_response_time = any('response_time' in at for at in assertion_types)

            # Either assertions or config should indicate performance monitoring
            perf_config = tc.get('performance_config', {})
            has_perf_criteria = 'expected_response_time' in perf_config or 'success_criteria' in perf_config

            assert has_response_time or has_perf_criteria, \
                f"Data-intensive test '{tc.get('test_name')}' should monitor response time"

    @pytest.mark.asyncio
    async def test_no_regressions_in_test_generation_count(self, performance_planner, agent_task, api_spec):
        """
        Verify test generation count hasn't regressed.

        With 5 endpoints in the spec, should generate multiple test types:
        - Load tests
        - Stress tests
        - Spike tests
        - System-wide tests

        Minimum expected: At least 10 tests total.
        """
        result = await performance_planner.execute(agent_task, api_spec)

        test_count = len(result.test_cases)

        # Should generate comprehensive test suite
        assert test_count >= 10, \
            f"Should generate at least 10 performance tests for 5-endpoint API. Got {test_count} tests"

        # Should have variety of test types
        test_types = {tc.get('test_subtype', tc.get('test_type', 'unknown')) for tc in result.test_cases}

        assert len(test_types) >= 2, \
            f"Should generate multiple test types. Found: {test_types}"
