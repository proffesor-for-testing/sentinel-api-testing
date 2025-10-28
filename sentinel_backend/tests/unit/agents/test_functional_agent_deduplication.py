"""
Unit Tests for FunctionalAgent Deduplication

This test suite validates that the improved MD5-based deduplication
correctly identifies and removes duplicate test cases.

TESTS COVER:
1. Same endpoint + method + values = DUPLICATE (should remove)
2. Same endpoint + method, different query VALUES = UNIQUE (should keep)
3. Same endpoint + method, different body VALUES = UNIQUE (should keep)
4. Same structure, different test_subtype = UNIQUE (should keep)
5. Cross-strategy duplicates are caught
"""

import pytest
from typing import Dict, List, Any
import hashlib

from sentinel_backend.orchestration_service.agents.functional_agent import FunctionalAgent


class TestFunctionalAgentDeduplication:
    """Test deduplication logic in FunctionalAgent"""

    @pytest.fixture
    def agent(self):
        """Create FunctionalAgent instance"""
        return FunctionalAgent()

    def test_identical_tests_are_duplicates(self, agent):
        """MUST detect identical tests as duplicates"""
        test1 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {'limit': 10},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get users with limit'
        }

        test2 = test1.copy()  # Exact duplicate

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 1, "Identical tests should be deduplicated"

    def test_different_query_values_are_unique(self, agent):
        """MUST keep tests with different query parameter VALUES"""
        test1 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {'limit': 10},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get users with limit 10'
        }

        test2 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {'limit': 50},  # DIFFERENT VALUE
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'parameter_variation',
            'test_name': 'Get users with limit 50'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 2, f"Different query values should be unique, got {len(unique)} tests"

    def test_different_body_values_are_unique(self, agent):
        """MUST keep tests with different body VALUES"""
        test1 = {
            'method': 'POST',
            'endpoint': '/users',
            'query_params': {},
            'body': {'name': 'Alice', 'email': 'alice@example.com'},
            'expected_status': 201,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Create user Alice'
        }

        test2 = {
            'method': 'POST',
            'endpoint': '/users',
            'query_params': {},
            'body': {'name': 'Bob', 'email': 'bob@example.com'},  # DIFFERENT VALUES
            'expected_status': 201,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Create user Bob'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 2, f"Different body values should be unique, got {len(unique)} tests"

    def test_different_subtype_are_unique(self, agent):
        """MUST keep tests with different test_subtype even if structure is same"""
        test1 = {
            'method': 'POST',
            'endpoint': '/users',
            'query_params': {},
            'body': {'name': 'Test'},
            'expected_status': 201,
            'test_type': 'functional-positive',
            'test_subtype': 'minimal',  # MINIMAL body
            'test_name': 'Minimal valid POST body'
        }

        test2 = {
            'method': 'POST',
            'endpoint': '/users',
            'query_params': {},
            'body': {'name': 'Test'},  # Same value but different intent
            'expected_status': 201,
            'test_type': 'functional-positive',
            'test_subtype': 'complete',  # COMPLETE body
            'test_name': 'Complete valid POST body'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        # These should be DIFFERENT because test_name differs
        assert len(unique) == 2, f"Different subtypes/descriptions should be unique, got {len(unique)} tests"

    def test_positive_vs_negative_same_structure(self, agent):
        """MUST keep positive and negative tests with same structure as unique"""
        test1 = {
            'method': 'POST',
            'endpoint': '/users',
            'query_params': {},
            'body': {'name': 'Valid', 'email': 'valid@example.com'},
            'expected_status': 201,
            'test_type': 'functional-positive',  # POSITIVE
            'test_subtype': 'valid',
            'test_name': 'Valid POST request'
        }

        test2 = {
            'method': 'POST',
            'endpoint': '/users',
            'query_params': {},
            'body': {'name': 'Valid', 'email': 'valid@example.com'},  # Same body
            'expected_status': 400,  # DIFFERENT expected status
            'test_type': 'functional-negative',  # NEGATIVE
            'test_subtype': 'missing_required',
            'test_name': 'Missing required fields in body'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        # Should be unique due to different expected_status and test_type
        assert len(unique) == 2, f"Positive vs negative should be unique, got {len(unique)} tests"

    def test_boundary_tests_with_different_values(self, agent):
        """MUST keep boundary tests with different values as unique"""
        test1 = {
            'method': 'GET',
            'endpoint': '/products',
            'query_params': {'limit': 1},  # MIN boundary
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-boundary',
            'test_subtype': 'min',
            'test_name': 'Boundary test: limit at min (1)'
        }

        test2 = {
            'method': 'GET',
            'endpoint': '/products',
            'query_params': {'limit': 100},  # MAX boundary
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-boundary',
            'test_subtype': 'max',
            'test_name': 'Boundary test: limit at max (100)'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 2, f"Different boundary values should be unique, got {len(unique)} tests"

    def test_signature_includes_description(self, agent):
        """MUST use description to distinguish otherwise identical tests"""
        test1 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {'limit': 10},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Test scenario A'  # Different description
        }

        test2 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {'limit': 10},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Test scenario B'  # Different description
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        # Should be unique due to different test_name
        assert len(unique) == 2, f"Different descriptions should make tests unique, got {len(unique)} tests"

    def test_empty_query_params_vs_no_query_params(self, agent):
        """MUST treat empty dict and None as equivalent for query_params"""
        test1 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {},  # Empty dict
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get all users'
        }

        test2 = {
            'method': 'GET',
            'endpoint': '/users',
            # query_params not specified (defaults to {})
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get all users'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 1, "Empty dict and missing query_params should be duplicate"

    def test_large_scale_deduplication(self, agent):
        """MUST handle large test suites efficiently"""
        tests = []

        # Generate 100 unique tests
        for i in range(100):
            tests.append({
                'method': 'GET',
                'endpoint': f'/resource/{i}',
                'query_params': {'id': i},
                'body': None,
                'expected_status': 200,
                'test_type': 'functional-positive',
                'test_subtype': 'valid',
                'test_name': f'Get resource {i}'
            })

        # Add 20 duplicates
        for i in range(20):
            tests.append(tests[i].copy())

        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 100, f"Should remove 20 duplicates from 120 tests, got {len(unique)}"

    def test_case_insensitive_method(self, agent):
        """MUST treat HTTP methods case-insensitively"""
        test1 = {
            'method': 'get',  # lowercase
            'endpoint': '/users',
            'query_params': {},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get users'
        }

        test2 = {
            'method': 'GET',  # uppercase
            'endpoint': '/users',
            'query_params': {},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get users'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 1, "Method comparison should be case-insensitive"

    def test_null_vs_missing_body_are_same(self, agent):
        """MUST treat None body and missing body as equivalent"""
        test1 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get users'
        }

        test2 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {},
            # body not specified
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Get users'
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 1, "None body and missing body should be duplicate"

    def test_signature_consistency(self, agent):
        """MUST generate same signature for identical tests"""
        test = {
            'method': 'POST',
            'endpoint': '/users',
            'query_params': {'validate': True},
            'body': {'name': 'Test', 'email': 'test@example.com'},
            'expected_status': 201,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Create test user'
        }

        sig1 = agent._create_test_signature(test)
        sig2 = agent._create_test_signature(test.copy())

        assert sig1 == sig2, "Signature must be consistent for identical tests"

    def test_deduplication_preserves_first_occurrence(self, agent):
        """MUST preserve the first occurrence when deduplicating"""
        test1 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Original test',
            'custom_field': 'first'  # Unique to test1
        }

        test2 = {
            'method': 'GET',
            'endpoint': '/users',
            'query_params': {},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'valid',
            'test_name': 'Original test',
            'custom_field': 'second'  # Unique to test2
        }

        tests = [test1, test2]
        unique = agent._deduplicate_tests(tests)

        assert len(unique) == 1
        assert unique[0]['custom_field'] == 'first', "Should preserve first occurrence"
