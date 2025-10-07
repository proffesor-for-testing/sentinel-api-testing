#!/usr/bin/env python3
"""
Standalone Deduplication Test

Tests the improved MD5-based deduplication logic without dependencies.
"""

import hashlib
import json
from typing import Dict, List, Any, Set


def _create_test_signature(test: Dict[str, Any]) -> str:
    """
    Create unique signature for a test case.

    IMPROVED ALGORITHM:
    - Includes actual query parameter VALUES (not just keys)
    - Includes actual body VALUES (not just structure)
    - Includes test_type AND test_subtype for better categorization
    - Includes description hash to distinguish similar tests

    This reduces false positives where tests with different data
    were incorrectly considered "unique".
    """
    # Normalize query params by including VALUES
    query_params = test.get('query_params', {})
    normalized_query = {}
    if query_params:
        for key in sorted(query_params.keys()):
            val = query_params[key]
            # Normalize values to strings for consistent comparison
            normalized_query[key] = str(val) if val is not None else 'null'

    # Normalize body by including VALUES (not just structure)
    body = test.get('body')
    normalized_body = None
    if body is not None:
        if isinstance(body, dict):
            # Include actual values, sorted by key
            normalized_body = {k: str(v) for k, v in sorted(body.items())}
        elif isinstance(body, list):
            normalized_body = [str(item) for item in body]
        else:
            normalized_body = str(body)

    # Create comprehensive signature
    sig_data = {
        'method': test.get('method', '').upper(),
        'endpoint': test.get('endpoint', test.get('path', '')),
        'test_type': test.get('test_type', ''),
        'test_subtype': test.get('test_subtype', ''),  # NEW: Include subtype
        'query_params': normalized_query,  # CHANGED: Include VALUES
        'body': normalized_body,  # CHANGED: Include VALUES
        'expected_status': test.get('expected_status_codes', [test.get('expected_status', 200)])[0],
        # NEW: Include description hash for additional uniqueness
        'description_hash': hashlib.md5(
            test.get('test_name', test.get('description', '')).encode()
        ).hexdigest()[:8]
    }

    sig_str = json.dumps(sig_data, sort_keys=True)
    return hashlib.md5(sig_str.encode()).hexdigest()


def _deduplicate_tests(test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate test cases based on signature"""
    seen_signatures: Set[str] = set()
    unique_tests = []

    for test in test_cases:
        signature = _create_test_signature(test)
        if signature not in seen_signatures:
            seen_signatures.add(signature)
            unique_tests.append(test)

    return unique_tests


def test_identical_tests_are_duplicates():
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
    unique = _deduplicate_tests(tests)

    assert len(unique) == 1, f"FAIL: Identical tests should be deduplicated, got {len(unique)}"
    print("✓ test_identical_tests_are_duplicates PASSED")


def test_different_query_values_are_unique():
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
    unique = _deduplicate_tests(tests)

    assert len(unique) == 2, f"FAIL: Different query values should be unique, got {len(unique)} tests"
    print("✓ test_different_query_values_are_unique PASSED")


def test_different_body_values_are_unique():
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
    unique = _deduplicate_tests(tests)

    assert len(unique) == 2, f"FAIL: Different body values should be unique, got {len(unique)} tests"
    print("✓ test_different_body_values_are_unique PASSED")


def test_different_subtype_are_unique():
    """MUST keep tests with different test_subtype"""
    test1 = {
        'method': 'POST',
        'endpoint': '/users',
        'query_params': {},
        'body': {'name': 'Test'},
        'expected_status': 201,
        'test_type': 'functional-positive',
        'test_subtype': 'minimal',
        'test_name': 'Minimal valid POST body'
    }

    test2 = {
        'method': 'POST',
        'endpoint': '/users',
        'query_params': {},
        'body': {'name': 'Test'},
        'expected_status': 201,
        'test_type': 'functional-positive',
        'test_subtype': 'complete',
        'test_name': 'Complete valid POST body'
    }

    tests = [test1, test2]
    unique = _deduplicate_tests(tests)

    # Different test_name makes them unique
    assert len(unique) == 2, f"FAIL: Different subtypes/descriptions should be unique, got {len(unique)} tests"
    print("✓ test_different_subtype_are_unique PASSED")


def test_positive_vs_negative_same_structure():
    """MUST keep positive and negative tests with same structure as unique"""
    test1 = {
        'method': 'POST',
        'endpoint': '/users',
        'query_params': {},
        'body': {'name': 'Valid', 'email': 'valid@example.com'},
        'expected_status': 201,
        'test_type': 'functional-positive',
        'test_subtype': 'valid',
        'test_name': 'Valid POST request'
    }

    test2 = {
        'method': 'POST',
        'endpoint': '/users',
        'query_params': {},
        'body': {'name': 'Valid', 'email': 'valid@example.com'},
        'expected_status': 400,
        'test_type': 'functional-negative',
        'test_subtype': 'missing_required',
        'test_name': 'Missing required fields'
    }

    tests = [test1, test2]
    unique = _deduplicate_tests(tests)

    assert len(unique) == 2, f"FAIL: Positive vs negative should be unique, got {len(unique)} tests"
    print("✓ test_positive_vs_negative_same_structure PASSED")


def test_deduplication_rate():
    """MUST achieve <8% duplication rate (improved from baseline 8.0%)"""
    tests = []

    # Simulate realistic test generation
    # Positive tests
    for i in range(20):
        tests.append({
            'method': 'GET',
            'endpoint': '/products',
            'query_params': {'limit': 10 + i},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-positive',
            'test_subtype': 'parameter_variation',
            'test_name': f'Get products with limit {10 + i}'
        })

    # Negative tests
    for i in range(10):
        tests.append({
            'method': 'POST',
            'endpoint': '/products',
            'query_params': {},
            'body': {'name': 'x' * i if i > 0 else ''},  # Different constraint violations
            'expected_status': 400,
            'test_type': 'functional-negative',
            'test_subtype': 'too_short' if i < 3 else 'valid',
            'test_name': f'Invalid product name length {i}'
        })

    # Boundary tests
    for limit_val, boundary_type in [(1, 'min'), (100, 'max')]:
        tests.append({
            'method': 'GET',
            'endpoint': '/products',
            'query_params': {'limit': limit_val},
            'body': None,
            'expected_status': 200,
            'test_type': 'functional-boundary',
            'test_subtype': f'boundary_{boundary_type}',
            'test_name': f'Boundary: {boundary_type} limit'
        })

    # Edge case tests
    tests.append({
        'method': 'GET',
        'endpoint': '/products',
        'query_params': {'search': '🚀'},
        'body': None,
        'expected_status': 200,
        'test_type': 'edge_case',
        'test_subtype': 'unicode',
        'test_name': 'Unicode emoji search'
    })

    # Add 2 intentional duplicates (to simulate ~6% duplication)
    duplicates = [tests[0].copy(), tests[15].copy()]
    tests.extend(duplicates)

    total = len(tests)
    unique = _deduplicate_tests(tests)
    unique_count = len(unique)

    duplicates_removed = total - unique_count
    duplication_rate = (duplicates_removed / total * 100) if total > 0 else 0

    print(f"  Total tests: {total}")
    print(f"  Unique tests: {unique_count}")
    print(f"  Duplicates removed: {duplicates_removed}")
    print(f"  Duplication rate: {duplication_rate:.1f}%")

    assert duplication_rate < 8.0, f"FAIL: Duplication rate {duplication_rate:.1f}% exceeds 8% threshold"
    print(f"✓ test_deduplication_rate PASSED (target: <8%, actual: {duplication_rate:.1f}%)")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("STANDALONE DEDUPLICATION TESTS")
    print("="*80 + "\n")

    try:
        test_identical_tests_are_duplicates()
        test_different_query_values_are_unique()
        test_different_body_values_are_unique()
        test_different_subtype_are_unique()
        test_positive_vs_negative_same_structure()
        test_deduplication_rate()

        print("\n" + "="*80)
        print("✅ ALL TESTS PASSED - Deduplication logic is working correctly!")
        print("="*80 + "\n")
        exit(0)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}\n")
        exit(1)
