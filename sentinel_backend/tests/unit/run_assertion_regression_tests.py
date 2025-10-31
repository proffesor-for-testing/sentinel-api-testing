#!/usr/bin/env python3
"""
Simple test runner for assertion semantics regression tests.
Runs tests without pytest fixtures to avoid configuration issues.
"""

import sys
sys.path.insert(0, '/workspaces/api-testing-agents/sentinel_backend')

# Import the evaluator and test classes
from tests.unit.test_assertion_semantics_regression import (
    evaluate_assertion,
    TestAssertionSemanticsRegression,
    TestAssertionTypeNameMapping,
    TestBackwardCompatibility,
    TestAllAssertionTypes,
)


def run_test_class(test_class, test_methods=None):
    """Run all tests in a test class."""
    instance = test_class()
    all_methods = [m for m in dir(instance) if m.startswith('test_')]

    if test_methods:
        methods_to_run = [m for m in all_methods if m in test_methods]
    else:
        methods_to_run = all_methods

    results = {'passed': 0, 'failed': 0, 'errors': []}

    for method_name in methods_to_run:
        try:
            method = getattr(instance, method_name)
            method()
            results['passed'] += 1
            print(f"  ✓ {method_name}")
        except AssertionError as e:
            results['failed'] += 1
            results['errors'].append((method_name, str(e)))
            print(f"  ✗ {method_name}: {e}")
        except Exception as e:
            results['failed'] += 1
            results['errors'].append((method_name, f"ERROR: {e}"))
            print(f"  ✗ {method_name}: ERROR - {e}")

    return results


def main():
    """Run all regression tests."""
    print("="*80)
    print("🔴 CRITICAL REGRESSION TESTS: PR #30 Assertion Semantics")
    print("="*80)
    print()

    total_passed = 0
    total_failed = 0
    all_errors = []

    # Test Critical Assertions
    print("Priority 1: CRITICAL - Assertion Semantics")
    print("-"*80)
    results = run_test_class(TestAssertionSemanticsRegression)
    total_passed += results['passed']
    total_failed += results['failed']
    all_errors.extend(results['errors'])
    print()

    # Test Name Mapping
    print("Priority 2: HIGH - Assertion Type Name Mapping")
    print("-"*80)
    results = run_test_class(TestAssertionTypeNameMapping)
    total_passed += results['passed']
    total_failed += results['failed']
    all_errors.extend(results['errors'])
    print()

    # Test Backward Compatibility
    print("Priority 3: MEDIUM - Backward Compatibility")
    print("-"*80)
    results = run_test_class(TestBackwardCompatibility)
    total_passed += results['passed']
    total_failed += results['failed']
    all_errors.extend(results['errors'])
    print()

    # Test All Assertion Types
    print("Priority 4: MEDIUM - Comprehensive Coverage")
    print("-"*80)
    results = run_test_class(TestAllAssertionTypes)
    total_passed += results['passed']
    total_failed += results['failed']
    all_errors.extend(results['errors'])
    print()

    # Summary
    print("="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Total tests run: {total_passed + total_failed}")
    print(f"Passed: {total_passed} ✓")
    print(f"Failed: {total_failed} ✗")
    print()

    if all_errors:
        print("FAILURES:")
        print("-"*80)
        for test_name, error in all_errors:
            print(f"  {test_name}:")
            print(f"    {error}")
        print()

    if total_failed == 0:
        print("✅ ALL TESTS PASSED")
        print("✅ Assertion semantics are IDENTICAL after PR #30")
        print("✅ SAFE for production deployment")
        return 0
    else:
        print("❌ TESTS FAILED")
        print("❌ Assertion semantics have changed - REGRESSION DETECTED")
        print("❌ DO NOT DEPLOY to production until fixed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
