#!/usr/bin/env python3
"""
Simplified test script for the Fixed Functional Positive Agent implementation.
Tests the core functionality without complex dependencies.
"""

import sys
import os
from typing import Dict, List, Any
from datetime import datetime, timedelta

# Mock the settings module
class MockSettings:
    test_execution_timeout = 600

def get_application_settings():
    return MockSettings()

# Inject mock settings
sys.modules['sentinel_backend.config.settings'] = type('MockModule', (), {
    'get_application_settings': get_application_settings
})()

# Now import the agent classes
from .base_agent import BaseAgent, AgentTask, AgentResult
from functional_positive_agent import FunctionalPositiveAgent


def test_parameter_test_values():
    """Test the _generate_parameter_test_values method."""
    print("Testing parameter test value generation...")

    agent = FunctionalPositiveAgent()

    # Test integer parameter with limits
    limit_schema = {
        "type": "integer",
        "minimum": 1,
        "maximum": 50
    }
    limit_values = agent._generate_parameter_test_values("limit", limit_schema)
    print(f"Limit parameter test values: {limit_values}")
    assert len(limit_values) > 1, "Should generate multiple test values for integer parameters"
    assert all(1 <= v <= 50 for v in limit_values), "All values should be within bounds"

    # Test enum parameter
    status_schema = {
        "type": "string",
        "enum": ["available", "pending", "sold"]
    }
    status_values = agent._generate_parameter_test_values("status", status_schema)
    print(f"Status parameter test values: {status_values}")
    assert set(status_values) == {"available", "pending", "sold"}, "Should generate all enum values"

    # Test boolean parameter
    bool_schema = {"type": "boolean"}
    bool_values = agent._generate_parameter_test_values("active", bool_schema)
    print(f"Boolean parameter test values: {bool_values}")
    assert set(bool_values) == {True, False}, "Should generate both boolean values"

    print("✓ Parameter test value generation working correctly\n")


def test_query_parameter_generation():
    """Test the fixed _generate_query_parameters method."""
    print("Testing query parameter generation...")

    agent = FunctionalPositiveAgent()

    parameters = [
        {
            "name": "limit",
            "in": "query",
            "required": False,
            "schema": {"type": "integer", "minimum": 1, "maximum": 50}
        },
        {
            "name": "status",
            "in": "query",
            "required": False,
            "schema": {"type": "string", "enum": ["available", "pending", "sold"]}
        }
    ]

    test_cases = agent._generate_query_parameters(parameters)
    print(f"Generated {len(test_cases)} query parameter test cases")

    # Verify we get multiple test cases
    assert len(test_cases) > 5, f"Should generate multiple test cases, got {len(test_cases)}"

    # Verify each test case has the expected structure
    for test_case in test_cases:
        assert "_description" in test_case, "Each test case should have a description"
        # Check that we have parameter values
        param_keys = [k for k in test_case.keys() if k != "_description"]
        assert len(param_keys) > 0, "Each test case should have at least one parameter"

    print("✓ Query parameter generation working correctly\n")


def test_get_schema_example():
    """Test the _get_schema_example method from base class."""
    print("Testing schema example generation...")

    agent = FunctionalPositiveAgent()

    # Test different schema types
    schemas = [
        {"type": "string", "example": "test"},
        {"type": "integer", "minimum": 1, "maximum": 100},
        {"type": "boolean"},
        {"type": "array", "items": {"type": "string"}},
        {"type": "object", "properties": {"name": {"type": "string"}}}
    ]

    for schema in schemas:
        example = agent._get_schema_example(schema)
        print(f"Schema {schema} -> Example: {example}")
        assert example is not None, f"Should generate an example for schema {schema}"

    print("✓ Schema example generation working correctly\n")


def test_realistic_property_value_generation():
    """Test the _generate_realistic_property_value method."""
    print("Testing realistic property value generation...")

    agent = FunctionalPositiveAgent()

    test_cases = [
        ("email", {"type": "string"}, "should contain email format"),
        ("firstName", {"type": "string"}, "should be a first name"),
        ("lastName", {"type": "string"}, "should be a last name"),
        ("age", {"type": "integer"}, "should be reasonable age"),
        ("price", {"type": "number"}, "should be a price value"),
        ("phoneNumber", {"type": "string"}, "should be phone format"),
    ]

    for prop_name, schema, description in test_cases:
        value = agent._generate_realistic_property_value(prop_name, schema)
        print(f"Property '{prop_name}' -> Value: {value} ({description})")
        assert value is not None, f"Should generate value for {prop_name}"

    print("✓ Realistic property value generation working correctly\n")


def main():
    """Run all tests."""
    print("🧪 Testing Fixed Functional Positive Agent Core Implementation\n")
    print("=" * 60)

    try:
        test_parameter_test_values()
        test_query_parameter_generation()
        test_get_schema_example()
        test_realistic_property_value_generation()

        print("=" * 60)
        print("✅ All core tests passed! The Positive Test Agent fixes are working correctly.")

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()