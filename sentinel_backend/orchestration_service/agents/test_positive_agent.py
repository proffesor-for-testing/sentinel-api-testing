#!/usr/bin/env python3
"""
Test script for the Fixed Functional Positive Agent implementation.
"""

import sys
import os
import asyncio
import json
from typing import Dict, Any

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../'))

# Import the modules directly
import importlib.util
import sys

# Load the functional_positive_agent module
spec = importlib.util.spec_from_file_location("functional_positive_agent",
    "/workspaces/api-testing-agents/sentinel_backend/orchestration_service/agents/functional_positive_agent.py")
fp_module = importlib.util.module_from_spec(spec)

# Load the base_agent module
base_spec = importlib.util.spec_from_file_location("base_agent",
    "/workspaces/api-testing-agents/sentinel_backend/orchestration_service/agents/base_agent.py")
base_module = importlib.util.module_from_spec(base_spec)

sys.modules['base_agent'] = base_module
base_spec.loader.exec_module(base_module)

sys.modules['functional_positive_agent'] = fp_module
spec.loader.exec_module(fp_module)

FunctionalPositiveAgent = fp_module.FunctionalPositiveAgent
AgentTask = base_module.AgentTask


def create_sample_openapi_spec() -> Dict[str, Any]:
    """Create a sample OpenAPI specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Pet Store API",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "https://api.petstore.com/v1"}
        ],
        "paths": {
            "/pets": {
                "get": {
                    "summary": "List all pets",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100
                            }
                        },
                        {
                            "name": "status",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "string",
                                "enum": ["available", "pending", "sold"]
                            }
                        },
                        {
                            "name": "category",
                            "in": "query",
                            "required": False,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "A list of pets",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/Pet"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create a pet",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/NewPet"
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Pet created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Pet"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/pets/{id}": {
                "get": {
                    "summary": "Get a pet by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {
                                "type": "integer"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Pet details",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Pet"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Pet": {
                    "type": "object",
                    "required": ["id", "name"],
                    "properties": {
                        "id": {
                            "type": "integer",
                            "format": "int64"
                        },
                        "name": {
                            "type": "string"
                        },
                        "status": {
                            "type": "string",
                            "enum": ["available", "pending", "sold"]
                        },
                        "category": {
                            "type": "string"
                        }
                    }
                },
                "NewPet": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": {
                            "type": "string"
                        },
                        "status": {
                            "type": "string",
                            "enum": ["available", "pending", "sold"]
                        },
                        "category": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    }


async def test_parameter_test_values():
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


async def test_query_parameter_generation():
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


async def test_parameter_variation_tests():
    """Test the parameter variation test generation."""
    print("Testing parameter variation test generation...")

    agent = FunctionalPositiveAgent()
    api_spec = create_sample_openapi_spec()

    # Extract the GET /pets endpoint
    pets_get_operation = api_spec["paths"]["/pets"]["get"]
    endpoint = {
        "path": "/pets",
        "method": "GET",
        "operation": pets_get_operation,
        "parameters": pets_get_operation.get("parameters", [])
    }

    test_cases = await agent._generate_parameter_variation_tests(endpoint, api_spec)
    print(f"Generated {len(test_cases)} parameter variation test cases")

    # Verify we get multiple test cases
    assert len(test_cases) > 0, "Should generate parameter variation test cases"

    # Verify test case structure
    for test_case in test_cases:
        assert "test_name" in test_case, "Test case should have a test_name"
        assert "method" in test_case, "Test case should have a method"
        assert "path" in test_case, "Test case should have a path"
        assert "query_params" in test_case, "Test case should have query_params"
        print(f"  - {test_case['test_name']}: {test_case['query_params']}")

    print("✓ Parameter variation test generation working correctly\n")


async def test_full_agent_execution():
    """Test the full agent execution."""
    print("Testing full agent execution...")

    agent = FunctionalPositiveAgent()
    api_spec = create_sample_openapi_spec()

    task = AgentTask(
        task_id="test-001",
        agent_type="functional-positive",
        spec_id="petstore-v1",
        parameters={}
    )

    result = await agent.execute(task, api_spec)

    assert result.status == "success", f"Agent execution should succeed, got status: {result.status}"
    assert result.test_cases is not None, "Should generate test cases"
    assert len(result.test_cases) > 0, "Should generate at least one test case"

    print(f"Generated {len(result.test_cases)} total test cases")

    # Verify test case variety
    methods = set(tc["method"] for tc in result.test_cases)
    paths = set(tc["path"] for tc in result.test_cases)

    print(f"Methods tested: {methods}")
    print(f"Paths tested: {paths}")

    # Print sample test cases
    print("\nSample test cases:")
    for i, test_case in enumerate(result.test_cases[:5]):
        print(f"  {i+1}. {test_case['test_name']}")
        print(f"     Method: {test_case['method']}")
        print(f"     Path: {test_case['path']}")
        if test_case.get('query_params'):
            print(f"     Query params: {test_case['query_params']}")
        if test_case.get('body'):
            print(f"     Body keys: {list(test_case['body'].keys()) if isinstance(test_case['body'], dict) else 'Not a dict'}")
        print()

    print("✓ Full agent execution working correctly\n")


async def main():
    """Run all tests."""
    print("🧪 Testing Fixed Functional Positive Agent Implementation\n")
    print("=" * 60)

    try:
        await test_parameter_test_values()
        await test_query_parameter_generation()
        await test_parameter_variation_tests()
        await test_full_agent_execution()

        print("=" * 60)
        print("✅ All tests passed! The Positive Test Agent fixes are working correctly.")

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())