"""
Standalone tests for DataMockingAgent - runs without full backend dependencies
"""
import sys
import os
import asyncio
import json
import time
from datetime import datetime

# Add parent to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sentinel_backend'))

# Direct import to avoid dependency issues
exec(open('/workspaces/api-testing-agents/sentinel_backend/orchestration_service/agents/data_mocking_agent.py').read())


def test_agent_initialization():
    """Test agent initialization and configuration"""
    agent = DataMockingAgent()
    assert agent.agent_type == "data-mocking"
    assert agent.default_count == 10
    assert len(agent.strategies) == 4
    print("✓ Agent initialization test passed")


async def test_string_generation():
    """Test string data generation"""
    agent = DataMockingAgent()
    
    # Test with minLength/maxLength
    schema = {"type": "string", "minLength": 5, "maxLength": 10}
    result = await agent._generate_from_schema(schema, {}, 'realistic')
    assert isinstance(result, str)
    assert 5 <= len(result) <= 10
    print(f"✓ String generation test passed: '{result}' (length: {len(result)})")
    
    # Test with enum
    schema = {"type": "string", "enum": ["red", "green", "blue"]}
    result = await agent._generate_from_schema(schema, {}, 'realistic')
    assert result in ["red", "green", "blue"]
    print(f"✓ Enum test passed: {result}")
    
    # Test with format
    schema = {"type": "string", "format": "email"}
    result = await agent._generate_from_schema(schema, {}, 'realistic')
    assert "@" in result
    print(f"✓ Email format test passed: {result}")


async def test_integer_generation():
    """Test integer data generation"""
    agent = DataMockingAgent()
    
    schema = {"type": "integer", "minimum": 10, "maximum": 20}
    result = await agent._generate_from_schema(schema, {}, 'realistic')
    assert isinstance(result, int)
    assert 10 <= result <= 20
    print(f"✓ Integer generation test passed: {result}")
    
    # Test edge cases
    result = await agent._generate_from_schema(schema, {}, 'edge_cases')
    assert result in [10, 11, 19, 20]
    print(f"✓ Integer edge cases test passed: {result}")


async def test_boolean_generation():
    """Test boolean data generation"""
    agent = DataMockingAgent()
    
    schema = {"type": "boolean"}
    result = await agent._generate_from_schema(schema, {}, 'realistic')
    assert isinstance(result, bool)
    print(f"✓ Boolean generation test passed: {result}")


async def test_array_generation():
    """Test array data generation"""
    agent = DataMockingAgent()
    
    schema = {
        "type": "array",
        "items": {"type": "string"},
        "minItems": 2,
        "maxItems": 5
    }
    result = await agent._generate_from_schema(schema, {}, 'realistic')
    assert isinstance(result, list)
    assert 2 <= len(result) <= 5
    assert all(isinstance(item, str) for item in result)
    print(f"✓ Array generation test passed: {len(result)} items")


async def test_object_generation():
    """Test object data generation"""
    agent = DataMockingAgent()
    
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "active": {"type": "boolean"}
        },
        "required": ["id", "name"]
    }
    result = await agent._generate_from_schema(schema, {}, 'realistic')
    assert isinstance(result, dict)
    assert "id" in result
    assert "name" in result
    assert isinstance(result["id"], int)
    assert isinstance(result["name"], str)
    print(f"✓ Object generation test passed: {len(result)} properties")


async def test_execute_with_api_spec():
    """Test full execution with OpenAPI spec"""
    agent = DataMockingAgent()
    
    api_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string", "minLength": 1, "maxLength": 100},
                        "email": {"type": "string", "format": "email"},
                        "age": {"type": "integer", "minimum": 18, "maximum": 120},
                        "active": {"type": "boolean"}
                    },
                    "required": ["name", "email"]
                }
            }
        }
    }
    
    config = {'strategy': 'realistic', 'count': 3}
    result = await agent.execute(api_spec, config)
    
    assert result['agent_type'] == 'data-mocking'
    assert result['strategy'] == 'realistic'
    assert 'mock_data' in result
    assert 'global_data' in result
    assert 'analysis' in result
    
    # Check mock data structure
    assert '/users' in result['mock_data']
    assert 'get' in result['mock_data']['/users']
    assert 'post' in result['mock_data']['/users']
    
    # Check global data
    assert 'users' in result['global_data']
    assert len(result['global_data']['users']) == 3
    
    print(f"✓ Full execution test passed")
    print(f"  Paths processed: {result['metadata']['paths_processed']}")
    print(f"  Users generated: {len(result['global_data']['users'])}")


async def test_deterministic_generation():
    """Test deterministic data generation with seed"""
    agent = DataMockingAgent()
    
    api_spec = {
        "openapi": "3.0.0",
        "paths": {
            "/test": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    config = {'strategy': 'realistic', 'count': 2, 'seed': 42}
    
    result1 = await agent.execute(api_spec, config)
    result2 = await agent.execute(api_spec, config)
    
    # Results should be identical with same seed
    assert json.dumps(result1['mock_data'], sort_keys=True) == json.dumps(result2['mock_data'], sort_keys=True)
    print("✓ Deterministic generation test passed")


async def test_custom_faker_provider():
    """Test custom API provider methods"""
    from faker import Faker
    faker = Faker()
    faker.add_provider(APIProvider)
    
    # Test API key
    api_key = faker.api_key()
    assert api_key.startswith("sk-")
    assert len(api_key) > 35
    print(f"✓ API key generation test passed: {api_key[:20]}...")
    
    # Test JWT token
    jwt = faker.jwt_token()
    assert jwt.count('.') == 2
    print(f"✓ JWT token generation test passed: {jwt[:30]}...")
    
    # Test resource ID
    resource_id = faker.resource_id("user")
    assert resource_id.startswith("user_")
    print(f"✓ Resource ID generation test passed: {resource_id}")
    
    # Test version string
    version = faker.version_string()
    assert '.' in version
    print(f"✓ Version string generation test passed: {version}")


async def test_performance_10k_records():
    """Test performance - should generate 10k records < 1 second"""
    agent = DataMockingAgent()
    
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"}
        }
    }
    
    start_time = time.time()
    records = []
    
    for _ in range(10000):
        record = await agent._generate_from_schema(schema, {}, 'realistic')
        records.append(record)
    
    elapsed = time.time() - start_time
    rate = 10000 / elapsed
    
    print(f"✓ Performance test passed:")
    print(f"  10,000 records generated in {elapsed:.3f}s")
    print(f"  Rate: {rate:.0f} records/second")
    
    assert elapsed < 1.0, f"Performance too slow: {elapsed:.3f}s (should be < 1.0s)"
    assert len(records) == 10000


def run_all_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("DATA MOCKING AGENT - COMPREHENSIVE TEST SUITE")
    print("="*60 + "\n")
    
    # Synchronous tests
    print("Running synchronous tests...")
    test_agent_initialization()
    
    # Async tests
    print("\nRunning async tests...")
    loop = asyncio.get_event_loop()
    
    tests = [
        ("String Generation", test_string_generation()),
        ("Integer Generation", test_integer_generation()),
        ("Boolean Generation", test_boolean_generation()),
        ("Array Generation", test_array_generation()),
        ("Object Generation", test_object_generation()),
        ("Full Execution", test_execute_with_api_spec()),
        ("Deterministic Generation", test_deterministic_generation()),
        ("Custom Faker Provider", test_custom_faker_provider()),
        ("Performance (10k records)", test_performance_10k_records()),
    ]
    
    for test_name, test_coro in tests:
        try:
            loop.run_until_complete(test_coro)
        except Exception as e:
            print(f"✗ {test_name} FAILED: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "="*60)
    print("ALL TESTS COMPLETED")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_all_tests()
