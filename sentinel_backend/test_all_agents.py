#!/usr/bin/env python3
import requests
import json
import sys

def test_agent(agent_name, api_spec):
    """Test a single agent with the petstore spec"""
    print(f"\n{'='*60}")
    print(f"Testing: {agent_name}")
    print(f"{'='*60}")
    
    payload = {
        "task": {
            "task_id": f"test_{agent_name}",
            "spec_id": "petstore-test",
            "agent_type": agent_name,
            "parameters": {},
            "target_environment": "test"
        },
        "api_spec": api_spec
    }
    
    try:
        response = requests.post(
            "http://localhost:8088/swarm/orchestrate",
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            test_cases = result.get('result', {}).get('test_cases', [])
            
            if test_cases:
                print(f"✓ Generated {len(test_cases)} test cases")
                
                # Analyze the first few test cases
                for i, test in enumerate(test_cases[:3]):
                    print(f"\nTest {i+1}: {test.get('test_name', 'N/A')}")
                    test_def = test.get('test_definition', {})
                    
                    # Check body for proper enum values
                    body = test_def.get('body')
                    if body and isinstance(body, dict):
                        # Check category field
                        if 'category' in body:
                            category = body['category']
                            valid_categories = ['dog', 'cat', 'bird', 'fish', 'other']
                            if category in valid_categories:
                                print(f"  ✓ Valid category: {category}")
                            else:
                                print(f"  ✗ Invalid category: {category}")
                                print(f"    Expected one of: {valid_categories}")
                        
                        # Check other fields
                        if 'name' in body:
                            print(f"  Name: {body['name']}")
                        if 'id' in body:
                            id_val = body['id']
                            if isinstance(id_val, int):
                                print(f"  ✓ ID is integer: {id_val}")
                            else:
                                print(f"  ⚠ ID type: {type(id_val).__name__} = {id_val}")
                    
                    # Check path parameters
                    path = test_def.get('path', '')
                    if '{' in path:
                        print(f"  Path with params: {path}")
                    elif path:
                        print(f"  Path: {path}")
                    
                    # Check query parameters
                    query = test_def.get('query_parameters')
                    if query:
                        print(f"  Query params: {query}")
                    
                if len(test_cases) > 3:
                    print(f"\n  ... and {len(test_cases) - 3} more test cases")
                    
            else:
                print(f"✗ No test cases generated")
        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(f"  Response: {response.text[:500]}")
            
    except requests.exceptions.Timeout:
        print(f"✗ Request timed out")
    except Exception as e:
        print(f"✗ Exception: {e}")
        
    return agent_name

def main():
    # Test each agent type
    agents = [
        "Functional-Positive-Agent",
        "Functional-Negative-Agent", 
        "Security-Auth-Agent",
        "Security-Injection-Agent",
        "Functional-Stateful-Agent",
        "Performance-Planner-Agent",
        "data-mocking"  # Note: This one has a different naming pattern
    ]
    
    print(f"Fetching petstore OpenAPI spec...")
    
    try:
        # Get the petstore OpenAPI spec
        spec_response = requests.get("http://localhost:8080/openapi.json", timeout=5)
        api_spec = spec_response.json()
        print(f"✓ Successfully fetched OpenAPI spec")
        print(f"  Title: {api_spec.get('info', {}).get('title', 'N/A')}")
        print(f"  Version: {api_spec.get('info', {}).get('version', 'N/A')}")
        
        # Check for enum definitions in the spec
        if 'components' in api_spec and 'schemas' in api_spec['components']:
            schemas = api_spec['components']['schemas']
            if 'PetCategory' in schemas:
                enum_values = schemas['PetCategory'].get('enum', [])
                print(f"  PetCategory enum values: {enum_values}")
        
    except Exception as e:
        print(f"✗ Failed to fetch OpenAPI spec: {e}")
        print(f"Make sure the petstore service is running on http://localhost:8080")
        sys.exit(1)
    
    print(f"\nTesting all agents...")
    print(f"This will test each agent's ability to generate valid test cases")
    
    results = []
    for agent in agents:
        result = test_agent(agent, api_spec)
        results.append(result)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Summary")
    print(f"{'='*60}")
    print(f"✓ Tested {len(results)} agents")
    
    print(f"\nNote: Check the test cases above to ensure:")
    print(f"  1. Enum fields (like 'category') use valid values")
    print(f"  2. Integer ID fields are numbers, not strings")
    print(f"  3. Path parameters are properly substituted")
    print(f"  4. Required fields are present")

if __name__ == "__main__":
    main()