#!/usr/bin/env python3
"""
Test the Functional-Positive-Agent specifically for enum and integer ID handling.
"""
import requests
import json
import sys

def test_positive_agent():
    """Test Functional-Positive-Agent with detailed output"""
    
    print("Fetching petstore OpenAPI spec...")
    
    try:
        # Get the petstore OpenAPI spec
        spec_response = requests.get("http://localhost:8080/openapi.json", timeout=5)
        api_spec = spec_response.json()
        print(f"✓ Successfully fetched OpenAPI spec")
        
        # Check for enum definitions in the spec
        if 'components' in api_spec and 'schemas' in api_spec['components']:
            schemas = api_spec['components']['schemas']
            if 'PetCategory' in schemas:
                enum_values = schemas['PetCategory'].get('enum', [])
                print(f"  PetCategory enum values: {enum_values}")
        
    except Exception as e:
        print(f"✗ Failed to fetch OpenAPI spec: {e}")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("Testing: Functional-Positive-Agent")
    print("="*60)
    
    payload = {
        "task": {
            "task_id": "test_positive_detailed",
            "spec_id": "petstore-test",
            "agent_type": "Functional-Positive-Agent",
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
                print(f"✓ Generated {len(test_cases)} test cases\n")
                
                # First, let's see what test cases were generated
                print("All generated test cases:")
                print("-" * 40)
                for i, tc in enumerate(test_cases):
                    print(f"\nTest {i+1}: {tc.get('test_name', 'N/A')}")
                    # Print the entire structure to understand it
                    print(f"  Structure: {json.dumps(tc, indent=4)[:500]}...")
                print()
                
                # Analyze POST /api/v1/pets test cases specifically
                post_pet_tests = [tc for tc in test_cases if 
                                 tc.get('test_definition', {}).get('method') == 'POST' and
                                 '/pets' in tc.get('test_definition', {}).get('path', '')]
                
                if post_pet_tests:
                    print(f"Found {len(post_pet_tests)} POST /api/v1/pets test cases:")
                    print("-" * 40)
                    
                    for i, test in enumerate(post_pet_tests[:3]):
                        print(f"\nTest {i+1}: {test.get('test_name', 'N/A')}")
                        test_def = test.get('test_definition', {})
                        
                        # Check body for proper enum values
                        body = test_def.get('body')
                        if body:
                            print(f"  Request Body:")
                            print(f"    {json.dumps(body, indent=4)}")
                            
                            # Validate specific fields
                            if isinstance(body, dict):
                                # Check category field
                                if 'category' in body:
                                    category = body['category']
                                    valid_categories = ['dog', 'cat', 'bird', 'fish', 'other']
                                    if category in valid_categories:
                                        print(f"    ✓ Valid category: {category}")
                                    else:
                                        print(f"    ✗ INVALID category: {category}")
                                        print(f"      Expected one of: {valid_categories}")
                                
                                # Check ID field
                                if 'id' in body:
                                    id_val = body['id']
                                    if isinstance(id_val, int):
                                        print(f"    ✓ ID is integer: {id_val}")
                                    else:
                                        print(f"    ✗ ID is not integer: {type(id_val).__name__} = {id_val}")
                                
                                # Check name field
                                if 'name' in body:
                                    name = body['name']
                                    if name and name != "example_string":
                                        print(f"    ✓ Realistic name: {name}")
                                    else:
                                        print(f"    ⚠ Generic name: {name}")
                
                # Check GET with path parameters
                get_pet_tests = [tc for tc in test_cases if 
                                tc.get('test_definition', {}).get('method') == 'GET' and
                                '{pet_id}' in tc.get('test_definition', {}).get('path', '')]
                
                if get_pet_tests:
                    print(f"\n\nFound {len(get_pet_tests)} GET /api/v1/pets/{{pet_id}} test cases:")
                    print("-" * 40)
                    
                    for test in get_pet_tests[:2]:
                        print(f"\nTest: {test.get('test_name', 'N/A')}")
                        test_def = test.get('test_definition', {})
                        path = test_def.get('path', '')
                        
                        # Check if path parameter was substituted
                        if '{' in path:
                            print(f"  ✗ Path parameter NOT substituted: {path}")
                        else:
                            print(f"  ✓ Path parameter substituted: {path}")
                            # Extract the ID from the path
                            parts = path.split('/')
                            if len(parts) > 0:
                                pet_id = parts[-1]
                                try:
                                    int_id = int(pet_id)
                                    print(f"    ✓ Integer ID in path: {int_id}")
                                except ValueError:
                                    print(f"    ✗ Non-integer ID in path: {pet_id}")
                
            else:
                print("✗ No test cases generated")
        else:
            print(f"✗ Error: HTTP {response.status_code}")
            print(f"  Response: {response.text[:500]}")
            
    except requests.exceptions.Timeout:
        print("✗ Request timed out")
    except Exception as e:
        print(f"✗ Exception: {e}")
    
    print("\n" + "="*60)
    print("Summary")
    print("="*60)
    print("The Functional-Positive-Agent should:")
    print("  1. Use valid enum values for 'category' field")
    print("  2. Generate integer IDs for path parameters")
    print("  3. Substitute path parameters correctly")
    print("  4. Generate realistic test data (not 'example_string')")

if __name__ == "__main__":
    test_positive_agent()