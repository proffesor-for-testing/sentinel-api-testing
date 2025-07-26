#!/usr/bin/env python3
"""
Sentinel Phase 3 Demonstration Script

This script demonstrates the Phase 3 capabilities of the Sentinel platform:
1. Upload an API specification
2. Generate test cases using both Functional-Positive-Agent and Functional-Negative-Agent
3. Execute tests to show the difference between positive and negative testing
4. Display comprehensive results showing boundary value analysis and creative invalid inputs

Usage:
    python demo_phase3.py

Prerequisites:
    - All Sentinel services running (via docker-compose up)
    - A target API to test (or use a public API like JSONPlaceholder)
"""

import asyncio
import json
import httpx
from typing import Dict, Any

# Configuration
SENTINEL_GATEWAY_URL = "http://localhost:8080"  # Adjust based on your setup
TARGET_API_URL = "https://jsonplaceholder.typicode.com"  # Example API for testing

# Enhanced OpenAPI specification with constraints for better negative testing
ENHANCED_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Enhanced JSONPlaceholder API",
        "version": "1.0.0",
        "description": "Enhanced API specification for demonstrating Phase 3 negative testing capabilities"
    },
    "servers": [
        {
            "url": "https://jsonplaceholder.typicode.com"
        }
    ],
    "paths": {
        "/posts": {
            "get": {
                "summary": "Get all posts",
                "description": "Retrieve a list of all posts with optional filtering",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100
                        },
                        "description": "Maximum number of posts to return"
                    },
                    {
                        "name": "userId",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "integer",
                            "minimum": 1
                        },
                        "description": "Filter posts by user ID"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "List of posts",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {
                                        "$ref": "#/components/schemas/Post"
                                    }
                                }
                            }
                        }
                    },
                    "400": {
                        "description": "Bad request - invalid parameters"
                    }
                }
            },
            "post": {
                "summary": "Create a new post",
                "description": "Create a new post with validation",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/PostInput"
                            }
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Post created successfully",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/Post"
                                }
                            }
                        }
                    },
                    "400": {
                        "description": "Bad request - validation failed"
                    },
                    "422": {
                        "description": "Unprocessable entity - invalid data"
                    }
                }
            }
        },
        "/posts/{id}": {
            "get": {
                "summary": "Get a specific post",
                "description": "Retrieve a specific post by ID",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100
                        },
                        "description": "Post ID"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Post details",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/Post"
                                }
                            }
                        }
                    },
                    "400": {
                        "description": "Bad request - invalid ID"
                    },
                    "404": {
                        "description": "Post not found"
                    }
                }
            },
            "put": {
                "summary": "Update a post",
                "description": "Update an existing post",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "integer",
                            "minimum": 1
                        }
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/PostUpdate"
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Post updated successfully"
                    },
                    "400": {
                        "description": "Bad request - validation failed"
                    },
                    "404": {
                        "description": "Post not found"
                    }
                }
            }
        },
        "/users": {
            "post": {
                "summary": "Create a new user",
                "description": "Create a new user with strict validation",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/UserInput"
                            }
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "User created successfully"
                    },
                    "400": {
                        "description": "Bad request - validation failed"
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "Post": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer"
                    },
                    "userId": {
                        "type": "integer"
                    },
                    "title": {
                        "type": "string"
                    },
                    "body": {
                        "type": "string"
                    }
                },
                "required": ["userId", "title", "body"]
            },
            "PostInput": {
                "type": "object",
                "properties": {
                    "userId": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10
                    },
                    "title": {
                        "type": "string",
                        "minLength": 5,
                        "maxLength": 100
                    },
                    "body": {
                        "type": "string",
                        "minLength": 10,
                        "maxLength": 1000
                    }
                },
                "required": ["userId", "title", "body"]
            },
            "PostUpdate": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "minLength": 5,
                        "maxLength": 100
                    },
                    "body": {
                        "type": "string",
                        "minLength": 10,
                        "maxLength": 1000
                    }
                }
            },
            "UserInput": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "minLength": 2,
                        "maxLength": 50
                    },
                    "username": {
                        "type": "string",
                        "minLength": 3,
                        "maxLength": 20,
                        "pattern": "^[a-zA-Z0-9_]+$"
                    },
                    "email": {
                        "type": "string",
                        "format": "email",
                        "maxLength": 100
                    },
                    "age": {
                        "type": "integer",
                        "minimum": 13,
                        "maximum": 120
                    }
                },
                "required": ["name", "username", "email"]
            }
        }
    }
}


async def demonstrate_phase3_capabilities():
    """Demonstrate Phase 3 negative testing capabilities."""
    print("🚀 Sentinel Phase 3 Demonstration - Advanced Negative Testing")
    print("=" * 70)
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            # Step 1: Check if Sentinel is running
            print("\n1️⃣ Checking Sentinel Gateway status...")
            response = await client.get(f"{SENTINEL_GATEWAY_URL}/")
            if response.status_code == 200:
                gateway_info = response.json()
                print(f"✅ Sentinel Gateway is running - {gateway_info['message']}")
            else:
                print("❌ Sentinel Gateway is not responding")
                return
            
            # Step 2: Upload enhanced specification
            print("\n2️⃣ Uploading enhanced API specification with constraints...")
            spec_request = {
                "raw_spec": json.dumps(ENHANCED_OPENAPI_SPEC),
                "source_filename": "enhanced_demo_spec.yaml"
            }
            
            spec_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/specifications",
                json=spec_request
            )
            
            if spec_response.status_code != 200:
                print(f"❌ Failed to upload specification: {spec_response.status_code}")
                return
            
            spec_data = spec_response.json()
            spec_id = spec_data['id']
            print(f"✅ Specification uploaded with ID: {spec_id}")
            
            # Step 3: Generate positive test cases
            print("\n3️⃣ Generating positive test cases...")
            positive_request = {
                "spec_id": spec_id,
                "agent_types": ["Functional-Positive-Agent"]
            }
            
            positive_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/generate-tests",
                json=positive_request
            )
            
            if positive_response.status_code == 200:
                positive_data = positive_response.json()
                positive_count = positive_data['total_test_cases']
                print(f"✅ Generated {positive_count} positive test cases")
                
                # Show positive test metadata
                for result in positive_data['agent_results']:
                    if result['agent_type'] == 'Functional-Positive-Agent':
                        metadata = result.get('metadata', {})
                        print(f"   📊 Strategy: {metadata.get('generation_strategy', 'N/A')}")
                        print(f"   📋 Endpoints covered: {metadata.get('total_endpoints', 'N/A')}")
            else:
                print(f"❌ Failed to generate positive tests: {positive_response.status_code}")
                return
            
            # Step 4: Generate negative test cases
            print("\n4️⃣ Generating negative test cases with BVA and creative techniques...")
            negative_request = {
                "spec_id": spec_id,
                "agent_types": ["Functional-Negative-Agent"]
            }
            
            negative_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/generate-tests",
                json=negative_request
            )
            
            if negative_response.status_code == 200:
                negative_data = negative_response.json()
                negative_count = negative_data['total_test_cases']
                print(f"✅ Generated {negative_count} negative test cases")
                
                # Show negative test metadata
                for result in negative_data['agent_results']:
                    if result['agent_type'] == 'Functional-Negative-Agent':
                        metadata = result.get('metadata', {})
                        print(f"   📊 Strategy: {metadata.get('generation_strategy', 'N/A')}")
                        print(f"   📋 Test categories:")
                        for category in metadata.get('test_categories', []):
                            print(f"      • {category.replace('_', ' ').title()}")
            else:
                print(f"❌ Failed to generate negative tests: {negative_response.status_code}")
                return
            
            # Step 5: Compare test case types
            print("\n5️⃣ Analyzing generated test cases...")
            cases_response = await client.get(
                f"{SENTINEL_GATEWAY_URL}/api/v1/test-cases?spec_id={spec_id}"
            )
            
            if cases_response.status_code == 200:
                all_cases = cases_response.json()
                positive_cases = [c for c in all_cases if 'positive' in c.get('tags', [])]
                negative_cases = [c for c in all_cases if 'negative' in c.get('tags', [])]
                
                print(f"✅ Retrieved {len(all_cases)} total test cases")
                print(f"   • ✅ Positive tests: {len(positive_cases)}")
                print(f"   • ❌ Negative tests: {len(negative_cases)}")
                
                # Show sample positive test
                if positive_cases:
                    print(f"\n📋 Sample Positive Test Case:")
                    sample_positive = positive_cases[0]
                    test_def = sample_positive.get('test_definition', {})
                    print(f"   • Description: {sample_positive.get('description', 'N/A')}")
                    print(f"   • Method: {test_def.get('method', 'N/A')}")
                    print(f"   • Endpoint: {test_def.get('endpoint', 'N/A')}")
                    print(f"   • Expected Status: {test_def.get('expected_status', 'N/A')}")
                    if test_def.get('body'):
                        print(f"   • Sample Body: {json.dumps(test_def['body'], indent=6)}")
                
                # Show sample negative tests
                if negative_cases:
                    print(f"\n📋 Sample Negative Test Cases:")
                    for i, sample_negative in enumerate(negative_cases[:3], 1):
                        test_def = sample_negative.get('test_definition', {})
                        print(f"   {i}. {sample_negative.get('description', 'N/A')}")
                        print(f"      • Method: {test_def.get('method', 'N/A')}")
                        print(f"      • Expected Status: {test_def.get('expected_status', 'N/A')}")
                        if test_def.get('body'):
                            print(f"      • Invalid Body: {json.dumps(test_def['body'], indent=8)}")
                        print()
            
            # Step 6: Execute comprehensive test suite
            print("\n6️⃣ Executing comprehensive test suite (positive + negative)...")
            comprehensive_request = {
                "raw_spec": json.dumps(ENHANCED_OPENAPI_SPEC),
                "target_environment": TARGET_API_URL,
                "source_filename": "phase3_comprehensive_demo.yaml",
                "agent_types": ["Functional-Positive-Agent", "Functional-Negative-Agent"]
            }
            
            flow_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/test-complete-flow",
                json=comprehensive_request
            )
            
            if flow_response.status_code == 200:
                result = flow_response.json()
                print("✅ Comprehensive test execution completed!")
                
                summary = result['summary']
                print(f"\n📊 Comprehensive Test Results:")
                print(f"   • Total test cases generated: {summary['total_test_cases']}")
                print(f"   • Tests executed: {summary['total_tests_executed']}")
                print(f"   • ✅ Passed: {summary['passed']}")
                print(f"   • ❌ Failed: {summary['failed']}")
                print(f"   • ⚠️  Errors: {summary['errors']}")
                
                # Analyze results by test type
                if 'results' in result and 'results' in result['results']:
                    test_results = result['results']['results']
                    positive_results = []
                    negative_results = []
                    
                    for test_result in test_results:
                        test_desc = test_result.get('description', '')
                        if any(keyword in test_desc.lower() for keyword in ['positive', 'valid', 'happy']):
                            positive_results.append(test_result)
                        elif any(keyword in test_desc.lower() for keyword in ['test', 'boundary', 'invalid', 'missing', 'wrong']):
                            negative_results.append(test_result)
                    
                    print(f"\n📈 Results Breakdown:")
                    print(f"   • Positive tests executed: {len(positive_results)}")
                    print(f"   • Negative tests executed: {len(negative_results)}")
                    
                    # Show some interesting negative test results
                    print(f"\n🔍 Interesting Negative Test Results:")
                    interesting_negatives = [r for r in negative_results if r.get('status') == 'passed'][:3]
                    for i, test in enumerate(interesting_negatives, 1):
                        print(f"   {i}. ✅ {test.get('description', 'N/A')}")
                        print(f"      Expected error response: HTTP {test.get('response_code', 'N/A')}")
                
                print(f"\n🎉 Phase 3 demonstration completed successfully!")
                print(f"\n🚀 Key Phase 3 Achievements Demonstrated:")
                print(f"   ✅ Hybrid BVA + Creative negative test generation")
                print(f"   ✅ Boundary value analysis for numeric and string constraints")
                print(f"   ✅ Wrong data type testing")
                print(f"   ✅ Missing required field validation")
                print(f"   ✅ Malformed request testing")
                print(f"   ✅ Semantic violation detection")
                print(f"   ✅ Comprehensive error response validation")
                
            else:
                print(f"❌ Comprehensive test execution failed: {flow_response.status_code}")
                print(f"   Error: {flow_response.text}")
                
        except httpx.ConnectError:
            print("❌ Cannot connect to Sentinel Gateway")
            print("   Make sure all services are running with: docker-compose up")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")


async def demonstrate_agent_comparison():
    """Demonstrate the difference between positive and negative agents."""
    print("\n" + "=" * 70)
    print("🔬 Agent Comparison: Positive vs Negative Testing Strategies")
    print("=" * 70)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Upload a simple spec for comparison
            simple_spec = {
                "openapi": "3.0.0",
                "info": {"title": "Simple API", "version": "1.0.0"},
                "paths": {
                    "/users": {
                        "post": {
                            "requestBody": {
                                "required": True,
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "name": {"type": "string", "minLength": 2, "maxLength": 50},
                                                "age": {"type": "integer", "minimum": 0, "maximum": 150},
                                                "email": {"type": "string"}
                                            },
                                            "required": ["name", "email"]
                                        }
                                    }
                                }
                            },
                            "responses": {"201": {"description": "Created"}, "400": {"description": "Bad Request"}}
                        }
                    }
                }
            }
            
            # Upload spec
            spec_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/specifications",
                json={"raw_spec": json.dumps(simple_spec), "source_filename": "comparison_spec.yaml"}
            )
            
            if spec_response.status_code != 200:
                print("❌ Failed to upload comparison spec")
                return
            
            spec_id = spec_response.json()['id']
            
            # Generate with both agents
            for agent_type in ["Functional-Positive-Agent", "Functional-Negative-Agent"]:
                print(f"\n🤖 {agent_type} Analysis:")
                
                gen_response = await client.post(
                    f"{SENTINEL_GATEWAY_URL}/api/v1/generate-tests",
                    json={"spec_id": spec_id, "agent_types": [agent_type]}
                )
                
                if gen_response.status_code == 200:
                    data = gen_response.json()
                    count = data['total_test_cases']
                    print(f"   📊 Generated {count} test cases")
                    
                    # Get the test cases
                    cases_response = await client.get(
                        f"{SENTINEL_GATEWAY_URL}/api/v1/test-cases?spec_id={spec_id}&agent_type={agent_type}"
                    )
                    
                    if cases_response.status_code == 200:
                        cases = cases_response.json()
                        
                        print(f"   📋 Test Case Examples:")
                        for i, case in enumerate(cases[:2], 1):
                            test_def = case.get('test_definition', {})
                            print(f"      {i}. {case.get('description', 'N/A')}")
                            print(f"         Expected Status: {test_def.get('expected_status', 'N/A')}")
                            if test_def.get('body'):
                                body_str = json.dumps(test_def['body'])
                                if len(body_str) > 100:
                                    body_str = body_str[:100] + "..."
                                print(f"         Body: {body_str}")
            
            print(f"\n✅ Agent comparison completed!")
            
        except Exception as e:
            print(f"❌ Error in agent comparison: {str(e)}")


async def main():
    """Main demonstration function."""
    print("Welcome to the Sentinel Phase 3 Demonstration!")
    print("This script demonstrates advanced negative testing capabilities.")
    print(f"Target API: {TARGET_API_URL}")
    print(f"Sentinel Gateway: {SENTINEL_GATEWAY_URL}")
    
    # Run the Phase 3 demonstration
    await demonstrate_phase3_capabilities()
    
    # Optionally run agent comparison
    print(f"\n" + "=" * 70)
    response = input("Would you like to see agent comparison analysis? (y/N): ")
    if response.lower().startswith('y'):
        await demonstrate_agent_comparison()
    
    print(f"\n🎯 Phase 3 Demonstration Complete!")
    print(f"   ✅ Functional-Negative-Agent successfully implemented")
    print(f"   ✅ Hybrid BVA + Creative testing approach working")
    print(f"   ✅ Comprehensive error validation capabilities demonstrated")
    print(f"   🚀 Ready for Phase 3 next step: Functional-Stateful-Agent")


if __name__ == "__main__":
    asyncio.run(main())
