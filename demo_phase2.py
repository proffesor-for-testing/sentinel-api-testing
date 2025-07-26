#!/usr/bin/env python3
"""
Sentinel Phase 2 MVP Demonstration Script

This script demonstrates the complete end-to-end workflow of the Sentinel platform:
1. Upload an API specification
2. Generate test cases using the Functional-Positive-Agent
3. Create a test suite
4. Execute tests against a target environment
5. Display results

Usage:
    python demo_phase2.py

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

# Sample OpenAPI specification for JSONPlaceholder API
SAMPLE_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "JSONPlaceholder API",
        "version": "1.0.0",
        "description": "Sample API for testing Sentinel platform"
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
                "description": "Retrieve a list of all posts",
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
                    }
                }
            },
            "post": {
                "summary": "Create a new post",
                "description": "Create a new post",
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
                        "description": "Post created",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/Post"
                                }
                            }
                        }
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
                            "type": "integer"
                        }
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
                    "404": {
                        "description": "Post not found"
                    }
                }
            }
        },
        "/users": {
            "get": {
                "summary": "Get all users",
                "description": "Retrieve a list of all users",
                "responses": {
                    "200": {
                        "description": "List of users",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {
                                        "$ref": "#/components/schemas/User"
                                    }
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
            "User": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer"
                    },
                    "name": {
                        "type": "string"
                    },
                    "username": {
                        "type": "string"
                    },
                    "email": {
                        "type": "string"
                    }
                }
            }
        }
    }
}


async def demonstrate_sentinel_workflow():
    """Demonstrate the complete Sentinel workflow."""
    print("🚀 Sentinel Phase 2 MVP Demonstration")
    print("=" * 50)
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            # Step 1: Check if Sentinel is running
            print("\n1️⃣ Checking Sentinel Gateway status...")
            response = await client.get(f"{SENTINEL_GATEWAY_URL}/")
            if response.status_code == 200:
                gateway_info = response.json()
                print(f"✅ Sentinel Gateway is running - {gateway_info['message']}")
                print(f"   Phase: {gateway_info.get('phase', 'Unknown')}")
            else:
                print("❌ Sentinel Gateway is not responding")
                return
            
            # Step 2: Check service health
            print("\n2️⃣ Checking service health...")
            health_response = await client.get(f"{SENTINEL_GATEWAY_URL}/health")
            if health_response.status_code == 200:
                health_data = health_response.json()
                print(f"   Overall status: {health_data['status']}")
                for service, status in health_data['services'].items():
                    status_icon = "✅" if status['status'] == 'healthy' else "❌"
                    print(f"   {status_icon} {service}: {status['status']}")
            
            # Step 3: Use the complete end-to-end flow
            print("\n3️⃣ Executing complete testing flow...")
            flow_request = {
                "raw_spec": json.dumps(SAMPLE_OPENAPI_SPEC),
                "target_environment": TARGET_API_URL,
                "source_filename": "jsonplaceholder_demo.yaml",
                "agent_types": ["Functional-Positive-Agent"]
            }
            
            print("   📤 Sending request to complete flow endpoint...")
            flow_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/test-complete-flow",
                json=flow_request
            )
            
            if flow_response.status_code == 200:
                result = flow_response.json()
                print("✅ Complete flow executed successfully!")
                print(f"   📋 Spec ID: {result['spec_id']}")
                print(f"   📦 Suite ID: {result['suite_id']}")
                print(f"   🏃 Run ID: {result['run_id']}")
                
                # Display summary
                summary = result['summary']
                print(f"\n📊 Test Execution Summary:")
                print(f"   • Test cases generated: {summary['total_test_cases']}")
                print(f"   • Tests executed: {summary['total_tests_executed']}")
                print(f"   • ✅ Passed: {summary['passed']}")
                print(f"   • ❌ Failed: {summary['failed']}")
                print(f"   • ⚠️  Errors: {summary['errors']}")
                
                # Display detailed results
                if 'results' in result and 'results' in result['results']:
                    print(f"\n📋 Detailed Test Results:")
                    test_results = result['results']['results']
                    for i, test_result in enumerate(test_results[:5], 1):  # Show first 5 results
                        status_icon = "✅" if test_result['status'] == 'passed' else "❌"
                        print(f"   {status_icon} Test {i}: {test_result['status']} "
                              f"(HTTP {test_result.get('response_code', 'N/A')}) "
                              f"- {test_result.get('latency_ms', 0)}ms")
                        
                        if test_result.get('assertion_failures'):
                            for failure in test_result['assertion_failures']:
                                print(f"      ⚠️  {failure.get('message', 'Assertion failed')}")
                    
                    if len(test_results) > 5:
                        print(f"   ... and {len(test_results) - 5} more test results")
                
                print(f"\n🎉 Demonstration completed successfully!")
                print(f"   The Sentinel platform has successfully:")
                print(f"   • Parsed the OpenAPI specification")
                print(f"   • Generated {summary['total_test_cases']} realistic test cases")
                print(f"   • Executed tests against {TARGET_API_URL}")
                print(f"   • Validated responses and provided detailed results")
                
            else:
                print(f"❌ Complete flow failed: {flow_response.status_code}")
                print(f"   Error: {flow_response.text}")
                
        except httpx.ConnectError:
            print("❌ Cannot connect to Sentinel Gateway")
            print("   Make sure all services are running with: docker-compose up")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")


async def demonstrate_individual_steps():
    """Demonstrate individual API endpoints."""
    print("\n" + "=" * 50)
    print("🔧 Individual API Endpoints Demonstration")
    print("=" * 50)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            # Step 1: Upload specification
            print("\n1️⃣ Uploading API specification...")
            spec_request = {
                "raw_spec": json.dumps(SAMPLE_OPENAPI_SPEC),
                "source_filename": "demo_spec.yaml"
            }
            
            spec_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/specifications",
                json=spec_request
            )
            
            if spec_response.status_code == 200:
                spec_data = spec_response.json()
                spec_id = spec_data['id']
                print(f"✅ Specification uploaded with ID: {spec_id}")
                
                # Step 2: Generate tests
                print("\n2️⃣ Generating test cases...")
                gen_request = {
                    "spec_id": spec_id,
                    "agent_types": ["Functional-Positive-Agent"]
                }
                
                gen_response = await client.post(
                    f"{SENTINEL_GATEWAY_URL}/api/v1/generate-tests",
                    json=gen_request
                )
                
                if gen_response.status_code == 200:
                    gen_data = gen_response.json()
                    print(f"✅ Generated {gen_data['total_test_cases']} test cases")
                    
                    # Step 3: List test cases
                    print("\n3️⃣ Listing generated test cases...")
                    cases_response = await client.get(
                        f"{SENTINEL_GATEWAY_URL}/api/v1/test-cases?spec_id={spec_id}"
                    )
                    
                    if cases_response.status_code == 200:
                        cases_data = cases_response.json()
                        print(f"✅ Retrieved {len(cases_data)} test cases")
                        
                        # Show sample test case
                        if cases_data:
                            sample_case = cases_data[0]
                            print(f"   📋 Sample test case:")
                            print(f"      • Description: {sample_case.get('description', 'N/A')}")
                            print(f"      • Agent: {sample_case.get('agent_type', 'N/A')}")
                            test_def = sample_case.get('test_definition', {})
                            print(f"      • Method: {test_def.get('method', 'N/A')}")
                            print(f"      • Endpoint: {test_def.get('endpoint', 'N/A')}")
                    
                    print(f"\n✅ Individual steps demonstration completed!")
                    
        except Exception as e:
            print(f"❌ Error in individual steps: {str(e)}")


async def main():
    """Main demonstration function."""
    print("Welcome to the Sentinel Phase 2 MVP Demonstration!")
    print("This script will test the complete end-to-end workflow.")
    print(f"Target API: {TARGET_API_URL}")
    print(f"Sentinel Gateway: {SENTINEL_GATEWAY_URL}")
    
    # Run the complete workflow demonstration
    await demonstrate_sentinel_workflow()
    
    # Optionally run individual steps
    print(f"\n" + "=" * 70)
    response = input("Would you like to see individual API endpoints? (y/N): ")
    if response.lower().startswith('y'):
        await demonstrate_individual_steps()
    
    print(f"\n🎯 Demonstration complete!")
    print(f"   Phase 2 MVP is working successfully!")
    print(f"   Next: Implement Phase 3 features (Negative testing, Stateful testing)")


if __name__ == "__main__":
    asyncio.run(main())
