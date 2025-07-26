#!/usr/bin/env python3
"""
Sentinel Phase 3 Frontend Demonstration Script

This script demonstrates the completed Phase 3 Enhanced Reporting UI capabilities:
1. Upload API specifications through the web interface
2. Generate comprehensive test suites using all three agent types
3. Execute tests and view results in the enhanced reporting UI
4. Explore detailed failure analysis and agent-specific insights

Usage:
    python demo_phase3_frontend.py

Prerequisites:
    - All Sentinel backend services running (via docker-compose up)
    - Sentinel frontend running (npm start in sentinel_frontend/)
    - A target API to test (or use JSONPlaceholder)
"""

import asyncio
import json
import httpx
import webbrowser
import time
from typing import Dict, Any

# Configuration
SENTINEL_GATEWAY_URL = "http://localhost:8080"  # Backend API
SENTINEL_FRONTEND_URL = "http://localhost:3000"  # Frontend UI
TARGET_API_URL = "https://jsonplaceholder.typicode.com"

# Enhanced OpenAPI specification for comprehensive Phase 3 testing
PHASE3_DEMO_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Phase 3 Demo API - Enhanced Testing Showcase",
        "version": "1.0.0",
        "description": "Comprehensive API specification designed to showcase Phase 3 enhanced testing capabilities including BVA, negative testing, and stateful workflows"
    },
    "servers": [
        {
            "url": "https://jsonplaceholder.typicode.com"
        }
    ],
    "paths": {
        "/posts": {
            "get": {
                "summary": "Get all posts with advanced filtering",
                "description": "Retrieve posts with comprehensive query parameter validation",
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
                        "description": "Maximum number of posts (BVA testing: 0, 1, 100, 101)"
                    },
                    {
                        "name": "userId",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10
                        },
                        "description": "Filter by user ID (BVA testing: 0, 1, 10, 11)"
                    },
                    {
                        "name": "title",
                        "in": "query",
                        "required": False,
                        "schema": {
                            "type": "string",
                            "minLength": 3,
                            "maxLength": 50
                        },
                        "description": "Filter by title substring (BVA testing: '', 'ab', 50+ chars)"
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
                    },
                    "422": {
                        "description": "Unprocessable entity - validation failed"
                    }
                }
            },
            "post": {
                "summary": "Create a new post with strict validation",
                "description": "Create post with comprehensive input validation for negative testing",
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
                "summary": "Get specific post",
                "description": "Retrieve post by ID with boundary value testing",
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
                        "description": "Post ID (BVA: 0, 1, 100, 101, -1, 'abc')"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Post details"
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
                "summary": "Update post (stateful workflow)",
                "description": "Update existing post - part of CRUD workflow",
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
                        "description": "Post updated"
                    },
                    "400": {
                        "description": "Bad request"
                    },
                    "404": {
                        "description": "Post not found"
                    }
                }
            },
            "delete": {
                "summary": "Delete post (stateful workflow)",
                "description": "Delete post - completes CRUD workflow",
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
                "responses": {
                    "200": {
                        "description": "Post deleted"
                    },
                    "404": {
                        "description": "Post not found"
                    }
                }
            }
        },
        "/users": {
            "get": {
                "summary": "Get users (stateful dependency)",
                "description": "Get users for stateful workflow testing",
                "responses": {
                    "200": {
                        "description": "List of users"
                    }
                }
            },
            "post": {
                "summary": "Create user with complex validation",
                "description": "Create user with extensive validation rules for negative testing",
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
                        "description": "User created"
                    },
                    "400": {
                        "description": "Validation failed"
                    }
                }
            }
        },
        "/users/{userId}/posts": {
            "get": {
                "summary": "Get user posts (stateful relationship)",
                "description": "Get posts by user - demonstrates parent-child relationship testing",
                "parameters": [
                    {
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {
                            "type": "integer",
                            "minimum": 1
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "User posts"
                    },
                    "404": {
                        "description": "User not found"
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
                    "id": {"type": "integer"},
                    "userId": {"type": "integer"},
                    "title": {"type": "string"},
                    "body": {"type": "string"}
                },
                "required": ["userId", "title", "body"]
            },
            "PostInput": {
                "type": "object",
                "properties": {
                    "userId": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                        "description": "BVA: 0, 1, 10, 11, -1, 'string'"
                    },
                    "title": {
                        "type": "string",
                        "minLength": 5,
                        "maxLength": 100,
                        "description": "BVA: '', 'abcd', 5-char, 100-char, 101-char, null, 123"
                    },
                    "body": {
                        "type": "string",
                        "minLength": 10,
                        "maxLength": 1000,
                        "description": "BVA: '', 9-char, 10-char, 1000-char, 1001-char, null, []"
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
                        "maxLength": 50,
                        "description": "BVA: '', 'a', 2-char, 50-char, 51-char, null, 123"
                    },
                    "username": {
                        "type": "string",
                        "minLength": 3,
                        "maxLength": 20,
                        "pattern": "^[a-zA-Z0-9_]+$",
                        "description": "BVA + Pattern: '', 'ab', 3-char, 20-char, 21-char, 'user@name', 'user-name'"
                    },
                    "email": {
                        "type": "string",
                        "format": "email",
                        "maxLength": 100,
                        "description": "Format validation: 'invalid', 'user@', '@domain.com', 'valid@email.com'"
                    },
                    "age": {
                        "type": "integer",
                        "minimum": 13,
                        "maximum": 120,
                        "description": "BVA: 12, 13, 120, 121, -1, 'string', null"
                    },
                    "website": {
                        "type": "string",
                        "format": "uri",
                        "description": "URI validation: 'invalid', 'http://', 'https://valid.com'"
                    }
                },
                "required": ["name", "username", "email"]
            }
        }
    }
}


async def demonstrate_phase3_frontend():
    """Demonstrate Phase 3 Enhanced Reporting UI capabilities."""
    print("🚀 Sentinel Phase 3 Frontend Demonstration")
    print("=" * 60)
    print("This demo showcases the Enhanced Reporting UI with:")
    print("✅ Advanced Dashboard with real-time analytics")
    print("✅ Detailed failure analysis and agent insights")
    print("✅ Interactive test case exploration")
    print("✅ Comprehensive test run reporting")
    print("=" * 60)
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            # Step 1: Check backend status
            print("\n1️⃣ Checking Sentinel Backend...")
            response = await client.get(f"{SENTINEL_GATEWAY_URL}/")
            if response.status_code == 200:
                print("✅ Backend is running")
            else:
                print("❌ Backend not responding - please start with 'docker-compose up'")
                return
            
            # Step 2: Upload comprehensive specification
            print("\n2️⃣ Uploading Phase 3 demonstration specification...")
            spec_request = {
                "raw_spec": json.dumps(PHASE3_DEMO_SPEC),
                "source_filename": "phase3_demo_comprehensive.yaml"
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
            
            # Step 3: Generate comprehensive test suite with all agents
            print("\n3️⃣ Generating comprehensive test suite with all Phase 3 agents...")
            generation_request = {
                "spec_id": spec_id,
                "agent_types": [
                    "Functional-Positive-Agent",
                    "Functional-Negative-Agent", 
                    "Functional-Stateful-Agent"
                ]
            }
            
            generation_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/generate-tests",
                json=generation_request
            )
            
            if generation_response.status_code == 200:
                generation_data = generation_response.json()
                total_tests = generation_data['total_test_cases']
                print(f"✅ Generated {total_tests} test cases across all agent types")
                
                # Show agent breakdown
                for result in generation_data['agent_results']:
                    agent_type = result['agent_type']
                    count = result['test_cases_generated']
                    print(f"   📊 {agent_type}: {count} test cases")
            else:
                print(f"❌ Failed to generate tests: {generation_response.status_code}")
                return
            
            # Step 4: Execute comprehensive test run
            print("\n4️⃣ Executing comprehensive test run...")
            flow_request = {
                "raw_spec": json.dumps(PHASE3_DEMO_SPEC),
                "target_environment": TARGET_API_URL,
                "source_filename": "phase3_comprehensive_demo.yaml",
                "agent_types": [
                    "Functional-Positive-Agent",
                    "Functional-Negative-Agent",
                    "Functional-Stateful-Agent"
                ]
            }
            
            flow_response = await client.post(
                f"{SENTINEL_GATEWAY_URL}/api/v1/test-complete-flow",
                json=flow_request
            )
            
            if flow_response.status_code == 200:
                result = flow_response.json()
                run_id = result['run_id']
                summary = result['summary']
                
                print("✅ Test execution completed!")
                print(f"   🆔 Run ID: {run_id}")
                print(f"   📊 Total tests: {summary['total_tests_executed']}")
                print(f"   ✅ Passed: {summary['passed']}")
                print(f"   ❌ Failed: {summary['failed']}")
                print(f"   ⚠️  Errors: {summary['errors']}")
                
                # Step 5: Launch frontend for enhanced reporting
                print(f"\n5️⃣ Launching Enhanced Reporting UI...")
                print(f"🌐 Opening frontend at: {SENTINEL_FRONTEND_URL}")
                
                # Open different views to showcase capabilities
                urls_to_open = [
                    f"{SENTINEL_FRONTEND_URL}/",  # Dashboard
                    f"{SENTINEL_FRONTEND_URL}/test-runs/{run_id}",  # Detailed results
                    f"{SENTINEL_FRONTEND_URL}/test-cases",  # Test case browser
                    f"{SENTINEL_FRONTEND_URL}/specifications"  # Specifications
                ]
                
                print("\n📱 Opening multiple tabs to showcase Phase 3 features:")
                for i, url in enumerate(urls_to_open, 1):
                    page_name = url.split('/')[-1] or 'Dashboard'
                    print(f"   {i}. {page_name}: {url}")
                    webbrowser.open(url)
                    time.sleep(1)  # Stagger tab opening
                
                print(f"\n🎯 Phase 3 Enhanced Reporting UI Features to Explore:")
                print(f"")
                print(f"📊 DASHBOARD:")
                print(f"   • Real-time analytics and system overview")
                print(f"   • Agent distribution pie chart")
                print(f"   • Recent test runs bar chart")
                print(f"   • Success rate tracking")
                print(f"   • Phase 3 feature highlights")
                print(f"")
                print(f"🔍 TEST RUN DETAILS (Run #{run_id}):")
                print(f"   • Comprehensive failure analysis")
                print(f"   • Agent-specific insights and strategies")
                print(f"   • Test type classification (BVA, Negative, Stateful, Positive)")
                print(f"   • Interactive request/response inspection")
                print(f"   • Enhanced error reporting with context")
                print(f"   • Expandable test details with code blocks")
                print(f"")
                print(f"🧪 TEST CASES BROWSER:")
                print(f"   • Filter by agent type and specification")
                print(f"   • Visual test type indicators")
                print(f"   • Agent-specific strategy explanations")
                print(f"   • Detailed test definition inspection")
                print(f"   • Interactive test case exploration")
                print(f"")
                print(f"📋 SPECIFICATIONS:")
                print(f"   • Upload and manage API specifications")
                print(f"   • Quick test execution with all agents")
                print(f"   • Phase 3 testing capability highlights")
                print(f"")
                print(f"🎉 PHASE 3 ENHANCED FEATURES DEMONSTRATED:")
                print(f"   ✅ Boundary Value Analysis (BVA) testing")
                print(f"   ✅ Creative negative testing with invalid data")
                print(f"   ✅ Stateful workflow testing with SODG")
                print(f"   ✅ Enhanced failure analysis and reporting")
                print(f"   ✅ Agent-specific insights and strategies")
                print(f"   ✅ Interactive test result exploration")
                print(f"   ✅ Real-time analytics and visualization")
                print(f"")
                print(f"🚀 Phase 3 Implementation Complete!")
                print(f"   The Enhanced Reporting UI provides comprehensive")
                print(f"   visibility into all advanced testing capabilities.")
                
            else:
                print(f"❌ Test execution failed: {flow_response.status_code}")
                print(f"   Error: {flow_response.text}")
                
        except httpx.ConnectError:
            print("❌ Cannot connect to Sentinel Backend")
            print("   Please ensure all services are running:")
            print("   1. Backend: docker-compose up")
            print("   2. Frontend: npm start (in sentinel_frontend/)")
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")


async def main():
    """Main demonstration function."""
    print("Welcome to the Sentinel Phase 3 Enhanced Reporting UI Demo!")
    print("")
    print("This demonstration will:")
    print("1. Upload a comprehensive API specification")
    print("2. Generate tests with all three Phase 3 agents")
    print("3. Execute a complete test run")
    print("4. Launch the Enhanced Reporting UI")
    print("5. Open multiple tabs showcasing different features")
    print("")
    print("Prerequisites:")
    print("• Backend services: docker-compose up")
    print("• Frontend: npm start (in sentinel_frontend/)")
    print("")
    
    response = input("Ready to start the demonstration? (y/N): ")
    if not response.lower().startswith('y'):
        print("Demo cancelled.")
        return
    
    await demonstrate_phase3_frontend()
    
    print(f"\n" + "=" * 60)
    print("🎯 Phase 3 Enhanced Reporting UI Demo Complete!")
    print("")
    print("The frontend tabs should now be open showing:")
    print("• Advanced dashboard with real-time analytics")
    print("• Detailed test run results with failure analysis")
    print("• Interactive test case browser with filtering")
    print("• Specification management interface")
    print("")
    print("Explore the enhanced reporting capabilities to see")
    print("how Phase 3 provides comprehensive insights into")
    print("advanced API testing with BVA, negative testing,")
    print("and stateful workflow validation.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
