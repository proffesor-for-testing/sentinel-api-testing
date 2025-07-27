#!/usr/bin/env python3
"""
Sentinel Phase 4 Demo Script

This script demonstrates the advanced security and performance testing capabilities
introduced in Phase 4, including:
- Security Authentication Agent (BOLA, Function-level Auth, Auth Bypass)
- Security Injection Agent (Prompt Injection, SQL/NoSQL/Command Injection)
- Performance Planner Agent (Load, Stress, Spike Testing)

Usage:
    python demo_phase4.py
"""

import asyncio
import json
import httpx
from typing import Dict, Any, List
import time

# Configuration
BASE_URL = "http://localhost:8000"
SPEC_SERVICE_URL = f"{BASE_URL}/spec"
ORCHESTRATION_SERVICE_URL = f"{BASE_URL}/orchestration"
DATA_SERVICE_URL = f"{BASE_URL}/data"
EXECUTION_SERVICE_URL = f"{BASE_URL}/execution"

# Demo API specification with security and performance considerations
DEMO_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "SecureBank API",
        "version": "1.0.0",
        "description": "A comprehensive banking API with security and performance requirements"
    },
    "servers": [
        {"url": "https://api.securebank.com/v1"}
    ],
    "security": [
        {"bearerAuth": []}
    ],
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        },
        "schemas": {
            "User": {
                "type": "object",
                "required": ["username", "email"],
                "properties": {
                    "id": {"type": "integer", "minimum": 1},
                    "username": {"type": "string", "minLength": 3, "maxLength": 50},
                    "email": {"type": "string", "format": "email"},
                    "role": {"type": "string", "enum": ["user", "admin", "manager"]},
                    "balance": {"type": "number", "minimum": 0}
                }
            },
            "Transaction": {
                "type": "object",
                "required": ["amount", "recipient"],
                "properties": {
                    "id": {"type": "integer"},
                    "amount": {"type": "number", "minimum": 0.01, "maximum": 10000},
                    "recipient": {"type": "string", "minLength": 1},
                    "description": {"type": "string", "maxLength": 500},
                    "timestamp": {"type": "string", "format": "date-time"}
                }
            },
            "ChatMessage": {
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": {"type": "string", "maxLength": 2000},
                    "context": {"type": "string", "maxLength": 1000}
                }
            }
        }
    },
    "paths": {
        "/auth/login": {
            "post": {
                "summary": "User authentication",
                "description": "Authenticate user and return JWT token",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["username", "password"],
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Authentication successful"},
                    "401": {"description": "Invalid credentials"},
                    "429": {"description": "Too many login attempts"}
                }
            }
        },
        "/users/{user_id}": {
            "get": {
                "summary": "Get user profile",
                "description": "Retrieve user profile information",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1}
                    }
                ],
                "responses": {
                    "200": {"description": "User profile retrieved"},
                    "401": {"description": "Unauthorized"},
                    "403": {"description": "Forbidden"},
                    "404": {"description": "User not found"}
                }
            },
            "put": {
                "summary": "Update user profile",
                "description": "Update user profile information",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "user_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer", "minimum": 1}
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/User"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Profile updated"},
                    "401": {"description": "Unauthorized"},
                    "403": {"description": "Forbidden"},
                    "422": {"description": "Validation error"}
                }
            }
        },
        "/admin/users": {
            "get": {
                "summary": "List all users (Admin only)",
                "description": "Administrative endpoint to list all users",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}
                    },
                    {
                        "name": "search",
                        "in": "query",
                        "schema": {"type": "string", "maxLength": 100}
                    }
                ],
                "responses": {
                    "200": {"description": "Users retrieved"},
                    "401": {"description": "Unauthorized"},
                    "403": {"description": "Admin access required"}
                }
            }
        },
        "/transactions": {
            "post": {
                "summary": "Create transaction",
                "description": "Create a new financial transaction",
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Transaction"}
                        }
                    }
                },
                "responses": {
                    "201": {"description": "Transaction created"},
                    "400": {"description": "Invalid transaction data"},
                    "401": {"description": "Unauthorized"},
                    "422": {"description": "Validation error"}
                }
            },
            "get": {
                "summary": "List transactions",
                "description": "Retrieve user's transaction history",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                    },
                    {
                        "name": "user_id",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 1}
                    }
                ],
                "responses": {
                    "200": {"description": "Transactions retrieved"},
                    "401": {"description": "Unauthorized"}
                }
            }
        },
        "/ai/chat": {
            "post": {
                "summary": "AI Chat Assistant",
                "description": "Chat with AI assistant for banking queries",
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ChatMessage"}
                        }
                    }
                },
                "responses": {
                    "200": {"description": "AI response generated"},
                    "400": {"description": "Invalid message"},
                    "401": {"description": "Unauthorized"},
                    "429": {"description": "Rate limit exceeded"}
                }
            }
        },
        "/reports/export": {
            "post": {
                "summary": "Export financial report",
                "description": "Generate and export comprehensive financial reports",
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["report_type", "date_range"],
                                "properties": {
                                    "report_type": {"type": "string", "enum": ["monthly", "quarterly", "annual"]},
                                    "date_range": {"type": "string"},
                                    "format": {"type": "string", "enum": ["pdf", "csv", "excel"], "default": "pdf"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"description": "Report generated"},
                    "401": {"description": "Unauthorized"},
                    "403": {"description": "Insufficient permissions"},
                    "422": {"description": "Invalid report parameters"}
                }
            }
        }
    }
}

class Phase4Demo:
    """Demo class for Phase 4 security and performance testing capabilities."""
    
    def __init__(self):
        self.spec_id = None
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def setup_demo(self):
        """Set up the demo by uploading the API specification."""
        print("🚀 Setting up Phase 4 Demo - Security & Performance Testing")
        print("=" * 60)
        
        try:
            # Upload the demo API specification
            response = await self.client.post(
                f"{SPEC_SERVICE_URL}/api/v1/specifications",
                json={
                    "name": "SecureBank API v1.0",
                    "description": "Banking API with comprehensive security and performance requirements",
                    "spec_content": json.dumps(DEMO_SPEC),
                    "spec_format": "openapi"
                }
            )
            
            if response.status_code in [200, 201]:
                spec_data = response.json()
                self.spec_id = spec_data["id"]
                print(f"✅ API Specification uploaded successfully (ID: {self.spec_id})")
                print(f"   - Endpoints: {len(DEMO_SPEC['paths'])}")
                print(f"   - Security schemes: {len(DEMO_SPEC['components']['securitySchemes'])}")
                print(f"   - Data models: {len(DEMO_SPEC['components']['schemas'])}")
                return True
            else:
                print(f"❌ Failed to upload specification: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error setting up demo: {str(e)}")
            return False
    
    async def demonstrate_security_auth_agent(self):
        """Demonstrate the Security Authentication Agent capabilities."""
        print("\n🔐 Security Authentication Agent Demo")
        print("-" * 40)
        
        try:
            response = await self.client.post(
                f"{ORCHESTRATION_SERVICE_URL}/generate-tests",
                json={
                    "spec_id": self.spec_id,
                    "agent_types": ["Security-Auth-Agent"],
                    "parameters": {
                        "focus_areas": ["bola", "function_level_auth", "auth_bypass"]
                    }
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Security Auth Agent executed successfully")
                print(f"   - Task ID: {result['task_id']}")
                print(f"   - Total test cases generated: {result['total_test_cases']}")
                
                for agent_result in result['agent_results']:
                    if agent_result['agent_type'] == 'Security-Auth-Agent':
                        print(f"   - Status: {agent_result['status']}")
                        print(f"   - Test cases: {agent_result['test_cases_generated']}")
                        
                        # Fetch and display some test cases
                        await self.display_security_auth_tests()
                        
                return True
            else:
                print(f"❌ Security Auth Agent failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error running Security Auth Agent: {str(e)}")
            return False
    
    async def demonstrate_security_injection_agent(self):
        """Demonstrate the Security Injection Agent capabilities."""
        print("\n💉 Security Injection Agent Demo")
        print("-" * 40)
        
        try:
            response = await self.client.post(
                f"{ORCHESTRATION_SERVICE_URL}/generate-tests",
                json={
                    "spec_id": self.spec_id,
                    "agent_types": ["Security-Injection-Agent"],
                    "parameters": {
                        "injection_types": ["prompt", "sql", "nosql", "command"]
                    }
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Security Injection Agent executed successfully")
                print(f"   - Task ID: {result['task_id']}")
                print(f"   - Total test cases generated: {result['total_test_cases']}")
                
                for agent_result in result['agent_results']:
                    if agent_result['agent_type'] == 'Security-Injection-Agent':
                        print(f"   - Status: {agent_result['status']}")
                        print(f"   - Test cases: {agent_result['test_cases_generated']}")
                        
                        # Fetch and display some test cases
                        await self.display_security_injection_tests()
                        
                return True
            else:
                print(f"❌ Security Injection Agent failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error running Security Injection Agent: {str(e)}")
            return False
    
    async def demonstrate_performance_planner_agent(self):
        """Demonstrate the Performance Planner Agent capabilities."""
        print("\n⚡ Performance Planner Agent Demo")
        print("-" * 40)
        
        try:
            response = await self.client.post(
                f"{ORCHESTRATION_SERVICE_URL}/generate-tests",
                json={
                    "spec_id": self.spec_id,
                    "agent_types": ["Performance-Planner-Agent"],
                    "parameters": {
                        "test_types": ["load", "stress", "spike"],
                        "target_environment": "staging"
                    }
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Performance Planner Agent executed successfully")
                print(f"   - Task ID: {result['task_id']}")
                print(f"   - Total test scenarios generated: {result['total_test_cases']}")
                
                for agent_result in result['agent_results']:
                    if agent_result['agent_type'] == 'Performance-Planner-Agent':
                        print(f"   - Status: {agent_result['status']}")
                        print(f"   - Test scenarios: {agent_result['test_cases_generated']}")
                        
                        # Fetch and display some test scenarios
                        await self.display_performance_tests()
                        
                return True
            else:
                print(f"❌ Performance Planner Agent failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error running Performance Planner Agent: {str(e)}")
            return False
    
    async def display_security_auth_tests(self):
        """Display sample security authentication test cases."""
        try:
            response = await self.client.get(
                f"{DATA_SERVICE_URL}/api/v1/test-cases",
                params={"spec_id": self.spec_id, "tags": "security,authentication"}
            )
            
            if response.status_code == 200:
                test_cases = response.json()
                print(f"\n   📋 Sample Security Authentication Tests:")
                
                for i, test_case in enumerate(test_cases[:3]):  # Show first 3
                    test_def = test_case.get('test_definition', {})
                    print(f"   {i+1}. {test_def.get('test_name', 'Unknown Test')}")
                    print(f"      Type: {test_def.get('test_subtype', 'N/A')}")
                    print(f"      Method: {test_def.get('method', 'N/A')} {test_def.get('path', 'N/A')}")
                    
                    security_check = test_def.get('security_check', {})
                    if security_check:
                        print(f"      Security Check: {security_check.get('type', 'N/A')}")
                        print(f"      Expected: {security_check.get('expected_behavior', 'N/A')}")
                    print()
                    
        except Exception as e:
            print(f"   ⚠️  Could not fetch test cases: {str(e)}")
    
    async def display_security_injection_tests(self):
        """Display sample security injection test cases."""
        try:
            response = await self.client.get(
                f"{DATA_SERVICE_URL}/api/v1/test-cases",
                params={"spec_id": self.spec_id, "tags": "security,injection"}
            )
            
            if response.status_code == 200:
                test_cases = response.json()
                print(f"\n   📋 Sample Security Injection Tests:")
                
                for i, test_case in enumerate(test_cases[:3]):  # Show first 3
                    test_def = test_case.get('test_definition', {})
                    print(f"   {i+1}. {test_def.get('test_name', 'Unknown Test')}")
                    print(f"      Type: {test_def.get('test_subtype', 'N/A')}")
                    print(f"      Method: {test_def.get('method', 'N/A')} {test_def.get('path', 'N/A')}")
                    
                    security_check = test_def.get('security_check', {})
                    if security_check:
                        print(f"      Injection Type: {security_check.get('type', 'N/A')}")
                        print(f"      Technique: {security_check.get('injection_technique', 'N/A')}")
                        print(f"      Target: {security_check.get('parameter', 'N/A')} ({security_check.get('parameter_location', 'N/A')})")
                    print()
                    
        except Exception as e:
            print(f"   ⚠️  Could not fetch test cases: {str(e)}")
    
    async def display_performance_tests(self):
        """Display sample performance test scenarios."""
        try:
            response = await self.client.get(
                f"{DATA_SERVICE_URL}/api/v1/test-cases",
                params={"spec_id": self.spec_id, "tags": "performance"}
            )
            
            if response.status_code == 200:
                test_cases = response.json()
                print(f"\n   📋 Sample Performance Test Scenarios:")
                
                for i, test_case in enumerate(test_cases[:3]):  # Show first 3
                    test_def = test_case.get('test_definition', {})
                    print(f"   {i+1}. {test_def.get('test_name', 'Unknown Test')}")
                    print(f"      Type: {test_def.get('test_subtype', 'N/A')}")
                    print(f"      Method: {test_def.get('method', 'N/A')} {test_def.get('path', 'N/A')}")
                    
                    perf_config = test_def.get('performance_config', {})
                    if perf_config:
                        print(f"      Test Type: {perf_config.get('test_type', 'N/A')}")
                        if 'virtual_users' in perf_config:
                            print(f"      Virtual Users: {perf_config.get('virtual_users', 'N/A')}")
                            print(f"      Duration: {perf_config.get('duration', 'N/A')}")
                        elif 'max_virtual_users' in perf_config:
                            print(f"      Max Users: {perf_config.get('max_virtual_users', 'N/A')}")
                        elif 'spike_users' in perf_config:
                            print(f"      Spike Users: {perf_config.get('spike_users', 'N/A')}")
                    print()
                    
        except Exception as e:
            print(f"   ⚠️  Could not fetch test cases: {str(e)}")
    
    async def demonstrate_comprehensive_testing(self):
        """Demonstrate running all Phase 4 agents together."""
        print("\n🎯 Comprehensive Phase 4 Testing Demo")
        print("-" * 40)
        
        try:
            response = await self.client.post(
                f"{ORCHESTRATION_SERVICE_URL}/generate-tests",
                json={
                    "spec_id": self.spec_id,
                    "agent_types": [
                        "Security-Auth-Agent",
                        "Security-Injection-Agent", 
                        "Performance-Planner-Agent"
                    ],
                    "parameters": {
                        "comprehensive_analysis": True
                    }
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Comprehensive testing completed successfully")
                print(f"   - Task ID: {result['task_id']}")
                print(f"   - Total test cases/scenarios: {result['total_test_cases']}")
                
                print(f"\n   📊 Agent Results Summary:")
                for agent_result in result['agent_results']:
                    agent_type = agent_result['agent_type']
                    status = agent_result['status']
                    count = agent_result['test_cases_generated']
                    print(f"   - {agent_type}: {status} ({count} tests)")
                
                return True
            else:
                print(f"❌ Comprehensive testing failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error running comprehensive testing: {str(e)}")
            return False
    
    async def cleanup(self):
        """Clean up demo resources."""
        await self.client.aclose()
    
    async def run_demo(self):
        """Run the complete Phase 4 demo."""
        try:
            # Setup
            if not await self.setup_demo():
                return False
            
            # Individual agent demonstrations
            await self.demonstrate_security_auth_agent()
            await asyncio.sleep(1)  # Brief pause between demos
            
            await self.demonstrate_security_injection_agent()
            await asyncio.sleep(1)
            
            await self.demonstrate_performance_planner_agent()
            await asyncio.sleep(1)
            
            # Comprehensive testing
            await self.demonstrate_comprehensive_testing()
            
            # Summary
            print("\n🎉 Phase 4 Demo Completed Successfully!")
            print("=" * 60)
            print("Phase 4 introduces advanced security and performance testing:")
            print("• Security Authentication Agent - BOLA, Function-level Auth, Auth Bypass")
            print("• Security Injection Agent - Prompt, SQL, NoSQL, Command Injection")
            print("• Performance Planner Agent - Load, Stress, Spike Testing with k6/JMeter")
            print("\nThe Sentinel platform now provides comprehensive API testing across")
            print("functional, security, and performance domains! 🚀")
            
            return True
            
        except Exception as e:
            print(f"❌ Demo failed: {str(e)}")
            return False
        finally:
            await self.cleanup()

async def main():
    """Main demo function."""
    demo = Phase4Demo()
    success = await demo.run_demo()
    return 0 if success else 1

if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
