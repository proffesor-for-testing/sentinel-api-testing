"""
End-to-End test for security testing pipeline.
Tests authentication, authorization, injection attacks, and security scanning.
"""

import pytest
import asyncio
import json
from typing import Dict, Any, List
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
from datetime import datetime, timedelta
import hashlib
import jwt
import base64

# Service URLs
ORCHESTRATION_URL = "http://localhost:8002"
EXECUTION_URL = "http://localhost:8003"
AUTH_SERVICE_URL = "http://localhost:8005"
SPEC_SERVICE_URL = "http://localhost:8001"
DATA_SERVICE_URL = "http://localhost:8004"
SECURITY_URL = "http://localhost:8007"  # Hypothetical security service


class TestSecurityPipeline:
    """E2E tests for security testing pipeline."""
    
    @pytest.fixture
    async def auth_headers(self):
        """Get authentication headers."""
        return {"Authorization": "Bearer mock-token-for-testing"}
    
    @pytest.fixture
    def secure_api_spec(self) -> Dict[str, Any]:
        """API spec with comprehensive security requirements."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Secure Banking API",
                "version": "2.0.0",
                "description": "Security-critical banking API"
            },
            "servers": [
                {"url": "https://secure.bank.com/api/v2"}
            ],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "apiKey": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key"
                    },
                    "oauth2": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": "https://auth.bank.com/oauth/authorize",
                                "tokenUrl": "https://auth.bank.com/oauth/token",
                                "scopes": {
                                    "read:accounts": "Read account information",
                                    "write:transfers": "Make transfers",
                                    "admin:users": "Manage users"
                                }
                            }
                        }
                    }
                },
                "schemas": {
                    "Account": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "account_number": {"type": "string", "pattern": "^[0-9]{10}$"},
                            "balance": {"type": "number"},
                            "owner_id": {"type": "string"},
                            "created_at": {"type": "string", "format": "date-time"}
                        }
                    },
                    "Transfer": {
                        "type": "object",
                        "required": ["from_account", "to_account", "amount"],
                        "properties": {
                            "from_account": {"type": "string"},
                            "to_account": {"type": "string"},
                            "amount": {"type": "number", "minimum": 0.01, "maximum": 1000000},
                            "description": {"type": "string", "maxLength": 255},
                            "otp_code": {"type": "string", "pattern": "^[0-9]{6}$"}
                        }
                    }
                }
            },
            "paths": {
                "/auth/login": {
                    "post": {
                        "summary": "User login",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"},
                                            "mfa_token": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Login successful"},
                            "401": {"description": "Invalid credentials"},
                            "429": {"description": "Too many attempts"}
                        }
                    }
                },
                "/accounts": {
                    "get": {
                        "summary": "List user accounts",
                        "security": [{"bearerAuth": []}, {"oauth2": ["read:accounts"]}],
                        "parameters": [
                            {"name": "user_id", "in": "query", "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {"description": "Account list"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"}
                        }
                    }
                },
                "/accounts/{accountId}": {
                    "get": {
                        "summary": "Get account details (BOLA test)",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "accountId", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {"description": "Account details"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Access denied"},
                            "404": {"description": "Account not found"}
                        }
                    },
                    "patch": {
                        "summary": "Update account (admin only)",
                        "security": [{"bearerAuth": []}, {"oauth2": ["admin:users"]}],
                        "parameters": [
                            {"name": "accountId", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Account"}
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Account updated"},
                            "403": {"description": "Admin access required"}
                        }
                    }
                },
                "/transfers": {
                    "post": {
                        "summary": "Create transfer (SQL injection target)",
                        "security": [{"bearerAuth": []}, {"oauth2": ["write:transfers"]}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Transfer"}
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Transfer created"},
                            "400": {"description": "Invalid transfer"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Insufficient permissions"},
                            "422": {"description": "Invalid OTP"}
                        }
                    }
                },
                "/admin/users": {
                    "get": {
                        "summary": "List all users (admin endpoint)",
                        "security": [{"bearerAuth": []}, {"apiKey": []}],
                        "responses": {
                            "200": {"description": "User list"},
                            "403": {"description": "Admin only"}
                        }
                    },
                    "delete": {
                        "summary": "Delete users (command injection risk)",
                        "security": [{"bearerAuth": []}, {"apiKey": []}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "user_ids": {"type": "array", "items": {"type": "string"}}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {"description": "Users deleted"},
                            "403": {"description": "Admin only"}
                        }
                    }
                },
                "/search": {
                    "get": {
                        "summary": "Search transactions (NoSQL injection risk)",
                        "security": [{"bearerAuth": []}],
                        "parameters": [
                            {"name": "query", "in": "query", "schema": {"type": "string"}},
                            {"name": "filters", "in": "query", "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {"description": "Search results"}
                        }
                    }
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_authentication_security_tests(self, auth_headers, secure_api_spec):
        """Test generation and execution of authentication security tests."""
        async with aiohttp.ClientSession() as session:
            # Upload security-focused specification
            spec_data = {
                "name": "Secure Banking API",
                "description": "API with security requirements",
                "content": json.dumps(secure_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id", "mock-spec-id")
            
            # Create security test run focused on authentication
            test_run_data = {
                "name": "Authentication Security Tests",
                "spec_id": spec_id,
                "agents": ["security-auth"],
                "configuration": {
                    "security_config": {
                        "test_categories": [
                            "authentication_bypass",
                            "token_manipulation",
                            "session_attacks",
                            "brute_force",
                            "credential_stuffing"
                        ],
                        "auth_test_scenarios": [
                            {
                                "name": "Missing Authentication",
                                "description": "Access protected endpoints without auth"
                            },
                            {
                                "name": "Invalid Token",
                                "description": "Use malformed or expired tokens"
                            },
                            {
                                "name": "Token Replay",
                                "description": "Replay captured tokens"
                            },
                            {
                                "name": "Privilege Escalation",
                                "description": "Access admin endpoints with user token"
                            },
                            {
                                "name": "JWT Vulnerabilities",
                                "description": "Test JWT signature bypass, algorithm confusion"
                            }
                        ],
                        "wordlists": {
                            "passwords": ["password123", "admin", "12345678", "qwerty"],
                            "usernames": ["admin", "root", "test", "user"]
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Wait for security test generation
            await asyncio.sleep(5)
            
            # Retrieve generated security tests
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/security-tests",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                security_tests = await response.json()
                
                # Verify authentication tests generated
                auth_tests = [t for t in security_tests if "auth" in t.get("category", "").lower()]
                assert len(auth_tests) > 0
                
                # Check for specific attack scenarios
                test_types = {t.get("attack_type") for t in auth_tests}
                expected_types = {
                    "missing_auth",
                    "invalid_token",
                    "expired_token",
                    "privilege_escalation",
                    "jwt_none_algorithm",
                    "jwt_key_confusion"
                }
                
                assert len(test_types.intersection(expected_types)) >= 3
                
                # Verify test payloads
                for test in auth_tests[:5]:
                    assert "endpoint" in test
                    assert "method" in test
                    assert "attack_vector" in test
                    
                    # Check for auth manipulation
                    if test.get("attack_type") == "invalid_token":
                        assert "headers" in test
                        auth_header = test["headers"].get("Authorization", "")
                        # Should have manipulated token
                        assert "Bearer" in auth_header
                        assert len(auth_header) > 20  # Has some token value
    
    @pytest.mark.asyncio
    async def test_authorization_bola_tests(self, auth_headers, secure_api_spec):
        """Test BOLA (Broken Object Level Authorization) detection."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "BOLA Test API",
                "description": "API for BOLA testing",
                "content": json.dumps(secure_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create BOLA-focused security test
            test_run_data = {
                "name": "BOLA Security Tests",
                "spec_id": spec_id,
                "agents": ["security-auth", "data-mocking"],
                "configuration": {
                    "security_config": {
                        "test_categories": ["bola", "idor"],
                        "bola_test_config": {
                            "create_test_users": True,
                            "user_roles": ["admin", "user1", "user2", "guest"],
                            "object_types": ["accounts", "transfers", "users"],
                            "test_scenarios": [
                                "access_other_user_data",
                                "modify_other_user_data",
                                "delete_other_user_data",
                                "enumerate_objects",
                                "predictable_ids"
                            ]
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Execute BOLA tests
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "security",
                "target_url": "https://secure.bank.com/api/v2"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/security/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Wait for execution
                    await asyncio.sleep(10)
                    
                    # Get BOLA test results
                    async with session.get(
                        f"{EXECUTION_URL}/api/security/{execution_id}/bola-results",
                        headers=auth_headers
                    ) as response:
                        if response.status == 200:
                            bola_results = await response.json()
                            
                            # Check for BOLA vulnerabilities found
                            vulnerabilities = bola_results.get("vulnerabilities", [])
                            
                            for vuln in vulnerabilities:
                                assert "endpoint" in vuln
                                assert "severity" in vuln
                                assert "description" in vuln
                                
                                # Should identify the specific BOLA issue
                                if vuln.get("type") == "bola":
                                    assert "object_id" in vuln or "resource" in vuln
                                    assert "unauthorized_access" in vuln
                            
                            # Check enumeration results
                            enumeration = bola_results.get("enumeration_results", {})
                            if enumeration:
                                assert "discovered_ids" in enumeration
                                assert "pattern" in enumeration  # ID pattern detected
    
    @pytest.mark.asyncio
    async def test_injection_attack_tests(self, auth_headers, secure_api_spec):
        """Test SQL, NoSQL, and command injection detection."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Injection Test API",
                "description": "API for injection testing",
                "content": json.dumps(secure_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create injection test run
            test_run_data = {
                "name": "Injection Security Tests",
                "spec_id": spec_id,
                "agents": ["security-injection"],
                "configuration": {
                    "security_config": {
                        "injection_types": [
                            "sql_injection",
                            "nosql_injection",
                            "command_injection",
                            "ldap_injection",
                            "xpath_injection",
                            "template_injection",
                            "header_injection"
                        ],
                        "injection_payloads": {
                            "sql": [
                                "' OR '1'='1",
                                "'; DROP TABLE users--",
                                "' UNION SELECT * FROM accounts--",
                                "1' AND SLEEP(5)--",
                                "' OR 1=1--"
                            ],
                            "nosql": [
                                '{"$ne": null}',
                                '{"$gt": ""}',
                                '{"$regex": ".*"}',
                                '{"$where": "this.balance > 0"}'
                            ],
                            "command": [
                                "; ls -la",
                                "| whoami",
                                "&& cat /etc/passwd",
                                "`id`",
                                "$(sleep 5)"
                            ],
                            "template": [
                                "{{7*7}}",
                                "${7*7}",
                                "#{7*7}",
                                "<%= 7*7 %>"
                            ]
                        },
                        "detection_methods": [
                            "error_based",
                            "blind_boolean",
                            "time_based",
                            "out_of_band"
                        ]
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Wait for test generation
            await asyncio.sleep(5)
            
            # Retrieve injection tests
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/injection-tests",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                injection_tests = await response.json()
                
                # Verify comprehensive injection tests
                assert len(injection_tests) > 0
                
                # Group by injection type
                tests_by_type = {}
                for test in injection_tests:
                    inj_type = test.get("injection_type")
                    if inj_type not in tests_by_type:
                        tests_by_type[inj_type] = []
                    tests_by_type[inj_type].append(test)
                
                # Should test multiple injection types
                assert len(tests_by_type) >= 3
                
                # Check SQL injection tests
                if "sql_injection" in tests_by_type:
                    sql_tests = tests_by_type["sql_injection"]
                    
                    for test in sql_tests[:3]:
                        assert "payload" in test
                        assert "injection_point" in test
                        assert "detection_method" in test
                        
                        # Should target appropriate endpoints
                        endpoint = test.get("endpoint", "")
                        assert "/transfers" in endpoint or "/search" in endpoint
                
                # Check command injection tests
                if "command_injection" in tests_by_type:
                    cmd_tests = tests_by_type["command_injection"]
                    
                    for test in cmd_tests[:3]:
                        payload = test.get("payload", "")
                        # Should contain command injection patterns
                        assert any(char in payload for char in [";", "|", "&", "`", "$"])
    
    @pytest.mark.asyncio
    async def test_rate_limiting_dos_tests(self, auth_headers, secure_api_spec):
        """Test rate limiting and DoS protection."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Rate Limit Test API",
                "description": "API for rate limiting tests",
                "content": json.dumps(secure_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create rate limiting test
            test_run_data = {
                "name": "Rate Limiting & DoS Tests",
                "spec_id": spec_id,
                "agents": ["security-auth", "performance-planner"],
                "configuration": {
                    "security_config": {
                        "dos_tests": {
                            "rate_limit_testing": True,
                            "endpoints_to_test": [
                                "/auth/login",  # Brute force protection
                                "/transfers",   # Transaction limits
                                "/search"      # Resource intensive
                            ],
                            "test_patterns": [
                                {
                                    "name": "Burst requests",
                                    "requests": 100,
                                    "duration": 1  # second
                                },
                                {
                                    "name": "Sustained load",
                                    "requests": 1000,
                                    "duration": 60  # seconds
                                },
                                {
                                    "name": "Slowloris",
                                    "connections": 100,
                                    "keep_alive": True
                                }
                            ],
                            "bypass_techniques": [
                                "header_manipulation",
                                "ip_rotation",
                                "user_agent_rotation",
                                "distributed_sources"
                            ]
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Execute rate limiting tests
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "rate_limit"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/security/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Monitor rate limiting test
                    await asyncio.sleep(10)
                    
                    async with session.get(
                        f"{EXECUTION_URL}/api/security/{execution_id}/rate-limit-results",
                        headers=auth_headers
                    ) as response:
                        if response.status == 200:
                            rate_results = await response.json()
                            
                            # Check rate limiting detection
                            endpoints_tested = rate_results.get("endpoints", {})
                            
                            for endpoint, results in endpoints_tested.items():
                                assert "rate_limit_detected" in results
                                
                                if results["rate_limit_detected"]:
                                    assert "limit" in results
                                    assert "window" in results
                                    assert "response_code" in results
                                    
                                    # Should return 429 when rate limited
                                    assert results["response_code"] == 429
                                
                                # Check bypass attempts
                                if "bypass_results" in results:
                                    bypass = results["bypass_results"]
                                    assert "successful_bypasses" in bypass
                                    
                                    # Log any successful bypasses as vulnerabilities
                                    if bypass["successful_bypasses"]:
                                        print(f"Rate limit bypass found: {bypass}")
    
    @pytest.mark.asyncio
    async def test_security_headers_validation(self, auth_headers, secure_api_spec):
        """Test security headers and response validation."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Security Headers Test API",
                "description": "API for security headers testing",
                "content": json.dumps(secure_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create security headers test
            test_run_data = {
                "name": "Security Headers Tests",
                "spec_id": spec_id,
                "agents": ["security-auth"],
                "configuration": {
                    "security_config": {
                        "headers_to_check": [
                            "X-Frame-Options",
                            "X-Content-Type-Options",
                            "X-XSS-Protection",
                            "Strict-Transport-Security",
                            "Content-Security-Policy",
                            "X-Permitted-Cross-Domain-Policies",
                            "Referrer-Policy",
                            "Feature-Policy",
                            "Cache-Control"
                        ],
                        "response_validation": {
                            "check_error_messages": True,  # Verbose errors leak info
                            "check_stack_traces": True,
                            "check_sensitive_data": True,
                            "patterns_to_detect": [
                                "password",
                                "token",
                                "api_key",
                                "secret",
                                "private_key"
                            ]
                        },
                        "cors_testing": {
                            "test_origins": [
                                "https://evil.com",
                                "null",
                                "file://",
                                "*"
                            ],
                            "check_credentials": True
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Generate and execute security header tests
            await asyncio.sleep(5)
            
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/header-tests",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                header_tests = await response.json()
                
                # Verify header tests generated
                assert len(header_tests) > 0
                
                # Check for missing headers detection
                missing_headers = []
                for test in header_tests:
                    if test.get("test_type") == "missing_header":
                        missing_headers.append(test.get("header_name"))
                
                # Should check critical security headers
                critical_headers = [
                    "X-Frame-Options",
                    "Content-Security-Policy",
                    "Strict-Transport-Security"
                ]
                
                for header in critical_headers:
                    assert header in missing_headers or any(
                        header in test.get("header_name", "") 
                        for test in header_tests
                    )
    
    @pytest.mark.asyncio
    async def test_cryptographic_weakness_detection(self, auth_headers, secure_api_spec):
        """Test detection of cryptographic weaknesses."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Crypto Test API",
                "description": "API for cryptographic testing",
                "content": json.dumps(secure_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create cryptographic testing
            test_run_data = {
                "name": "Cryptographic Security Tests",
                "spec_id": spec_id,
                "agents": ["security-auth"],
                "configuration": {
                    "security_config": {
                        "crypto_tests": {
                            "jwt_vulnerabilities": [
                                "none_algorithm",
                                "weak_secret",
                                "algorithm_confusion",
                                "key_injection",
                                "expired_token_accepted"
                            ],
                            "tls_tests": {
                                "check_protocols": ["SSLv3", "TLSv1.0", "TLSv1.1"],
                                "check_ciphers": True,
                                "check_certificate": True
                            },
                            "encryption_tests": {
                                "weak_algorithms": ["MD5", "SHA1", "DES", "RC4"],
                                "check_randomness": True,
                                "check_key_length": True
                            },
                            "hash_tests": {
                                "check_salting": True,
                                "check_iterations": True,
                                "timing_attacks": True
                            }
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Generate crypto tests
            await asyncio.sleep(5)
            
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/crypto-tests",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                crypto_tests = await response.json()
                
                # Check JWT vulnerability tests
                jwt_tests = [t for t in crypto_tests if "jwt" in t.get("category", "").lower()]
                assert len(jwt_tests) > 0
                
                for test in jwt_tests[:3]:
                    if test.get("vulnerability") == "none_algorithm":
                        # Should have JWT with alg: none
                        token = test.get("payload", {}).get("token", "")
                        if token:
                            # Decode JWT header
                            header_b64 = token.split('.')[0] if '.' in token else ""
                            if header_b64:
                                # Would decode to check alg: none
                                pass
                    
                    elif test.get("vulnerability") == "weak_secret":
                        # Should test common/weak secrets
                        assert "secret_tested" in test or "dictionary_attack" in test
    
    @pytest.mark.asyncio
    async def test_comprehensive_security_scan(self, auth_headers, secure_api_spec):
        """Test comprehensive security scanning with all agents."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Comprehensive Security API",
                "description": "Full security testing",
                "content": json.dumps(secure_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create comprehensive security test
            test_run_data = {
                "name": "Comprehensive Security Scan",
                "spec_id": spec_id,
                "agents": [
                    "security-auth",
                    "security-injection",
                    "data-mocking"  # For test data
                ],
                "configuration": {
                    "security_config": {
                        "scan_type": "comprehensive",
                        "owasp_top_10": True,
                        "compliance_checks": ["PCI-DSS", "GDPR", "SOC2"],
                        "severity_threshold": "medium",
                        "max_test_duration": 600,  # 10 minutes
                        "parallel_tests": True
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Execute comprehensive scan
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "comprehensive_security"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/security/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Monitor comprehensive scan
                    await asyncio.sleep(15)
                    
                    # Get comprehensive results
                    async with session.get(
                        f"{EXECUTION_URL}/api/security/{execution_id}/comprehensive-report",
                        headers=auth_headers
                    ) as response:
                        if response.status == 200:
                            report = await response.json()
                            
                            # Verify comprehensive coverage
                            assert "summary" in report
                            assert "vulnerabilities" in report
                            assert "compliance" in report
                            assert "recommendations" in report
                            
                            # Check vulnerability categorization
                            vulns = report["vulnerabilities"]
                            vuln_by_severity = {
                                "critical": [],
                                "high": [],
                                "medium": [],
                                "low": [],
                                "info": []
                            }
                            
                            for vuln in vulns:
                                severity = vuln.get("severity", "info").lower()
                                if severity in vuln_by_severity:
                                    vuln_by_severity[severity].append(vuln)
                            
                            # Check OWASP coverage
                            owasp_categories = set()
                            for vuln in vulns:
                                if "owasp" in vuln:
                                    owasp_categories.add(vuln["owasp"])
                            
                            # Should cover multiple OWASP categories
                            assert len(owasp_categories) >= 3
                            
                            # Save security report
                            async with session.post(
                                f"{DATA_SERVICE_URL}/api/security/reports",
                                json={
                                    "test_run_id": test_run_id,
                                    "execution_id": execution_id,
                                    "report": report,
                                    "timestamp": datetime.utcnow().isoformat()
                                },
                                headers=auth_headers
                            ) as save_response:
                                assert save_response.status in [200, 201]