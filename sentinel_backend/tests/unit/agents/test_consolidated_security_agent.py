"""
Comprehensive TDD Tests for Consolidated Security Agents

This test suite ensures:
1. NO OVERLAP between Auth and Injection testing
2. Proper categorization of security vulnerabilities
3. UNIQUE attack vectors for each vulnerability type
4. Meaningful security assertions
5. Tests FAIL before implementation (TDD approach)
"""

import pytest
import asyncio
from typing import Dict, List, Any, Set
from unittest.mock import Mock, patch, AsyncMock
import hashlib

from sentinel_backend.orchestration_service.agents.security_auth_agent import SecurityAuthAgent
from sentinel_backend.orchestration_service.agents.security_injection_agent import SecurityInjectionAgent
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


def create_security_test_signature(test_case: Dict[str, Any]) -> str:
    """Create unique signature for security test to detect duplicates"""
    components = [
        test_case.get('endpoint', test_case.get('path', '')),
        test_case.get('method', ''),
        test_case.get('test_subtype', ''),
        str(test_case.get('security_check', {})),
        str(test_case.get('attack_vector', ''))
    ]
    signature = '|'.join(components)
    return hashlib.md5(signature.encode()).hexdigest()


class TestConsolidatedSecurityAgent:
    """Test suite for consolidated security testing agents"""

    @pytest.fixture
    def auth_agent(self):
        """Create Security Auth Agent instance"""
        return SecurityAuthAgent()

    @pytest.fixture
    def injection_agent(self):
        """Create Security Injection Agent instance"""
        return SecurityInjectionAgent()

    @pytest.fixture
    def agent_task(self):
        """Standard agent task for testing"""
        return AgentTask(
            task_id="test-security-001",
            spec_id=1,
            agent_type="Security-Agent",
            parameters={},
            enable_llm=False
        )

    @pytest.fixture
    def secure_api_spec(self):
        """API spec with security requirements"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Banking API", "version": "1.0.0"},
            "paths": {
                "/accounts/{accountId}": {
                    "get": {
                        "summary": "Get account details",
                        "parameters": [
                            {
                                "name": "accountId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"}
                            }
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "Success"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"},
                            "404": {"description": "Not Found"}
                        }
                    },
                    "delete": {
                        "summary": "Delete account",
                        "parameters": [
                            {
                                "name": "accountId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"}
                            }
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "204": {"description": "Deleted"},
                            "401": {"description": "Unauthorized"},
                            "403": {"description": "Forbidden"}
                        }
                    }
                },
                "/admin/users": {
                    "get": {
                        "summary": "Admin: List all users",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "Success"},
                            "403": {"description": "Forbidden"}
                        }
                    },
                    "delete": {
                        "summary": "Admin: Delete all users",
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "204": {"description": "Deleted"},
                            "403": {"description": "Forbidden"}
                        }
                    }
                },
                "/search": {
                    "get": {
                        "summary": "Search with query",
                        "parameters": [
                            {
                                "name": "query",
                                "in": "query",
                                "schema": {"type": "string"}
                            },
                            {
                                "name": "userId",
                                "in": "query",
                                "schema": {"type": "string"}
                            }
                        ],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "post": {
                        "summary": "Advanced search",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "searchTerm": {"type": "string"},
                                            "filter": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "Success"}}
                    }
                },
                "/ai/chat": {
                    "post": {
                        "summary": "AI chat endpoint",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "message": {"type": "string"},
                                            "context": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "AI response"}}
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            }
        }

    # ==================== AUTH AGENT TESTS ====================

    @pytest.mark.asyncio
    async def test_auth_agent_generates_bola_tests(self, auth_agent, agent_task, secure_api_spec):
        """MUST generate BOLA (Broken Object Level Authorization) tests"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        # Find BOLA tests specifically
        bola_tests = [tc for tc in result.test_cases if tc.get('test_subtype') == 'bola']

        assert len(bola_tests) > 0, "Auth agent MUST generate BOLA tests"

        # Check BOLA-specific attributes
        for test in bola_tests:
            security_check = test.get('security_check', {})
            assert security_check.get('type') == 'bola', "BOLA test must have correct type"

            # BOLA tests must attempt unauthorized access
            assert 401 in test.get('expected_status_codes', []) or 403 in test.get('expected_status_codes', []), (
                "BOLA test must expect auth failure status"
            )

    @pytest.mark.asyncio
    async def test_auth_agent_generates_function_level_auth_tests(self, auth_agent, agent_task, secure_api_spec):
        """MUST generate function-level authorization tests for admin endpoints"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        # Find function-level auth tests
        func_auth_tests = [
            tc for tc in result.test_cases
            if tc.get('test_subtype') == 'function-level-auth'
        ]

        assert len(func_auth_tests) > 0, "Auth agent MUST generate function-level auth tests"

        # Check for admin endpoint testing
        admin_tests = [
            tc for tc in func_auth_tests
            if 'admin' in tc.get('endpoint', '').lower() or 'admin' in tc.get('path', '').lower()
        ]

        assert len(admin_tests) > 0, "Must test admin endpoints for privilege escalation"

    @pytest.mark.asyncio
    async def test_auth_agent_generates_auth_bypass_tests(self, auth_agent, agent_task, secure_api_spec):
        """MUST generate authentication bypass tests"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        bypass_tests = [
            tc for tc in result.test_cases
            if tc.get('test_subtype') == 'auth-bypass'
        ]

        assert len(bypass_tests) > 0, "Auth agent MUST generate auth bypass tests"

        # Check for bypass techniques
        techniques_used = set()
        for test in bypass_tests:
            security_check = test.get('security_check', {})
            technique = security_check.get('technique', '')
            if technique:
                techniques_used.add(technique)

        assert len(techniques_used) >= 2, (
            f"Expected diverse bypass techniques, only got: {techniques_used}"
        )

    @pytest.mark.asyncio
    async def test_auth_agent_tests_different_auth_scenarios(self, auth_agent, agent_task, secure_api_spec):
        """MUST test multiple authentication scenarios"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        # Collect auth scenarios from all tests
        auth_scenarios = set()
        for test in result.test_cases:
            headers = test.get('headers', {})

            if 'Authorization' not in headers:
                auth_scenarios.add('no_auth')
            elif 'invalid' in headers.get('Authorization', '').lower():
                auth_scenarios.add('invalid_token')
            elif 'different' in headers.get('Authorization', '').lower():
                auth_scenarios.add('different_user')

        # Must test at least 2 different auth scenarios
        assert len(auth_scenarios) >= 2, (
            f"Expected diverse auth scenarios, only got: {auth_scenarios}"
        )

    # ==================== INJECTION AGENT TESTS ====================

    @pytest.mark.asyncio
    async def test_injection_agent_generates_sql_injection_tests(self, injection_agent, agent_task, secure_api_spec):
        """MUST generate SQL injection tests"""
        result = await injection_agent.execute(agent_task, secure_api_spec)

        sql_tests = [
            tc for tc in result.test_cases
            if 'sql' in tc.get('test_subtype', '').lower() or
            'sql' in str(tc.get('attack_vector', '')).lower()
        ]

        assert len(sql_tests) > 0, "Injection agent MUST generate SQL injection tests"

        # Check for SQL injection payloads
        has_sql_payloads = False
        for test in sql_tests:
            body = str(test.get('body', ''))
            query_params = str(test.get('query_params', ''))
            combined = body + query_params

            # Look for SQL injection patterns
            sql_patterns = ["' OR '1'='1", "'; DROP TABLE", "UNION SELECT", "--", "/*"]
            if any(pattern in combined for pattern in sql_patterns):
                has_sql_payloads = True
                break

        assert has_sql_payloads, "SQL injection tests must include actual SQL injection payloads"

    @pytest.mark.asyncio
    async def test_injection_agent_generates_nosql_injection_tests(self, injection_agent, agent_task, secure_api_spec):
        """MUST generate NoSQL injection tests"""
        result = await injection_agent.execute(agent_task, secure_api_spec)

        nosql_tests = [
            tc for tc in result.test_cases
            if 'nosql' in tc.get('test_subtype', '').lower() or
            'nosql' in str(tc.get('attack_vector', '')).lower()
        ]

        assert len(nosql_tests) > 0, "Injection agent MUST generate NoSQL injection tests"

        # Check for NoSQL injection payloads
        has_nosql_payloads = False
        for test in nosql_tests:
            body = str(test.get('body', ''))
            query_params = str(test.get('query_params', ''))
            combined = body + query_params

            # Look for NoSQL injection patterns
            nosql_patterns = ["$ne", "$gt", "$where", ".*", "^", "||"]
            if any(pattern in combined for pattern in nosql_patterns):
                has_nosql_payloads = True
                break

        assert has_nosql_payloads, "NoSQL injection tests must include NoSQL-specific payloads"

    @pytest.mark.asyncio
    async def test_injection_agent_generates_prompt_injection_tests(self, injection_agent, agent_task, secure_api_spec):
        """MUST generate prompt injection tests for AI/LLM endpoints"""
        result = await injection_agent.execute(agent_task, secure_api_spec)

        prompt_tests = [
            tc for tc in result.test_cases
            if 'prompt' in tc.get('test_subtype', '').lower() or
            'prompt' in str(tc.get('attack_vector', '')).lower()
        ]

        # Should have prompt injection tests for AI endpoint
        if any('/ai' in str(tc.get('endpoint', tc.get('path', ''))) for tc in result.test_cases):
            assert len(prompt_tests) > 0, "Injection agent MUST generate prompt injection tests for AI endpoints"

            # Check for prompt injection patterns
            has_prompt_payloads = False
            for test in prompt_tests:
                body = str(test.get('body', ''))

                # Look for prompt injection patterns
                prompt_patterns = [
                    "Ignore previous instructions",
                    "You are now",
                    "SYSTEM:",
                    "%%__USER_INPUT__%%",
                    "Disregard all"
                ]
                if any(pattern.lower() in body.lower() for pattern in prompt_patterns):
                    has_prompt_payloads = True
                    break

            assert has_prompt_payloads, "Prompt injection tests must include actual prompt injection payloads"

    @pytest.mark.asyncio
    async def test_injection_agent_generates_command_injection_tests(self, injection_agent, agent_task, secure_api_spec):
        """MUST generate command injection tests"""
        result = await injection_agent.execute(agent_task, secure_api_spec)

        cmd_tests = [
            tc for tc in result.test_cases
            if 'command' in tc.get('test_subtype', '').lower() or
            'command' in str(tc.get('attack_vector', '')).lower()
        ]

        assert len(cmd_tests) > 0, "Injection agent MUST generate command injection tests"

        # Check for command injection payloads
        has_cmd_payloads = False
        for test in cmd_tests:
            body = str(test.get('body', ''))
            query_params = str(test.get('query_params', ''))
            combined = body + query_params

            # Look for command injection patterns
            cmd_patterns = ["; ls", "| cat", "`whoami`", "$(", "&& echo"]
            if any(pattern in combined for pattern in cmd_patterns):
                has_cmd_payloads = True
                break

        assert has_cmd_payloads, "Command injection tests must include actual command injection payloads"

    # ==================== NO OVERLAP TESTS (CRITICAL!) ====================

    @pytest.mark.asyncio
    async def test_no_overlap_between_auth_and_injection_tests(
        self, auth_agent, injection_agent, agent_task, secure_api_spec
    ):
        """CRITICAL: Auth and Injection agents MUST NOT test the same vulnerabilities"""
        auth_result = await auth_agent.execute(agent_task, secure_api_spec)
        injection_result = await injection_agent.execute(agent_task, secure_api_spec)

        # Create signatures
        auth_signatures = {create_security_test_signature(tc) for tc in auth_result.test_cases}
        injection_signatures = {create_security_test_signature(tc) for tc in injection_result.test_cases}

        # Check for overlaps
        overlaps = auth_signatures & injection_signatures

        assert len(overlaps) == 0, (
            f"Found {len(overlaps)} overlapping tests between Auth and Injection agents! "
            f"Agents MUST test different vulnerability types."
        )

    @pytest.mark.asyncio
    async def test_auth_focuses_on_authorization_not_injection(self, auth_agent, agent_task, secure_api_spec):
        """Auth agent MUST focus on authorization, NOT injection"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        # Auth tests should NOT contain injection payloads
        injection_payloads = [
            "' OR '1'='1", "UNION SELECT", "$ne", "; ls", "Ignore previous instructions"
        ]

        for test in result.test_cases:
            test_content = str(test.get('body', '')) + str(test.get('query_params', ''))

            has_injection = any(payload in test_content for payload in injection_payloads)

            assert not has_injection, (
                f"Auth agent test contains injection payload - should be tested by Injection agent: {test}"
            )

    @pytest.mark.asyncio
    async def test_injection_focuses_on_injection_not_authorization(self, injection_agent, agent_task, secure_api_spec):
        """Injection agent MUST focus on injection, NOT authorization"""
        result = await injection_agent.execute(agent_task, secure_api_spec)

        # Count tests that are primarily about authorization
        auth_focused = 0
        for test in result.test_cases:
            test_subtype = test.get('test_subtype', '').lower()
            security_check = test.get('security_check', {})

            # Should NOT be testing BOLA or function-level auth
            if 'bola' in test_subtype or 'auth' in test_subtype:
                auth_focused += 1

        # Allow small overlap but majority should be injection
        assert auth_focused <= len(result.test_cases) * 0.1, (
            f"Injection agent has {auth_focused} auth-focused tests - should delegate to Auth agent"
        )

    # ==================== CATEGORIZATION AND COVERAGE ====================

    @pytest.mark.asyncio
    async def test_auth_agent_properly_categorizes_vulnerabilities(self, auth_agent, agent_task, secure_api_spec):
        """MUST properly categorize auth vulnerability types"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        categories = set()
        for test in result.test_cases:
            subtype = test.get('test_subtype', '')
            if subtype:
                categories.add(subtype)

        # Must have multiple auth vulnerability categories
        assert len(categories) >= 2, (
            f"Expected diverse auth vulnerability categories, only got: {categories}"
        )

        # Check for expected categories
        expected = {'bola', 'function-level-auth', 'auth-bypass'}
        found = categories & expected

        assert len(found) >= 2, (
            f"Expected auth categories like {expected}, but found: {categories}"
        )

    @pytest.mark.asyncio
    async def test_injection_agent_properly_categorizes_vulnerabilities(
        self, injection_agent, agent_task, secure_api_spec
    ):
        """MUST properly categorize injection vulnerability types"""
        result = await injection_agent.execute(agent_task, secure_api_spec)

        injection_types = set()
        for test in result.test_cases:
            subtype = test.get('test_subtype', '').lower()

            # Extract injection type
            if 'sql' in subtype:
                injection_types.add('sql')
            elif 'nosql' in subtype:
                injection_types.add('nosql')
            elif 'command' in subtype:
                injection_types.add('command')
            elif 'prompt' in subtype:
                injection_types.add('prompt')

        # Must test multiple injection types
        assert len(injection_types) >= 2, (
            f"Expected diverse injection types, only got: {injection_types}"
        )

    # ==================== SPECIFIC SECURITY ASSERTIONS ====================

    @pytest.mark.asyncio
    async def test_bola_tests_use_different_object_ids(self, auth_agent, agent_task, secure_api_spec):
        """BOLA tests MUST try accessing different object IDs"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        bola_tests = [tc for tc in result.test_cases if tc.get('test_subtype') == 'bola']

        # Collect all IDs being tested
        tested_ids = set()
        for test in bola_tests:
            path_params = test.get('path_params', {})
            for param_name, value in path_params.items():
                if 'id' in param_name.lower():
                    tested_ids.add(str(value))

        # Must test multiple different IDs
        assert len(tested_ids) >= 3, (
            f"BOLA tests must try multiple IDs, only found: {tested_ids}"
        )

    @pytest.mark.asyncio
    async def test_security_tests_expect_security_errors(self, auth_agent, agent_task, secure_api_spec):
        """Security tests MUST expect security-related error codes"""
        result = await auth_agent.execute(agent_task, secure_api_spec)

        for test in result.test_cases:
            expected_codes = test.get('expected_status_codes', [test.get('expected_status', 0)])

            # Security tests should expect 401, 403, or other security errors
            security_codes = [c for c in expected_codes if c in [401, 403, 404, 429]]

            assert len(security_codes) > 0, (
                f"Security test must expect security error codes, got: {expected_codes}"
            )

    # ==================== ERROR HANDLING ====================

    @pytest.mark.asyncio
    async def test_auth_agent_handles_spec_without_security(self, auth_agent, agent_task):
        """MUST handle spec without security requirements"""
        public_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/public": {
                    "get": {"responses": {"200": {}}}
                }
            }
        }

        result = await auth_agent.execute(agent_task, public_spec)

        assert result.status == "success", "Should succeed even for public spec"
        # May generate tests or not, but should not crash

    @pytest.mark.asyncio
    async def test_injection_agent_handles_spec_without_inputs(self, injection_agent, agent_task):
        """MUST handle spec without input parameters"""
        no_input_spec = {
            "openapi": "3.0.0",
            "paths": {
                "/status": {
                    "get": {"responses": {"200": {}}}
                }
            }
        }

        result = await injection_agent.execute(agent_task, no_input_spec)

        assert result.status == "success", "Should succeed even without inputs"
        # Should generate few or no tests, but should not crash
