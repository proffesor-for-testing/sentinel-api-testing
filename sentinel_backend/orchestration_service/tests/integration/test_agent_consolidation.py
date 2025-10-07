"""
Integration tests for Agent Consolidation and Duplication Validation

This test suite validates:
1. Test case duplication across all agents
2. Test case quality and structure
3. Agent strategy implementation
4. Data generation service integration

Critical Success Criteria:
- Duplication rate < 10% (was 60-75%)
- All test cases have proper structure
- Different strategies produce different test types
- No overlap between agent responsibilities
"""

import pytest
import asyncio
import json
import hashlib
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict
import sys
from pathlib import Path

# Add the parent directory to sys.path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agents.functional_positive_agent import FunctionalPositiveAgent
from agents.functional_negative_agent import FunctionalNegativeAgent
from agents.edge_cases_agent import EdgeCasesAgent
from agents.functional_stateful_agent import FunctionalStatefulAgent
from agents.security_agent import SecurityAgent
from agents.performance_agent import PerformanceAgent
from agents.data_mocking_agent import DataMockingAgent
from agents.base_agent import AgentTask, AgentResult


class TestSignatureGenerator:
    """Utility to generate unique signatures for test cases."""

    @staticmethod
    def create_signature(test_case: Dict[str, Any]) -> str:
        """
        Create a unique signature for a test case.

        Signature is based on:
        - HTTP method
        - Endpoint path
        - Query parameters (keys only)
        - Request body structure (keys only, recursively)
        - Expected status code
        """
        signature_data = {
            'method': test_case.get('method', '').upper(),
            'path': test_case.get('path', ''),
            'query_params': sorted(test_case.get('query_params', {}).keys()),
            'body_structure': TestSignatureGenerator._get_body_structure(test_case.get('body')),
            'expected_status': test_case.get('expected_status_codes', [200])[0] if test_case.get('expected_status_codes') else 200
        }

        # Create a deterministic JSON string
        signature_str = json.dumps(signature_data, sort_keys=True)

        # Return MD5 hash for compact signature
        return hashlib.md5(signature_str.encode()).hexdigest()

    @staticmethod
    def _get_body_structure(body: Any) -> Any:
        """Extract the structure of a request body (keys only, recursive)."""
        if body is None:
            return None
        elif isinstance(body, dict):
            return {k: TestSignatureGenerator._get_body_structure(v) for k, v in body.items()}
        elif isinstance(body, list):
            return ['array'] if body else []
        else:
            return type(body).__name__


class DuplicationAnalyzer:
    """Analyze and report on test case duplication."""

    def __init__(self):
        self.test_signatures: Dict[str, List[Tuple[str, Dict]]] = defaultdict(list)
        self.agent_test_counts: Dict[str, int] = defaultdict(int)

    def add_tests(self, agent_name: str, test_cases: List[Dict[str, Any]]):
        """Add test cases from an agent for analysis."""
        self.agent_test_counts[agent_name] = len(test_cases)

        for test in test_cases:
            sig = TestSignatureGenerator.create_signature(test)
            self.test_signatures[sig].append((agent_name, test))

    def get_duplication_report(self) -> Dict[str, Any]:
        """Generate a comprehensive duplication report."""
        total_tests = sum(self.agent_test_counts.values())
        unique_tests = len(self.test_signatures)
        duplicate_tests = total_tests - unique_tests
        duplication_rate = (duplicate_tests / total_tests * 100) if total_tests > 0 else 0

        # Find duplicates by agent pair
        agent_pairs_duplication = defaultdict(int)
        duplicates_by_signature = {}

        for sig, tests in self.test_signatures.items():
            if len(tests) > 1:
                duplicates_by_signature[sig] = tests
                # Count duplicates between agent pairs
                agents = [t[0] for t in tests]
                for i, agent1 in enumerate(agents):
                    for agent2 in agents[i+1:]:
                        pair = tuple(sorted([agent1, agent2]))
                        agent_pairs_duplication[pair] += 1

        return {
            'total_tests': total_tests,
            'unique_tests': unique_tests,
            'duplicate_tests': duplicate_tests,
            'duplication_rate': duplication_rate,
            'tests_by_agent': dict(self.agent_test_counts),
            'duplicate_count': len(duplicates_by_signature),
            'agent_pair_duplication': dict(agent_pairs_duplication),
            'duplicate_signatures': duplicates_by_signature
        }

    def print_report(self):
        """Print a human-readable duplication report."""
        report = self.get_duplication_report()

        print("\n" + "="*80)
        print("AGENT TEST DUPLICATION ANALYSIS REPORT")
        print("="*80)
        print(f"\nTotal Tests Generated: {report['total_tests']}")
        print(f"Unique Tests: {report['unique_tests']}")
        print(f"Duplicate Tests: {report['duplicate_tests']}")
        print(f"Duplication Rate: {report['duplication_rate']:.2f}%")

        print("\n" + "-"*80)
        print("Tests by Agent:")
        print("-"*80)
        for agent, count in sorted(report['tests_by_agent'].items()):
            print(f"  {agent}: {count} tests")

        print("\n" + "-"*80)
        print("Agent Pair Duplication:")
        print("-"*80)
        for (agent1, agent2), count in sorted(report['agent_pair_duplication'].items(), key=lambda x: x[1], reverse=True):
            print(f"  {agent1} ↔ {agent2}: {count} duplicate tests")

        if report['duplicate_signatures']:
            print("\n" + "-"*80)
            print(f"Sample Duplicates (showing first 5 of {len(report['duplicate_signatures'])}):")
            print("-"*80)
            for i, (sig, tests) in enumerate(list(report['duplicate_signatures'].items())[:5]):
                print(f"\n  Signature {i+1} ({sig[:8]}...):")
                for agent, test in tests:
                    print(f"    - {agent}: {test.get('method', 'N/A')} {test.get('path', 'N/A')}")


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI spec for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "operationId": "getUsers",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100
                            }
                        },
                        {
                            "name": "offset",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "minimum": 0
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
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
                },
                "post": {
                    "summary": "Create user",
                    "operationId": "createUser",
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
                            "description": "Created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/User"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "operationId": "getUserById",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/User"
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
                "User": {
                    "type": "object",
                    "required": ["id", "name", "email"],
                    "properties": {
                        "id": {"type": "string"},
                        "name": {"type": "string"},
                        "email": {"type": "string", "format": "email"},
                        "age": {
                            "type": "integer",
                            "minimum": 18,
                            "maximum": 100
                        }
                    }
                },
                "UserInput": {
                    "type": "object",
                    "required": ["name", "email"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1, "maxLength": 100},
                        "email": {"type": "string", "format": "email"},
                        "age": {
                            "type": "integer",
                            "minimum": 18,
                            "maximum": 100
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def agent_task():
    """Create a sample agent task."""
    return AgentTask(
        task_id="test-task-001",
        spec_id="test-spec-001",
        agent_types=["functional-positive"],
        enable_llm=False,
        parameters={}
    )


@pytest.mark.asyncio
class TestAgentDuplication:
    """Test suite for agent duplication analysis."""

    async def test_no_duplication_across_all_agents(self, sample_openapi_spec, agent_task):
        """
        CRITICAL TEST: Verify NO duplicate tests between agents.

        Success Criteria: Duplication rate < 10%
        """
        analyzer = DuplicationAnalyzer()

        # Initialize all agents
        agents = {
            'functional-positive': FunctionalPositiveAgent(),
            'functional-negative': FunctionalNegativeAgent(),
            'edge-cases': EdgeCasesAgent(),
            'stateful': FunctionalStatefulAgent(),
            'security': SecurityAgent(),
            'performance': PerformanceAgent(),
            'data-mocking': DataMockingAgent()
        }

        # Execute each agent and collect test cases
        for agent_name, agent in agents.items():
            task = AgentTask(
                task_id=f"test-{agent_name}",
                spec_id="test-spec-001",
                agent_types=[agent_name],
                enable_llm=False,
                parameters={}
            )

            result = await agent.execute(task, sample_openapi_spec)

            if result.status == "success" and result.test_cases:
                analyzer.add_tests(agent_name, result.test_cases)

        # Generate and print report
        analyzer.print_report()
        report = analyzer.get_duplication_report()

        # Assert duplication rate is below 10%
        duplication_rate = report['duplication_rate']
        assert duplication_rate < 10, (
            f"Duplication rate {duplication_rate:.1f}% exceeds 10% threshold!\n"
            f"Total tests: {report['total_tests']}, "
            f"Unique: {report['unique_tests']}, "
            f"Duplicates: {report['duplicate_tests']}"
        )

    async def test_functional_positive_strategies(self, sample_openapi_spec):
        """Test that positive strategies produce valid test types."""
        agent = FunctionalPositiveAgent()

        task = AgentTask(
            task_id="test-positive",
            spec_id="test-spec-001",
            agent_types=["functional-positive"],
            enable_llm=False,
            parameters={"strategy": "positive"}
        )

        result = await agent.execute(task, sample_openapi_spec)

        assert result.status == "success"
        assert len(result.test_cases) > 0

        # Verify all tests are positive (expecting success responses)
        for test in result.test_cases:
            expected_status = test.get('expected_status_codes', [200])[0]
            assert 200 <= expected_status < 300, f"Positive test should expect 2xx status, got {expected_status}"

    async def test_functional_negative_strategies(self, sample_openapi_spec):
        """Test that negative strategies produce invalid test types."""
        agent = FunctionalNegativeAgent()

        task = AgentTask(
            task_id="test-negative",
            spec_id="test-spec-001",
            agent_types=["functional-negative"],
            enable_llm=False,
            parameters={"strategy": "negative"}
        )

        result = await agent.execute(task, sample_openapi_spec)

        assert result.status == "success"
        assert len(result.test_cases) > 0

        # Verify tests expect error responses
        for test in result.test_cases:
            expected_status = test.get('expected_status_codes', [400])[0]
            assert expected_status >= 400, f"Negative test should expect 4xx/5xx status, got {expected_status}"


@pytest.mark.asyncio
class TestCaseQuality:
    """Test case structure and quality validation."""

    async def test_test_case_structure(self, sample_openapi_spec, agent_task):
        """Verify all test cases have proper structure."""
        agent = FunctionalPositiveAgent()
        result = await agent.execute(agent_task, sample_openapi_spec)

        required_fields = ['method', 'path', 'expected_status_codes']

        for test in result.test_cases:
            # Check required fields
            for field in required_fields:
                assert field in test, f"Test case missing required field: {field}"

            # Validate method
            assert test['method'] in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'], \
                f"Invalid HTTP method: {test['method']}"

            # Validate expected status
            assert isinstance(test['expected_status_codes'], list), \
                "expected_status_codes must be a list"
            assert len(test['expected_status_codes']) > 0, \
                "expected_status_codes cannot be empty"
            assert all(isinstance(s, int) for s in test['expected_status_codes']), \
                "All status codes must be integers"

    async def test_no_duplicate_within_single_agent(self, sample_openapi_spec, agent_task):
        """Verify a single agent doesn't generate duplicate tests."""
        agent = FunctionalPositiveAgent()
        result = await agent.execute(agent_task, sample_openapi_spec)

        signatures = set()
        duplicates = []

        for test in result.test_cases:
            sig = TestSignatureGenerator.create_signature(test)
            if sig in signatures:
                duplicates.append(test)
            signatures.add(sig)

        assert len(duplicates) == 0, (
            f"Agent generated {len(duplicates)} duplicate tests within its own output:\n"
            f"{json.dumps(duplicates[:3], indent=2)}"
        )


@pytest.mark.asyncio
class TestAgentSpecialization:
    """Verify agents maintain their specialized roles without overlap."""

    async def test_functional_vs_security_no_overlap(self, sample_openapi_spec):
        """Functional and security agents should test different aspects."""
        functional_agent = FunctionalPositiveAgent()
        security_agent = SecurityAgent()

        func_task = AgentTask(
            task_id="func-test",
            spec_id="test-spec",
            agent_types=["functional-positive"],
            enable_llm=False,
            parameters={}
        )

        sec_task = AgentTask(
            task_id="sec-test",
            spec_id="test-spec",
            agent_types=["security"],
            enable_llm=False,
            parameters={}
        )

        func_result = await functional_agent.execute(func_task, sample_openapi_spec)
        sec_result = await security_agent.execute(sec_task, sample_openapi_spec)

        # Get signatures
        func_sigs = {TestSignatureGenerator.create_signature(t) for t in func_result.test_cases}
        sec_sigs = {TestSignatureGenerator.create_signature(t) for t in sec_result.test_cases}

        # Calculate overlap
        overlap = func_sigs & sec_sigs
        overlap_rate = len(overlap) / len(func_sigs) * 100 if func_sigs else 0

        assert overlap_rate < 5, (
            f"Functional and Security agents have {overlap_rate:.1f}% overlap, "
            f"should be < 5%. They test different concerns."
        )


@pytest.mark.asyncio
class TestPerformanceMetrics:
    """Validate performance and efficiency of test generation."""

    async def test_test_generation_count_reasonable(self, sample_openapi_spec, agent_task):
        """Verify test count is reasonable (not excessive)."""
        agent = FunctionalPositiveAgent()
        result = await agent.execute(agent_task, sample_openapi_spec)

        # For the sample spec with 3 endpoints, expect reasonable test count
        # Positive agent should generate: basic + variations
        # Reasonable range: 5-20 tests per endpoint
        endpoint_count = len(sample_openapi_spec['paths'])
        expected_min = endpoint_count * 2  # At least 2 tests per endpoint
        expected_max = endpoint_count * 25  # At most 25 tests per endpoint

        actual_count = len(result.test_cases)

        assert expected_min <= actual_count <= expected_max, (
            f"Test count {actual_count} outside reasonable range [{expected_min}, {expected_max}] "
            f"for {endpoint_count} endpoints"
        )


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
