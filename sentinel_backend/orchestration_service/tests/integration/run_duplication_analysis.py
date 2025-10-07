#!/usr/bin/env python3
"""
Standalone script to analyze agent test duplication

This script runs independently of pytest to measure baseline duplication
across all agents in the current implementation.
"""

import asyncio
import json
import hashlib
from typing import Dict, List, Any, Tuple
from collections import defaultdict
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

# Set PYTHONPATH environment variable
os.environ['PYTHONPATH'] = str(project_root)

from orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from orchestration_service.agents.edge_cases_agent import EdgeCasesAgent
from orchestration_service.agents.functional_stateful_agent import FunctionalStatefulAgent
from orchestration_service.agents.security_agent import SecurityAgent
from orchestration_service.agents.performance_agent import PerformanceAgent
from orchestration_service.agents.data_mocking_agent import DataMockingAgent
from orchestration_service.agents.base_agent import AgentTask


class TestSignatureGenerator:
    """Generate unique signatures for test cases using IMPROVED algorithm."""

    @staticmethod
    def create_signature(test_case: Dict[str, Any]) -> str:
        """
        Create unique signature based on test characteristics.

        IMPROVED ALGORITHM (matches functional_agent.py):
        - Includes actual query parameter VALUES (not just keys)
        - Includes actual body VALUES (not just structure)
        - Includes test_type AND test_subtype for better categorization
        - Includes description hash to distinguish similar tests
        """
        # Normalize query params by including VALUES
        query_params = test_case.get('query_params', {})
        normalized_query = {}
        if query_params:
            for key in sorted(query_params.keys()):
                val = query_params[key]
                normalized_query[key] = str(val) if val is not None else 'null'

        # Normalize body by including VALUES (not just structure)
        body = test_case.get('body')
        normalized_body = None
        if body is not None:
            if isinstance(body, dict):
                normalized_body = {k: str(v) for k, v in sorted(body.items())}
            elif isinstance(body, list):
                normalized_body = [str(item) for item in body]
            else:
                normalized_body = str(body)

        # Create comprehensive signature
        signature_data = {
            'method': test_case.get('method', '').upper(),
            'path': test_case.get('path', test_case.get('endpoint', '')),
            'test_type': test_case.get('test_type', ''),
            'test_subtype': test_case.get('test_subtype', ''),
            'query_params': normalized_query,  # CHANGED: Include VALUES
            'body': normalized_body,  # CHANGED: Include VALUES
            'expected_status': test_case.get('expected_status_codes', [test_case.get('expected_status', 200)])[0] if test_case.get('expected_status_codes') else test_case.get('expected_status', 200),
            'description_hash': hashlib.md5(
                test_case.get('test_name', test_case.get('description', '')).encode()
            ).hexdigest()[:8]
        }

        signature_str = json.dumps(signature_data, sort_keys=True)
        return hashlib.md5(signature_str.encode()).hexdigest()


class DuplicationAnalyzer:
    """Analyze test case duplication across agents."""

    def __init__(self):
        self.test_signatures: Dict[str, List[Tuple[str, Dict]]] = defaultdict(list)
        self.agent_test_counts: Dict[str, int] = defaultdict(int)

    def add_tests(self, agent_name: str, test_cases: List[Dict[str, Any]]):
        """Add test cases from an agent."""
        self.agent_test_counts[agent_name] = len(test_cases)

        for test in test_cases:
            sig = TestSignatureGenerator.create_signature(test)
            self.test_signatures[sig].append((agent_name, test))

    def get_report(self) -> Dict[str, Any]:
        """Generate duplication report."""
        total_tests = sum(self.agent_test_counts.values())
        unique_tests = len(self.test_signatures)
        duplicate_tests = total_tests - unique_tests
        duplication_rate = (duplicate_tests / total_tests * 100) if total_tests > 0 else 0

        # Find agent pair duplicates
        agent_pairs = defaultdict(int)
        duplicates_by_sig = {}

        for sig, tests in self.test_signatures.items():
            if len(tests) > 1:
                duplicates_by_sig[sig] = tests
                agents = [t[0] for t in tests]
                for i, agent1 in enumerate(agents):
                    for agent2 in agents[i+1:]:
                        pair = tuple(sorted([agent1, agent2]))
                        agent_pairs[pair] += 1

        return {
            'total_tests': total_tests,
            'unique_tests': unique_tests,
            'duplicate_tests': duplicate_tests,
            'duplication_rate': duplication_rate,
            'tests_by_agent': dict(self.agent_test_counts),
            'agent_pair_duplication': dict(agent_pairs),
            'duplicate_signatures': duplicates_by_sig
        }

    def print_report(self):
        """Print detailed report."""
        report = self.get_report()

        print("\n" + "="*80)
        print("BASELINE AGENT TEST DUPLICATION ANALYSIS")
        print("="*80)
        print(f"\nTotal Tests Generated: {report['total_tests']}")
        print(f"Unique Tests: {report['unique_tests']}")
        print(f"Duplicate Tests: {report['duplicate_tests']}")
        print(f"Duplication Rate: {report['duplication_rate']:.2f}%")

        if report['duplication_rate'] > 10:
            print(f"\n⚠️  WARNING: Duplication rate {report['duplication_rate']:.1f}% exceeds 10% threshold!")
        else:
            print(f"\n✅ PASS: Duplication rate {report['duplication_rate']:.1f}% is below 10% threshold")

        print("\n" + "-"*80)
        print("Tests Generated by Agent:")
        print("-"*80)
        for agent, count in sorted(report['tests_by_agent'].items()):
            pct = (count / report['total_tests'] * 100) if report['total_tests'] > 0 else 0
            print(f"  {agent:25s} {count:4d} tests ({pct:5.1f}%)")

        if report['agent_pair_duplication']:
            print("\n" + "-"*80)
            print("Agent Pair Duplication (Top 10):")
            print("-"*80)
            sorted_pairs = sorted(report['agent_pair_duplication'].items(),
                                key=lambda x: x[1], reverse=True)[:10]
            for (agent1, agent2), count in sorted_pairs:
                print(f"  {agent1:20s} ↔ {agent2:20s} {count:4d} duplicates")

        if report['duplicate_signatures']:
            print("\n" + "-"*80)
            print(f"Sample Duplicate Test Cases (showing 3 of {len(report['duplicate_signatures'])}):")
            print("-"*80)
            for i, (sig, tests) in enumerate(list(report['duplicate_signatures'].items())[:3]):
                print(f"\n  Duplicate Group {i+1} (signature: {sig[:12]}...):")
                for agent, test in tests:
                    method = test.get('method', 'N/A')
                    path = test.get('path', 'N/A')
                    test_type = test.get('test_type', 'N/A')
                    print(f"    [{agent:20s}] {method:6s} {path:30s} type={test_type}")

        print("\n" + "="*80)
        return report


def get_sample_spec():
    """Get sample OpenAPI spec for testing."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0}}
                    ],
                    "responses": {
                        "200": {
                            "description": "Success",
                            "content": {"application/json": {"schema": {"type": "array"}}}
                        }
                    }
                },
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/UserInput"}
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Success"}}
                }
            }
        },
        "components": {
            "schemas": {
                "UserInput": {
                    "type": "object",
                    "required": ["name", "email"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1, "maxLength": 100},
                        "email": {"type": "string", "format": "email"},
                        "age": {"type": "integer", "minimum": 18, "maximum": 100}
                    }
                }
            }
        }
    }


async def main():
    """Run the duplication analysis."""
    print("\nInitializing agents...")

    agents = {
        'functional-positive': FunctionalPositiveAgent(),
        'functional-negative': FunctionalNegativeAgent(),
        'edge-cases': EdgeCasesAgent(),
        'stateful': FunctionalStatefulAgent(),
        'security': SecurityAgent(),
        'performance': PerformanceAgent(),
        'data-mocking': DataMockingAgent()
    }

    spec = get_sample_spec()
    analyzer = DuplicationAnalyzer()

    print("Executing agents and collecting test cases...\n")

    for agent_name, agent in agents.items():
        print(f"  Running {agent_name}...", end=" ")

        task = AgentTask(
            task_id=f"baseline-{agent_name}",
            spec_id="baseline-spec",
            agent_types=[agent_name],
            enable_llm=False,
            parameters={}
        )

        try:
            result = await agent.execute(task, spec)

            if result.status == "success" and result.test_cases:
                analyzer.add_tests(agent_name, result.test_cases)
                print(f"✓ ({len(result.test_cases)} tests)")
            else:
                print(f"✗ (status: {result.status})")
        except Exception as e:
            print(f"✗ (error: {str(e)[:50]}...)")

    # Generate and print report
    report = analyzer.print_report()

    # Write report to file
    report_file = Path(__file__).parent / "duplication_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\nDetailed report saved to: {report_file}")

    # Exit with appropriate code
    if report['duplication_rate'] > 10:
        print("\n❌ VALIDATION FAILED: Duplication rate exceeds 10% threshold")
        sys.exit(1)
    else:
        print("\n✅ VALIDATION PASSED: Duplication rate is acceptable")
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
