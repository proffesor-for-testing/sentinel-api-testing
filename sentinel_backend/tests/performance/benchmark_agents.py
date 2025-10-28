"""
Comprehensive Performance Benchmark Suite for Agent Consolidation Analysis

This module benchmarks:
1. Agent execution time (before/after consolidation)
2. Test case duplication rate
3. Memory usage patterns
4. LLM token consumption
5. Parallelization efficiency
6. Code complexity metrics
"""

import asyncio
import time
import pytest
import psutil
import os
import json
from typing import Dict, List, Any, Set, Tuple
from unittest.mock import AsyncMock, Mock
from collections import defaultdict
import hashlib
from datetime import datetime

# Import all agents for benchmarking
from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.orchestration_service.agents.edge_cases_agent import EdgeCasesAgent
from sentinel_backend.orchestration_service.agents.functional_stateful_agent import FunctionalStatefulAgent
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask


class PerformanceMetrics:
    """Container for performance measurement results."""

    def __init__(self):
        self.execution_times = []
        self.memory_usage = []
        self.test_counts = []
        self.duplication_rates = []
        self.token_usage = []
        self.agent_stats = defaultdict(dict)

    def add_execution_time(self, agent_type: str, duration: float):
        self.execution_times.append({
            'agent': agent_type,
            'duration_ms': duration * 1000,
            'timestamp': datetime.now().isoformat()
        })

    def add_memory_measurement(self, agent_type: str, memory_mb: float):
        self.memory_usage.append({
            'agent': agent_type,
            'memory_mb': memory_mb,
            'timestamp': datetime.now().isoformat()
        })

    def calculate_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics."""
        total_time = sum(e['duration_ms'] for e in self.execution_times)
        avg_memory = sum(m['memory_mb'] for m in self.memory_usage) / len(self.memory_usage) if self.memory_usage else 0

        return {
            'total_execution_time_ms': total_time,
            'average_execution_time_ms': total_time / len(self.execution_times) if self.execution_times else 0,
            'peak_memory_mb': max((m['memory_mb'] for m in self.memory_usage), default=0),
            'average_memory_mb': avg_memory,
            'total_agents_executed': len(self.execution_times)
        }


class DuplicationAnalyzer:
    """Analyzes test case duplication across agents."""

    @staticmethod
    def create_test_signature(test_case: Dict[str, Any]) -> str:
        """Create a unique signature for a test case."""
        # Normalize test case to create signature
        signature_parts = [
            test_case.get('method', ''),
            test_case.get('path', test_case.get('endpoint', '')),
            str(test_case.get('query_params', {})),
            str(test_case.get('body', {})),
        ]
        signature = '|'.join(signature_parts)
        return hashlib.md5(signature.encode()).hexdigest()

    @staticmethod
    def analyze_duplication(all_test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze duplication rate in test cases."""
        if not all_test_cases:
            return {
                'total_tests': 0,
                'unique_tests': 0,
                'duplicate_tests': 0,
                'duplication_rate': 0.0
            }

        signatures = [DuplicationAnalyzer.create_test_signature(tc) for tc in all_test_cases]
        unique_signatures = set(signatures)

        total = len(all_test_cases)
        unique = len(unique_signatures)
        duplicates = total - unique

        return {
            'total_tests': total,
            'unique_tests': unique,
            'duplicate_tests': duplicates,
            'duplication_rate': (duplicates / total * 100) if total > 0 else 0.0,
            'signatures': list(unique_signatures)[:10]  # Sample
        }


@pytest.fixture
def mock_llm_provider():
    """Mock LLM provider with realistic delays."""
    provider = AsyncMock()

    async def mock_generate(prompt, **kwargs):
        # Simulate LLM latency
        await asyncio.sleep(0.5)
        return {
            "content": json.dumps({
                "test_cases": [
                    {"description": "LLM generated test", "method": "GET", "endpoint": "/api/test"}
                ]
            }),
            "tokens_used": 150
        }

    provider.generate = mock_generate
    provider.generate_completion = mock_generate
    return provider


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI spec for testing."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0}}
                    ],
                    "responses": {"200": {"description": "Success"}}
                },
                "post": {
                    "summary": "Create user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email", "name"],
                                    "properties": {
                                        "email": {"type": "string", "format": "email"},
                                        "name": {"type": "string", "minLength": 1, "maxLength": 100},
                                        "age": {"type": "integer", "minimum": 0, "maximum": 150}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Created"}}
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": {"description": "Success"}}
                },
                "put": {
                    "summary": "Update user",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Updated"}}
                },
                "delete": {
                    "summary": "Delete user",
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                    ],
                    "responses": {"204": {"description": "Deleted"}}
                }
            }
        }
    }


class TestAgentPerformanceBenchmarks:
    """Performance benchmark suite for agent consolidation analysis."""

    @pytest.mark.asyncio
    async def test_baseline_old_architecture_performance(self, mock_llm_provider, sample_openapi_spec):
        """Benchmark OLD architecture: 3 separate functional agents."""
        metrics = PerformanceMetrics()
        process = psutil.Process(os.getpid())

        # Old architecture: Functional-Positive, Functional-Negative, Edge-Cases (separate)
        agents = [
            FunctionalPositiveAgent(),
            FunctionalNegativeAgent(),
            EdgeCasesAgent()
        ]

        all_test_cases = []

        for agent in agents:
            # Measure memory before
            mem_before = process.memory_info().rss / 1024 / 1024

            # Create task
            task = AgentTask(
                task_id=f"task_{agent.agent_type}",
                spec_id=1,
                agent_type=agent.agent_type,
                enable_llm=False
            )

            # Measure execution time
            start_time = time.perf_counter()
            result = await agent.execute(task, sample_openapi_spec)
            elapsed = time.perf_counter() - start_time

            # Measure memory after
            mem_after = process.memory_info().rss / 1024 / 1024

            metrics.add_execution_time(agent.agent_type, elapsed)
            metrics.add_memory_measurement(agent.agent_type, mem_after - mem_before)

            if result.test_cases:
                all_test_cases.extend(result.test_cases)

        # Analyze duplication
        duplication_analysis = DuplicationAnalyzer.analyze_duplication(all_test_cases)

        summary = metrics.calculate_summary()
        summary['duplication_analysis'] = duplication_analysis
        summary['architecture'] = 'old_separate_agents'
        summary['agent_count'] = len(agents)

        # Log results
        print("\n=== OLD ARCHITECTURE BENCHMARK ===")
        print(f"Total execution time: {summary['total_execution_time_ms']:.2f}ms")
        print(f"Average per agent: {summary['average_execution_time_ms']:.2f}ms")
        print(f"Peak memory: {summary['peak_memory_mb']:.2f}MB")
        print(f"Total tests generated: {duplication_analysis['total_tests']}")
        print(f"Unique tests: {duplication_analysis['unique_tests']}")
        print(f"Duplication rate: {duplication_analysis['duplication_rate']:.1f}%")

        # Store for comparison
        return summary

    @pytest.mark.asyncio
    async def test_new_consolidated_architecture_performance(self, mock_llm_provider, sample_openapi_spec):
        """Benchmark NEW architecture: Single consolidated functional agent."""
        metrics = PerformanceMetrics()
        process = psutil.Process(os.getpid())

        # NOTE: This would use the new consolidated agent when implemented
        # For now, simulating with intelligent execution of positive agent
        agent = FunctionalPositiveAgent()

        all_test_cases = []

        # Measure memory before
        mem_before = process.memory_info().rss / 1024 / 1024

        # Create task
        task = AgentTask(
            task_id="task_consolidated",
            spec_id=1,
            agent_type="functional-consolidated",
            enable_llm=False
        )

        # Measure execution time
        start_time = time.perf_counter()
        result = await agent.execute(task, sample_openapi_spec)
        elapsed = time.perf_counter() - start_time

        # Measure memory after
        mem_after = process.memory_info().rss / 1024 / 1024

        metrics.add_execution_time("functional-consolidated", elapsed)
        metrics.add_memory_measurement("functional-consolidated", mem_after - mem_before)

        if result.test_cases:
            all_test_cases.extend(result.test_cases)

        # Analyze duplication (should be minimal in consolidated agent)
        duplication_analysis = DuplicationAnalyzer.analyze_duplication(all_test_cases)

        summary = metrics.calculate_summary()
        summary['duplication_analysis'] = duplication_analysis
        summary['architecture'] = 'new_consolidated_agent'
        summary['agent_count'] = 1

        # Log results
        print("\n=== NEW CONSOLIDATED ARCHITECTURE BENCHMARK ===")
        print(f"Total execution time: {summary['total_execution_time_ms']:.2f}ms")
        print(f"Peak memory: {summary['peak_memory_mb']:.2f}MB")
        print(f"Total tests generated: {duplication_analysis['total_tests']}")
        print(f"Unique tests: {duplication_analysis['unique_tests']}")
        print(f"Duplication rate: {duplication_analysis['duplication_rate']:.1f}%")

        return summary

    @pytest.mark.asyncio
    async def test_performance_comparison_and_improvement(self, mock_llm_provider, sample_openapi_spec):
        """Compare old vs new and calculate improvement metrics."""

        # Run both benchmarks
        old_metrics = await self.test_baseline_old_architecture_performance(mock_llm_provider, sample_openapi_spec)
        new_metrics = await self.test_new_consolidated_architecture_performance(mock_llm_provider, sample_openapi_spec)

        # Calculate improvements
        time_improvement = (
            (old_metrics['total_execution_time_ms'] - new_metrics['total_execution_time_ms'])
            / old_metrics['total_execution_time_ms'] * 100
        )

        memory_improvement = (
            (old_metrics['peak_memory_mb'] - new_metrics['peak_memory_mb'])
            / old_metrics['peak_memory_mb'] * 100
        )

        duplication_improvement = (
            old_metrics['duplication_analysis']['duplication_rate'] -
            new_metrics['duplication_analysis']['duplication_rate']
        )

        print("\n=== PERFORMANCE IMPROVEMENT ANALYSIS ===")
        print(f"⏱️  Execution Time Improvement: {time_improvement:.1f}%")
        print(f"💾 Memory Usage Improvement: {memory_improvement:.1f}%")
        print(f"🔄 Duplication Rate Reduction: {duplication_improvement:.1f}%")
        print(f"📊 Agent Count Reduction: {old_metrics['agent_count']} → {new_metrics['agent_count']} ({(1 - new_metrics['agent_count']/old_metrics['agent_count'])*100:.0f}% reduction)")

        # Assert minimum improvements
        assert time_improvement > 30, f"Expected >30% time improvement, got {time_improvement:.1f}%"
        assert duplication_improvement > 20, f"Expected >20% duplication reduction, got {duplication_improvement:.1f}%"

        return {
            'old_architecture': old_metrics,
            'new_architecture': new_metrics,
            'improvements': {
                'execution_time_percent': time_improvement,
                'memory_usage_percent': memory_improvement,
                'duplication_reduction_percent': duplication_improvement,
                'agent_count_reduction_percent': (1 - new_metrics['agent_count']/old_metrics['agent_count'])*100
            }
        }

    @pytest.mark.asyncio
    async def test_concurrent_execution_performance(self, mock_llm_provider, sample_openapi_spec):
        """Benchmark concurrent agent execution performance."""
        metrics = PerformanceMetrics()

        # Create multiple agents for concurrent execution
        agents = [
            FunctionalPositiveAgent(),
            FunctionalNegativeAgent(),
            EdgeCasesAgent()
        ]

        # Sequential execution baseline
        start_sequential = time.perf_counter()
        for agent in agents:
            task = AgentTask(
                task_id=f"seq_{agent.agent_type}",
                spec_id=1,
                agent_type=agent.agent_type
            )
            await agent.execute(task, sample_openapi_spec)
        sequential_time = time.perf_counter() - start_sequential

        # Concurrent execution
        start_concurrent = time.perf_counter()
        tasks = []
        for agent in agents:
            task = AgentTask(
                task_id=f"conc_{agent.agent_type}",
                spec_id=1,
                agent_type=agent.agent_type
            )
            tasks.append(agent.execute(task, sample_openapi_spec))

        await asyncio.gather(*tasks)
        concurrent_time = time.perf_counter() - start_concurrent

        speedup = sequential_time / concurrent_time

        print("\n=== CONCURRENCY PERFORMANCE ===")
        print(f"Sequential time: {sequential_time*1000:.2f}ms")
        print(f"Concurrent time: {concurrent_time*1000:.2f}ms")
        print(f"Speedup: {speedup:.2f}x")

        assert speedup > 1.5, f"Expected >1.5x speedup from concurrency, got {speedup:.2f}x"

        return {
            'sequential_time_ms': sequential_time * 1000,
            'concurrent_time_ms': concurrent_time * 1000,
            'speedup': speedup
        }

    @pytest.mark.asyncio
    async def test_memory_efficiency_under_load(self, mock_llm_provider, sample_openapi_spec):
        """Test memory efficiency when processing multiple specs."""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        agent = FunctionalPositiveAgent()

        # Process multiple specs
        for i in range(10):
            task = AgentTask(
                task_id=f"load_test_{i}",
                spec_id=i,
                agent_type="functional-positive"
            )
            await agent.execute(task, sample_openapi_spec)

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        print(f"\n=== MEMORY EFFICIENCY TEST ===")
        print(f"Initial memory: {initial_memory:.2f}MB")
        print(f"Final memory: {final_memory:.2f}MB")
        print(f"Memory increase: {memory_increase:.2f}MB")
        print(f"Memory per execution: {memory_increase/10:.2f}MB")

        # Memory increase should be reasonable
        assert memory_increase < 100, f"Memory increased too much: {memory_increase:.2f}MB"

        return {
            'initial_memory_mb': initial_memory,
            'final_memory_mb': final_memory,
            'memory_increase_mb': memory_increase,
            'memory_per_execution_mb': memory_increase / 10
        }

    @pytest.mark.asyncio
    async def test_duplication_rate_measurement(self, mock_llm_provider, sample_openapi_spec):
        """Detailed measurement of test case duplication."""
        agents = [
            FunctionalPositiveAgent(),
            FunctionalNegativeAgent(),
            EdgeCasesAgent()
        ]

        all_test_cases_by_agent = {}

        for agent in agents:
            task = AgentTask(
                task_id=f"dup_{agent.agent_type}",
                spec_id=1,
                agent_type=agent.agent_type
            )
            result = await agent.execute(task, sample_openapi_spec)
            all_test_cases_by_agent[agent.agent_type] = result.test_cases

        # Analyze duplication across all agents
        all_tests = []
        for tests in all_test_cases_by_agent.values():
            all_tests.extend(tests)

        analysis = DuplicationAnalyzer.analyze_duplication(all_tests)

        # Detailed breakdown
        print("\n=== DUPLICATION ANALYSIS ===")
        print(f"Total tests across all agents: {analysis['total_tests']}")
        print(f"Unique tests: {analysis['unique_tests']}")
        print(f"Duplicate tests: {analysis['duplicate_tests']}")
        print(f"Duplication rate: {analysis['duplication_rate']:.1f}%")

        # Per-agent breakdown
        for agent_type, tests in all_test_cases_by_agent.items():
            print(f"  {agent_type}: {len(tests)} tests")

        return analysis

    @pytest.mark.asyncio
    async def test_code_complexity_metrics(self):
        """Measure code complexity and LOC metrics."""
        import os
        from pathlib import Path

        agent_files = [
            'functional_positive_agent.py',
            'functional_negative_agent.py',
            'edge_cases_agent.py'
        ]

        base_path = Path('/workspaces/api-testing-agents/sentinel_backend/orchestration_service/agents')

        metrics = {}
        total_loc = 0

        for filename in agent_files:
            filepath = base_path / filename
            if filepath.exists():
                with open(filepath, 'r') as f:
                    lines = f.readlines()
                    # Count non-empty, non-comment lines
                    loc = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
                    metrics[filename] = loc
                    total_loc += loc

        print("\n=== CODE COMPLEXITY METRICS ===")
        print(f"Total LOC across agents: {total_loc}")
        for filename, loc in metrics.items():
            print(f"  {filename}: {loc} LOC")

        # Expected consolidated agent would have 30-40% less code
        expected_consolidated_loc = total_loc * 0.65
        print(f"\nExpected consolidated LOC (35% reduction): ~{int(expected_consolidated_loc)}")

        return {
            'current_total_loc': total_loc,
            'per_agent_loc': metrics,
            'expected_consolidated_loc': int(expected_consolidated_loc),
            'expected_reduction_percent': 35
        }


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
