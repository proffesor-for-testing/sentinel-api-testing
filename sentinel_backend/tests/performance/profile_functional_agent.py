"""
Performance Profiling Script for FunctionalAgent
Identifies bottlenecks causing 95% slowdown (25x slower per test)

Analysis Target:
- Old: 5.7ms per test (1,813ms / 320 tests)
- New: 141.6ms per test (3,540ms / 25 tests)
- **25x slower per test!**
"""

import asyncio
import time
import cProfile
import pstats
import io
from typing import Dict, Any, List
from contextlib import contextmanager
from dataclasses import dataclass, field
from collections import defaultdict

from sentinel_backend.orchestration_service.agents.functional_agent import FunctionalAgent
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask


@dataclass
class ProfileMetrics:
    """Container for profiling metrics"""
    operation: str
    duration_ms: float
    call_count: int = 1
    percentage: float = 0.0


class TimingProfiler:
    """Lightweight timing profiler for identifying bottlenecks"""

    def __init__(self):
        self.timings: Dict[str, List[float]] = defaultdict(list)
        self.current_scope = []

    @contextmanager
    def time(self, operation: str):
        """Context manager for timing operations"""
        start = time.perf_counter()
        self.current_scope.append(operation)
        try:
            yield
        finally:
            elapsed = (time.perf_counter() - start) * 1000  # Convert to ms
            self.timings[operation].append(elapsed)
            self.current_scope.pop()

    def get_metrics(self, total_time_ms: float) -> List[ProfileMetrics]:
        """Calculate metrics with percentages"""
        metrics = []
        for operation, times in self.timings.items():
            total = sum(times)
            metrics.append(ProfileMetrics(
                operation=operation,
                duration_ms=total,
                call_count=len(times),
                percentage=(total / total_time_ms * 100) if total_time_ms > 0 else 0
            ))
        return sorted(metrics, key=lambda m: m.duration_ms, reverse=True)


# Monkey-patch FunctionalAgent for detailed profiling
_original_execute = FunctionalAgent.execute
_original_deduplicate = FunctionalAgent._deduplicate_tests
_original_create_signature = FunctionalAgent._create_test_signature
_original_resolve_schema = FunctionalAgent._resolve_schema_ref

profiler = TimingProfiler()


async def profiled_execute(self, task: AgentTask, api_spec: Dict[str, Any]):
    """Profiled execute method"""
    with profiler.time("total_execute"):
        # Strategy selection
        with profiler.time("strategy_selection"):
            requested_strategies = task.parameters.get('strategies', ['positive', 'negative', 'boundary'])

        # Endpoint extraction
        with profiler.time("endpoint_extraction"):
            endpoints = self._extract_endpoints(api_spec)

        # Strategy execution
        all_tests = []
        for strategy_name in requested_strategies:
            if strategy_name not in self.strategies:
                continue

            with profiler.time(f"strategy_{strategy_name}"):
                strategy = self.strategies[strategy_name]
                strategy_tests = await strategy.generate_tests(endpoints, api_spec)
                all_tests.extend(strategy_tests)

        # Deduplication
        with profiler.time("deduplication"):
            unique_tests = self._deduplicate_tests(all_tests)

        # LLM enhancement
        use_llm = task.enable_llm and self.llm_enabled
        if use_llm and unique_tests:
            with profiler.time("llm_enhancement"):
                enhanced_count = min(3, len(unique_tests) // 5)
                for i in range(enhanced_count):
                    variant = await self.generate_creative_variant(unique_tests[i], "realistic")
                    if variant:
                        variant['description'] = f"[LLM Enhanced] {variant.get('description', 'Creative variant')}"
                        unique_tests.append(variant)

        # Result creation
        with profiler.time("result_creation"):
            from sentinel_backend.orchestration_service.agents.base_agent import AgentResult
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="success",
                test_cases=unique_tests,
                metadata={
                    "total_endpoints": len(endpoints),
                    "strategies_used": requested_strategies,
                    "total_generated": len(all_tests),
                    "unique_tests": len(unique_tests),
                    "duplicates_removed": len(all_tests) - len(unique_tests),
                }
            )


def profiled_deduplicate(self, test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Profiled deduplication method"""
    with profiler.time("dedup_setup"):
        seen_signatures = set()
        unique_tests = []

    for test in test_cases:
        with profiler.time("dedup_per_test"):
            with profiler.time("signature_creation"):
                signature = self._create_test_signature(test)

            with profiler.time("signature_check"):
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    unique_tests.append(test)

    return unique_tests


def profiled_create_signature(self, test: Dict[str, Any]) -> str:
    """Profiled signature creation"""
    with profiler.time("sig_data_assembly"):
        sig_data = {
            'method': test.get('method', '').upper(),
            'endpoint': test.get('endpoint', test.get('path', '')),
            'test_type': test.get('test_type', ''),
            'query_keys': sorted(test.get('query_params', {}).keys()),
            'body_keys': sorted(test.get('body', {}).keys()) if isinstance(test.get('body'), dict) else [],
            'expected_status': test.get('expected_status_codes', [test.get('expected_status', 200)])[0]
        }

    with profiler.time("sig_json_dumps"):
        import json
        sig_str = json.dumps(sig_data, sort_keys=True)

    with profiler.time("sig_md5_hash"):
        import hashlib
        return hashlib.md5(sig_str.encode()).hexdigest()


def profiled_resolve_schema(self, schema: Dict[str, Any], api_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Profiled schema resolution"""
    with profiler.time("schema_resolution"):
        if "$ref" in schema:
            with profiler.time("ref_parsing"):
                ref_path = schema["$ref"]
                if ref_path.startswith("#/"):
                    parts = ref_path[2:].split("/")
                    resolved = api_spec
                    for part in parts:
                        resolved = resolved.get(part, {})
                    return resolved
        return schema


# Apply monkey patches
FunctionalAgent.execute = profiled_execute
FunctionalAgent._deduplicate_tests = profiled_deduplicate
FunctionalAgent._create_test_signature = profiled_create_signature
FunctionalAgent._resolve_schema_ref = profiled_resolve_schema


async def run_profiling():
    """Run profiling on FunctionalAgent"""

    # Sample OpenAPI spec
    api_spec = {
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
                }
            }
        }
    }

    # Create agent and task
    agent = FunctionalAgent()
    task = AgentTask(
        task_id="profile_test",
        spec_id=1,
        agent_type="functional-agent",
        enable_llm=False,
        parameters={'strategies': ['positive', 'negative', 'boundary']}
    )

    # Warm-up run
    await agent.execute(task, api_spec)
    profiler.timings.clear()

    # Profile run
    print("Running profiling...")
    start_time = time.perf_counter()
    result = await agent.execute(task, api_spec)
    total_time = (time.perf_counter() - start_time) * 1000

    # Generate report
    print("\n" + "="*80)
    print("PERFORMANCE BOTTLENECK ANALYSIS - FunctionalAgent")
    print("="*80)
    print(f"\nTotal execution time: {total_time:.2f}ms")
    print(f"Tests generated: {len(result.test_cases)}")
    print(f"Time per test: {total_time / len(result.test_cases):.2f}ms" if result.test_cases else "N/A")

    print("\n" + "-"*80)
    print("EXECUTION BREAKDOWN:")
    print("-"*80)

    metrics = profiler.get_metrics(total_time)

    # Calculate per-category totals
    strategy_time = sum(m.duration_ms for m in metrics if m.operation.startswith('strategy_'))
    dedup_time = sum(m.duration_ms for m in metrics if 'dedup' in m.operation or 'sig_' in m.operation)
    schema_time = sum(m.duration_ms for m in metrics if 'schema' in m.operation or 'ref_' in m.operation)

    print(f"\n{'Operation':<40} {'Time (ms)':<12} {'Calls':<8} {'%':<8}")
    print("-"*80)

    for metric in metrics[:15]:  # Top 15 operations
        print(f"{metric.operation:<40} {metric.duration_ms:>10.2f}ms {metric.call_count:>6} {metric.percentage:>6.1f}%")

    print("\n" + "-"*80)
    print("CATEGORY SUMMARY:")
    print("-"*80)
    print(f"Strategy execution:     {strategy_time:>10.2f}ms ({strategy_time/total_time*100:>5.1f}%)")
    print(f"Deduplication:          {dedup_time:>10.2f}ms ({dedup_time/total_time*100:>5.1f}%)")
    print(f"Schema resolution:      {schema_time:>10.2f}ms ({schema_time/total_time*100:>5.1f}%)")

    # Identify top bottlenecks
    print("\n" + "-"*80)
    print("TOP 3 BOTTLENECKS:")
    print("-"*80)

    top_3 = sorted(metrics, key=lambda m: m.duration_ms, reverse=True)[:3]
    for i, metric in enumerate(top_3, 1):
        avg_per_call = metric.duration_ms / metric.call_count if metric.call_count > 0 else 0
        print(f"\n{i}. {metric.operation}")
        print(f"   Total: {metric.duration_ms:.2f}ms ({metric.percentage:.1f}%)")
        print(f"   Calls: {metric.call_count}")
        print(f"   Avg per call: {avg_per_call:.2f}ms")

        # Root cause analysis
        if 'strategy_' in metric.operation:
            print(f"   ROOT CAUSE: Strategy execution overhead - each strategy re-processes endpoints")
        elif 'dedup' in metric.operation or 'sig_' in metric.operation:
            print(f"   ROOT CAUSE: MD5 hashing + JSON serialization for every test case")
        elif 'schema' in metric.operation:
            print(f"   ROOT CAUSE: Repeated $ref resolution without caching")
        elif 'data_service' in metric.operation:
            print(f"   ROOT CAUSE: Redundant DataGenerationService calls")

    # Optimization recommendations
    print("\n" + "="*80)
    print("OPTIMIZATION RECOMMENDATIONS:")
    print("="*80)

    recommendations = []

    if dedup_time > total_time * 0.3:
        recommendations.append({
            'priority': 'HIGH',
            'component': 'Deduplication',
            'issue': f'MD5 hashing takes {dedup_time:.0f}ms ({dedup_time/total_time*100:.1f}%)',
            'fix': 'Use lightweight tuple-based signatures instead of MD5',
            'estimated_impact': '50-70% reduction in dedup time'
        })

    if schema_time > total_time * 0.2:
        recommendations.append({
            'priority': 'HIGH',
            'component': 'Schema Resolution',
            'issue': f'Repeated $ref resolution takes {schema_time:.0f}ms',
            'fix': 'Implement schema resolution cache with @lru_cache',
            'estimated_impact': '80-90% reduction in schema resolution time'
        })

    if strategy_time > total_time * 0.4:
        recommendations.append({
            'priority': 'MEDIUM',
            'component': 'Strategy Execution',
            'issue': f'Strategy overhead is {strategy_time:.0f}ms ({strategy_time/total_time*100:.1f}%)',
            'fix': 'Optimize data service calls, batch endpoint processing',
            'estimated_impact': '20-30% reduction in strategy time'
        })

    for i, rec in enumerate(recommendations, 1):
        print(f"\n{i}. [{rec['priority']}] {rec['component']}")
        print(f"   Issue: {rec['issue']}")
        print(f"   Fix: {rec['fix']}")
        print(f"   Impact: {rec['estimated_impact']}")

    # Comparison with old architecture
    print("\n" + "="*80)
    print("COMPARISON WITH OLD ARCHITECTURE:")
    print("="*80)
    print(f"Old architecture: ~5.7ms per test (320 tests in 1,813ms)")
    print(f"New architecture: {total_time / len(result.test_cases):.1f}ms per test ({len(result.test_cases)} tests in {total_time:.0f}ms)")
    print(f"Slowdown factor: {(total_time / len(result.test_cases)) / 5.7:.1f}x")
    print(f"\nKey differences causing slowdown:")
    print("- Strategy pattern adds initialization overhead")
    print("- MD5-based deduplication vs simpler comparison")
    print("- DataGenerationService creates Faker instance per call")
    print("- $ref resolution not cached")

    print("\n" + "="*80)


if __name__ == "__main__":
    asyncio.run(run_profiling())
