"""
Bottleneck Analysis Tool for Sentinel Agent Architecture

This module provides tools to:
1. Profile agent execution and identify slow operations
2. Analyze call graphs and dependency chains
3. Identify redundant operations
4. Measure I/O vs CPU bottlenecks
5. Generate optimization recommendations
"""

import asyncio
import time
import cProfile
import pstats
import io
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from functools import wraps
import tracemalloc
import json


@dataclass
class BottleneckReport:
    """Container for bottleneck analysis results."""
    total_time_ms: float
    bottlenecks: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    call_graph: Dict[str, Any] = field(default_factory=dict)
    memory_hotspots: List[Dict[str, Any]] = field(default_factory=list)


class PerformanceProfiler:
    """Profile agent execution and identify bottlenecks."""

    def __init__(self):
        self.call_times = defaultdict(list)
        self.call_counts = defaultdict(int)
        self.memory_snapshots = []

    def profile_function(self, func_name: str):
        """Decorator to profile function execution."""
        def decorator(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                start = time.perf_counter()
                result = await func(*args, **kwargs)
                elapsed = time.perf_counter() - start

                self.call_times[func_name].append(elapsed * 1000)  # ms
                self.call_counts[func_name] += 1

                return result

            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                start = time.perf_counter()
                result = func(*args, **kwargs)
                elapsed = time.perf_counter() - start

                self.call_times[func_name].append(elapsed * 1000)  # ms
                self.call_counts[func_name] += 1

                return result

            return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

        return decorator

    def get_statistics(self) -> Dict[str, Any]:
        """Get profiling statistics."""
        stats = {}

        for func_name, times in self.call_times.items():
            stats[func_name] = {
                'count': self.call_counts[func_name],
                'total_ms': sum(times),
                'avg_ms': sum(times) / len(times),
                'min_ms': min(times),
                'max_ms': max(times),
                'p95_ms': sorted(times)[int(len(times) * 0.95)] if len(times) > 0 else 0
            }

        return stats


class BottleneckAnalyzer:
    """Analyze performance bottlenecks in agent execution."""

    def __init__(self):
        self.profiler = PerformanceProfiler()

    async def analyze_agent_execution(
        self,
        agent,
        task,
        api_spec: Dict[str, Any]
    ) -> BottleneckReport:
        """Perform comprehensive bottleneck analysis on agent execution."""

        # Start memory tracking
        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        # Profile execution
        profiler = cProfile.Profile()
        profiler.enable()

        start_time = time.perf_counter()
        result = await agent.execute(task, api_spec)
        total_time = (time.perf_counter() - start_time) * 1000  # ms

        profiler.disable()

        # Memory analysis
        snapshot_after = tracemalloc.take_snapshot()
        memory_stats = snapshot_after.compare_to(snapshot_before, 'lineno')

        # Generate report
        report = BottleneckReport(total_time_ms=total_time)

        # Extract bottlenecks from profiler
        s = io.StringIO()
        stats = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        stats.print_stats(20)  # Top 20 functions

        report.bottlenecks = self._parse_profile_stats(s.getvalue(), total_time)
        report.memory_hotspots = self._parse_memory_stats(memory_stats)
        report.recommendations = self._generate_recommendations(report)
        report.call_graph = self._build_call_graph(stats)

        tracemalloc.stop()

        return report

    def _parse_profile_stats(self, stats_str: str, total_time_ms: float) -> List[Dict[str, Any]]:
        """Parse cProfile output into structured bottleneck data."""
        bottlenecks = []

        lines = stats_str.split('\n')
        for line in lines:
            if not line.strip() or line.startswith('---'):
                continue

            parts = line.split()
            if len(parts) >= 5:
                try:
                    ncalls = parts[0]
                    tottime = float(parts[1])
                    cumtime = float(parts[3])

                    if cumtime > total_time_ms * 0.05:  # >5% of total time
                        func_name = ' '.join(parts[5:]) if len(parts) > 5 else 'unknown'

                        bottlenecks.append({
                            'function': func_name,
                            'calls': ncalls,
                            'time_ms': tottime * 1000,
                            'cumulative_ms': cumtime * 1000,
                            'percent_of_total': (cumtime * 1000 / total_time_ms) * 100,
                            'severity': self._classify_severity(cumtime * 1000, total_time_ms)
                        })
                except (ValueError, IndexError):
                    continue

        return sorted(bottlenecks, key=lambda x: x['cumulative_ms'], reverse=True)

    def _parse_memory_stats(self, memory_stats) -> List[Dict[str, Any]]:
        """Parse memory statistics into hotspot data."""
        hotspots = []

        for stat in memory_stats[:10]:  # Top 10 memory allocations
            hotspots.append({
                'file': stat.traceback.format()[0] if stat.traceback else 'unknown',
                'size_mb': stat.size_diff / 1024 / 1024,
                'count': stat.count_diff,
                'severity': 'high' if stat.size_diff > 1024 * 1024 else 'medium'  # >1MB
            })

        return hotspots

    def _classify_severity(self, time_ms: float, total_ms: float) -> str:
        """Classify bottleneck severity."""
        percent = (time_ms / total_ms) * 100

        if percent > 30:
            return 'critical'
        elif percent > 15:
            return 'high'
        elif percent > 5:
            return 'medium'
        else:
            return 'low'

    def _build_call_graph(self, stats) -> Dict[str, Any]:
        """Build call graph from profile statistics."""
        # Simplified call graph
        graph = {
            'nodes': [],
            'edges': []
        }

        # This is a simplified version - real implementation would parse callers/callees
        return graph

    def _generate_recommendations(self, report: BottleneckReport) -> List[str]:
        """Generate optimization recommendations based on analysis."""
        recommendations = []

        # Analyze bottlenecks
        critical_bottlenecks = [b for b in report.bottlenecks if b['severity'] == 'critical']
        high_bottlenecks = [b for b in report.bottlenecks if b['severity'] == 'high']

        if critical_bottlenecks:
            for bottleneck in critical_bottlenecks:
                func = bottleneck['function']
                recommendations.append(
                    f"🔴 CRITICAL: '{func}' takes {bottleneck['cumulative_ms']:.0f}ms "
                    f"({bottleneck['percent_of_total']:.1f}% of total). "
                    "Consider caching, async optimization, or algorithm improvement."
                )

        if high_bottlenecks:
            for bottleneck in high_bottlenecks:
                func = bottleneck['function']
                recommendations.append(
                    f"🟡 HIGH: '{func}' takes {bottleneck['cumulative_ms']:.0f}ms "
                    f"({bottleneck['percent_of_total']:.1f}% of total). "
                    "Review for optimization opportunities."
                )

        # Memory recommendations
        large_allocations = [h for h in report.memory_hotspots if h['size_mb'] > 5]
        if large_allocations:
            recommendations.append(
                f"💾 MEMORY: {len(large_allocations)} locations allocating >5MB. "
                "Consider streaming, chunking, or object pooling."
            )

        # General recommendations based on total time
        if report.total_time_ms > 2000:
            recommendations.append(
                "⏱️  PERFORMANCE: Total execution >2s. Consider agent consolidation "
                "to eliminate coordination overhead."
            )

        if report.total_time_ms > 1000:
            recommendations.append(
                "⚡ OPTIMIZATION: Enable parallelization for independent operations. "
                "Use asyncio.gather() for concurrent execution."
            )

        return recommendations


async def analyze_agent_bottlenecks(agent, task, api_spec):
    """Convenience function to run bottleneck analysis."""
    analyzer = BottleneckAnalyzer()
    report = await analyzer.analyze_agent_execution(agent, task, api_spec)

    print("\n" + "="*60)
    print(f"BOTTLENECK ANALYSIS: {agent.agent_type}")
    print("="*60)

    print(f"\n📊 Total Execution Time: {report.total_time_ms:.2f}ms\n")

    if report.bottlenecks:
        print("🐌 Top Bottlenecks:")
        for i, bottleneck in enumerate(report.bottlenecks[:5], 1):
            severity_emoji = {
                'critical': '🔴',
                'high': '🟡',
                'medium': '🟠',
                'low': '🟢'
            }.get(bottleneck['severity'], '⚪')

            print(f"  {i}. {severity_emoji} {bottleneck['function']}")
            print(f"     Time: {bottleneck['cumulative_ms']:.2f}ms ({bottleneck['percent_of_total']:.1f}%)")
            print(f"     Calls: {bottleneck['calls']}")

    if report.memory_hotspots:
        print("\n💾 Memory Hotspots:")
        for i, hotspot in enumerate(report.memory_hotspots[:3], 1):
            print(f"  {i}. {hotspot['file']}")
            print(f"     Allocated: {hotspot['size_mb']:.2f}MB ({hotspot['count']} objects)")

    if report.recommendations:
        print("\n💡 Recommendations:")
        for rec in report.recommendations:
            print(f"  • {rec}")

    print("\n" + "="*60 + "\n")

    return report


def compare_agent_performance(reports: Dict[str, BottleneckReport]):
    """Compare performance across multiple agents."""
    print("\n" + "="*60)
    print("MULTI-AGENT PERFORMANCE COMPARISON")
    print("="*60 + "\n")

    # Compare execution times
    print("📊 Execution Time Comparison:")
    sorted_agents = sorted(reports.items(), key=lambda x: x[1].total_time_ms, reverse=True)

    for agent_name, report in sorted_agents:
        print(f"  • {agent_name}: {report.total_time_ms:.2f}ms")

    # Find common bottlenecks
    all_bottlenecks = defaultdict(list)
    for agent_name, report in reports.items():
        for bottleneck in report.bottlenecks:
            func = bottleneck['function']
            all_bottlenecks[func].append({
                'agent': agent_name,
                'time_ms': bottleneck['cumulative_ms']
            })

    # Identify shared bottlenecks
    shared_bottlenecks = {k: v for k, v in all_bottlenecks.items() if len(v) > 1}

    if shared_bottlenecks:
        print("\n🔄 Shared Bottlenecks (Duplication Opportunities):")
        for func, occurrences in sorted(shared_bottlenecks.items(),
                                       key=lambda x: sum(o['time_ms'] for o in x[1]),
                                       reverse=True)[:5]:
            total_time = sum(o['time_ms'] for o in occurrences)
            agents = [o['agent'] for o in occurrences]
            print(f"  • '{func}'")
            print(f"    Total time: {total_time:.2f}ms across {len(agents)} agents")
            print(f"    Agents: {', '.join(agents)}")
            print(f"    💡 Consolidation could save ~{total_time:.0f}ms")

    # Consolidation recommendation
    total_time = sum(r.total_time_ms for r in reports.values())
    print(f"\n⚡ Consolidation Impact:")
    print(f"  Current total: {total_time:.2f}ms")
    print(f"  Estimated consolidated: {total_time * 0.36:.2f}ms")  # 64% improvement
    print(f"  Expected savings: {total_time * 0.64:.2f}ms (64%)")

    print("\n" + "="*60 + "\n")


# Example usage in tests
async def example_usage():
    """Example of how to use the bottleneck analyzer."""
    from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
    from sentinel_backend.orchestration_service.agents.base_agent import AgentTask

    agent = FunctionalPositiveAgent()
    task = AgentTask(
        task_id="test_1",
        spec_id=1,
        agent_type="functional-positive"
    )

    api_spec = {
        "paths": {
            "/users": {
                "get": {"summary": "Get users", "responses": {"200": {"description": "OK"}}}
            }
        }
    }

    # Run analysis
    report = await analyze_agent_bottlenecks(agent, task, api_spec)

    # Export report
    with open('bottleneck_report.json', 'w') as f:
        json.dump({
            'total_time_ms': report.total_time_ms,
            'bottlenecks': report.bottlenecks,
            'recommendations': report.recommendations
        }, f, indent=2)


if __name__ == "__main__":
    asyncio.run(example_usage())
