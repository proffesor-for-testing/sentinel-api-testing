"""
Python vs Rust Agent Performance Benchmark

Comprehensive benchmarking tool to accurately measure performance differences
between Python and Rust agent implementations using the same API specification.

This tool addresses the false performance claim issue by providing:
1. Fair comparison using identical API specs and test scenarios
2. Statistical analysis with confidence intervals
3. Multiple iterations to account for variance
4. Detailed metrics per agent type
5. JSON report generation for documentation

Usage:
    pytest sentinel_backend/tests/benchmark/test_python_vs_rust_performance.py -v --benchmark

    # With custom parameters
    pytest sentinel_backend/tests/benchmark/test_python_vs_rust_performance.py \
        --iterations=20 --specs=5 --output=benchmark_results.json
"""

import asyncio
import json
import time
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import pytest
import numpy as np
import logging

logger = logging.getLogger(__name__)

# Import validation and graceful error handling
AGENTS_AVAILABLE = False
IMPORT_ERROR_MESSAGE = None

try:
    # Import both Python and Rust agent implementations
    from sentinel_backend.orchestration_service.agents.python_agents import (
        functional_positive_python,
        functional_negative_python,
        functional_stateful_python,
        security_auth_python,
        security_injection_python,
        performance_planner_python,
        data_mocking_python
    )

    # Rust agents (via HTTP to Rust core service)
    from sentinel_backend.orchestration_service.agents.rust_agents import (
        functional_positive_rust,
        functional_negative_rust,
        functional_stateful_rust,
        security_auth_rust,
        security_injection_rust,
        performance_planner_rust,
        data_mocking_rust
    )

    from sentinel_backend.orchestration_service.agent_performance_tracker import (
        PerformanceMetric,
        AgentPerformanceTracker
    )

    AGENTS_AVAILABLE = True
    logger.info("✅ Agent imports successful - benchmark ready to run")

except ImportError as e:
    IMPORT_ERROR_MESSAGE = f"""
    ❌ Agent Import Error: {str(e)}

    The benchmark tool requires agent wrapper modules:
    - sentinel_backend/orchestration_service/agents/python_agents.py
    - sentinel_backend/orchestration_service/agents/rust_agents.py

    These modules have been created. If you're still seeing this error:
    1. Verify Python path includes sentinel_backend/
    2. Check that agent classes exist in agents/ directory
    3. Run: python -c "from sentinel_backend.orchestration_service.agents.python_agents import functional_positive_python"

    Original error: {str(e)}
    """
    logger.error(IMPORT_ERROR_MESSAGE)


@dataclass
class BenchmarkResult:
    """Single benchmark execution result"""
    agent_type: str
    language: str  # "python" or "rust"
    execution_time_ms: float
    test_cases_generated: int
    success: bool
    spec_name: str
    iteration: int
    timestamp: datetime
    error: Optional[str] = None
    memory_mb: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            **asdict(self),
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class AgentComparison:
    """Comparison between Python and Rust for single agent"""
    agent_type: str
    python_avg_ms: float
    python_std_ms: float
    python_success_rate: float
    rust_avg_ms: float
    rust_std_ms: float
    rust_success_rate: float
    speedup_factor: float  # rust_time / python_time (>1 means Rust faster)
    statistical_significance: bool
    winner: str  # "rust", "python", or "tie"
    confidence_interval_95: Tuple[float, float]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            **asdict(self),
            "confidence_interval_95": list(self.confidence_interval_95)
        }


class PythonVsRustBenchmark:
    """
    Comprehensive benchmark comparing Python and Rust agent implementations.

    Provides accurate performance measurements to replace false claims in documentation.
    """

    AGENT_TYPES = [
        "Functional-Positive-Agent",
        "Functional-Negative-Agent",
        "Functional-Stateful-Agent",
        "Security-Auth-Agent",
        "Security-Injection-Agent",
        "Performance-Planner-Agent",
        "Data-Mocking-Agent"
    ]

    def __init__(self,
                 iterations: int = 10,
                 num_specs: int = 3,
                 output_file: Optional[str] = None):
        """
        Initialize benchmark.

        Args:
            iterations: Number of iterations per agent+spec combination
            num_specs: Number of different API specs to test
            output_file: Optional JSON file to save results
        """
        self.iterations = iterations
        self.num_specs = num_specs
        self.output_file = output_file

        self.results: List[BenchmarkResult] = []
        self.comparisons: List[AgentComparison] = []

        # Load test API specifications
        self.specs = self._load_test_specs()

    def _load_test_specs(self) -> List[Dict[str, Any]]:
        """Load API specifications for testing"""
        specs = []

        # 1. Petstore API (simple)
        petstore_path = Path(__file__).parent.parent.parent.parent / "petstore_api" / "petstore-openapi-spec.json"
        if petstore_path.exists():
            with open(petstore_path) as f:
                specs.append({
                    "name": "Petstore API",
                    "spec": json.load(f),
                    "complexity": "simple"
                })

        # 2. Generate synthetic complex API
        specs.append({
            "name": "Complex E-Commerce API",
            "spec": self._generate_complex_ecommerce_spec(),
            "complexity": "complex"
        })

        # 3. Generate synthetic microservice API
        specs.append({
            "name": "Microservice API Gateway",
            "spec": self._generate_microservice_spec(),
            "complexity": "medium"
        })

        return specs[:self.num_specs]

    def _generate_complex_ecommerce_spec(self) -> Dict[str, Any]:
        """Generate a complex e-commerce API spec"""
        return {
            "openapi": "3.1.0",
            "info": {"title": "E-Commerce API", "version": "1.0.0"},
            "paths": {
                "/api/v1/products": {
                    "get": {
                        "operationId": "list_products",
                        "parameters": [
                            {"name": "category", "in": "query", "schema": {"type": "string"}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer", "minimum": 0}}
                        ],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "post": {
                        "operationId": "create_product",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name", "price", "category"],
                                        "properties": {
                                            "name": {"type": "string", "minLength": 3, "maxLength": 100},
                                            "price": {"type": "number", "minimum": 0.01},
                                            "category": {"type": "string", "enum": ["electronics", "clothing", "food"]},
                                            "stock": {"type": "integer", "minimum": 0}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}}
                    }
                },
                "/api/v1/products/{id}": {
                    "get": {"operationId": "get_product", "responses": {"200": {"description": "Success"}}},
                    "put": {"operationId": "update_product", "responses": {"200": {"description": "Updated"}}},
                    "delete": {"operationId": "delete_product", "responses": {"204": {"description": "Deleted"}}}
                },
                "/api/v1/orders": {
                    "post": {"operationId": "create_order", "responses": {"201": {"description": "Created"}}}
                },
                "/api/v1/cart/{userId}": {
                    "get": {"operationId": "get_cart", "responses": {"200": {"description": "Success"}}},
                    "post": {"operationId": "add_to_cart", "responses": {"200": {"description": "Added"}}}
                }
            }
        }

    def _generate_microservice_spec(self) -> Dict[str, Any]:
        """Generate a microservice gateway API spec"""
        return {
            "openapi": "3.1.0",
            "info": {"title": "API Gateway", "version": "1.0.0"},
            "paths": {
                "/api/v1/users": {"get": {}, "post": {}},
                "/api/v1/users/{id}": {"get": {}, "put": {}, "delete": {}},
                "/api/v1/auth/login": {"post": {}},
                "/api/v1/auth/refresh": {"post": {}},
                "/api/v1/services": {"get": {}},
                "/api/v1/health": {"get": {}}
            }
        }

    async def benchmark_agent(self,
                             agent_type: str,
                             language: str,
                             spec: Dict[str, Any],
                             spec_name: str) -> BenchmarkResult:
        """
        Benchmark a single agent execution.

        Args:
            agent_type: Agent type to benchmark
            language: "python" or "rust"
            spec: OpenAPI specification
            spec_name: Name of the spec for reporting

        Returns:
            BenchmarkResult with execution metrics
        """
        start_time = time.time()
        success = False
        test_cases = 0
        error = None

        try:
            # Execute agent based on language
            if language == "python":
                result = await self._execute_python_agent(agent_type, spec)
            else:  # rust
                result = await self._execute_rust_agent(agent_type, spec)

            # Extract metrics
            test_cases = len(result.get("test_cases", []))
            success = result.get("success", False)

        except Exception as e:
            error = str(e)
            success = False

        execution_time = (time.time() - start_time) * 1000  # Convert to ms

        return BenchmarkResult(
            agent_type=agent_type,
            language=language,
            execution_time_ms=execution_time,
            test_cases_generated=test_cases,
            success=success,
            spec_name=spec_name,
            iteration=0,  # Will be set by caller
            timestamp=datetime.now(),
            error=error
        )

    async def _execute_python_agent(self, agent_type: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Python agent"""
        agent_map = {
            "Functional-Positive-Agent": functional_positive_python,
            "Functional-Negative-Agent": functional_negative_python,
            "Functional-Stateful-Agent": functional_stateful_python,
            "Security-Auth-Agent": security_auth_python,
            "Security-Injection-Agent": security_injection_python,
            "Performance-Planner-Agent": performance_planner_python,
            "Data-Mocking-Agent": data_mocking_python
        }

        agent_func = agent_map.get(agent_type)
        if not agent_func:
            raise ValueError(f"Unknown agent type: {agent_type}")

        return await agent_func(spec)

    async def _execute_rust_agent(self, agent_type: str, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Rust agent"""
        agent_map = {
            "Functional-Positive-Agent": functional_positive_rust,
            "Functional-Negative-Agent": functional_negative_rust,
            "Functional-Stateful-Agent": functional_stateful_rust,
            "Security-Auth-Agent": security_auth_rust,
            "Security-Injection-Agent": security_injection_rust,
            "Performance-Planner-Agent": performance_planner_rust,
            "Data-Mocking-Agent": data_mocking_rust
        }

        agent_func = agent_map.get(agent_type)
        if not agent_func:
            raise ValueError(f"Unknown agent type: {agent_type}")

        return await agent_func(spec)

    async def run_full_benchmark(self) -> Dict[str, Any]:
        """
        Run complete benchmark suite.

        Returns:
            Dict with comprehensive benchmark results
        """
        print(f"\n{'='*80}")
        print(f"Python vs Rust Agent Performance Benchmark")
        print(f"{'='*80}")
        print(f"Iterations per test: {self.iterations}")
        print(f"Number of API specs: {len(self.specs)}")
        print(f"Total tests: {len(self.AGENT_TYPES) * 2 * len(self.specs) * self.iterations}")
        print(f"{'='*80}\n")

        # Run benchmarks for each combination
        for agent_type in self.AGENT_TYPES:
            print(f"\nBenchmarking {agent_type}...")

            for spec_info in self.specs:
                spec = spec_info["spec"]
                spec_name = spec_info["name"]

                print(f"  Testing with {spec_name}...")

                # Python benchmarks
                python_results = []
                for i in range(self.iterations):
                    result = await self.benchmark_agent(agent_type, "python", spec, spec_name)
                    result.iteration = i + 1
                    python_results.append(result)
                    self.results.append(result)
                    print(f"    Python iteration {i+1}/{self.iterations}: {result.execution_time_ms:.2f}ms")

                # Rust benchmarks
                rust_results = []
                for i in range(self.iterations):
                    result = await self.benchmark_agent(agent_type, "rust", spec, spec_name)
                    result.iteration = i + 1
                    rust_results.append(result)
                    self.results.append(result)
                    print(f"    Rust iteration {i+1}/{self.iterations}: {result.execution_time_ms:.2f}ms")

        # Analyze results
        self._analyze_results()

        # Generate report
        report = self._generate_report()

        # Save to file if specified
        if self.output_file:
            self._save_report(report)

        return report

    def _analyze_results(self):
        """Perform statistical analysis on results"""
        # Group by agent type
        by_agent = {}
        for result in self.results:
            if result.agent_type not in by_agent:
                by_agent[result.agent_type] = {"python": [], "rust": []}
            by_agent[result.agent_type][result.language].append(result)

        # Compare Python vs Rust for each agent
        for agent_type, lang_results in by_agent.items():
            python = [r.execution_time_ms for r in lang_results["python"] if r.success]
            rust = [r.execution_time_ms for r in lang_results["rust"] if r.success]

            if not python or not rust:
                continue

            # Calculate statistics
            python_avg = statistics.mean(python)
            python_std = statistics.stdev(python) if len(python) > 1 else 0
            python_success = sum(1 for r in lang_results["python"] if r.success) / len(lang_results["python"])

            rust_avg = statistics.mean(rust)
            rust_std = statistics.stdev(rust) if len(rust) > 1 else 0
            rust_success = sum(1 for r in lang_results["rust"] if r.success) / len(lang_results["rust"])

            # Speedup factor (positive means Python faster, negative means Rust faster)
            speedup = python_avg / rust_avg

            # Statistical significance (t-test)
            is_significant = self._t_test(python, rust, alpha=0.05)

            # Determine winner
            if abs(speedup - 1.0) < 0.05:  # Within 5%
                winner = "tie"
            elif speedup > 1.0:
                winner = "rust"
            else:
                winner = "python"

            # Confidence interval
            ci = self._confidence_interval(python, rust)

            comparison = AgentComparison(
                agent_type=agent_type,
                python_avg_ms=python_avg,
                python_std_ms=python_std,
                python_success_rate=python_success,
                rust_avg_ms=rust_avg,
                rust_std_ms=rust_std,
                rust_success_rate=rust_success,
                speedup_factor=speedup,
                statistical_significance=is_significant,
                winner=winner,
                confidence_interval_95=ci
            )

            self.comparisons.append(comparison)

    def _t_test(self, sample1: List[float], sample2: List[float], alpha: float = 0.05) -> bool:
        """
        Perform two-sample t-test for statistical significance.

        Returns:
            True if difference is statistically significant
        """
        from scipy import stats

        try:
            t_stat, p_value = stats.ttest_ind(sample1, sample2)
            return p_value < alpha
        except:
            return False

    def _confidence_interval(self, sample1: List[float], sample2: List[float]) -> Tuple[float, float]:
        """Calculate 95% confidence interval for mean difference"""
        try:
            diff_mean = statistics.mean(sample1) - statistics.mean(sample2)
            diff_std = statistics.stdev([s1 - s2 for s1, s2 in zip(sample1, sample2)])
            margin = 1.96 * (diff_std / (len(sample1) ** 0.5))  # 95% CI
            return (diff_mean - margin, diff_mean + margin)
        except:
            return (0.0, 0.0)

    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive benchmark report"""
        # Overall statistics
        python_times = [r.execution_time_ms for r in self.results if r.language == "python" and r.success]
        rust_times = [r.execution_time_ms for r in self.results if r.language == "rust" and r.success]

        overall_speedup = statistics.mean(python_times) / statistics.mean(rust_times) if rust_times else 1.0

        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "iterations": self.iterations,
                "num_specs": self.num_specs,
                "total_tests": len(self.results)
            },
            "overall_summary": {
                "python_avg_ms": statistics.mean(python_times) if python_times else 0,
                "rust_avg_ms": statistics.mean(rust_times) if rust_times else 0,
                "overall_speedup": overall_speedup,
                "overall_speedup_description": f"Python is {overall_speedup:.2f}x faster" if overall_speedup > 1 else f"Rust is {1/overall_speedup:.2f}x faster",
                "python_success_rate": sum(1 for r in self.results if r.language == "python" and r.success) / sum(1 for r in self.results if r.language == "python"),
                "rust_success_rate": sum(1 for r in self.results if r.language == "rust" and r.success) / sum(1 for r in self.results if r.language == "rust")
            },
            "agent_comparisons": [c.to_dict() for c in self.comparisons],
            "raw_results": [r.to_dict() for r in self.results]
        }

        return report

    def _save_report(self, report: Dict[str, Any]):
        """Save report to JSON file"""
        output_path = Path(self.output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n✅ Benchmark report saved to: {output_path}")

    def print_summary(self, report: Dict[str, Any]):
        """Print human-readable summary"""
        print(f"\n{'='*80}")
        print("BENCHMARK SUMMARY")
        print(f"{'='*80}\n")

        summary = report["overall_summary"]
        print(f"Overall Results:")
        print(f"  Python Average: {summary['python_avg_ms']:.2f}ms")
        print(f"  Rust Average: {summary['rust_avg_ms']:.2f}ms")
        print(f"  Overall Speedup: {summary['overall_speedup_description']}")
        print(f"  Python Success Rate: {summary['python_success_rate']*100:.1f}%")
        print(f"  Rust Success Rate: {summary['rust_success_rate']*100:.1f}%")

        print(f"\n{'='*80}")
        print("PER-AGENT COMPARISON")
        print(f"{'='*80}\n")

        for comparison in report["agent_comparisons"]:
            print(f"\n{comparison['agent_type']}:")
            print(f"  Python: {comparison['python_avg_ms']:.2f}ms ± {comparison['python_std_ms']:.2f}ms")
            print(f"  Rust: {comparison['rust_avg_ms']:.2f}ms ± {comparison['rust_std_ms']:.2f}ms")
            print(f"  Speedup: {comparison['speedup_factor']:.2f}x")
            print(f"  Winner: {comparison['winner'].upper()}")
            print(f"  Statistical Significance: {'YES' if comparison['statistical_significance'] else 'NO'}")

        print(f"\n{'='*80}\n")


# Pytest fixtures and tests

@pytest.fixture
def benchmark():
    """Create benchmark instance"""
    return PythonVsRustBenchmark(iterations=5, num_specs=2)


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_full_benchmark(benchmark):
    """Run full benchmark suite"""
    # Validate imports before running
    if not AGENTS_AVAILABLE:
        pytest.skip(f"Agent imports failed: {IMPORT_ERROR_MESSAGE}")

    report = await benchmark.run_full_benchmark()
    benchmark.print_summary(report)

    # Assertions
    assert report["metadata"]["total_tests"] > 0
    assert "overall_summary" in report
    assert len(report["agent_comparisons"]) > 0


@pytest.mark.asyncio
@pytest.mark.benchmark
async def test_single_agent_benchmark():
    """Test single agent benchmark"""
    # Validate imports before running
    if not AGENTS_AVAILABLE:
        pytest.skip(f"Agent imports failed: {IMPORT_ERROR_MESSAGE}")

    benchmark = PythonVsRustBenchmark(iterations=3, num_specs=1)

    spec = benchmark.specs[0]["spec"]
    spec_name = benchmark.specs[0]["name"]

    # Test Python
    python_result = await benchmark.benchmark_agent(
        "Functional-Positive-Agent",
        "python",
        spec,
        spec_name
    )

    assert python_result.language == "python"
    assert python_result.execution_time_ms > 0

    # Test Rust
    rust_result = await benchmark.benchmark_agent(
        "Functional-Positive-Agent",
        "rust",
        spec,
        spec_name
    )

    assert rust_result.language == "rust"
    assert rust_result.execution_time_ms > 0

    print(f"\nPython: {python_result.execution_time_ms:.2f}ms")
    print(f"Rust: {rust_result.execution_time_ms:.2f}ms")
    print(f"Speedup: {python_result.execution_time_ms / rust_result.execution_time_ms:.2f}x")


if __name__ == "__main__":
    # Run benchmark from command line
    import sys

    # Validate imports before running
    if not AGENTS_AVAILABLE:
        print(IMPORT_ERROR_MESSAGE)
        sys.exit(1)

    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    output_file = sys.argv[2] if len(sys.argv) > 2 else "benchmark_results.json"

    print(f"✅ Agent imports successful")
    print(f"⚙️  Starting benchmark: {iterations} iterations, 3 specs")

    benchmark = PythonVsRustBenchmark(iterations=iterations, num_specs=3, output_file=output_file)

    loop = asyncio.get_event_loop()
    report = loop.run_until_complete(benchmark.run_full_benchmark())
    benchmark.print_summary(report)

    print(f"\n✅ Benchmark complete! Results saved to: {output_file}")
