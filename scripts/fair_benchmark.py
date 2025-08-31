#!/usr/bin/env python3
"""
Fair Performance Benchmark Script for Rust vs Python Agents
Uses the same Petstore specification and testing methodology for both
"""

import json
import time
import statistics
import requests
from typing import Dict, List, Tuple
from datetime import datetime
import asyncio
import aiohttp
from tabulate import tabulate
import sys
import os
import yaml

# Add parent directory to path for Python agents
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sentinel_backend'))

# Import Python agents
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult
from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.orchestration_service.agents.functional_stateful_agent import FunctionalStatefulAgent
from sentinel_backend.orchestration_service.agents.security_auth_agent import SecurityAuthAgent
from sentinel_backend.orchestration_service.agents.security_injection_agent import SecurityInjectionAgent
from sentinel_backend.orchestration_service.agents.performance_planner_agent import PerformancePlannerAgent
from sentinel_backend.orchestration_service.agents.data_mocking_agent import DataMockingAgent

# Configuration
ITERATIONS = 10  # Minimum 5 as requested, using 10 for better statistics
WARMUP_ITERATIONS = 2
RUST_SERVICE_URL = "http://localhost:8088"

# Load Petstore specification
def load_petstore_spec():
    """Load the Petstore specification"""
    yaml_path = "/Users/profa/coding/Agents for API testing/sample-petstore.yaml"
    
    try:
        with open(yaml_path, 'r') as f:
            spec = yaml.safe_load(f)
        print(f"✅ Loaded Petstore spec: {spec['info']['title']} v{spec['info']['version']}")
        print(f"   Endpoints: {len(spec.get('paths', {}))}")
        print(f"   Schemas: {len(spec.get('components', {}).get('schemas', {}))}")
        return spec
    except Exception as e:
        print(f"❌ Error loading spec: {e}")
        return None

# Agent types to benchmark
AGENTS_TO_BENCHMARK = [
    "Functional-Positive-Agent",
    "Functional-Negative-Agent", 
    "Functional-Stateful-Agent",
    "Security-Auth-Agent",
    "Security-Injection-Agent",
    "Performance-Planner-Agent",
    "Data-Mocking-Agent"
]

class FairBenchmark:
    def __init__(self):
        self.results = {}
        self.api_spec = load_petstore_spec()
        if not self.api_spec:
            raise Exception("Failed to load Petstore specification")
        
        # Initialize Python agents
        self.python_agents = {
            "Functional-Positive-Agent": FunctionalPositiveAgent(),
            "Functional-Negative-Agent": FunctionalNegativeAgent(),
            "Functional-Stateful-Agent": FunctionalStatefulAgent(),
            "Security-Auth-Agent": SecurityAuthAgent(),
            "Security-Injection-Agent": SecurityInjectionAgent(),
            "Performance-Planner-Agent": PerformancePlannerAgent(),
            "Data-Mocking-Agent": DataMockingAgent()
        }
    
    async def benchmark_rust_agent(self, agent_type: str) -> Dict:
        """Benchmark a Rust agent with Petstore spec"""
        times = []
        test_counts = []
        
        async with aiohttp.ClientSession() as session:
            # Warmup runs
            for _ in range(WARMUP_ITERATIONS):
                await self._execute_rust_agent(session, agent_type)
            
            # Actual benchmark runs
            for i in range(ITERATIONS):
                start_time = time.perf_counter()
                result = await self._execute_rust_agent(session, agent_type)
                end_time = time.perf_counter()
                
                execution_time = (end_time - start_time) * 1000  # Convert to ms
                
                if result and result.get('result'):
                    times.append(execution_time)
                    test_count = len(result['result'].get('test_cases', []))
                    test_counts.append(test_count)
                    print(f"    Rust Run {i+1}: {execution_time:.2f}ms ({test_count} tests)")
                else:
                    print(f"    Rust Run {i+1}: FAILED")
        
        return self._calculate_stats(times, test_counts)
    
    async def _execute_rust_agent(self, session: aiohttp.ClientSession, agent_type: str):
        """Execute a single Rust agent request"""
        url = f"{RUST_SERVICE_URL}/swarm/orchestrate"
        
        # Map agent names for Rust
        rust_agent_type = "data-mocking" if agent_type == "Data-Mocking-Agent" else agent_type
        
        payload = {
            "task": {
                "task_id": f"bench-{agent_type}-{time.time()}",
                "spec_id": "petstore",
                "agent_type": rust_agent_type,
                "parameters": {},
                "target_environment": None
            },
            "api_spec": self.api_spec
        }
        
        try:
            async with session.post(url, json=payload, timeout=30) as response:
                if response.status == 200:
                    return await response.json()
                return None
        except Exception as e:
            print(f"    Rust error: {str(e)[:50]}")
            return None
    
    async def benchmark_python_agent(self, agent_type: str) -> Dict:
        """Benchmark a Python agent with Petstore spec"""
        times = []
        test_counts = []
        
        agent = self.python_agents[agent_type]
        
        # Warmup runs
        for _ in range(WARMUP_ITERATIONS):
            task = AgentTask(
                task_id=f"warmup-{time.time()}",
                spec_id=1,
                agent_type=agent_type,
                parameters={},
                target_environment=None
            )
            try:
                await agent.execute(task, self.api_spec)
            except:
                pass
        
        # Actual benchmark runs
        for i in range(ITERATIONS):
            task = AgentTask(
                task_id=f"bench-{i}-{time.time()}",
                spec_id=1,
                agent_type=agent_type,
                parameters={},
                target_environment=None
            )
            
            try:
                start_time = time.perf_counter()
                result = await agent.execute(task, self.api_spec)
                end_time = time.perf_counter()
                
                execution_time = (end_time - start_time) * 1000  # Convert to ms
                times.append(execution_time)
                
                test_count = len(result.test_cases) if hasattr(result, 'test_cases') and result.test_cases else 0
                test_counts.append(test_count)
                
                status = "✓" if result.status == "success" else "✗"
                print(f"    Python Run {i+1}: {execution_time:.2f}ms ({test_count} tests) {status}")
            except Exception as e:
                print(f"    Python Run {i+1}: FAILED - {str(e)[:50]}")
        
        return self._calculate_stats(times, test_counts)
    
    def _calculate_stats(self, times: List[float], test_counts: List[int]) -> Dict:
        """Calculate statistics from benchmark runs"""
        if not times:
            return {
                "runs": 0,
                "mean": 0,
                "median": 0,
                "std": 0,
                "min": 0,
                "max": 0,
                "avg_tests": 0
            }
        
        return {
            "runs": len(times),
            "mean": statistics.mean(times),
            "median": statistics.median(times),
            "std": statistics.stdev(times) if len(times) > 1 else 0,
            "min": min(times),
            "max": max(times),
            "avg_tests": statistics.mean(test_counts) if test_counts else 0
        }
    
    async def run_comparison(self):
        """Run complete comparison benchmark"""
        print("\n" + "="*80)
        print("FAIR PERFORMANCE COMPARISON - RUST vs PYTHON AGENTS")
        print("="*80)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Specification: Petstore API")
        print(f"Iterations: {ITERATIONS} (with {WARMUP_ITERATIONS} warmup)")
        print("="*80 + "\n")
        
        # Check services
        print("Checking service availability...")
        rust_available = await self._check_rust_health()
        print(f"  Rust service: {'✅ Available' if rust_available else '❌ Not available'}")
        print(f"  Python agents: ✅ Available (direct execution)")
        print()
        
        # Benchmark each agent type
        for agent_type in AGENTS_TO_BENCHMARK:
            print(f"\n{'='*60}")
            print(f"Benchmarking: {agent_type}")
            print('='*60)
            
            # Rust benchmark
            print("\n  🦀 Rust Agent:")
            rust_stats = {}
            if rust_available:
                rust_stats = await self.benchmark_rust_agent(agent_type)
                if rust_stats['runs'] > 0:
                    print(f"    Summary: Mean={rust_stats['mean']:.2f}ms, Median={rust_stats['median']:.2f}ms, Tests={rust_stats['avg_tests']:.0f}")
            else:
                print("    Skipped (service not available)")
            
            # Python benchmark
            print("\n  🐍 Python Agent:")
            python_stats = await self.benchmark_python_agent(agent_type)
            if python_stats['runs'] > 0:
                print(f"    Summary: Mean={python_stats['mean']:.2f}ms, Median={python_stats['median']:.2f}ms, Tests={python_stats['avg_tests']:.0f}")
            
            # Store results
            self.results[agent_type] = {
                "rust": rust_stats,
                "python": python_stats
            }
            
            # Compare if both have data
            if rust_stats.get('runs', 0) > 0 and python_stats.get('runs', 0) > 0:
                speedup = rust_stats['mean'] / python_stats['mean']
                faster = "Python" if speedup > 1 else "Rust"
                factor = max(speedup, 1/speedup)
                print(f"\n  ⚡ {faster} is {factor:.2f}x faster")
    
    async def _check_rust_health(self) -> bool:
        """Check if Rust service is available"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{RUST_SERVICE_URL}/health", timeout=5) as response:
                    return response.status == 200
        except:
            return False
    
    def print_final_summary(self):
        """Print final comparison summary"""
        print("\n" + "="*80)
        print("FINAL COMPARISON SUMMARY")
        print("="*80)
        
        # Prepare comparison table
        table_data = []
        headers = ["Agent", "Python Mean", "Python Median", "Rust Mean", "Rust Median", "Winner", "Factor"]
        
        for agent_type in AGENTS_TO_BENCHMARK:
            if agent_type in self.results:
                rust_stats = self.results[agent_type]["rust"]
                python_stats = self.results[agent_type]["python"]
                
                if rust_stats.get('runs', 0) > 0 and python_stats.get('runs', 0) > 0:
                    # Determine winner
                    if python_stats['mean'] < rust_stats['mean']:
                        winner = "🐍 Python"
                        factor = f"{rust_stats['mean']/python_stats['mean']:.2f}x"
                    else:
                        winner = "🦀 Rust"
                        factor = f"{python_stats['mean']/rust_stats['mean']:.2f}x"
                else:
                    winner = "N/A"
                    factor = "N/A"
                
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    f"{python_stats.get('mean', 0):.2f}ms" if python_stats.get('runs', 0) else "N/A",
                    f"{python_stats.get('median', 0):.2f}ms" if python_stats.get('runs', 0) else "N/A",
                    f"{rust_stats.get('mean', 0):.2f}ms" if rust_stats.get('runs', 0) else "N/A",
                    f"{rust_stats.get('median', 0):.2f}ms" if rust_stats.get('runs', 0) else "N/A",
                    winner,
                    factor
                ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Calculate overall statistics
        print("\n" + "="*80)
        print("STATISTICAL ANALYSIS")
        print("="*80)
        
        python_means = []
        rust_means = []
        
        for agent_type in self.results:
            if self.results[agent_type]["python"].get('runs', 0) > 0:
                python_means.append(self.results[agent_type]["python"]["mean"])
            if self.results[agent_type]["rust"].get('runs', 0) > 0:
                rust_means.append(self.results[agent_type]["rust"]["mean"])
        
        if python_means and rust_means:
            print(f"\n📊 Overall Performance:")
            print(f"  Python Average: {statistics.mean(python_means):.2f}ms")
            print(f"  Rust Average: {statistics.mean(rust_means):.2f}ms")
            
            overall_winner = "Python" if statistics.mean(python_means) < statistics.mean(rust_means) else "Rust"
            overall_factor = max(
                statistics.mean(rust_means) / statistics.mean(python_means),
                statistics.mean(python_means) / statistics.mean(rust_means)
            )
            print(f"\n🏆 Overall Winner: {overall_winner} ({overall_factor:.2f}x faster on average)")
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save benchmark results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fair_benchmark_results_{timestamp}.json"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "specification": "Petstore API",
            "iterations": ITERATIONS,
            "warmup_iterations": WARMUP_ITERATIONS,
            "results": self.results
        }
        
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")

async def main():
    # Suppress warnings
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    
    benchmark = FairBenchmark()
    await benchmark.run_comparison()
    benchmark.print_final_summary()

if __name__ == "__main__":
    asyncio.run(main())