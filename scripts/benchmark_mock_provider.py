#!/usr/bin/env python3
"""
Benchmark Mock LLM Provider for baseline comparison

This script runs benchmarks using the Mock provider to establish
a baseline for comparing with Anthropic and Ollama.
"""

import os
import sys
import json
import time
import asyncio
import statistics
from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime
import httpx

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent / "sentinel_backend"))


class MockProviderBenchmark:
    """Benchmark Mock provider with Sentinel agents"""
    
    def __init__(self, iterations: int = 10, warmup: int = 2):
        self.iterations = iterations
        self.warmup = warmup
        self.results = {}
        self.api_base = "http://localhost:8002"  # Orchestration service
        
        # Test agents to benchmark
        self.test_agents = [
            "Functional-Positive-Agent",
            "Functional-Negative-Agent",
            "Security-Auth-Agent",
            "Security-Injection-Agent",
            "Data-Mocking-Agent"
        ]
        
        # Test spec ID (PetStore API)
        self.spec_id = 6
    
    def configure_mock_provider(self):
        """Configure system to use Mock provider"""
        env_path = Path(__file__).parent.parent / "sentinel_backend" / ".env"
        
        # Read existing environment
        env_vars = {}
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    if '=' in line and not line.startswith('#'):
                        key, value = line.strip().split('=', 1)
                        env_vars[key] = value
        
        # Update to use Mock provider
        env_vars['SENTINEL_APP_LLM_PROVIDER'] = 'mock'
        env_vars['SENTINEL_APP_LLM_MODEL'] = 'mock-instant'
        
        # Write back
        with open(env_path, 'w') as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        print("✅ Configured to use Mock LLM Provider")
    
    async def benchmark_agent(self, agent: str) -> Dict[str, Any]:
        """Benchmark a specific agent with Mock provider"""
        times = []
        test_counts = []
        errors = 0
        
        print(f"  Testing {agent}...")
        
        # Run iterations
        for i in range(self.iterations + self.warmup):
            try:
                start_time = time.time()
                
                # Make request to orchestration service
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        f"{self.api_base}/generate-tests",
                        json={
                            "spec_id": self.spec_id,
                            "agent_types": [agent],
                            "parameters": {}
                        }
                    )
                    
                    elapsed = (time.time() - start_time) * 1000  # Convert to ms
                    
                    if response.status_code == 200:
                        result = response.json()
                        agent_results = result.get("agent_results", [])
                        
                        if agent_results:
                            test_count = agent_results[0].get("test_cases_generated", 0)
                            
                            # Skip warmup runs
                            if i >= self.warmup:
                                times.append(elapsed)
                                test_counts.append(test_count)
                                print(f"    Round {i-self.warmup+1}/{self.iterations}: ✓ {elapsed:.0f}ms, {test_count} tests")
                            else:
                                print(f"    Warmup {i+1}/{self.warmup}: {elapsed:.0f}ms")
                    else:
                        errors += 1
                        print(f"    Round {i-self.warmup+1}: ✗ HTTP {response.status_code}")
                        
            except Exception as e:
                errors += 1
                print(f"    Round {i-self.warmup+1}: ✗ Error: {str(e)}")
                continue
            
            # Small delay between requests
            await asyncio.sleep(0.1)
        
        # Calculate statistics
        if times:
            return {
                "mean": statistics.mean(times),
                "median": statistics.median(times),
                "min": min(times),
                "max": max(times),
                "std": statistics.stdev(times) if len(times) > 1 else 0,
                "percentile_95": sorted(times)[int(len(times) * 0.95)] if len(times) > 1 else max(times),
                "runs": len(times),
                "errors": errors,
                "avg_tests": statistics.mean(test_counts) if test_counts else 0
            }
        else:
            return {"mean": 0, "median": 0, "min": 0, "max": 0, "std": 0, 
                   "percentile_95": 0, "runs": 0, "errors": errors, "avg_tests": 0}
    
    async def run_benchmarks(self):
        """Run complete benchmark suite"""
        print("\n" + "="*60)
        print("MOCK LLM PROVIDER BENCHMARK (10 ROUNDS)")
        print("="*60)
        
        # Configure to use Mock provider
        self.configure_mock_provider()
        
        print(f"\n📊 Configuration:")
        print(f"   Provider: Mock (instant responses)")
        print(f"   Iterations: {self.iterations} (+ {self.warmup} warmup)")
        print(f"   Agents: {len(self.test_agents)}")
        
        # Note: Service restart needed
        print("\n⚠️  Note: Restart orchestration service to apply Mock provider config")
        print("   Waiting 3 seconds for any config reload...")
        await asyncio.sleep(3)
        
        # Initialize results structure
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "provider": "mock",
            "configuration": {
                "iterations": self.iterations,
                "warmup": self.warmup,
                "agents": self.test_agents,
                "spec_id": self.spec_id
            },
            "agent_results": {},
            "summary": {}
        }
        
        # Run benchmarks for each agent
        total_start = time.time()
        
        for agent in self.test_agents:
            print(f"\n📊 Benchmarking {agent}:")
            metrics = await self.benchmark_agent(agent)
            self.results["agent_results"][agent] = metrics
            
            if metrics["runs"] > 0:
                print(f"  ✅ Summary: {metrics['mean']:.0f}ms mean, {metrics['median']:.0f}ms median")
        
        total_time = time.time() - total_start
        
        # Generate summary
        self._generate_summary()
        self.results["summary"]["total_benchmark_time"] = total_time
        
        # Save results
        self._save_results()
        
        # Print summary
        self._print_summary()
    
    def _generate_summary(self):
        """Generate summary statistics"""
        summary = {"overall_stats": {}, "by_agent": {}}
        
        # Collect all times
        all_times = []
        for agent, metrics in self.results["agent_results"].items():
            if metrics["runs"] > 0:
                all_times.append(metrics["mean"])
                summary["by_agent"][agent] = {
                    "mean_ms": metrics["mean"],
                    "median_ms": metrics["median"]
                }
        
        # Overall statistics
        if all_times:
            summary["overall_stats"] = {
                "mean_response_time_ms": statistics.mean(all_times),
                "median_response_time_ms": statistics.median(all_times),
                "mean_response_time_seconds": statistics.mean(all_times) / 1000
            }
        
        self.results["summary"] = summary
    
    def _save_results(self):
        """Save benchmark results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mock_provider_benchmark_{timestamp}.json"
        filepath = Path(__file__).parent / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Results saved to: {filepath}")
    
    def _print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY - MOCK PROVIDER")
        print("="*60)
        
        summary = self.results.get("summary", {})
        
        if not summary.get("overall_stats"):
            print("No results collected")
            return
        
        # Overall performance
        overall = summary["overall_stats"]
        print(f"\n📊 Mock Provider Performance (Baseline):")
        print(f"   Mean response time: {overall['mean_response_time_ms']:.0f}ms")
        print(f"   Median response time: {overall['median_response_time_ms']:.0f}ms")
        
        # Agent-specific results
        print(f"\n📈 Results by Agent:")
        print("-" * 40)
        for agent in self.test_agents:
            if agent in summary["by_agent"]:
                stats = summary["by_agent"][agent]
                agent_name = agent.replace("-Agent", "")[:28]
                print(f"{agent_name:<30} {stats['mean_ms']:>8.0f}ms")


async def main():
    benchmark = MockProviderBenchmark(iterations=10, warmup=2)
    await benchmark.run_benchmarks()


if __name__ == "__main__":
    asyncio.run(main())