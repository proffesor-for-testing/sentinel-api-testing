#!/usr/bin/env python3
"""
Benchmark Anthropic API for Sentinel AI Agents

This script runs comprehensive benchmarks of Anthropic's Claude API
to compare with Ollama and Mock providers.
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


class AnthropicBenchmark:
    """Benchmark Anthropic API with Sentinel agents"""
    
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
    
    def check_orchestration_service(self) -> bool:
        """Check if orchestration service is running"""
        try:
            response = httpx.get(f"{self.api_base}/", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def check_anthropic_config(self) -> bool:
        """Check if Anthropic is configured"""
        env_path = Path(__file__).parent.parent / "sentinel_backend" / ".env"
        if env_path.exists():
            with open(env_path, 'r') as f:
                content = f.read()
                return "SENTINEL_APP_ANTHROPIC_API_KEY" in content
        return False
    
    def configure_anthropic(self):
        """Configure system to use Anthropic"""
        env_path = Path(__file__).parent.parent / "sentinel_backend" / ".env"
        
        # Read existing environment
        env_vars = {}
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    if '=' in line and not line.startswith('#'):
                        key, value = line.strip().split('=', 1)
                        env_vars[key] = value
        
        # Update to use Anthropic
        env_vars['SENTINEL_APP_LLM_PROVIDER'] = 'anthropic'
        env_vars['SENTINEL_APP_LLM_MODEL'] = 'claude-sonnet-4-20250514'  # Claude Sonnet 4
        
        # Write back
        with open(env_path, 'w') as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        print("✅ Configured to use Anthropic Claude API")
    
    async def benchmark_agent(self, agent: str) -> Dict[str, Any]:
        """Benchmark a specific agent with Anthropic"""
        times = []
        test_counts = []
        errors = 0
        
        print(f"  Testing {agent}...")
        
        # Run iterations
        for i in range(self.iterations + self.warmup):
            try:
                start_time = time.time()
                
                # Make request to orchestration service
                async with httpx.AsyncClient(timeout=60.0) as client:
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
            await asyncio.sleep(0.5)
        
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
                "avg_tests": statistics.mean(test_counts) if test_counts else 0,
                "total_tests": sum(test_counts)
            }
        else:
            return {
                "mean": 0,
                "median": 0,
                "min": 0,
                "max": 0,
                "std": 0,
                "percentile_95": 0,
                "runs": 0,
                "errors": errors,
                "avg_tests": 0,
                "total_tests": 0
            }
    
    async def run_benchmarks(self):
        """Run complete benchmark suite"""
        print("\n" + "="*60)
        print("ANTHROPIC CLAUDE API BENCHMARK (10 ROUNDS)")
        print("="*60)
        
        # Check orchestration service
        if not self.check_orchestration_service():
            print("❌ Orchestration service is not running")
            print("   Please start it with: cd sentinel_backend/orchestration_service && poetry run uvicorn main:app --reload --port 8002")
            return
        
        print("✅ Orchestration service is running")
        
        # Check Anthropic configuration
        if not self.check_anthropic_config():
            print("❌ Anthropic API key not configured")
            print("   Please set SENTINEL_APP_ANTHROPIC_API_KEY in .env file")
            return
        
        # Configure to use Anthropic
        self.configure_anthropic()
        
        print(f"\n📊 Configuration:")
        print(f"   Provider: Anthropic")
        print(f"   Model: claude-sonnet-4-20250514 (Claude Sonnet 4)")
        print(f"   Iterations: {self.iterations} (+ {self.warmup} warmup)")
        print(f"   Agents: {len(self.test_agents)}")
        
        # Initialize results structure
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "provider": "anthropic",
            "model": "claude-sonnet-4-20250514",
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
                print(f"  ✅ Summary: {metrics['mean']:.0f}ms mean, {metrics['median']:.0f}ms median, {metrics['avg_tests']:.1f} tests/run")
        
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
        summary = {
            "overall_stats": {},
            "by_agent": {},
            "comparison": {}
        }
        
        # Collect all times
        all_times = []
        for agent, metrics in self.results["agent_results"].items():
            if metrics["runs"] > 0:
                all_times.append(metrics["mean"])
                summary["by_agent"][agent] = {
                    "mean_ms": metrics["mean"],
                    "median_ms": metrics["median"],
                    "min_ms": metrics["min"],
                    "max_ms": metrics["max"],
                    "test_count": metrics["avg_tests"]
                }
        
        # Overall statistics
        if all_times:
            summary["overall_stats"] = {
                "mean_response_time_ms": statistics.mean(all_times),
                "median_response_time_ms": statistics.median(all_times),
                "min_response_time_ms": min(all_times),
                "max_response_time_ms": max(all_times),
                "mean_response_time_seconds": statistics.mean(all_times) / 1000
            }
        
        # Add comparison with Ollama and Mock
        summary["comparison"] = {
            "anthropic_mean_seconds": summary["overall_stats"].get("mean_response_time_seconds", 0),
            "ollama_mean_seconds": 15,  # From previous benchmarks
            "mock_mean_seconds": 0.05,  # From previous benchmarks
            "anthropic_vs_ollama_speedup": 15 / (summary["overall_stats"].get("mean_response_time_seconds", 1) if summary["overall_stats"].get("mean_response_time_seconds", 0) > 0 else 1),
            "anthropic_vs_mock_slowdown": summary["overall_stats"].get("mean_response_time_seconds", 0) / 0.05
        }
        
        self.results["summary"] = summary
    
    def _save_results(self):
        """Save benchmark results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"anthropic_benchmark_results_{timestamp}.json"
        filepath = Path(__file__).parent / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Results saved to: {filepath}")
    
    def _print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY - ANTHROPIC CLAUDE API")
        print("="*60)
        
        summary = self.results.get("summary", {})
        
        if not summary.get("overall_stats"):
            print("No results collected")
            return
        
        # Overall performance
        overall = summary["overall_stats"]
        print(f"\n📊 Overall Performance:")
        print(f"   Mean response time: {overall['mean_response_time_ms']:.0f}ms ({overall['mean_response_time_seconds']:.2f}s)")
        print(f"   Median response time: {overall['median_response_time_ms']:.0f}ms")
        print(f"   Range: {overall['min_response_time_ms']:.0f}ms - {overall['max_response_time_ms']:.0f}ms")
        
        # Agent-specific results
        print(f"\n📈 Results by Agent:")
        print("-" * 50)
        print(f"{'Agent':<30} {'Mean':<10} {'Median':<10} {'Tests'}")
        print("-" * 50)
        
        for agent in self.test_agents:
            if agent in summary["by_agent"]:
                stats = summary["by_agent"][agent]
                agent_name = agent.replace("-Agent", "")[:28]
                print(f"{agent_name:<30} {stats['mean_ms']:>8.0f}ms {stats['median_ms']:>8.0f}ms {stats['test_count']:>6.1f}")
        
        # Provider comparison
        comparison = summary["comparison"]
        print(f"\n🏆 Provider Comparison:")
        print(f"   Anthropic: {comparison['anthropic_mean_seconds']:.2f}s")
        print(f"   Ollama: {comparison['ollama_mean_seconds']:.1f}s")
        print(f"   Mock: {comparison['mock_mean_seconds']:.3f}s")
        
        if comparison.get("anthropic_vs_ollama_speedup"):
            print(f"\n   Anthropic is {comparison['anthropic_vs_ollama_speedup']:.1f}x faster than Ollama")
            print(f"   Anthropic is {comparison['anthropic_vs_mock_slowdown']:.0f}x slower than Mock")
        
        # Verification of claim
        print(f"\n✅ Verification:")
        actual_time = overall['mean_response_time_seconds']
        if 2 <= actual_time <= 5:
            print(f"   ✅ Confirmed: Anthropic response time ({actual_time:.2f}s) is within claimed 2-5s range")
        else:
            print(f"   ⚠️  Actual time ({actual_time:.2f}s) differs from claimed 2-5s range")


async def main():
    """Run the Anthropic benchmark"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Benchmark Anthropic Claude API")
    parser.add_argument("--iterations", type=int, default=10,
                       help="Number of iterations per agent (default: 10)")
    parser.add_argument("--warmup", type=int, default=2,
                       help="Number of warmup iterations (default: 2)")
    
    args = parser.parse_args()
    
    benchmark = AnthropicBenchmark(
        iterations=args.iterations,
        warmup=args.warmup
    )
    
    await benchmark.run_benchmarks()


if __name__ == "__main__":
    asyncio.run(main())