#!/usr/bin/env python3
"""
Fast Benchmark with Mock LLM - Tests actual agent performance without LLM overhead
"""

import json
import time
import statistics
import requests
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from tabulate import tabulate
import os

# Configuration
ITERATIONS = 5
WARMUP_ITERATIONS = 1
ORCHESTRATION_URL = "http://localhost:8002"
RUST_SERVICE_URL = "http://localhost:8088"

AGENT_TYPES = [
    "Functional-Positive-Agent",
    "Functional-Negative-Agent",
    "Functional-Stateful-Agent",
    "Security-Auth-Agent",
    "Security-Injection-Agent",
    "Performance-Planner-Agent",
    "Data-Mocking-Agent"
]

class FastBenchmark:
    def __init__(self):
        self.results = {"rust": {}, "python": {}}
        self.spec_id = 6
        
    def check_rust_service(self) -> bool:
        """Check if Rust service is running"""
        try:
            response = requests.get(f"{RUST_SERVICE_URL}/health", timeout=1)
            return response.status_code == 200
        except:
            return False
    
    def control_rust_service(self, action: str) -> bool:
        """Control Rust service"""
        try:
            if action == "stop":
                print(f"  🛑 Stopping Rust service...")
                subprocess.run(["docker", "stop", "sentinel_rust_core"], 
                             capture_output=True, timeout=5)
            else:
                print(f"  🚀 Starting Rust service...")
                subprocess.run(["docker", "start", "sentinel_rust_core"], 
                             capture_output=True, timeout=5)
            time.sleep(2)
            return True
        except Exception as e:
            print(f"  ⚠️ Error: {e}")
            return False
    
    def test_agent(self, agent_type: str) -> Tuple[bool, float, str]:
        """Test agent through orchestration"""
        try:
            start = time.perf_counter()
            response = requests.post(
                f"{ORCHESTRATION_URL}/generate-tests",
                json={
                    "spec_id": self.spec_id,
                    "agent_types": [agent_type],
                    "config": {"max_tests_per_agent": 10, "timeout_seconds": 5}
                },
                timeout=10
            )
            elapsed = (time.perf_counter() - start) * 1000
            
            if response.status_code == 200:
                result = response.json()
                engine = "unknown"
                tests = 0
                if "agent_results" in result and result["agent_results"]:
                    agent_result = result["agent_results"][0]
                    engine = agent_result.get("execution_engine", "unknown")
                    tests = agent_result.get("test_cases_generated", 0)
                return True, elapsed, engine, tests
            return False, elapsed, "failed", 0
        except Exception as e:
            return False, 0, "error", 0
    
    def benchmark_phase(self, phase: str) -> Dict:
        """Run benchmark for a phase"""
        results = {}
        
        for agent_type in AGENT_TYPES:
            print(f"  Testing {agent_type}...")
            times = []
            engines = []
            test_counts = []
            
            # Warmup
            for _ in range(WARMUP_ITERATIONS):
                self.test_agent(agent_type)
            
            # Actual runs
            for i in range(ITERATIONS):
                success, elapsed, engine, tests = self.test_agent(agent_type)
                if success and elapsed > 0:
                    times.append(elapsed)
                    engines.append(engine)
                    test_counts.append(tests)
                    print(f"    Run {i+1}: {elapsed:6.2f}ms [{engine}] {tests} tests")
                else:
                    print(f"    Run {i+1}: Failed")
            
            if times:
                results[agent_type] = {
                    "mean": statistics.mean(times),
                    "median": statistics.median(times),
                    "min": min(times),
                    "max": max(times),
                    "std": statistics.stdev(times) if len(times) > 1 else 0,
                    "runs": len(times),
                    "avg_tests": statistics.mean(test_counts) if test_counts else 0,
                    "engine": max(set(engines), key=engines.count) if engines else "unknown"
                }
            else:
                results[agent_type] = {
                    "mean": 0, "median": 0, "min": 0, "max": 0, "std": 0,
                    "runs": 0, "avg_tests": 0, "engine": "failed"
                }
        
        return results
    
    def run(self):
        """Run the fast benchmark"""
        print("\n" + "="*70)
        print(" FAST BENCHMARK WITH MOCK LLM ".center(70))
        print("="*70)
        print(f"Iterations: {ITERATIONS} | Agents: {len(AGENT_TYPES)} | Spec ID: {self.spec_id}")
        print("Mock LLM provides instant responses for accurate agent benchmarking")
        print("="*70)
        
        # Phase 1: Rust
        print("\n📍 PHASE 1: RUST AGENTS")
        print("-"*70)
        
        if not self.check_rust_service():
            self.control_rust_service("start")
        
        if self.check_rust_service():
            print("✅ Rust service running - testing Rust agents\n")
            self.results["rust"] = self.benchmark_phase("rust")
        else:
            print("❌ Rust service unavailable\n")
        
        # Phase 2: Python
        print("\n📍 PHASE 2: PYTHON AGENTS (FALLBACK)")
        print("-"*70)
        
        self.control_rust_service("stop")
        if not self.check_rust_service():
            print("✅ Rust stopped - testing Python fallback\n")
            self.results["python"] = self.benchmark_phase("python")
        
        # Restart Rust
        self.control_rust_service("start")
        
        # Results
        self.print_results()
        self.save_results()
    
    def print_results(self):
        """Print detailed results"""
        print("\n" + "="*70)
        print(" BENCHMARK RESULTS ".center(70))
        print("="*70)
        
        # Comparison table
        table_data = []
        headers = ["Agent", "Rust (ms)", "Python (ms)", "Speedup", "Tests"]
        
        total_rust = 0
        total_python = 0
        rust_wins = 0
        python_wins = 0
        
        for agent in AGENT_TYPES:
            rust = self.results.get("rust", {}).get(agent, {})
            python = self.results.get("python", {}).get(agent, {})
            
            if rust.get("runs", 0) > 0 and python.get("runs", 0) > 0:
                rust_mean = rust["mean"]
                python_mean = python["mean"]
                total_rust += rust_mean
                total_python += python_mean
                
                if rust_mean < python_mean:
                    speedup = f"Rust {python_mean/rust_mean:.2f}x"
                    rust_wins += 1
                else:
                    speedup = f"Python {rust_mean/python_mean:.2f}x"
                    python_wins += 1
                
                table_data.append([
                    agent.replace("-Agent", ""),
                    f"{rust_mean:.2f} ± {rust['std']:.2f}",
                    f"{python_mean:.2f} ± {python['std']:.2f}",
                    speedup,
                    f"{rust['avg_tests']:.0f}/{python['avg_tests']:.0f}"
                ])
        
        if table_data:
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            # Summary
            print(f"\n📊 SUMMARY:")
            print(f"  • Total Rust time: {total_rust:.2f}ms")
            print(f"  • Total Python time: {total_python:.2f}ms")
            if total_rust < total_python:
                print(f"  • Overall: Rust is {total_python/total_rust:.2f}x faster")
            else:
                print(f"  • Overall: Python is {total_rust/total_python:.2f}x faster")
            print(f"  • Rust wins: {rust_wins}/{len(AGENT_TYPES)}")
            print(f"  • Python wins: {python_wins}/{len(AGENT_TYPES)}")
            
            # Verify fallback
            rust_engines = [r.get("engine", "") for r in self.results.get("rust", {}).values()]
            python_engines = [r.get("engine", "") for r in self.results.get("python", {}).values()]
            
            print(f"\n✅ FALLBACK VERIFICATION:")
            print(f"  • Phase 1: {rust_engines.count('rust')}/{len(rust_engines)} used Rust")
            print(f"  • Phase 2: {python_engines.count('python')}/{len(python_engines)} used Python")
    
    def save_results(self):
        """Save results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mock_benchmark_results_{timestamp}.json"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "iterations": ITERATIONS,
                "warmup": WARMUP_ITERATIONS,
                "agents": len(AGENT_TYPES),
                "llm": "mock"
            },
            "results": self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")

if __name__ == "__main__":
    print("\n🔍 Checking environment...")
    
    # Check if mock provider is configured
    llm_provider = os.environ.get("SENTINEL_APP_LLM_PROVIDER", "")
    if llm_provider != "mock":
        print(f"⚠️  LLM provider is '{llm_provider}', not 'mock'")
        print("   Assuming Docker has been configured with mock provider")
        print("   Continuing with benchmark...")
    else:
        print(f"✅ Mock provider configured")
    
    benchmark = FastBenchmark()
    benchmark.run()