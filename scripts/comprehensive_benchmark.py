#!/usr/bin/env python3
"""
Comprehensive 10-Iteration Benchmark with Detailed Statistics
Tests Rust vs Python agent performance with mock LLM
"""

import json
import time
import statistics
import requests
import subprocess
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from tabulate import tabulate

# Configuration
ITERATIONS = 10  # 10 iterations as requested
WARMUP_ITERATIONS = 2
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

class ComprehensiveBenchmark:
    def __init__(self):
        self.results = {"rust": {}, "python": {}}
        self.raw_data = {"rust": {}, "python": {}}  # Store all individual measurements
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
    
    def test_agent(self, agent_type: str) -> Tuple[bool, float, str, int]:
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
    
    def calculate_statistics(self, times: List[float]) -> Dict:
        """Calculate comprehensive statistics"""
        if not times:
            return {
                "mean": 0, "median": 0, "min": 0, "max": 0, 
                "std": 0, "variance": 0, "percentile_25": 0,
                "percentile_75": 0, "percentile_95": 0,
                "cv": 0  # Coefficient of variation
            }
        
        sorted_times = sorted(times)
        n = len(sorted_times)
        mean = statistics.mean(times)
        std = statistics.stdev(times) if n > 1 else 0
        
        # Calculate percentiles
        def percentile(data, p):
            k = (n - 1) * p / 100
            f = int(k)
            c = f + 1 if f < n - 1 else f
            if f == c:
                return data[f]
            return data[f] + (data[c] - data[f]) * (k - f)
        
        return {
            "mean": mean,
            "median": statistics.median(times),
            "min": min(times),
            "max": max(times),
            "std": std,
            "variance": statistics.variance(times) if n > 1 else 0,
            "percentile_25": percentile(sorted_times, 25),
            "percentile_75": percentile(sorted_times, 75),
            "percentile_95": percentile(sorted_times, 95),
            "cv": (std / mean * 100) if mean > 0 else 0  # CV in percentage
        }
    
    def benchmark_phase(self, phase: str) -> Dict:
        """Run benchmark for a phase"""
        results = {}
        
        for agent_type in AGENT_TYPES:
            print(f"  Testing {agent_type}...")
            times = []
            engines = []
            test_counts = []
            all_runs = []  # Store all run data
            
            # Warmup
            print("    Warmup runs...")
            for _ in range(WARMUP_ITERATIONS):
                self.test_agent(agent_type)
            
            # Actual runs
            print("    Benchmark runs:")
            for i in range(ITERATIONS):
                success, elapsed, engine, tests = self.test_agent(agent_type)
                if success and elapsed > 0:
                    times.append(elapsed)
                    engines.append(engine)
                    test_counts.append(tests)
                    all_runs.append({
                        "run": i + 1,
                        "time_ms": elapsed,
                        "tests": tests,
                        "engine": engine
                    })
                    print(f"      Run {i+1:2d}: {elapsed:7.2f}ms [{engine:6s}] {tests:3d} tests")
                else:
                    print(f"      Run {i+1:2d}: Failed")
                    all_runs.append({
                        "run": i + 1,
                        "time_ms": None,
                        "tests": 0,
                        "engine": "failed"
                    })
            
            # Store raw data
            self.raw_data[phase][agent_type] = all_runs
            
            if times:
                stats = self.calculate_statistics(times)
                results[agent_type] = {
                    **stats,
                    "runs": len(times),
                    "failures": ITERATIONS - len(times),
                    "avg_tests": statistics.mean(test_counts) if test_counts else 0,
                    "min_tests": min(test_counts) if test_counts else 0,
                    "max_tests": max(test_counts) if test_counts else 0,
                    "engine": max(set(engines), key=engines.count) if engines else "unknown",
                    "raw_times": times,  # Store raw times for detailed analysis
                    "raw_test_counts": test_counts
                }
            else:
                results[agent_type] = {
                    **self.calculate_statistics([]),
                    "runs": 0,
                    "failures": ITERATIONS,
                    "avg_tests": 0,
                    "min_tests": 0,
                    "max_tests": 0,
                    "engine": "failed",
                    "raw_times": [],
                    "raw_test_counts": []
                }
        
        return results
    
    def run(self):
        """Run the comprehensive benchmark"""
        print("\n" + "="*80)
        print(" COMPREHENSIVE 10-ITERATION BENCHMARK WITH MOCK LLM ".center(80))
        print("="*80)
        print(f"Iterations: {ITERATIONS} | Warmup: {WARMUP_ITERATIONS} | Agents: {len(AGENT_TYPES)} | Spec ID: {self.spec_id}")
        print("Mock LLM provides instant responses for accurate agent benchmarking")
        print("="*80)
        
        # Phase 1: Rust
        print("\n📍 PHASE 1: RUST AGENTS")
        print("-"*80)
        
        if not self.check_rust_service():
            self.control_rust_service("start")
        
        if self.check_rust_service():
            print("✅ Rust service running - testing Rust agents\n")
            self.results["rust"] = self.benchmark_phase("rust")
        else:
            print("❌ Rust service unavailable\n")
        
        # Phase 2: Python
        print("\n📍 PHASE 2: PYTHON AGENTS (FALLBACK)")
        print("-"*80)
        
        self.control_rust_service("stop")
        if not self.check_rust_service():
            print("✅ Rust stopped - testing Python fallback\n")
            self.results["python"] = self.benchmark_phase("python")
        
        # Restart Rust
        self.control_rust_service("start")
        
        # Results
        self.print_summary()
        self.print_detailed_statistics()
        self.print_raw_data_table()
        self.save_results()
    
    def print_summary(self):
        """Print summary comparison table"""
        print("\n" + "="*80)
        print(" SUMMARY COMPARISON (Mean ± Std Dev) ".center(80))
        print("="*80)
        
        # Comparison table
        table_data = []
        headers = ["Agent", "Rust (ms)", "Python (ms)", "Speedup", "Tests (R/P)"]
        
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
            
            # Overall summary
            print(f"\n📊 OVERALL SUMMARY:")
            print(f"  • Total Rust time: {total_rust:.2f}ms")
            print(f"  • Total Python time: {total_python:.2f}ms")
            if total_rust < total_python:
                print(f"  • Overall: Rust is {total_python/total_rust:.2f}x faster")
            else:
                print(f"  • Overall: Python is {total_rust/total_python:.2f}x faster")
            print(f"  • Rust wins: {rust_wins}/{len(AGENT_TYPES)}")
            print(f"  • Python wins: {python_wins}/{len(AGENT_TYPES)}")
    
    def print_detailed_statistics(self):
        """Print detailed statistics table"""
        print("\n" + "="*80)
        print(" DETAILED STATISTICS ".center(80))
        print("="*80)
        
        for engine in ["rust", "python"]:
            print(f"\n{engine.upper()} AGENTS:")
            print("-"*80)
            
            table_data = []
            headers = ["Agent", "Min", "P25", "Median", "Mean", "P75", "P95", "Max", "Std", "CV%"]
            
            for agent in AGENT_TYPES:
                stats = self.results.get(engine, {}).get(agent, {})
                if stats.get("runs", 0) > 0:
                    table_data.append([
                        agent.replace("-Agent", "")[:15],
                        f"{stats['min']:.1f}",
                        f"{stats['percentile_25']:.1f}",
                        f"{stats['median']:.1f}",
                        f"{stats['mean']:.1f}",
                        f"{stats['percentile_75']:.1f}",
                        f"{stats['percentile_95']:.1f}",
                        f"{stats['max']:.1f}",
                        f"{stats['std']:.1f}",
                        f"{stats['cv']:.1f}"
                    ])
            
            if table_data:
                print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    def print_raw_data_table(self):
        """Print all individual run results"""
        print("\n" + "="*80)
        print(" RAW DATA - ALL INDIVIDUAL RUNS ".center(80))
        print("="*80)
        
        for agent in AGENT_TYPES:
            print(f"\n{agent}:")
            print("-"*60)
            
            # Prepare data for both engines
            rust_runs = self.raw_data.get("rust", {}).get(agent, [])
            python_runs = self.raw_data.get("python", {}).get(agent, [])
            
            table_data = []
            headers = ["Run", "Rust (ms)", "R Tests", "Python (ms)", "P Tests"]
            
            for i in range(ITERATIONS):
                rust_data = rust_runs[i] if i < len(rust_runs) else {}
                python_data = python_runs[i] if i < len(python_runs) else {}
                
                table_data.append([
                    i + 1,
                    f"{rust_data.get('time_ms', 0):.2f}" if rust_data.get('time_ms') else "Failed",
                    rust_data.get('tests', 0),
                    f"{python_data.get('time_ms', 0):.2f}" if python_data.get('time_ms') else "Failed",
                    python_data.get('tests', 0)
                ])
            
            print(tabulate(table_data, headers=headers, tablefmt="simple"))
    
    def save_results(self):
        """Save comprehensive results to JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"comprehensive_benchmark_{timestamp}.json"
        
        # Remove raw_times and raw_test_counts from saved results (they're in raw_data)
        clean_results = {}
        for engine in ["rust", "python"]:
            clean_results[engine] = {}
            for agent, stats in self.results.get(engine, {}).items():
                clean_stats = {k: v for k, v in stats.items() 
                             if k not in ["raw_times", "raw_test_counts"]}
                clean_results[engine][agent] = clean_stats
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "iterations": ITERATIONS,
                "warmup": WARMUP_ITERATIONS,
                "agents": len(AGENT_TYPES),
                "spec_id": self.spec_id,
                "llm": "mock"
            },
            "summary_statistics": clean_results,
            "raw_data": self.raw_data
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")

if __name__ == "__main__":
    print("\n🔍 Starting Comprehensive Benchmark...")
    benchmark = ComprehensiveBenchmark()
    benchmark.run()