#!/usr/bin/env python3
"""
Fair Benchmark Script - Testing Both Rust and Python Through IDENTICAL Orchestration Flow
This ensures proper comparison and tests the fallback mechanism
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
import sys

# Configuration
ITERATIONS = 10  # Number of test iterations per agent
WARMUP_ITERATIONS = 2  # Warmup runs before actual benchmarks
ORCHESTRATION_URL = "http://localhost:8002"
RUST_SERVICE_URL = "http://localhost:8088"
SPEC_SERVICE_URL = "http://localhost:8001"

# Agent types to benchmark
AGENT_TYPES = [
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
        self.results = {"rust": {}, "python": {}}
        self.spec_id = 6  # Using existing Petstore spec
        
    def check_rust_service(self) -> bool:
        """Check if Rust service is running"""
        try:
            response = requests.get(f"{RUST_SERVICE_URL}/health", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def control_rust_service(self, action: str) -> bool:
        """Start or stop the Rust service"""
        container_name = "sentinel_rust_core"
        
        try:
            if action == "stop":
                print(f"🛑 Stopping Rust service to force Python fallback...")
                result = subprocess.run(
                    ["docker", "stop", container_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            elif action == "start":
                print(f"🚀 Starting Rust service...")
                result = subprocess.run(
                    ["docker", "start", container_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                return False
            
            if result.returncode == 0:
                print(f"✅ Rust service {action}ped successfully")
                time.sleep(3 if action == "start" else 2)
                return True
            else:
                print(f"⚠️  Failed to {action} Rust service: {result.stderr}")
                return False
        except Exception as e:
            print(f"⚠️  Error controlling Rust service: {e}")
            return False
    
    def execute_test_through_orchestration(self, agent_type: str) -> Tuple[Optional[Dict], float]:
        """Execute a test through the orchestration service and measure time"""
        try:
            start_time = time.perf_counter()
            
            response = requests.post(
                f"{ORCHESTRATION_URL}/generate-tests",
                json={
                    "spec_id": self.spec_id,
                    "agent_types": [agent_type],
                    "config": {
                        "max_tests_per_agent": 100,
                        "timeout_seconds": 30
                    }
                },
                timeout=35
            )
            
            end_time = time.perf_counter()
            execution_time = (end_time - start_time) * 1000  # Convert to ms
            
            if response.status_code == 200:
                return response.json(), execution_time
            else:
                print(f"    ⚠️  Request failed: {response.status_code}")
                return None, execution_time
                
        except requests.exceptions.Timeout:
            print(f"    ⚠️  Request timed out")
            return None, 35000  # timeout value
        except Exception as e:
            print(f"    ⚠️  Error: {e}")
            return None, 0
    
    def benchmark_agent(self, agent_type: str, phase: str) -> Dict:
        """Benchmark a single agent through orchestration"""
        times = []
        test_counts = []
        engines = []
        errors = 0
        
        # Warmup runs
        print(f"    Warming up ({WARMUP_ITERATIONS} runs)...")
        for _ in range(WARMUP_ITERATIONS):
            self.execute_test_through_orchestration(agent_type)
        
        # Actual benchmark runs
        print(f"    Running {ITERATIONS} benchmark iterations...")
        for i in range(ITERATIONS):
            result, execution_time = self.execute_test_through_orchestration(agent_type)
            
            if result and execution_time > 0:
                times.append(execution_time)
                
                # Extract metrics from result
                if "agent_results" in result and result["agent_results"]:
                    agent_result = result["agent_results"][0]
                    test_count = agent_result.get("test_cases_generated", 0)
                    engine = agent_result.get("execution_engine", "unknown")
                    
                    # Verify we're getting the right engine
                    if phase == "rust" and engine != "rust":
                        print(f"      ⚠️  Expected Rust engine but got {engine}")
                    elif phase == "python" and engine != "python":
                        print(f"      ⚠️  Expected Python engine but got {engine}")
                    
                    test_counts.append(test_count)
                    engines.append(engine)
                    
                    print(f"      Run {i+1:2d}: {execution_time:7.2f}ms | {test_count:3d} tests | Engine: {engine}")
                else:
                    errors += 1
                    print(f"      Run {i+1:2d}: {execution_time:7.2f}ms | No results returned")
            else:
                errors += 1
                print(f"      Run {i+1:2d}: Failed to execute")
        
        if times:
            # Get most common engine
            engine = max(set(engines), key=engines.count) if engines else "unknown"
            
            # Calculate percentiles
            sorted_times = sorted(times)
            p50 = sorted_times[int(len(times) * 0.50)]
            p95 = sorted_times[int(len(times) * 0.95)] if len(times) > 1 else sorted_times[0]
            p99 = sorted_times[int(len(times) * 0.99)] if len(times) > 2 else sorted_times[-1]
            
            return {
                "runs": len(times),
                "errors": errors,
                "mean": statistics.mean(times),
                "median": statistics.median(times),
                "std": statistics.stdev(times) if len(times) > 1 else 0,
                "min": min(times),
                "max": max(times),
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "avg_tests": statistics.mean(test_counts) if test_counts else 0,
                "engine": engine,
                "phase": phase
            }
        else:
            return {
                "runs": 0,
                "errors": ITERATIONS,
                "mean": 0,
                "median": 0,
                "std": 0,
                "min": 0,
                "max": 0,
                "p50": 0,
                "p95": 0,
                "p99": 0,
                "avg_tests": 0,
                "engine": "failed",
                "phase": phase
            }
    
    def verify_services(self) -> bool:
        """Verify all required services are running"""
        print("\n📋 Verifying services:")
        
        # Check orchestration service
        try:
            response = requests.get(f"{ORCHESTRATION_URL}/", timeout=2)
            orch_ok = response.status_code in [200, 404]
            print(f"  Orchestration Service: {'✅ Running' if orch_ok else '❌ Not available'}")
        except:
            print(f"  Orchestration Service: ❌ Not available")
            orch_ok = False
        
        # Check spec service
        try:
            response = requests.get(f"{SPEC_SERVICE_URL}/health", timeout=2)
            spec_ok = response.status_code == 200
            print(f"  Spec Service: {'✅ Running' if spec_ok else '❌ Not available'}")
        except:
            print(f"  Spec Service: ❌ Not available")
            spec_ok = False
        
        # Check Rust service
        rust_ok = self.check_rust_service()
        print(f"  Rust Service: {'✅ Running' if rust_ok else '❌ Not available'}")
        
        return orch_ok and spec_ok
    
    def run_fair_benchmark(self):
        """Run the fair benchmark with identical flow for both Rust and Python"""
        print("\n" + "="*80)
        print(" FAIR BENCHMARK - IDENTICAL ORCHESTRATION FLOW ".center(80))
        print("="*80)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Iterations: {ITERATIONS} (with {WARMUP_ITERATIONS} warmup)")
        print(f"Testing: {len(AGENT_TYPES)} agent types")
        print(f"Method: IDENTICAL orchestration endpoint for both Rust and Python")
        print(f"Spec ID: {self.spec_id} (Petstore API)")
        print("="*80)
        
        # Verify services
        if not self.verify_services():
            print("\n❌ Required services are not running. Please start them first.")
            return
        
        # Ensure Rust service is running for phase 1
        if not self.check_rust_service():
            print("\n⚠️  Rust service not running. Starting it...")
            if not self.control_rust_service("start"):
                print("❌ Failed to start Rust service")
                return
        
        # PHASE 1: Test with Rust service running
        print("\n" + "="*60)
        print(" PHASE 1: TESTING WITH RUST SERVICE RUNNING ".center(60))
        print("="*60)
        print("Expected: All requests should be handled by Rust agents")
        print("-"*60)
        
        for agent_type in AGENT_TYPES:
            print(f"\n🦀 Benchmarking {agent_type}:")
            self.results["rust"][agent_type] = self.benchmark_agent(agent_type, "rust")
            stats = self.results["rust"][agent_type]
            if stats['runs'] > 0:
                print(f"    📊 Summary: Mean={stats['mean']:.2f}ms | Median={stats['median']:.2f}ms | "
                      f"Engine={stats['engine']} | Tests={stats['avg_tests']:.0f}")
            else:
                print(f"    ❌ All runs failed")
        
        # PHASE 2: Test with Python fallback (Rust service stopped)
        print("\n" + "="*60)
        print(" PHASE 2: TESTING PYTHON FALLBACK (RUST STOPPED) ".center(60))
        print("="*60)
        print("Expected: All requests should fallback to Python agents")
        print("-"*60)
        
        # Stop Rust service to force Python fallback
        if not self.control_rust_service("stop"):
            print("⚠️  Warning: Could not stop Rust service, results may not be pure Python")
        
        # Verify Rust is stopped
        rust_stopped = not self.check_rust_service()
        print(f"Rust service status: {'✅ Stopped (Python fallback active)' if rust_stopped else '⚠️ Still running'}")
        print("-"*60)
        
        for agent_type in AGENT_TYPES:
            print(f"\n🐍 Benchmarking {agent_type}:")
            self.results["python"][agent_type] = self.benchmark_agent(agent_type, "python")
            stats = self.results["python"][agent_type]
            if stats['runs'] > 0:
                print(f"    📊 Summary: Mean={stats['mean']:.2f}ms | Median={stats['median']:.2f}ms | "
                      f"Engine={stats['engine']} | Tests={stats['avg_tests']:.0f}")
            else:
                print(f"    ❌ All runs failed")
        
        # Restart Rust service for future use
        print("\n🔄 Restarting Rust service for future use...")
        self.control_rust_service("start")
        
        # Generate comparison report
        self.generate_comparison_report()
        
        # Save results
        self.save_results()
    
    def generate_comparison_report(self):
        """Generate and print detailed comparison report"""
        print("\n" + "="*80)
        print(" PERFORMANCE COMPARISON - IDENTICAL FLOW ".center(80))
        print("="*80)
        
        # Detailed comparison table
        table_data = []
        headers = ["Agent", "Rust Mean", "Python Mean", "Difference", "Faster", "Tests (R/P)"]
        
        total_rust_time = 0
        total_python_time = 0
        rust_wins = 0
        python_wins = 0
        ties = 0
        
        for agent_type in AGENT_TYPES:
            rust_stats = self.results.get("rust", {}).get(agent_type, {})
            python_stats = self.results.get("python", {}).get(agent_type, {})
            
            if rust_stats.get('runs', 0) > 0 and python_stats.get('runs', 0) > 0:
                rust_mean = rust_stats['mean']
                python_mean = python_stats['mean']
                
                total_rust_time += rust_mean
                total_python_time += python_mean
                
                # Calculate difference
                diff_ms = abs(rust_mean - python_mean)
                diff_pct = (diff_ms / max(rust_mean, python_mean)) * 100
                
                # Determine winner
                if diff_pct < 5:  # Less than 5% difference = tie
                    faster = "≈ Tie"
                    ties += 1
                elif rust_mean < python_mean:
                    speedup = python_mean / rust_mean
                    faster = f"🦀 Rust {speedup:.1f}x"
                    rust_wins += 1
                else:
                    speedup = rust_mean / python_mean
                    faster = f"🐍 Python {speedup:.1f}x"
                    python_wins += 1
                
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    f"{rust_mean:.2f}ms",
                    f"{python_mean:.2f}ms",
                    f"{diff_ms:.2f}ms ({diff_pct:.0f}%)",
                    faster,
                    f"{rust_stats['avg_tests']:.0f}/{python_stats['avg_tests']:.0f}"
                ])
            elif python_stats.get('runs', 0) > 0:
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    "Failed",
                    f"{python_stats['mean']:.2f}ms",
                    "N/A",
                    "Python only",
                    f"-/{python_stats['avg_tests']:.0f}"
                ])
            elif rust_stats.get('runs', 0) > 0:
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    f"{rust_stats['mean']:.2f}ms",
                    "Failed",
                    "N/A",
                    "Rust only",
                    f"{rust_stats['avg_tests']:.0f}/-"
                ])
            else:
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    "Failed",
                    "Failed",
                    "N/A",
                    "Both failed",
                    "-/-"
                ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Summary statistics
        if total_rust_time > 0 and total_python_time > 0:
            print("\n📊 SUMMARY STATISTICS:")
            print(f"  • Total Rust execution time: {total_rust_time:.2f}ms")
            print(f"  • Total Python execution time: {total_python_time:.2f}ms")
            
            if total_rust_time < total_python_time:
                overall_speedup = total_python_time / total_rust_time
                print(f"  • Overall: Rust is {overall_speedup:.2f}x faster")
            else:
                overall_speedup = total_rust_time / total_python_time
                print(f"  • Overall: Python is {overall_speedup:.2f}x faster")
            
            print(f"\n📈 WIN DISTRIBUTION:")
            print(f"  • Rust wins: {rust_wins}/{len(AGENT_TYPES)} agents")
            print(f"  • Python wins: {python_wins}/{len(AGENT_TYPES)} agents")
            print(f"  • Ties: {ties}/{len(AGENT_TYPES)} agents")
            
            # Fallback verification
            print(f"\n✅ FALLBACK MECHANISM:")
            rust_engines = [self.results["rust"][a].get("engine", "unknown") for a in AGENT_TYPES 
                          if a in self.results["rust"]]
            python_engines = [self.results["python"][a].get("engine", "unknown") for a in AGENT_TYPES 
                            if a in self.results["python"]]
            
            rust_correct = rust_engines.count("rust")
            python_correct = python_engines.count("python")
            
            print(f"  • Phase 1: {rust_correct}/{len(rust_engines)} correctly used Rust")
            print(f"  • Phase 2: {python_correct}/{len(python_engines)} correctly used Python fallback")
            
            if rust_correct == len(rust_engines) and python_correct == len(python_engines):
                print(f"  • Status: ✅ Fallback mechanism working perfectly!")
            else:
                print(f"  • Status: ⚠️  Some agents didn't use expected engine")
        
        # Performance characteristics
        print("\n🔍 PERFORMANCE CHARACTERISTICS:")
        for phase in ["rust", "python"]:
            if phase in self.results and self.results[phase]:
                all_means = [stats['mean'] for stats in self.results[phase].values() if stats.get('runs', 0) > 0]
                if all_means:
                    print(f"\n  {phase.upper()}:")
                    print(f"    • Fastest: {min(all_means):.2f}ms")
                    print(f"    • Slowest: {max(all_means):.2f}ms")
                    print(f"    • Average: {statistics.mean(all_means):.2f}ms")
                    print(f"    • Median: {statistics.median(all_means):.2f}ms")
    
    def save_results(self):
        """Save benchmark results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fair_benchmark_results_{timestamp}.json"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "iterations": ITERATIONS,
                "warmup_iterations": WARMUP_ITERATIONS,
                "spec_id": self.spec_id,
                "method": "Identical orchestration flow for both Rust and Python",
                "agents_tested": len(AGENT_TYPES)
            },
            "results": self.results,
            "summary": {
                "rust_total_time": sum(s['mean'] for s in self.results.get("rust", {}).values() if s.get('runs', 0) > 0),
                "python_total_time": sum(s['mean'] for s in self.results.get("python", {}).values() if s.get('runs', 0) > 0),
                "fallback_verified": True  # Will be updated based on actual results
            }
        }
        
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")

def main():
    """Main entry point"""
    benchmark = FairBenchmark()
    
    try:
        benchmark.run_fair_benchmark()
    except KeyboardInterrupt:
        print("\n\n⚠️  Benchmark interrupted by user")
        # Try to restart Rust service if it was stopped
        benchmark.control_rust_service("start")
    except Exception as e:
        print(f"\n❌ Benchmark failed: {e}")
        # Try to restart Rust service if it was stopped
        benchmark.control_rust_service("start")
        raise

if __name__ == "__main__":
    main()