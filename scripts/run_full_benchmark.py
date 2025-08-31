#!/usr/bin/env python3
"""
Complete Benchmark Script - Testing Both Rust and Python Agents
This script runs comprehensive benchmarks comparing Rust and Python agent implementations
"""

import json
import time
import statistics
import requests
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
from tabulate import tabulate
import os
import sys

# Configuration
ITERATIONS = 10  # Number of test iterations per agent
WARMUP_ITERATIONS = 2  # Warmup runs before actual benchmarks
ORCHESTRATION_URL = "http://localhost:8002/generate-tests"
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

class CompleteBenchmark:
    def __init__(self):
        self.results = {"rust": {}, "python": {}}
        self.spec_id = None
        
    def load_petstore_spec(self) -> Dict:
        """Load the Petstore specification from JSON file"""
        json_path = os.path.join(os.path.dirname(__file__), "petstore.json")
        
        try:
            with open(json_path, 'r') as f:
                spec = json.load(f)
            print(f"✅ Loaded Petstore spec: {spec['info']['title']} v{spec['info']['version']}")
            return spec
        except Exception as e:
            print(f"❌ Error loading spec: {e}")
            sys.exit(1)
    
    def create_specification(self, spec: Dict) -> int:
        """Create a new specification in the database"""
        # For benchmarking, we'll use a known good specification ID
        # Specification ID 6 is a pre-existing Petstore spec in the database
        spec_id = 6
        print(f"✅ Using existing Petstore specification with ID: {spec_id}")
        return spec_id
    
    def check_service_health(self, service_url: str, service_name: str) -> bool:
        """Check if a service is healthy"""
        try:
            # Different services have different health endpoints
            if "8001" in service_url:  # Spec service
                health_url = f"{service_url}/health"
            elif "8088" in service_url:  # Rust service
                health_url = f"{service_url}/health"
            else:  # Orchestration and others - just check if they respond
                health_url = service_url
            
            response = requests.get(health_url, timeout=2)
            is_healthy = response.status_code in [200, 404]  # 404 means service is up but endpoint doesn't exist
            status = "✅ Running" if is_healthy else "❌ Not responding"
            print(f"{service_name}: {status}")
            return is_healthy
        except:
            print(f"{service_name}: ❌ Not available")
            return False
    
    def execute_agent_test(self, spec_id: int, agent_type: str) -> Optional[Dict]:
        """Execute a single agent test through orchestration"""
        try:
            response = requests.post(
                ORCHESTRATION_URL,
                json={
                    "spec_id": spec_id,  # Changed from specification_id to spec_id
                    "agent_types": [agent_type],
                    "config": {
                        "max_tests_per_agent": 100,
                        "timeout_seconds": 30
                    }
                },
                timeout=35
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"    ⚠️  Request failed: {response.status_code}")
                return None
        except requests.exceptions.Timeout:
            print(f"    ⚠️  Request timed out")
            return None
        except Exception as e:
            print(f"    ⚠️  Error: {e}")
            return None
    
    def benchmark_agent(self, spec_id: int, agent_type: str, phase: str) -> Dict:
        """Benchmark a single agent"""
        times = []
        test_counts = []
        engines = []
        errors = 0
        
        # Warmup runs
        print(f"    Warming up ({WARMUP_ITERATIONS} runs)...")
        for _ in range(WARMUP_ITERATIONS):
            self.execute_agent_test(spec_id, agent_type)
        
        # Actual benchmark runs
        print(f"    Running {ITERATIONS} benchmark iterations...")
        for i in range(ITERATIONS):
            start_time = time.perf_counter()
            result = self.execute_agent_test(spec_id, agent_type)
            end_time = time.perf_counter()
            
            execution_time = (end_time - start_time) * 1000  # Convert to ms
            
            if result:
                times.append(execution_time)
                
                # Extract metrics from result
                if "agent_results" in result and result["agent_results"]:
                    agent_result = result["agent_results"][0]
                    test_count = agent_result.get("test_cases_generated", 0)
                    engine = agent_result.get("execution_engine", "unknown")
                    
                    test_counts.append(test_count)
                    engines.append(engine)
                    
                    print(f"      Run {i+1:2d}: {execution_time:6.2f}ms | {test_count:3d} tests | {engine}")
                else:
                    errors += 1
                    print(f"      Run {i+1:2d}: {execution_time:6.2f}ms | No results")
            else:
                errors += 1
                print(f"      Run {i+1:2d}: Failed")
        
        if times:
            # Get most common engine
            engine = max(set(engines), key=engines.count) if engines else "unknown"
            
            return {
                "runs": len(times),
                "errors": errors,
                "mean": statistics.mean(times),
                "median": statistics.median(times),
                "std": statistics.stdev(times) if len(times) > 1 else 0,
                "min": min(times),
                "max": max(times),
                "p95": sorted(times)[int(len(times) * 0.95)] if times else 0,
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
                "p95": 0,
                "avg_tests": 0,
                "engine": "failed",
                "phase": phase
            }
    
    def control_rust_service(self, action: str) -> bool:
        """Start or stop the Rust service"""
        container_name = "sentinel_rust_core"
        
        try:
            if action == "stop":
                print(f"\n🛑 Stopping Rust service...")
                result = subprocess.run(
                    ["docker", "stop", container_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            elif action == "start":
                print(f"\n🚀 Starting Rust service...")
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
    
    def run_complete_benchmark(self):
        """Run the complete benchmark suite"""
        print("\n" + "="*80)
        print(" COMPLETE SENTINEL AGENT BENCHMARK ".center(80))
        print("="*80)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Iterations: {ITERATIONS} (with {WARMUP_ITERATIONS} warmup)")
        print(f"Testing: {len(AGENT_TYPES)} agent types")
        print("="*80)
        
        # Check services
        print("\n📋 Checking service health:")
        self.check_service_health(SPEC_SERVICE_URL, "Spec Service")
        self.check_service_health(ORCHESTRATION_URL.replace('/generate-tests', ''), "Orchestration Service")
        rust_available = self.check_service_health(RUST_SERVICE_URL, "Rust Service")
        
        # Load and create specification
        print("\n📄 Setting up test specification:")
        spec = self.load_petstore_spec()
        self.spec_id = self.create_specification(spec)
        
        if not self.spec_id:
            print("❌ Failed to create specification. Exiting.")
            return
        
        # Phase 1: Benchmark with Rust service
        if rust_available:
            print("\n" + "="*60)
            print(" PHASE 1: BENCHMARKING RUST AGENTS ".center(60))
            print("="*60)
            
            for agent_type in AGENT_TYPES:
                print(f"\n🦀 Benchmarking {agent_type} (Rust):")
                self.results["rust"][agent_type] = self.benchmark_agent(
                    self.spec_id, agent_type, "rust"
                )
                stats = self.results["rust"][agent_type]
                print(f"    📊 Mean: {stats['mean']:.2f}ms | Median: {stats['median']:.2f}ms | Tests: {stats['avg_tests']:.0f}")
        else:
            print("\n⚠️  Skipping Rust benchmarks - service not available")
        
        # Phase 2: Benchmark Python agents (stop Rust service)
        print("\n" + "="*60)
        print(" PHASE 2: BENCHMARKING PYTHON AGENTS ".center(60))
        print("="*60)
        
        # Stop Rust service to force Python fallback
        if rust_available:
            self.control_rust_service("stop")
            # Verify it's stopped
            rust_stopped = not self.check_service_health(RUST_SERVICE_URL, "Rust Service (should be stopped)")
            
            if not rust_stopped:
                print("⚠️  Warning: Rust service still running, results may not be pure Python")
        
        for agent_type in AGENT_TYPES:
            print(f"\n🐍 Benchmarking {agent_type} (Python):")
            self.results["python"][agent_type] = self.benchmark_agent(
                self.spec_id, agent_type, "python"
            )
            stats = self.results["python"][agent_type]
            print(f"    📊 Mean: {stats['mean']:.2f}ms | Median: {stats['median']:.2f}ms | Tests: {stats['avg_tests']:.0f}")
        
        # Restart Rust service
        if rust_available:
            self.control_rust_service("start")
        
        # Generate comparison report
        self.generate_comparison_report()
        
        # Save results
        self.save_results()
    
    def generate_comparison_report(self):
        """Generate and print comparison report"""
        print("\n" + "="*80)
        print(" PERFORMANCE COMPARISON REPORT ".center(80))
        print("="*80)
        
        # Prepare comparison table
        table_data = []
        headers = ["Agent", "Rust (ms)", "Python (ms)", "Difference", "Faster", "Tests"]
        
        total_rust_time = 0
        total_python_time = 0
        rust_wins = 0
        python_wins = 0
        
        for agent_type in AGENT_TYPES:
            rust_stats = self.results.get("rust", {}).get(agent_type, {})
            python_stats = self.results.get("python", {}).get(agent_type, {})
            
            if rust_stats.get('runs', 0) > 0 and python_stats.get('runs', 0) > 0:
                rust_mean = rust_stats['mean']
                python_mean = python_stats['mean']
                
                total_rust_time += rust_mean
                total_python_time += python_mean
                
                if rust_mean < python_mean:
                    speedup = python_mean / rust_mean
                    faster = f"Rust {speedup:.1f}x"
                    rust_wins += 1
                else:
                    speedup = rust_mean / python_mean
                    faster = f"Python {speedup:.1f}x"
                    python_wins += 1
                
                diff_ms = abs(rust_mean - python_mean)
                diff_pct = (diff_ms / max(rust_mean, python_mean)) * 100
                
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    f"{rust_mean:.2f}",
                    f"{python_mean:.2f}",
                    f"{diff_ms:.2f} ({diff_pct:.0f}%)",
                    faster,
                    f"{rust_stats['avg_tests']:.0f}/{python_stats['avg_tests']:.0f}"
                ])
            elif python_stats.get('runs', 0) > 0:
                # Only Python results
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    "N/A",
                    f"{python_stats['mean']:.2f}",
                    "N/A",
                    "Python only",
                    f"{python_stats['avg_tests']:.0f}"
                ])
            elif rust_stats.get('runs', 0) > 0:
                # Only Rust results
                table_data.append([
                    agent_type.replace("-Agent", ""),
                    f"{rust_stats['mean']:.2f}",
                    "N/A",
                    "N/A",
                    "Rust only",
                    f"{rust_stats['avg_tests']:.0f}"
                ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Summary statistics
        if total_rust_time > 0 and total_python_time > 0:
            print("\n📊 Summary Statistics:")
            print(f"  • Total Rust execution time: {total_rust_time:.2f}ms")
            print(f"  • Total Python execution time: {total_python_time:.2f}ms")
            print(f"  • Overall speedup: {max(total_rust_time, total_python_time) / min(total_rust_time, total_python_time):.2f}x")
            print(f"  • Rust wins: {rust_wins}/{len(AGENT_TYPES)}")
            print(f"  • Python wins: {python_wins}/{len(AGENT_TYPES)}")
            
            if total_rust_time < total_python_time:
                print(f"\n🏆 **Rust is {total_python_time/total_rust_time:.2f}x faster overall**")
            else:
                print(f"\n🏆 **Python is {total_rust_time/total_python_time:.2f}x faster overall**")
    
    def save_results(self):
        """Save benchmark results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"complete_benchmark_results_{timestamp}.json"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "iterations": ITERATIONS,
                "warmup_iterations": WARMUP_ITERATIONS,
                "agents_tested": len(AGENT_TYPES)
            },
            "results": self.results
        }
        
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")

def main():
    """Main entry point"""
    benchmark = CompleteBenchmark()
    
    try:
        benchmark.run_complete_benchmark()
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