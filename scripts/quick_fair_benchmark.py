#!/usr/bin/env python3
"""
Quick Fair Benchmark - Testing Rust vs Python with Mock LLM responses
This tests the actual agent execution performance without LLM API overhead
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
ITERATIONS = 5  # Reduced for quicker testing
WARMUP_ITERATIONS = 1
ORCHESTRATION_URL = "http://localhost:8002"
RUST_SERVICE_URL = "http://localhost:8088"

# Simplified agent list for quick testing
AGENT_TYPES = [
    "Functional-Positive-Agent",
    "Functional-Negative-Agent",
    "Security-Auth-Agent",
    "Performance-Planner-Agent",
]

class QuickBenchmark:
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
                print(f"🛑 Stopping Rust service...")
                subprocess.run(["docker", "stop", "sentinel_rust_core"], 
                             capture_output=True, timeout=5)
            else:
                print(f"🚀 Starting Rust service...")
                subprocess.run(["docker", "start", "sentinel_rust_core"], 
                             capture_output=True, timeout=5)
            time.sleep(2)
            return True
        except:
            return False
    
    def test_direct_rust_agent(self, agent_type: str) -> Tuple[bool, float]:
        """Test Rust agent directly via HTTP"""
        try:
            start = time.perf_counter()
            response = requests.post(
                f"{RUST_SERVICE_URL}/execute",
                json={
                    "agent_type": agent_type,
                    "spec_id": self.spec_id,
                    "config": {"max_tests": 10}
                },
                timeout=5
            )
            elapsed = (time.perf_counter() - start) * 1000
            return response.status_code == 200, elapsed
        except:
            return False, 0
    
    def test_through_orchestration(self, agent_type: str) -> Tuple[bool, float, str]:
        """Test through orchestration (will use Rust or Python based on availability)"""
        try:
            start = time.perf_counter()
            response = requests.post(
                f"{ORCHESTRATION_URL}/generate-tests",
                json={
                    "spec_id": self.spec_id,
                    "agent_types": [agent_type],
                    "config": {"max_tests_per_agent": 10, "timeout_seconds": 10}
                },
                timeout=15
            )
            elapsed = (time.perf_counter() - start) * 1000
            
            if response.status_code == 200:
                result = response.json()
                engine = "unknown"
                if "agent_results" in result and result["agent_results"]:
                    engine = result["agent_results"][0].get("execution_engine", "unknown")
                return True, elapsed, engine
            return False, elapsed, "failed"
        except:
            return False, 0, "error"
    
    def benchmark_phase(self, phase: str) -> Dict:
        """Run benchmark for a specific phase"""
        results = {}
        
        for agent_type in AGENT_TYPES:
            print(f"\n  Testing {agent_type}...")
            times = []
            engines = []
            
            # Warmup
            for _ in range(WARMUP_ITERATIONS):
                self.test_through_orchestration(agent_type)
            
            # Actual runs
            for i in range(ITERATIONS):
                success, elapsed, engine = self.test_through_orchestration(agent_type)
                if success and elapsed > 0:
                    times.append(elapsed)
                    engines.append(engine)
                    print(f"    Run {i+1}: {elapsed:.2f}ms [{engine}]")
                else:
                    print(f"    Run {i+1}: Failed")
            
            if times:
                results[agent_type] = {
                    "mean": statistics.mean(times),
                    "median": statistics.median(times),
                    "min": min(times),
                    "max": max(times),
                    "runs": len(times),
                    "engine": max(set(engines), key=engines.count) if engines else "unknown"
                }
            else:
                results[agent_type] = {
                    "mean": 0, "median": 0, "min": 0, "max": 0, "runs": 0, "engine": "failed"
                }
        
        return results
    
    def run(self):
        """Run the quick benchmark"""
        print("\n" + "="*60)
        print(" QUICK FAIR BENCHMARK ".center(60))
        print("="*60)
        print(f"Testing {len(AGENT_TYPES)} agents, {ITERATIONS} iterations each")
        print(f"Using spec_id: {self.spec_id}")
        
        # Phase 1: With Rust
        print("\n📍 PHASE 1: RUST SERVICE RUNNING")
        print("-"*60)
        
        if not self.check_rust_service():
            self.control_rust_service("start")
        
        if self.check_rust_service():
            print("✅ Rust service is running")
            self.results["rust"] = self.benchmark_phase("rust")
        else:
            print("❌ Rust service unavailable")
        
        # Phase 2: Python fallback
        print("\n📍 PHASE 2: PYTHON FALLBACK (RUST STOPPED)")
        print("-"*60)
        
        self.control_rust_service("stop")
        if not self.check_rust_service():
            print("✅ Rust service stopped - Python fallback active")
            self.results["python"] = self.benchmark_phase("python")
        else:
            print("⚠️ Failed to stop Rust service")
        
        # Restart Rust
        self.control_rust_service("start")
        
        # Print results
        self.print_results()
    
    def print_results(self):
        """Print comparison results"""
        print("\n" + "="*60)
        print(" RESULTS ".center(60))
        print("="*60)
        
        table_data = []
        headers = ["Agent", "Rust (ms)", "Python (ms)", "Faster"]
        
        for agent in AGENT_TYPES:
            rust = self.results.get("rust", {}).get(agent, {})
            python = self.results.get("python", {}).get(agent, {})
            
            if rust.get("runs", 0) > 0 and python.get("runs", 0) > 0:
                rust_mean = rust["mean"]
                python_mean = python["mean"]
                
                if rust_mean < python_mean:
                    faster = f"Rust {python_mean/rust_mean:.1f}x"
                else:
                    faster = f"Python {rust_mean/python_mean:.1f}x"
                
                table_data.append([
                    agent.replace("-Agent", ""),
                    f"{rust_mean:.2f}",
                    f"{python_mean:.2f}",
                    faster
                ])
        
        if table_data:
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            # Verify fallback
            rust_engines = [r.get("engine", "") for r in self.results.get("rust", {}).values()]
            python_engines = [r.get("engine", "") for r in self.results.get("python", {}).values()]
            
            print(f"\n✅ FALLBACK VERIFICATION:")
            print(f"  Phase 1: {rust_engines.count('rust')}/{len(rust_engines)} used Rust")
            print(f"  Phase 2: {python_engines.count('python')}/{len(python_engines)} used Python")

if __name__ == "__main__":
    benchmark = QuickBenchmark()
    benchmark.run()