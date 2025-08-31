#!/usr/bin/env python3
"""
Comprehensive Agent Performance Benchmark Script
Compares Rust and Python agent execution times
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

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configuration
RUST_SERVICE_URL = "http://localhost:8088"
ORCHESTRATION_SERVICE_URL = "http://localhost:8002"
ITERATIONS = 10  # Number of iterations per agent
WARMUP_ITERATIONS = 2  # Warmup runs to prime caches

# Test OpenAPI spec (minimal but representative)
TEST_API_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Benchmark Test API",
        "version": "1.0.0"
    },
    "paths": {
        "/users": {
            "get": {
                "summary": "List users",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "schema": {"type": "integer", "minimum": 0}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        }
                    }
                }
            },
            "post": {
                "summary": "Create user",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UserInput"}
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                }
            }
        },
        "/users/{id}": {
            "get": {
                "summary": "Get user by ID",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                }
            },
            "put": {
                "summary": "Update user",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UserInput"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Updated",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        }
                    }
                }
            },
            "delete": {
                "summary": "Delete user",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"}
                    }
                ],
                "responses": {
                    "204": {"description": "Deleted"}
                }
            }
        },
        "/products": {
            "get": {
                "summary": "List products",
                "parameters": [
                    {
                        "name": "category",
                        "in": "query",
                        "schema": {"type": "string"}
                    },
                    {
                        "name": "minPrice",
                        "in": "query",
                        "schema": {"type": "number", "minimum": 0}
                    },
                    {
                        "name": "maxPrice",
                        "in": "query",
                        "schema": {"type": "number", "minimum": 0}
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Product"}
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "User": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "email": {"type": "string", "format": "email"},
                    "username": {"type": "string", "minLength": 3, "maxLength": 50},
                    "firstName": {"type": "string"},
                    "lastName": {"type": "string"},
                    "age": {"type": "integer", "minimum": 0, "maximum": 150},
                    "createdAt": {"type": "string", "format": "date-time"}
                },
                "required": ["id", "email", "username"]
            },
            "UserInput": {
                "type": "object",
                "properties": {
                    "email": {"type": "string", "format": "email"},
                    "username": {"type": "string", "minLength": 3, "maxLength": 50},
                    "firstName": {"type": "string"},
                    "lastName": {"type": "string"},
                    "age": {"type": "integer", "minimum": 0, "maximum": 150}
                },
                "required": ["email", "username"]
            },
            "Product": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "price": {"type": "number", "minimum": 0},
                    "category": {"type": "string"},
                    "stock": {"type": "integer", "minimum": 0}
                },
                "required": ["id", "name", "price"]
            }
        },
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            },
            "apiKey": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            }
        }
    }
}

# Agent types to benchmark
AGENTS_TO_BENCHMARK = [
    "Functional-Positive-Agent",
    "Functional-Negative-Agent",
    "Functional-Stateful-Agent",
    "Security-Auth-Agent",
    "Security-Injection-Agent",
    "Performance-Planner-Agent",
    "data-mocking"
]

class AgentBenchmark:
    def __init__(self):
        self.results = {}
        
    async def benchmark_rust_agent(self, agent_type: str, iterations: int = ITERATIONS) -> List[float]:
        """Benchmark a Rust agent"""
        times = []
        
        async with aiohttp.ClientSession() as session:
            # Warmup runs
            for _ in range(WARMUP_ITERATIONS):
                await self._execute_rust_agent(session, agent_type)
            
            # Actual benchmark runs
            for i in range(iterations):
                start_time = time.perf_counter()
                result = await self._execute_rust_agent(session, agent_type)
                end_time = time.perf_counter()
                
                if result:
                    times.append((end_time - start_time) * 1000)  # Convert to ms
                    print(f"  Rust {agent_type} - Run {i+1}: {times[-1]:.2f}ms")
                else:
                    print(f"  Rust {agent_type} - Run {i+1}: FAILED")
        
        return times
    
    async def _execute_rust_agent(self, session: aiohttp.ClientSession, agent_type: str):
        """Execute a single Rust agent request"""
        url = f"{RUST_SERVICE_URL}/swarm/orchestrate"
        
        payload = {
            "task": {
                "task_id": f"benchmark-{agent_type}-{time.time()}",
                "spec_id": "benchmark-spec",
                "agent_type": agent_type,  # Use the original agent type name
                "parameters": {},
                "target_environment": None
            },
            "api_spec": TEST_API_SPEC
        }
        
        try:
            async with session.post(url, json=payload, timeout=30) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    print(f"Error: {response.status} - {await response.text()}")
                    return None
        except Exception as e:
            print(f"Exception in Rust agent: {e}")
            return None
    
    async def benchmark_python_agent(self, agent_type: str, iterations: int = ITERATIONS) -> List[float]:
        """Benchmark a Python agent through orchestration service"""
        times = []
        
        async with aiohttp.ClientSession() as session:
            # Warmup runs
            for _ in range(WARMUP_ITERATIONS):
                await self._execute_python_agent(session, agent_type)
            
            # Actual benchmark runs
            for i in range(iterations):
                start_time = time.perf_counter()
                result = await self._execute_python_agent(session, agent_type)
                end_time = time.perf_counter()
                
                if result:
                    times.append((end_time - start_time) * 1000)  # Convert to ms
                    print(f"  Python {agent_type} - Run {i+1}: {times[-1]:.2f}ms")
                else:
                    print(f"  Python {agent_type} - Run {i+1}: FAILED")
        
        return times
    
    async def _execute_python_agent(self, session: aiohttp.ClientSession, agent_type: str):
        """Execute a single Python agent request through orchestration"""
        url = f"{ORCHESTRATION_SERVICE_URL}/swarm/orchestrate"
        
        # Map agent type to Python fallback mode
        agent_mapping = {
            "data-mocking": "data_mocking"
        }
        python_agent_type = agent_mapping.get(agent_type, agent_type.lower().replace("-", "_"))
        
        payload = {
            "request": {
                "task_id": f"py-benchmark-{time.time()}",
                "api_spec": TEST_API_SPEC,
                "agent_type": python_agent_type,
                "configuration": {
                    "use_python_fallback": True,
                    "force_python": True
                }
            }
        }
        
        try:
            async with session.post(url, json=payload, timeout=60) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    text = await response.text()
                    print(f"Python agent error: {response.status} - {text[:200]}")
                    return None
        except Exception as e:
            print(f"Exception in Python agent: {e}")
            return None
    
    def calculate_statistics(self, times: List[float]) -> Dict:
        """Calculate statistics for timing data"""
        if not times:
            return {
                "mean": 0,
                "median": 0,
                "std": 0,
                "min": 0,
                "max": 0,
                "p95": 0,
                "p99": 0
            }
        
        sorted_times = sorted(times)
        return {
            "mean": statistics.mean(times),
            "median": statistics.median(times),
            "std": statistics.stdev(times) if len(times) > 1 else 0,
            "min": min(times),
            "max": max(times),
            "p95": sorted_times[int(len(sorted_times) * 0.95)] if len(sorted_times) > 0 else 0,
            "p99": sorted_times[int(len(sorted_times) * 0.99)] if len(sorted_times) > 0 else 0
        }
    
    async def run_benchmark(self):
        """Run complete benchmark suite"""
        print("\n" + "="*80)
        print("SENTINEL AGENT PERFORMANCE BENCHMARK")
        print("="*80)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Iterations per agent: {ITERATIONS}")
        print(f"Warmup iterations: {WARMUP_ITERATIONS}")
        print("="*80 + "\n")
        
        # Check service health first
        print("Checking service health...")
        rust_healthy = await self.check_rust_health()
        python_healthy = await self.check_python_health()
        
        if not rust_healthy:
            print("❌ Rust service is not healthy!")
        if not python_healthy:
            print("⚠️  Python/Orchestration service may not be fully operational")
        
        print("\n" + "-"*80)
        
        # Benchmark each agent
        for agent_type in AGENTS_TO_BENCHMARK:
            print(f"\nBenchmarking: {agent_type}")
            print("-"*40)
            
            # Rust benchmark
            print("Running Rust agent benchmark...")
            rust_times = await self.benchmark_rust_agent(agent_type)
            rust_stats = self.calculate_statistics(rust_times)
            
            # Python benchmark (may fail for some agents)
            print("\nRunning Python agent benchmark...")
            python_times = await self.benchmark_python_agent(agent_type)
            python_stats = self.calculate_statistics(python_times)
            
            # Store results
            self.results[agent_type] = {
                "rust": rust_stats,
                "python": python_stats,
                "rust_times": rust_times,
                "python_times": python_times
            }
            
            # Calculate speedup
            if python_stats["mean"] > 0 and rust_stats["mean"] > 0:
                speedup = python_stats["mean"] / rust_stats["mean"]
                print(f"\n✅ Speedup: {speedup:.1f}x faster with Rust")
            else:
                print("\n⚠️  Could not calculate speedup (missing data)")
    
    async def check_rust_health(self) -> bool:
        """Check if Rust service is healthy"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{RUST_SERVICE_URL}/health", timeout=5) as response:
                    return response.status == 200
        except:
            return False
    
    async def check_python_health(self) -> bool:
        """Check if Python orchestration service is healthy"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{ORCHESTRATION_SERVICE_URL}/", timeout=5) as response:
                    return response.status in [200, 404]  # 404 is ok, means service is running
        except:
            return False
    
    def print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*80)
        print("BENCHMARK SUMMARY")
        print("="*80)
        
        # Prepare table data
        table_data = []
        headers = ["Agent", "Python (ms)", "Rust (ms)", "Speedup", "Status"]
        
        for agent_type in AGENTS_TO_BENCHMARK:
            if agent_type in self.results:
                result = self.results[agent_type]
                rust_mean = result["rust"]["mean"]
                python_mean = result["python"]["mean"]
                
                if python_mean > 0 and rust_mean > 0:
                    speedup = python_mean / rust_mean
                    status = "✅ PASS" if speedup > 10 else "⚠️  CHECK"
                else:
                    speedup = 0
                    status = "❌ FAIL"
                
                table_data.append([
                    agent_type,
                    f"{python_mean:.1f}" if python_mean > 0 else "N/A",
                    f"{rust_mean:.1f}" if rust_mean > 0 else "N/A",
                    f"{speedup:.1f}x" if speedup > 0 else "N/A",
                    status
                ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Compare with documented claims
        print("\n" + "="*80)
        print("COMPARISON WITH DOCUMENTED CLAIMS")
        print("="*80)
        
        documented_claims = {
            "Functional-Positive-Agent": {"python": 450, "rust": 25, "speedup": 18},
            "Functional-Negative-Agent": {"python": 680, "rust": 35, "speedup": 19},
            "Functional-Stateful-Agent": {"python": 1200, "rust": 65, "speedup": 18},
            "Security-Auth-Agent": {"python": 520, "rust": 30, "speedup": 17},
            "Security-Injection-Agent": {"python": 890, "rust": 42, "speedup": 21},
            "Performance-Planner-Agent": {"python": 560, "rust": 28, "speedup": 20},
            "data-mocking": {"python": 380, "rust": 20, "speedup": 19}
        }
        
        comparison_data = []
        comparison_headers = ["Agent", "Documented", "Measured", "Difference", "Verification"]
        
        for agent_type in AGENTS_TO_BENCHMARK:
            if agent_type in self.results and agent_type in documented_claims:
                result = self.results[agent_type]
                rust_mean = result["rust"]["mean"]
                python_mean = result["python"]["mean"]
                
                if python_mean > 0 and rust_mean > 0:
                    measured_speedup = python_mean / rust_mean
                    documented_speedup = documented_claims[agent_type]["speedup"]
                    diff = abs(measured_speedup - documented_speedup) / documented_speedup * 100
                    
                    if diff < 15:
                        verification = "✅ VERIFIED"
                    elif diff < 30:
                        verification = "⚠️  CLOSE"
                    else:
                        verification = "❌ MISMATCH"
                    
                    comparison_data.append([
                        agent_type,
                        f"{documented_speedup}x",
                        f"{measured_speedup:.1f}x",
                        f"{diff:.1f}%",
                        verification
                    ])
        
        print(tabulate(comparison_data, headers=comparison_headers, tablefmt="grid"))
        
        # Print detailed statistics
        print("\n" + "="*80)
        print("DETAILED STATISTICS")
        print("="*80)
        
        for agent_type in AGENTS_TO_BENCHMARK:
            if agent_type in self.results:
                result = self.results[agent_type]
                print(f"\n{agent_type}:")
                print(f"  Rust  - Mean: {result['rust']['mean']:.2f}ms, "
                      f"Median: {result['rust']['median']:.2f}ms, "
                      f"StdDev: {result['rust']['std']:.2f}ms, "
                      f"P95: {result['rust']['p95']:.2f}ms")
                
                if result['python']['mean'] > 0:
                    print(f"  Python - Mean: {result['python']['mean']:.2f}ms, "
                          f"Median: {result['python']['median']:.2f}ms, "
                          f"StdDev: {result['python']['std']:.2f}ms, "
                          f"P95: {result['python']['p95']:.2f}ms")
        
        # Save results to file
        self.save_results()
    
    def save_results(self):
        """Save benchmark results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_results_{timestamp}.json"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "iterations": ITERATIONS,
            "warmup_iterations": WARMUP_ITERATIONS,
            "results": {}
        }
        
        for agent_type, data in self.results.items():
            output["results"][agent_type] = {
                "rust": data["rust"],
                "python": data["python"],
                "speedup": data["python"]["mean"] / data["rust"]["mean"] if data["rust"]["mean"] > 0 and data["python"]["mean"] > 0 else 0
            }
        
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")

async def main():
    benchmark = AgentBenchmark()
    await benchmark.run_benchmark()
    benchmark.print_summary()

if __name__ == "__main__":
    asyncio.run(main())