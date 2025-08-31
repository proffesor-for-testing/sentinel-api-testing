#!/usr/bin/env python3
"""
Direct Python Agent Benchmark Script
Tests Python agents directly without database dependencies
"""

import sys
import os
import time
import statistics
import json
from datetime import datetime
from tabulate import tabulate
import asyncio

# Add parent directory to path to import agents
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'sentinel_backend'))

# Import the Python agents directly
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult
from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.orchestration_service.agents.functional_stateful_agent import FunctionalStatefulAgent
from sentinel_backend.orchestration_service.agents.security_auth_agent import SecurityAuthAgent
from sentinel_backend.orchestration_service.agents.security_injection_agent import SecurityInjectionAgent
from sentinel_backend.orchestration_service.agents.performance_planner_agent import PerformancePlannerAgent
from sentinel_backend.orchestration_service.agents.data_mocking_agent import DataMockingAgent

# Configuration
ITERATIONS = 10  # Number of iterations per agent
WARMUP_ITERATIONS = 2  # Warmup runs to prime caches

# Test OpenAPI spec (same as Rust benchmark)
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

class PythonAgentBenchmark:
    def __init__(self):
        self.results = {}
        self.agents = {
            "Functional-Positive-Agent": FunctionalPositiveAgent(),
            "Functional-Negative-Agent": FunctionalNegativeAgent(),
            "Functional-Stateful-Agent": FunctionalStatefulAgent(),
            "Security-Auth-Agent": SecurityAuthAgent(),
            "Security-Injection-Agent": SecurityInjectionAgent(),
            "Performance-Planner-Agent": PerformancePlannerAgent(),
            "Data-Mocking-Agent": DataMockingAgent()
        }
    
    async def benchmark_agent(self, agent_name: str, iterations: int = ITERATIONS):
        """Benchmark a Python agent"""
        times = []
        agent = self.agents[agent_name]
        
        # Warmup runs
        for _ in range(WARMUP_ITERATIONS):
            task = AgentTask(
                task_id=f"warmup-{agent_name}-{time.time()}",
                spec_id=1,  # Use integer spec_id
                agent_type=agent_name,
                parameters={},
                target_environment=None
            )
            try:
                await agent.execute(task, TEST_API_SPEC)
            except Exception as e:
                print(f"  Warmup error for {agent_name}: {e}")
        
        # Actual benchmark runs
        for i in range(iterations):
            task = AgentTask(
                task_id=f"benchmark-{agent_name}-{i}-{time.time()}",
                spec_id=1,  # Use integer spec_id
                agent_type=agent_name,
                parameters={},
                target_environment=None
            )
            
            try:
                start_time = time.perf_counter()
                result = await agent.execute(task, TEST_API_SPEC)
                end_time = time.perf_counter()
                
                execution_time = (end_time - start_time) * 1000  # Convert to ms
                times.append(execution_time)
                
                status = "✓" if result.status == "success" else "✗"
                test_count = len(result.test_cases) if hasattr(result, 'test_cases') and result.test_cases else 0
                print(f"  Python {agent_name} - Run {i+1}: {execution_time:.2f}ms {status} ({test_count} tests)")
            except Exception as e:
                print(f"  Python {agent_name} - Run {i+1}: FAILED - {str(e)[:50]}")
        
        return times
    
    def calculate_statistics(self, times):
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
        print("PYTHON AGENT PERFORMANCE BENCHMARK")
        print("="*80)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Iterations per agent: {ITERATIONS}")
        print(f"Warmup iterations: {WARMUP_ITERATIONS}")
        print("="*80 + "\n")
        
        # Benchmark each agent
        for agent_name in self.agents.keys():
            print(f"\nBenchmarking: {agent_name}")
            print("-"*40)
            
            times = await self.benchmark_agent(agent_name)
            stats = self.calculate_statistics(times)
            
            self.results[agent_name] = {
                "times": times,
                "stats": stats
            }
            
            if stats["mean"] > 0:
                print(f"\nStats: Mean={stats['mean']:.2f}ms, Median={stats['median']:.2f}ms, StdDev={stats['std']:.2f}ms")
    
    def print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*80)
        print("PYTHON AGENT BENCHMARK SUMMARY")
        print("="*80)
        
        # Prepare table data
        table_data = []
        headers = ["Agent", "Mean (ms)", "Median (ms)", "StdDev (ms)", "Min (ms)", "Max (ms)", "P95 (ms)"]
        
        for agent_name, data in self.results.items():
            stats = data["stats"]
            table_data.append([
                agent_name,
                f"{stats['mean']:.2f}",
                f"{stats['median']:.2f}",
                f"{stats['std']:.2f}",
                f"{stats['min']:.2f}",
                f"{stats['max']:.2f}",
                f"{stats['p95']:.2f}"
            ])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save benchmark results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"python_benchmark_results_{timestamp}.json"
        
        output = {
            "timestamp": datetime.now().isoformat(),
            "iterations": ITERATIONS,
            "warmup_iterations": WARMUP_ITERATIONS,
            "results": {}
        }
        
        for agent_name, data in self.results.items():
            output["results"][agent_name] = data["stats"]
        
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"\n💾 Results saved to: {filename}")

async def main():
    # Set up environment to suppress warnings
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    
    benchmark = PythonAgentBenchmark()
    await benchmark.run_benchmark()
    benchmark.print_summary()

if __name__ == "__main__":
    asyncio.run(main())