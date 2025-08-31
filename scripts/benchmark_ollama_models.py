#!/usr/bin/env python3
"""
Benchmark Ollama Models for Sentinel AI Agents

This script runs comprehensive benchmarks of all available Ollama models
with the Sentinel AI testing agents.
"""

import os
import sys
import json
import time
import asyncio
import statistics
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import argparse

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent / "sentinel_backend"))

import httpx
import requests


class OllamaModelBenchmark:
    """Benchmark Ollama models with Sentinel agents"""
    
    def __init__(self, iterations: int = 10, warmup: int = 2):
        self.iterations = iterations
        self.warmup = warmup
        self.results = {}
        self.api_base = "http://localhost:8002"  # Orchestration service
        self.ollama_base = "http://localhost:11434"
        
        # Test agents to benchmark
        self.test_agents = [
            "Functional-Positive-Agent",
            "Functional-Negative-Agent",
            "Security-Auth-Agent",
            "Security-Injection-Agent",
            "Data-Mocking-Agent"
        ]
        
        # Available Ollama models
        self.ollama_models = [
            "mistral:7b",
            "codellama:7b",
            "deepseek-coder:6.7b"
        ]
        
        # Test spec ID (should exist in your database)
        self.spec_id = 6  # PetStore API
    
    def check_ollama_status(self) -> bool:
        """Check if Ollama is running"""
        try:
            response = requests.get(f"{self.ollama_base}/api/tags", timeout=2)
            return response.status_code == 200
        except:
            return False
    
    def get_available_models(self) -> List[str]:
        """Get list of available Ollama models"""
        try:
            response = requests.get(f"{self.ollama_base}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", [])
                return [m.get("name", "") for m in models]
        except:
            pass
        return []
    
    def configure_ollama_model(self, model: str):
        """Configure the system to use a specific Ollama model"""
        env_path = Path(__file__).parent.parent / "sentinel_backend" / ".env"
        
        # Update environment
        env_vars = {}
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    if '=' in line and not line.startswith('#'):
                        key, value = line.strip().split('=', 1)
                        env_vars[key] = value
        
        env_vars['SENTINEL_APP_LLM_PROVIDER'] = 'ollama'
        env_vars['SENTINEL_APP_LLM_MODEL'] = model
        env_vars['SENTINEL_APP_OLLAMA_API_BASE'] = 'http://localhost:11434'
        
        with open(env_path, 'w') as f:
            for key, value in env_vars.items():
                f.write(f"{key}={value}\n")
        
        print(f"Configured to use Ollama model: {model}")
        
        # Note: In production, you'd restart the service here
        # For this benchmark, we'll use direct API calls with model specification
    
    async def benchmark_agent_with_model(self, agent: str, model: str) -> Dict[str, Any]:
        """Benchmark a specific agent with a specific Ollama model"""
        times = []
        test_counts = []
        errors = 0
        
        print(f"  Testing {agent} with {model}...")
        
        # Run iterations
        for i in range(self.iterations + self.warmup):
            try:
                start_time = time.time()
                
                # Make request to orchestration service
                # Note: This assumes the orchestration service can accept model specification
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.post(
                        f"{self.api_base}/generate-tests",
                        json={
                            "spec_id": self.spec_id,
                            "agent_types": [agent],
                            "parameters": {
                                "llm_model": model,
                                "llm_provider": "ollama"
                            }
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
                    else:
                        errors += 1
                        print(f"    Error: HTTP {response.status_code}")
                        
            except Exception as e:
                errors += 1
                print(f"    Error: {str(e)}")
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
                "runs": len(times),
                "errors": errors,
                "avg_tests": statistics.mean(test_counts) if test_counts else 0
            }
        else:
            return {
                "mean": 0,
                "median": 0,
                "min": 0,
                "max": 0,
                "std": 0,
                "runs": 0,
                "errors": errors,
                "avg_tests": 0
            }
    
    async def benchmark_with_direct_ollama(self, agent: str, model: str) -> Dict[str, Any]:
        """Benchmark by calling Ollama directly (bypass orchestration service)"""
        times = []
        token_counts = []
        errors = 0
        
        print(f"  Direct testing {agent} with {model}...")
        
        # Create a test prompt for the agent
        test_prompt = self._get_agent_prompt(agent)
        
        for i in range(self.iterations + self.warmup):
            try:
                start_time = time.time()
                
                # Call Ollama directly
                response = requests.post(
                    f"{self.ollama_base}/api/chat",
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": "You are an API testing expert."},
                            {"role": "user", "content": test_prompt}
                        ],
                        "stream": False,
                        "options": {
                            "temperature": 0.5,
                            "num_predict": 2000
                        }
                    },
                    timeout=60
                )
                
                elapsed = (time.time() - start_time) * 1000  # Convert to ms
                
                if response.status_code == 200:
                    result = response.json()
                    eval_count = result.get("eval_count", 0)
                    
                    # Skip warmup runs
                    if i >= self.warmup:
                        times.append(elapsed)
                        token_counts.append(eval_count)
                else:
                    errors += 1
                    
            except Exception as e:
                errors += 1
                print(f"    Error: {str(e)}")
                continue
            
            # Small delay
            await asyncio.sleep(0.1)
        
        # Calculate statistics
        if times:
            return {
                "mean": statistics.mean(times),
                "median": statistics.median(times),
                "min": min(times),
                "max": max(times),
                "std": statistics.stdev(times) if len(times) > 1 else 0,
                "runs": len(times),
                "errors": errors,
                "avg_tokens": statistics.mean(token_counts) if token_counts else 0,
                "tokens_per_second": statistics.mean([t/e*1000 for t, e in zip(token_counts, times)]) if token_counts else 0
            }
        else:
            return {
                "mean": 0,
                "median": 0,
                "min": 0,
                "max": 0,
                "std": 0,
                "runs": 0,
                "errors": errors,
                "avg_tokens": 0,
                "tokens_per_second": 0
            }
    
    def _get_agent_prompt(self, agent: str) -> str:
        """Get a test prompt for each agent type"""
        prompts = {
            "Functional-Positive-Agent": """Generate 5 positive test cases for a REST API with these endpoints:
                GET /pets - List all pets
                POST /pets - Create a new pet
                GET /pets/{id} - Get pet by ID
                Include valid test data and expected responses.""",
            
            "Functional-Negative-Agent": """Generate 5 negative test cases for the same REST API.
                Focus on boundary conditions, invalid inputs, and error scenarios.""",
            
            "Security-Auth-Agent": """Generate 5 security test cases focusing on authentication and authorization
                for a REST API. Include BOLA, function-level auth, and JWT tests.""",
            
            "Security-Injection-Agent": """Generate 5 injection vulnerability test cases for a REST API.
                Include SQL injection, NoSQL injection, and command injection tests.""",
            
            "Data-Mocking-Agent": """Generate realistic mock data for testing a pet store API.
                Include 5 different pet objects with varied attributes."""
        }
        
        return prompts.get(agent, "Generate test cases for a REST API")
    
    async def run_benchmarks(self, direct_mode: bool = False):
        """Run complete benchmark suite"""
        print("\n" + "="*60)
        print("OLLAMA MODEL BENCHMARKING FOR SENTINEL AI AGENTS")
        print("="*60)
        
        # Check Ollama status
        if not self.check_ollama_status():
            print("❌ Ollama is not running. Please start Ollama first.")
            return
        
        # Get available models
        available = self.get_available_models()
        print(f"\n📦 Available Ollama models: {', '.join(available)}")
        
        # Filter to only test available models
        models_to_test = [m for m in self.ollama_models if m in available]
        
        if not models_to_test:
            print("❌ None of the required models are available")
            print(f"   Please pull models: {', '.join(self.ollama_models)}")
            return
        
        print(f"\n🧪 Testing models: {', '.join(models_to_test)}")
        print(f"   Iterations: {self.iterations} (+ {self.warmup} warmup)")
        print(f"   Agents: {', '.join(self.test_agents)}")
        
        # Initialize results structure
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "configuration": {
                "iterations": self.iterations,
                "warmup": self.warmup,
                "agents": len(self.test_agents),
                "models": models_to_test,
                "mode": "direct" if direct_mode else "orchestration"
            },
            "model_results": {},
            "agent_results": {},
            "summary": {}
        }
        
        # Run benchmarks for each model
        for model in models_to_test:
            print(f"\n📊 Benchmarking model: {model}")
            self.results["model_results"][model] = {}
            
            for agent in self.test_agents:
                if direct_mode:
                    metrics = await self.benchmark_with_direct_ollama(agent, model)
                else:
                    metrics = await self.benchmark_agent_with_model(agent, model)
                
                self.results["model_results"][model][agent] = metrics
                
                # Also organize by agent
                if agent not in self.results["agent_results"]:
                    self.results["agent_results"][agent] = {}
                self.results["agent_results"][agent][model] = metrics
                
                print(f"    {agent}: {metrics['mean']:.2f}ms (±{metrics['std']:.2f})")
        
        # Generate summary
        self._generate_summary()
        
        # Save results
        self._save_results()
        
        # Print summary
        self._print_summary()
    
    def _generate_summary(self):
        """Generate summary statistics"""
        summary = {}
        
        # Best model per agent
        for agent in self.test_agents:
            agent_data = self.results["agent_results"].get(agent, {})
            if agent_data:
                best_model = min(agent_data.items(), key=lambda x: x[1]["mean"] if x[1]["mean"] > 0 else float('inf'))
                summary[agent] = {
                    "best_model": best_model[0],
                    "best_time": best_model[1]["mean"]
                }
        
        # Overall best model
        model_averages = {}
        for model in self.results["model_results"]:
            times = [m["mean"] for m in self.results["model_results"][model].values() if m["mean"] > 0]
            if times:
                model_averages[model] = statistics.mean(times)
        
        if model_averages:
            best_overall = min(model_averages.items(), key=lambda x: x[1])
            summary["overall_best"] = {
                "model": best_overall[0],
                "average_time": best_overall[1]
            }
        
        self.results["summary"] = summary
    
    def _save_results(self):
        """Save benchmark results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ollama_benchmark_results_{timestamp}.json"
        filepath = Path(__file__).parent / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Results saved to: {filepath}")
    
    def _print_summary(self):
        """Print summary of results"""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        
        # Print model comparison table
        print("\n📊 Model Performance (Average Response Time in ms):")
        print("-" * 60)
        
        # Header
        print(f"{'Agent':<30} ", end="")
        for model in self.results["configuration"]["models"]:
            model_name = model.split(":")[0]
            print(f"{model_name:<15} ", end="")
        print()
        print("-" * 60)
        
        # Data rows
        for agent in self.test_agents:
            agent_name = agent.replace("-Agent", "")[:28]
            print(f"{agent_name:<30} ", end="")
            
            for model in self.results["configuration"]["models"]:
                metrics = self.results["agent_results"].get(agent, {}).get(model, {})
                if metrics and metrics["mean"] > 0:
                    print(f"{metrics['mean']:>12.2f}ms ", end="")
                else:
                    print(f"{'N/A':>15} ", end="")
            print()
        
        # Summary
        summary = self.results.get("summary", {})
        if "overall_best" in summary:
            print(f"\n🏆 Overall Best Model: {summary['overall_best']['model']}")
            print(f"   Average time: {summary['overall_best']['average_time']:.2f}ms")
        
        print("\n📈 Best Model per Agent:")
        for agent in self.test_agents:
            if agent in summary:
                agent_name = agent.replace("-Agent", "")
                print(f"   {agent_name}: {summary[agent]['best_model']} ({summary[agent]['best_time']:.2f}ms)")


async def main():
    parser = argparse.ArgumentParser(description="Benchmark Ollama models with Sentinel agents")
    parser.add_argument("--iterations", type=int, default=10, help="Number of test iterations")
    parser.add_argument("--warmup", type=int, default=2, help="Number of warmup iterations")
    parser.add_argument("--direct", action="store_true", help="Use direct Ollama API calls (bypass orchestration)")
    
    args = parser.parse_args()
    
    benchmark = OllamaModelBenchmark(
        iterations=args.iterations,
        warmup=args.warmup
    )
    
    await benchmark.run_benchmarks(direct_mode=args.direct)


if __name__ == "__main__":
    asyncio.run(main())