#!/usr/bin/env python3
"""
Quick Ollama Model Benchmark

A faster benchmark script that tests Ollama models with shorter prompts
and provides progress updates.
"""

import os
import sys
import json
import time
import requests
from typing import Dict, List, Any
from pathlib import Path
from datetime import datetime
import statistics

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))


class QuickOllamaBenchmark:
    """Quick benchmarking for Ollama models"""
    
    def __init__(self, iterations: int = 10):
        self.iterations = iterations
        self.ollama_base = "http://localhost:11434"
        self.results = {}
        
        # Available models
        self.models = [
            "mistral:7b",
            "codellama:7b", 
            "deepseek-coder:6.7b"
        ]
        
        # Shorter test prompts for faster execution
        self.test_prompts = {
            "simple": "Generate a REST API test: GET /users returns 200 OK",
            "code": "Write a test function for POST /api/login endpoint",
            "security": "List 3 security test cases for an API endpoint"
        }
    
    def test_model(self, model: str, prompt_type: str = "simple") -> Dict[str, Any]:
        """Test a single model with a simple prompt"""
        prompt = self.test_prompts[prompt_type]
        
        try:
            start_time = time.time()
            
            response = requests.post(
                f"{self.ollama_base}/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.5,
                        "num_predict": 200  # Limit tokens for speed
                    }
                },
                timeout=30
            )
            
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                tokens = result.get("eval_count", 0)
                return {
                    "success": True,
                    "time": elapsed,
                    "tokens": tokens,
                    "tokens_per_sec": tokens / elapsed if elapsed > 0 else 0
                }
            else:
                return {"success": False, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def run_benchmark(self):
        """Run the benchmark for all models"""
        print("\n" + "="*60)
        print("QUICK OLLAMA MODEL BENCHMARK (10 ROUNDS)")
        print("="*60)
        
        # Check Ollama status
        try:
            response = requests.get(f"{self.ollama_base}/api/tags", timeout=2)
            if response.status_code != 200:
                print("❌ Ollama is not running")
                return
            print("✅ Ollama is running\n")
        except:
            print("❌ Cannot connect to Ollama")
            return
        
        # Initialize results
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "iterations": self.iterations,
            "models": {}
        }
        
        # Test each model
        for model in self.models:
            print(f"\n📊 Testing {model}...")
            model_times = []
            model_tokens = []
            errors = 0
            
            # Progress bar setup
            for i in range(self.iterations):
                # Rotate through prompt types for variety
                prompt_type = ["simple", "code", "security"][i % 3]
                
                print(f"  Round {i+1}/{self.iterations}: ", end="", flush=True)
                result = self.test_model(model, prompt_type)
                
                if result["success"]:
                    model_times.append(result["time"])
                    model_tokens.append(result["tokens_per_sec"])
                    print(f"✓ {result['time']:.2f}s", flush=True)
                else:
                    errors += 1
                    print(f"✗ {result['error']}", flush=True)
                
                # Small delay between requests
                time.sleep(0.5)
            
            # Calculate statistics
            if model_times:
                self.results["models"][model] = {
                    "mean_time": statistics.mean(model_times),
                    "median_time": statistics.median(model_times),
                    "min_time": min(model_times),
                    "max_time": max(model_times),
                    "std_time": statistics.stdev(model_times) if len(model_times) > 1 else 0,
                    "mean_tokens_per_sec": statistics.mean(model_tokens) if model_tokens else 0,
                    "successful_runs": len(model_times),
                    "errors": errors
                }
                
                print(f"\n  Summary for {model}:")
                print(f"    Mean: {self.results['models'][model]['mean_time']:.2f}s")
                print(f"    Tokens/sec: {self.results['models'][model]['mean_tokens_per_sec']:.1f}")
                print(f"    Success rate: {len(model_times)}/{self.iterations}")
        
        # Find best performer
        if self.results["models"]:
            best_model = min(
                self.results["models"].items(),
                key=lambda x: x[1]["mean_time"]
            )
            self.results["best_model"] = {
                "name": best_model[0],
                "mean_time": best_model[1]["mean_time"]
            }
        
        # Save results
        self.save_results()
        
        # Print summary
        self.print_summary()
    
    def save_results(self):
        """Save results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ollama_quick_benchmark_{timestamp}.json"
        filepath = Path(__file__).parent / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n💾 Results saved to: {filepath}")
    
    def print_summary(self):
        """Print benchmark summary"""
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        
        if not self.results.get("models"):
            print("No results collected")
            return
        
        # Create comparison table
        print("\n📊 Model Comparison (10 rounds each):")
        print("-" * 50)
        print(f"{'Model':<20} {'Mean Time':<12} {'Tokens/sec':<12} {'Success'}")
        print("-" * 50)
        
        for model, stats in self.results["models"].items():
            model_name = model.split(":")[0]
            mean_time = stats["mean_time"]
            tokens_sec = stats["mean_tokens_per_sec"]
            success = stats["successful_runs"]
            
            print(f"{model_name:<20} {mean_time:>10.2f}s {tokens_sec:>10.1f} {success:>7}/{self.iterations}")
        
        # Best performer
        if "best_model" in self.results:
            print(f"\n🏆 Best Performer: {self.results['best_model']['name']}")
            print(f"   Average time: {self.results['best_model']['mean_time']:.2f}s")
        
        # Performance ranking
        print("\n📈 Performance Ranking:")
        sorted_models = sorted(
            self.results["models"].items(),
            key=lambda x: x[1]["mean_time"]
        )
        for i, (model, stats) in enumerate(sorted_models, 1):
            print(f"   {i}. {model}: {stats['mean_time']:.2f}s")


def main():
    """Run the quick benchmark"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Quick Ollama benchmark")
    parser.add_argument("--iterations", type=int, default=10,
                       help="Number of iterations per model (default: 10)")
    
    args = parser.parse_args()
    
    benchmark = QuickOllamaBenchmark(iterations=args.iterations)
    benchmark.run_benchmark()


if __name__ == "__main__":
    main()