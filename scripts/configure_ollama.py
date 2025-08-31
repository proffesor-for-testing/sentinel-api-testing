#!/usr/bin/env python3
"""
Configure Ollama LLM Provider

This script helps configure and test Ollama models for the Sentinel platform.
"""

import os
import sys
import json
import argparse
import requests
from typing import Optional, List, Dict, Any
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent / "sentinel_backend"))


def check_ollama_status(api_base: str = "http://localhost:11434") -> bool:
    """Check if Ollama is running"""
    try:
        response = requests.get(f"{api_base}/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False


def get_available_models(api_base: str = "http://localhost:11434") -> List[Dict[str, Any]]:
    """Get list of available Ollama models"""
    try:
        response = requests.get(f"{api_base}/api/tags", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get("models", [])
    except:
        pass
    return []


def test_model(model_name: str, api_base: str = "http://localhost:11434") -> Dict[str, Any]:
    """Test a specific model"""
    print(f"\nTesting model: {model_name}")
    
    test_prompt = "Generate a simple REST API test case for a GET /users endpoint"
    
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": "You are an API testing expert."},
            {"role": "user", "content": test_prompt}
        ],
        "stream": False,
        "options": {
            "temperature": 0.5,
            "num_predict": 500
        }
    }
    
    try:
        import time
        start_time = time.time()
        
        response = requests.post(
            f"{api_base}/api/chat",
            json=payload,
            timeout=30
        )
        
        elapsed_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            content = result.get("message", {}).get("content", "")
            eval_count = result.get("eval_count", 0)
            prompt_eval_count = result.get("prompt_eval_count", 0)
            
            return {
                "success": True,
                "model": model_name,
                "response_time": elapsed_time,
                "prompt_tokens": prompt_eval_count,
                "completion_tokens": eval_count,
                "total_tokens": prompt_eval_count + eval_count,
                "tokens_per_second": eval_count / elapsed_time if elapsed_time > 0 else 0,
                "response_preview": content[:200] + "..." if len(content) > 200 else content
            }
    except Exception as e:
        return {
            "success": False,
            "model": model_name,
            "error": str(e)
        }


def configure_environment(model: str, docker: bool = False):
    """Configure environment variables for Ollama"""
    env_file = ".env.docker" if docker else ".env"
    env_path = Path(__file__).parent.parent / "sentinel_backend" / env_file
    
    # Read existing environment
    env_vars = {}
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    env_vars[key] = value
    
    # Update Ollama configuration
    env_vars['SENTINEL_APP_LLM_PROVIDER'] = 'ollama'
    env_vars['SENTINEL_APP_LLM_MODEL'] = model
    env_vars['SENTINEL_APP_OLLAMA_API_BASE'] = 'http://host.docker.internal:11434' if docker else 'http://localhost:11434'
    
    # Write back
    with open(env_path, 'w') as f:
        for key, value in env_vars.items():
            f.write(f"{key}={value}\n")
    
    print(f"\n✅ Configured {env_file} to use Ollama with model: {model}")


def main():
    parser = argparse.ArgumentParser(description="Configure Ollama for Sentinel")
    parser.add_argument("--test", action="store_true", help="Test all available models")
    parser.add_argument("--model", help="Select a specific model")
    parser.add_argument("--docker", action="store_true", help="Configure for Docker environment")
    parser.add_argument("--api-base", default="http://localhost:11434", help="Ollama API base URL")
    parser.add_argument("--list", action="store_true", help="List available models")
    
    args = parser.parse_args()
    
    # Check Ollama status
    print("🔍 Checking Ollama status...")
    if not check_ollama_status(args.api_base):
        print("❌ Ollama is not running or not accessible")
        print(f"   Please ensure Ollama is running at {args.api_base}")
        return 1
    
    print("✅ Ollama is running")
    
    # Get available models
    models = get_available_models(args.api_base)
    if not models:
        print("❌ No models found in Ollama")
        print("   Please pull models using: ollama pull <model-name>")
        return 1
    
    print(f"\n📦 Found {len(models)} models:")
    available_models = []
    for model in models:
        name = model.get("name", "unknown")
        size = model.get("size", 0) / (1024**3)  # Convert to GB
        print(f"   - {name} ({size:.1f} GB)")
        available_models.append(name)
    
    if args.list:
        return 0
    
    # Test models
    if args.test:
        print("\n🧪 Testing all models...")
        results = []
        for model_name in available_models:
            result = test_model(model_name, args.api_base)
            results.append(result)
            
            if result["success"]:
                print(f"   ✅ {model_name}: {result['response_time']:.2f}s, {result['tokens_per_second']:.1f} tokens/s")
            else:
                print(f"   ❌ {model_name}: {result['error']}")
        
        # Find best performer
        successful = [r for r in results if r["success"]]
        if successful:
            best = min(successful, key=lambda x: x["response_time"])
            print(f"\n🏆 Best performer: {best['model']} ({best['response_time']:.2f}s)")
            
            if not args.model:
                args.model = best['model']
    
    # Configure selected model
    if args.model:
        if args.model not in available_models:
            print(f"\n❌ Model {args.model} not found")
            print(f"   Available models: {', '.join(available_models)}")
            return 1
        
        configure_environment(args.model, args.docker)
        
        # Create configuration file
        config_path = Path(__file__).parent.parent / "sentinel_backend" / "ollama_config.json"
        config = {
            "selected_model": args.model,
            "available_models": available_models,
            "api_base": args.api_base,
            "agent_models": {
                "Functional-Positive-Agent": "mistral:7b",
                "Functional-Negative-Agent": "codellama:7b",
                "Functional-Stateful-Agent": "deepseek-coder:6.7b",
                "Security-Auth-Agent": "deepseek-coder:6.7b",
                "Security-Injection-Agent": "deepseek-coder:6.7b",
                "Performance-Planner-Agent": "codellama:7b",
                "Data-Mocking-Agent": "mistral:7b"
            }
        }
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Saved configuration to {config_path}")
        print("\n📝 Next steps:")
        print("   1. Restart the Orchestration Service")
        if args.docker:
            print("   2. Rebuild and restart Docker containers:")
            print("      docker-compose build orchestration")
            print("      docker-compose up -d")
        else:
            print("   2. Run: cd sentinel_backend/orchestration_service && poetry run uvicorn main:app --reload")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())