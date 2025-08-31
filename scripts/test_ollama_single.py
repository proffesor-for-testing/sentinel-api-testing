#!/usr/bin/env python3
"""
Single quick test for each Ollama model
"""

import requests
import time
import json
from datetime import datetime

def test_model(model_name):
    """Test a single model with one request"""
    print(f"\nTesting {model_name}...")
    
    start = time.time()
    
    response = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": model_name,
            "messages": [
                {"role": "user", "content": "Write a simple API test for GET /users"}
            ],
            "stream": False,
            "options": {
                "temperature": 0.5,
                "num_predict": 100  # Very short for quick test
            }
        },
        timeout=60
    )
    
    elapsed = time.time() - start
    
    if response.status_code == 200:
        result = response.json()
        tokens = result.get("eval_count", 0)
        print(f"✅ {model_name}: {elapsed:.2f}s, {tokens} tokens, {tokens/elapsed:.1f} tokens/sec")
        return {"model": model_name, "time": elapsed, "tokens": tokens, "tokens_per_sec": tokens/elapsed}
    else:
        print(f"❌ {model_name}: Failed with status {response.status_code}")
        return None

# Test all three models
models = ["mistral:7b", "codellama:7b", "deepseek-coder:6.7b"]
results = []

print("="*50)
print("OLLAMA MODELS - SINGLE TEST")
print("="*50)

for model in models:
    result = test_model(model)
    if result:
        results.append(result)
    time.sleep(1)  # Brief pause between tests

# Summary
if results:
    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    
    # Sort by speed
    results.sort(key=lambda x: x["time"])
    
    print("\nRanking by speed:")
    for i, r in enumerate(results, 1):
        print(f"{i}. {r['model']}: {r['time']:.2f}s ({r['tokens_per_sec']:.1f} tokens/sec)")
    
    # Save results
    with open("ollama_single_test_results.json", "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "results": results
        }, f, indent=2)
    
    print("\n✅ Results saved to ollama_single_test_results.json")