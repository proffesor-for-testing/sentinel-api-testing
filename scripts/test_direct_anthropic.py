#!/usr/bin/env python3
"""
Test Anthropic API directly to verify response times
"""

import os
import time
import httpx

# Set up Anthropic API key from environment
api_key = os.environ.get("SENTINEL_APP_ANTHROPIC_API_KEY", "")

print("Testing direct Anthropic API call...")
print("="*50)

# Prepare request
headers = {
    "x-api-key": api_key,
    "anthropic-version": "2023-06-01",
    "content-type": "application/json"
}

data = {
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1000,
    "messages": [
        {
            "role": "user",
            "content": "Generate a simple test case for a GET /users API endpoint. Reply with just the test."
        }
    ]
}

try:
    # Make direct API call
    start_time = time.time()
    
    with httpx.Client() as client:
        response = client.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=data,
            timeout=30.0
        )
    
    elapsed = time.time() - start_time
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Time: {elapsed*1000:.0f}ms ({elapsed:.2f}s)")
    
    if response.status_code == 200:
        result = response.json()
        content = result.get("content", [{}])[0].get("text", "")
        print(f"Response Length: {len(content)} characters")
        print(f"\nFirst 200 chars of response:")
        print(content[:200])
    else:
        print(f"Error: {response.text}")
    
    print("\n" + "="*50)
    print("Analysis:")
    if elapsed < 0.5:
        print(f"⚠️  {elapsed*1000:.0f}ms is too fast for real Anthropic API")
        print("    This might be cached or mock response")
    elif elapsed >= 0.5 and elapsed < 5:
        print(f"✅ {elapsed:.2f}s is typical for Anthropic API")
    else:
        print(f"⚠️  {elapsed:.2f}s is slower than usual for Anthropic")
        
except Exception as e:
    print(f"Error: {str(e)}")