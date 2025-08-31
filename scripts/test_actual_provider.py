#!/usr/bin/env python3
"""
Test which LLM provider is actually being used
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent.parent / "sentinel_backend"))

# Import the provider factory
from sentinel_backend.llm_providers.provider_factory import LLMProviderFactory
from sentinel_backend.llm_providers.base_provider import LLMConfig, LLMProvider
from sentinel_backend.config.settings import get_application_settings

# Get current settings
app_settings = get_application_settings()

print("="*60)
print("TESTING ACTUAL LLM PROVIDER")
print("="*60)

print(f"\nEnvironment Configuration:")
print(f"  Provider: {app_settings.llm_provider}")
print(f"  Model: {app_settings.llm_model}")
print(f"  Has Anthropic Key: {bool(app_settings.anthropic_api_key)}")

# Create provider config
config = LLMConfig(
    provider=LLMProvider(app_settings.llm_provider),
    model=app_settings.llm_model,
    api_key=app_settings.anthropic_api_key if app_settings.llm_provider == "anthropic" else None,
    temperature=0.5,
    max_tokens=1000
)

print(f"\nCreating provider...")
try:
    provider = LLMProviderFactory.create_provider(config)
    print(f"  Provider class: {provider.__class__.__name__}")
    
    # Test with actual generation
    print(f"\nTesting generation...")
    start = time.time()
    
    test_prompt = "Generate a simple test case for GET /users endpoint. Reply with just the test."
    
    response = provider.generate(
        prompt=test_prompt,
        system_prompt="You are an API testing assistant. Be concise."
    )
    
    elapsed = time.time() - start
    
    print(f"  Response time: {elapsed*1000:.0f}ms")
    print(f"  Response length: {len(response.content)} chars")
    print(f"  Provider used: {response.provider}")
    print(f"  Model used: {response.model}")
    
    # Show first 200 chars of response
    print(f"\n  Response preview:")
    print(f"  {response.content[:200]}...")
    
    # Determine actual provider based on response time
    print(f"\n🎯 Analysis:")
    if elapsed < 0.01:  # Less than 10ms
        print(f"  ✅ Definitely Mock provider (instant response)")
    elif elapsed < 0.5:  # Less than 500ms
        print(f"  ⚠️  Possibly Mock or cached response")
    elif elapsed < 5:  # Less than 5 seconds
        print(f"  ✅ Likely Anthropic API ({elapsed:.2f}s is typical)")
    else:
        print(f"  ✅ Likely Ollama or slow API ({elapsed:.2f}s)")
        
except Exception as e:
    print(f"  ❌ Error: {str(e)}")
    print(f"  This might mean the provider is not properly configured")