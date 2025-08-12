#!/usr/bin/env python3
"""
LLM Provider Demo

Demonstrates how to use the multi-vendor LLM provider system.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sentinel_backend.llm_providers import LLMProviderFactory, LLMConfig, Message
from sentinel_backend.llm_providers.base_provider import LLMProvider
from sentinel_backend.config.settings import get_application_settings


async def demo_basic_generation():
    """Demonstrate basic text generation."""
    print("\n=== Basic Text Generation ===\n")
    
    # Example 1: Anthropic Claude (DEFAULT)
    if os.getenv("SENTINEL_APP_ANTHROPIC_API_KEY"):
        print("1. Anthropic Claude Sonnet 4 (Default):")
        config = LLMConfig(
            provider=LLMProvider.ANTHROPIC,
            model="claude-sonnet-4",
            api_key=os.getenv("SENTINEL_APP_ANTHROPIC_API_KEY"),
            temperature=0.7,
            max_tokens=150
        )
        
        provider = LLMProviderFactory.create_provider(config)
        
        messages = [
            Message(role="user", content="What are the key principles of API testing?")
        ]
        
        response = await provider.generate(messages)
        print(f"Response: {response.content[:200]}...")
        print(f"Tokens used: {response.total_tokens}")
        print(f"Estimated cost: ${response.estimated_cost:.6f}\n")
    
    # Example 2: OpenAI
    if os.getenv("SENTINEL_APP_OPENAI_API_KEY"):
        print("2. OpenAI GPT-3.5 Turbo:")
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            model="gpt-3.5-turbo",
            api_key=os.getenv("SENTINEL_APP_OPENAI_API_KEY"),
            temperature=0.5,
            max_tokens=100
        )
        
        provider = LLMProviderFactory.create_provider(config)
        
        messages = [
            Message(role="system", content="You are a helpful API testing assistant."),
            Message(role="user", content="Generate a simple REST API test case for a GET /users endpoint")
        ]
        
        response = await provider.generate(messages)
        print(f"Response: {response.content[:200]}...")
        print(f"Model: {response.model}\n")
    
    # Example 3: Ollama (Local)
    print("3. Ollama (Local Model):")
    config = LLMConfig(
        provider=LLMProvider.OLLAMA,
        model="mistral:7b",
        api_base="http://localhost:11434",
        temperature=0.7,
        max_tokens=100
    )
    
    try:
        provider = LLMProviderFactory.create_provider(config)
        
        # Check if model exists
        if await provider.model_exists():
            messages = [
                Message(role="user", content="What is API mocking?")
            ]
            
            response = await provider.generate(messages)
            print(f"Response: {response.content[:200]}...")
            print(f"Local inference - No API costs!\n")
        else:
            print(f"Model {config.model} not found. Run: ollama pull {config.model}\n")
    except Exception as e:
        print(f"Ollama not available: {e}\n")


async def demo_streaming():
    """Demonstrate streaming responses."""
    print("\n=== Streaming Response ===\n")
    
    if not os.getenv("SENTINEL_APP_OPENAI_API_KEY"):
        print("Skipping streaming demo (no OpenAI API key)\n")
        return
    
    config = LLMConfig(
        provider=LLMProvider.OPENAI,
        model="gpt-3.5-turbo",
        api_key=os.getenv("SENTINEL_APP_OPENAI_API_KEY")
    )
    
    provider = LLMProviderFactory.create_provider(config)
    
    messages = [
        Message(role="user", content="Write a short API test scenario")
    ]
    
    print("Streaming response: ", end="", flush=True)
    async for chunk in provider.stream_generate(messages):
        print(chunk, end="", flush=True)
    print("\n")


async def demo_fallback():
    """Demonstrate fallback mechanism."""
    print("\n=== Fallback Mechanism ===\n")
    
    # Create primary config with invalid API key
    primary_config = LLMConfig(
        provider=LLMProvider.OPENAI,
        model="gpt-3.5-turbo",
        api_key="invalid_key_to_trigger_fallback"
    )
    
    # Create fallback config (Ollama)
    fallback_config = LLMConfig(
        provider=LLMProvider.OLLAMA,
        model="mistral:7b",
        api_base="http://localhost:11434"
    )
    
    try:
        # Create provider with fallback
        provider = LLMProviderFactory.create_with_fallback(
            primary_config=primary_config,
            fallback_configs=[fallback_config]
        )
        
        messages = [
            Message(role="user", content="Hello!")
        ]
        
        print("Attempting generation with fallback...")
        response = await provider.generate(messages, max_tokens=20)
        print(f"Success! Used provider: {response.provider.value}")
        print(f"Response: {response.content}\n")
    except Exception as e:
        print(f"All providers failed: {e}\n")


async def demo_model_info():
    """Demonstrate model information retrieval."""
    print("\n=== Model Information ===\n")
    
    models_to_check = [
        ("openai", "gpt-4-turbo"),
        ("anthropic", "claude-opus-4.1"),
        ("ollama", "llama3.3:70b")
    ]
    
    for provider_name, model_name in models_to_check:
        try:
            config = LLMConfig(
                provider=LLMProvider(provider_name),
                model=model_name,
                api_key="dummy"  # Just for info, not making actual calls
            )
            
            provider = LLMProviderFactory.create_provider(config)
            info = provider.get_model_info()
            
            print(f"{info['display_name']}:")
            print(f"  Context Window: {info.get('context_window', 'N/A'):,} tokens")
            print(f"  Max Output: {info.get('max_output_tokens', 'N/A')}")
            if 'pricing' in info:
                pricing = info['pricing']
                print(f"  Cost: ${pricing.get('input_per_1k', 0):.4f} input / ${pricing.get('output_per_1k', 0):.4f} output per 1K tokens")
            print()
        except Exception as e:
            print(f"Could not get info for {model_name}: {e}\n")


async def demo_agent_integration():
    """Demonstrate agent integration with LLM."""
    print("\n=== Agent Integration Demo ===\n")
    
    from sentinel_backend.orchestration_service.agents.llm_functional_positive_agent import (
        LLMFunctionalPositiveAgent
    )
    from sentinel_backend.orchestration_service.agents.base_agent import AgentTask
    
    # Create a sample API spec
    api_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Sample API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get all users",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "minimum": 1, "maximum": 100}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Success"}
                    }
                },
                "post": {
                    "summary": "Create a new user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name", "email"],
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string", "format": "email"},
                                        "age": {"type": "integer", "minimum": 0}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Created"}
                    }
                }
            }
        }
    }
    
    # Create task
    task = AgentTask(
        task_id="demo_task_001",
        spec_id=1,
        agent_type="LLM-Functional-Positive-Agent",
        parameters={}
    )
    
    # Test without LLM (deterministic only)
    print("1. Deterministic Generation (no LLM):")
    agent_no_llm = LLMFunctionalPositiveAgent(use_llm=False)
    result = await agent_no_llm.execute(task, api_spec)
    print(f"   Generated {len(result.test_cases)} test cases")
    print(f"   Status: {result.status}")
    
    # Test with LLM (if configured)
    if os.getenv("SENTINEL_APP_OPENAI_API_KEY") or os.getenv("SENTINEL_APP_ANTHROPIC_API_KEY"):
        print("\n2. Hybrid Generation (with LLM):")
        agent_with_llm = LLMFunctionalPositiveAgent(use_llm=True)
        result = await agent_with_llm.execute(task, api_spec)
        print(f"   Generated {len(result.test_cases)} test cases")
        print(f"   LLM Enhanced: {result.metadata.get('llm_enhanced', False)}")
        print(f"   Creative Tests: {result.metadata.get('llm_creative_tests', 0)}")
        
        # Show sample test case
        if result.test_cases:
            print("\n   Sample LLM-Enhanced Test Case:")
            test = result.test_cases[0]
            print(f"   - Endpoint: {test['method']} {test['endpoint']}")
            print(f"   - Description: {test['description']}")
            if test.get('body'):
                print(f"   - Body: {test['body']}")


async def main():
    """Run all demos."""
    print("\n" + "="*60)
    print(" LLM Provider System Demo")
    print("="*60)
    
    # Check for API keys
    has_anthropic = bool(os.getenv("SENTINEL_APP_ANTHROPIC_API_KEY"))
    has_openai = bool(os.getenv("SENTINEL_APP_OPENAI_API_KEY"))
    
    print("\nConfiguration:")
    print(f"  Anthropic API Key (Default): {'✓ Configured' if has_anthropic else '✗ Not configured'}")
    print(f"  OpenAI API Key: {'✓ Configured' if has_openai else '✗ Not configured'}")
    print(f"  Ollama: Assuming localhost:11434")
    
    if not has_anthropic:
        print("\nNote: Set SENTINEL_APP_ANTHROPIC_API_KEY environment variable")
        print("      to use the default Claude Sonnet 4 model.")
        if not has_openai:
            print("      Alternatively, set SENTINEL_APP_OPENAI_API_KEY for OpenAI models.")
    
    # Run demos
    await demo_basic_generation()
    await demo_streaming()
    await demo_fallback()
    await demo_model_info()
    await demo_agent_integration()
    
    print("\n" + "="*60)
    print(" Demo Complete!")
    print("="*60 + "\n")


if __name__ == "__main__":
    # Set up environment variables if needed
    # os.environ["SENTINEL_APP_OPENAI_API_KEY"] = "your-key-here"
    # os.environ["SENTINEL_APP_ANTHROPIC_API_KEY"] = "your-key-here"
    
    asyncio.run(main())