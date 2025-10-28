#!/usr/bin/env python3
"""
Test LLM Enhancement for Sentinel Agents

This script demonstrates the difference between:
1. Basic test generation (without LLM)
2. LLM-enhanced test generation (with Claude/GPT)
"""

import asyncio
import json
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "sentinel_backend"))

from dotenv import load_dotenv
load_dotenv()

# Import agent and provider classes
from orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from orchestration_service.agents.base_agent import AgentTask
from llm_providers import LLMProviderFactory, LLMConfig, LLMProvider
from llm_providers.base_provider import Message
from config.settings import get_application_settings


# Sample API specification
SAMPLE_API_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Pet Store API",
        "version": "1.0.0"
    },
    "paths": {
        "/pets": {
            "get": {
                "summary": "List all pets",
                "operationId": "listPets",
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "description": "How many items to return",
                        "required": False,
                        "schema": {
                            "type": "integer",
                            "format": "int32",
                            "minimum": 1,
                            "maximum": 100
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "A list of pets",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "integer"},
                                            "name": {"type": "string"},
                                            "tag": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "post": {
                "summary": "Create a pet",
                "operationId": "createPet",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": {"type": "string", "example": "Fluffy"},
                                    "tag": {"type": "string", "example": "cat"}
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Pet created successfully"
                    }
                }
            }
        }
    }
}


async def test_basic_generation():
    """Test basic test generation without LLM."""
    print("\n" + "="*80)
    print("🔧 BASIC TEST GENERATION (No LLM)")
    print("="*80)

    # Create agent without LLM
    agent = FunctionalPositiveAgent("functional_positive")
    agent.llm_enabled = False  # Force disable LLM

    # Create task
    task = AgentTask(
        task_id="test_basic",
        spec_id=1,
        agent_type="functional_positive",
        parameters={}
    )

    # Execute
    result = await agent.execute(task, SAMPLE_API_SPEC)

    print(f"\n✅ Generated {len(result.test_cases)} test cases")
    print(f"📊 Status: {result.status}")

    print("\n📝 Sample Test Case (Basic):")
    if result.test_cases:
        print(json.dumps(result.test_cases[0], indent=2))

    return result


async def test_llm_enhanced_generation():
    """Test LLM-enhanced test generation."""
    print("\n" + "="*80)
    print("🤖 LLM-ENHANCED TEST GENERATION")
    print("="*80)

    # Get settings
    settings = get_application_settings()

    print(f"\n🔧 Configuration:")
    print(f"   Provider: {settings.llm_provider}")
    print(f"   Model: {settings.llm_model}")
    print(f"   Temperature: {settings.llm_temperature}")
    print(f"   Max Tokens: {settings.llm_max_tokens}")

    # Create agent with LLM
    agent = FunctionalPositiveAgent("functional_positive_llm")

    if not agent.llm_enabled:
        print("\n⚠️  WARNING: LLM not enabled. Checking configuration...")
        print(f"   llm_provider: {settings.llm_provider}")
        print(f"   anthropic_api_key: {'SET' if settings.anthropic_api_key else 'NOT SET'}")
        return None

    print(f"\n✅ LLM Provider initialized: {agent.llm_provider.config.provider.value}")

    # Create task
    task = AgentTask(
        task_id="test_llm",
        spec_id=1,
        agent_type="functional_positive",
        parameters={}
    )

    # Execute basic generation
    print("\n⏳ Generating basic test cases...")
    result = await agent.execute(task, SAMPLE_API_SPEC)

    print(f"\n✅ Generated {len(result.test_cases)} test cases")

    # Now enhance one test case with LLM
    if result.test_cases:
        print("\n⏳ Enhancing test case with LLM...")

        basic_test = result.test_cases[0]

        enhanced_test = await agent.enhance_with_llm(
            data=basic_test,
            prompt="Enhance this API test case with more realistic data, better descriptions, and additional edge case assertions. Maintain the same structure but make it more comprehensive.",
            system_prompt="You are an expert API testing engineer. Enhance test cases to be more thorough and realistic while maintaining valid JSON structure.",
            temperature=0.7
        )

        print("\n📝 COMPARISON:")
        print("\n" + "-"*80)
        print("BASIC TEST CASE:")
        print("-"*80)
        print(json.dumps(basic_test, indent=2))

        print("\n" + "-"*80)
        print("LLM-ENHANCED TEST CASE:")
        print("-"*80)
        if isinstance(enhanced_test, dict):
            print(json.dumps(enhanced_test, indent=2))
        else:
            print(enhanced_test)

        # Generate creative variants
        print("\n" + "="*80)
        print("🎨 CREATIVE VARIANTS")
        print("="*80)

        for variant_type in ["realistic", "edge_case", "unusual"]:
            print(f"\n⏳ Generating {variant_type} variant...")
            variant = await agent.generate_creative_variant(basic_test, variant_type)

            if variant:
                print(f"\n📝 {variant_type.upper()} VARIANT:")
                print(json.dumps(variant, indent=2))

    return result


async def test_llm_connection():
    """Test direct LLM connection."""
    print("\n" + "="*80)
    print("🔌 TESTING LLM CONNECTION")
    print("="*80)

    try:
        settings = get_application_settings()

        print(f"\n🔧 Settings loaded:")
        print(f"   Provider: {settings.llm_provider}")
        print(f"   Model: {settings.llm_model}")
        print(f"   API Key: {'✓ SET' if settings.anthropic_api_key else '✗ NOT SET'}")

        # Create LLM config
        config = LLMConfig(
            provider=LLMProvider(settings.llm_provider),
            model=settings.llm_model,
            api_key=settings.anthropic_api_key,
            temperature=settings.llm_temperature,
            max_tokens=100,  # Small for health check
            timeout=30
        )

        print(f"\n⏳ Creating provider: {config.provider.value}")
        provider = LLMProviderFactory.create_provider(config)

        print(f"✅ Provider created: {provider.__class__.__name__}")

        # Health check
        print("\n⏳ Running health check...")
        is_healthy = await provider.health_check()

        if is_healthy:
            print("✅ LLM provider is HEALTHY and responding!")

            # Test generation
            print("\n⏳ Testing generation...")
            response = await provider.generate([
                Message(role="user", content="Say 'Hello from Sentinel API Testing!'")
            ])

            print(f"\n✅ Response received:")
            print(f"   Content: {response.content}")
            print(f"   Tokens: {response.total_tokens}")
            print(f"   Cost: ${response.estimated_cost:.4f}")

            return True
        else:
            print("❌ LLM provider health check FAILED")
            return False

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("🧪 SENTINEL LLM ENHANCEMENT TEST SUITE")
    print("="*80)

    # Test 1: LLM Connection
    print("\n📍 Test 1: LLM Connection")
    connection_ok = await test_llm_connection()

    if not connection_ok:
        print("\n❌ LLM connection failed. Cannot proceed with enhancement tests.")
        return

    # Test 2: Basic Generation
    print("\n📍 Test 2: Basic Test Generation")
    basic_result = await test_basic_generation()

    # Test 3: LLM Enhanced Generation
    print("\n📍 Test 3: LLM-Enhanced Test Generation")
    enhanced_result = await test_llm_enhanced_generation()

    # Summary
    print("\n" + "="*80)
    print("📊 SUMMARY")
    print("="*80)
    print(f"✅ LLM Connection: {'PASSED' if connection_ok else 'FAILED'}")
    print(f"✅ Basic Generation: {len(basic_result.test_cases) if basic_result else 0} test cases")
    print(f"✅ LLM Enhancement: {'ENABLED' if enhanced_result else 'DISABLED'}")

    print("\n" + "="*80)
    print("✨ Test Complete!")
    print("="*80)


if __name__ == "__main__":
    asyncio.run(main())
