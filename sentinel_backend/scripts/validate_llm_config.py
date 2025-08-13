#!/usr/bin/env python3
"""
LLM Configuration Validation Script

Validates LLM provider configuration and tests connectivity.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from sentinel_backend.llm_providers import LLMProviderFactory, LLMConfig
from sentinel_backend.llm_providers.base_provider import LLMProvider, Message
from sentinel_backend.config.settings import get_application_settings


class LLMConfigValidator:
    """Validates LLM configuration and tests providers"""
    
    def __init__(self):
        self.settings = get_application_settings()
        self.results = {}
        
    def print_header(self, text: str):
        """Print a formatted header"""
        print("\n" + "=" * 60)
        print(f" {text}")
        print("=" * 60)
    
    def print_status(self, item: str, status: bool, details: str = ""):
        """Print status with color"""
        symbol = "✓" if status else "✗"
        color = "\033[92m" if status else "\033[91m"  # Green or Red
        reset = "\033[0m"
        
        status_text = f"{color}{symbol}{reset}"
        print(f"  {status_text} {item}")
        if details:
            print(f"    {details}")
    
    def validate_environment(self) -> Dict[str, bool]:
        """Validate environment configuration"""
        self.print_header("Environment Configuration")
        
        results = {}
        
        # Check provider
        provider = self.settings.llm_provider
        if provider and provider != "none":
            self.print_status(f"Provider: {provider}", True)
            results["provider"] = True
        else:
            self.print_status("Provider", False, "No provider configured")
            results["provider"] = False
        
        # Check model
        model = self.settings.llm_model
        if model:
            self.print_status(f"Model: {model}", True)
            results["model"] = True
        else:
            self.print_status("Model", False, "No model configured")
            results["model"] = False
        
        # Check API keys
        api_keys = {
            "openai": self.settings.openai_api_key,
            "anthropic": self.settings.anthropic_api_key,
            "google": self.settings.google_api_key,
            "mistral": self.settings.mistral_api_key
        }
        
        configured_keys = [k for k, v in api_keys.items() if v]
        if configured_keys:
            for key_type in configured_keys:
                masked_key = api_keys[key_type][:10] + "..." if api_keys[key_type] else ""
                self.print_status(f"{key_type.capitalize()} API Key", True, f"Configured ({masked_key})")
            results["api_keys"] = True
        else:
            if provider not in ["ollama", "vllm", "none"]:
                self.print_status("API Keys", False, "No API keys configured")
                results["api_keys"] = False
            else:
                results["api_keys"] = True  # Not needed for local providers
        
        # Check fallback configuration
        if self.settings.llm_fallback_enabled:
            fallback_providers = self.settings.llm_fallback_providers
            self.print_status(
                "Fallback", 
                True, 
                f"Enabled with {len(fallback_providers)} providers: {', '.join(fallback_providers)}"
            )
            results["fallback"] = True
        else:
            self.print_status("Fallback", False, "Disabled")
            results["fallback"] = False
        
        return results
    
    async def test_provider(
        self, 
        provider: str, 
        model: str, 
        api_key: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Test a specific provider"""
        try:
            # Create configuration
            config = LLMConfig(
                provider=LLMProvider(provider),
                model=model,
                api_key=api_key,
                max_tokens=10,
                temperature=0.0
            )
            
            # Create provider
            llm_provider = LLMProviderFactory.create_provider(config)
            
            # Test generation
            messages = [Message(role="user", content="Hi")]
            response = await llm_provider.generate(messages)
            
            if response and response.content:
                return True, f"Response: {response.content[:50]}..."
            else:
                return False, "Empty response"
                
        except Exception as e:
            return False, f"Error: {str(e)[:100]}"
    
    async def test_configured_provider(self) -> bool:
        """Test the configured primary provider"""
        self.print_header("Testing Primary Provider")
        
        if not self.settings.llm_provider or self.settings.llm_provider == "none":
            self.print_status("Primary Provider", False, "No provider configured")
            return False
        
        # Get API key
        api_key = None
        if self.settings.llm_provider == "openai":
            api_key = self.settings.openai_api_key
        elif self.settings.llm_provider == "anthropic":
            api_key = self.settings.anthropic_api_key
        elif self.settings.llm_provider == "google":
            api_key = self.settings.google_api_key
        elif self.settings.llm_provider == "mistral":
            api_key = self.settings.mistral_api_key
        
        # Test the provider
        success, details = await self.test_provider(
            self.settings.llm_provider,
            self.settings.llm_model,
            api_key
        )
        
        self.print_status(
            f"{self.settings.llm_provider.capitalize()} ({self.settings.llm_model})",
            success,
            details
        )
        
        return success
    
    async def test_fallback_providers(self) -> Dict[str, bool]:
        """Test fallback providers"""
        if not self.settings.llm_fallback_enabled:
            return {}
        
        self.print_header("Testing Fallback Providers")
        
        results = {}
        for provider in self.settings.llm_fallback_providers:
            # Skip if same as primary
            if provider == self.settings.llm_provider:
                continue
            
            # Get model and API key
            model = self.settings.llm_fallback_models.get(provider, "gpt-3.5-turbo")
            api_key = None
            
            if provider == "openai":
                api_key = self.settings.openai_api_key
            elif provider == "anthropic":
                api_key = self.settings.anthropic_api_key
            elif provider == "google":
                api_key = self.settings.google_api_key
            elif provider == "mistral":
                api_key = self.settings.mistral_api_key
            
            # Test the provider
            success, details = await self.test_provider(provider, model, api_key)
            self.print_status(f"{provider.capitalize()} ({model})", success, details)
            results[provider] = success
        
        return results
    
    def test_model_registry(self):
        """Test model registry"""
        self.print_header("Model Registry")
        
        from sentinel_backend.llm_providers.model_registry import MODEL_REGISTRY
        
        total_models = len(MODEL_REGISTRY)
        providers = {}
        
        for model_key, spec in MODEL_REGISTRY.items():
            provider = spec.provider.value
            if provider not in providers:
                providers[provider] = []
            providers[provider].append(model_key)
        
        self.print_status(f"Total Models", True, f"{total_models} models registered")
        
        for provider, models in providers.items():
            self.print_status(f"{provider.capitalize()}", True, f"{len(models)} models")
    
    async def test_agent_integration(self):
        """Test agent LLM integration"""
        self.print_header("Agent Integration")
        
        try:
            from sentinel_backend.orchestration_service.agents.functional_positive_agent import (
                FunctionalPositiveAgent
            )
            
            agent = FunctionalPositiveAgent()
            
            if agent.llm_enabled:
                self.print_status(
                    "Agent LLM Integration",
                    True,
                    f"Enabled with {self.settings.llm_provider}"
                )
                
                # Test enhance_with_llm
                test_data = {"test": "data"}
                enhanced = await agent.enhance_with_llm(
                    test_data,
                    "Return the same data",
                    temperature=0.0
                )
                
                if enhanced:
                    self.print_status("enhance_with_llm()", True, "Working")
                else:
                    self.print_status("enhance_with_llm()", False, "No response")
            else:
                self.print_status(
                    "Agent LLM Integration",
                    False,
                    "LLM not enabled in agent"
                )
                
        except Exception as e:
            self.print_status("Agent Integration", False, str(e))
    
    def generate_recommendations(self, results: Dict):
        """Generate configuration recommendations"""
        self.print_header("Recommendations")
        
        recommendations = []
        
        # Check if provider is configured
        if not results.get("env_validation", {}).get("provider"):
            recommendations.append(
                "Configure an LLM provider:\n"
                "  export SENTINEL_APP_LLM_PROVIDER=anthropic"
            )
        
        # Check if API key is configured
        if not results.get("env_validation", {}).get("api_keys"):
            provider = self.settings.llm_provider
            if provider == "anthropic":
                recommendations.append(
                    "Set Anthropic API key:\n"
                    "  export SENTINEL_APP_ANTHROPIC_API_KEY=sk-ant-..."
                )
            elif provider == "openai":
                recommendations.append(
                    "Set OpenAI API key:\n"
                    "  export SENTINEL_APP_OPENAI_API_KEY=sk-..."
                )
        
        # Check if primary provider test failed
        if not results.get("primary_test"):
            recommendations.append(
                "Primary provider test failed. Check:\n"
                "  - API key is valid\n"
                "  - Model name is correct\n"
                "  - Network connectivity"
            )
        
        # Suggest enabling fallback
        if not results.get("env_validation", {}).get("fallback"):
            recommendations.append(
                "Consider enabling fallback for high availability:\n"
                "  export SENTINEL_APP_LLM_FALLBACK_ENABLED=true"
            )
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"\n{i}. {rec}")
        else:
            print("\n✓ Configuration looks good!")
    
    async def run_validation(self):
        """Run complete validation"""
        print("\n" + "=" * 60)
        print(" LLM Configuration Validator")
        print("=" * 60)
        
        results = {}
        
        # Validate environment
        results["env_validation"] = self.validate_environment()
        
        # Test model registry
        self.test_model_registry()
        
        # Test primary provider
        if results["env_validation"].get("provider"):
            results["primary_test"] = await self.test_configured_provider()
        else:
            results["primary_test"] = False
        
        # Test fallback providers
        if results["env_validation"].get("fallback"):
            results["fallback_tests"] = await self.test_fallback_providers()
        
        # Test agent integration
        if results.get("primary_test"):
            await self.test_agent_integration()
        
        # Generate recommendations
        self.generate_recommendations(results)
        
        # Summary
        self.print_header("Summary")
        
        all_good = (
            results["env_validation"].get("provider", False) and
            results.get("primary_test", False)
        )
        
        if all_good:
            print("\n✅ LLM configuration is valid and working!")
            print(f"   Provider: {self.settings.llm_provider}")
            print(f"   Model: {self.settings.llm_model}")
        else:
            print("\n⚠️  Configuration needs attention.")
            print("   Please review the recommendations above.")
        
        return 0 if all_good else 1


async def main():
    """Main entry point"""
    validator = LLMConfigValidator()
    return await validator.run_validation()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)