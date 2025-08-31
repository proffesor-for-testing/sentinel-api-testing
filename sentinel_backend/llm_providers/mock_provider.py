"""
Mock LLM Provider for Benchmarking

Provides instant, deterministic responses for accurate performance benchmarking
without the overhead of actual LLM API calls.
"""

import json
import random
from typing import Dict, List, Optional, Any
from datetime import datetime
from .base_provider import BaseLLMProvider, LLMConfig, LLMResponse, ModelCapability


class MockLLMProvider(BaseLLMProvider):
    """Mock LLM provider that returns instant, deterministic responses"""
    
    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.response_counter = 0
        
    def generate(self, 
                 prompt: str, 
                 system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate a mock response instantly"""
        
        self.response_counter += 1
        
        # Generate deterministic test cases based on prompt content
        if "positive" in prompt.lower() or "valid" in prompt.lower():
            response_text = self._generate_positive_tests()
        elif "negative" in prompt.lower() or "invalid" in prompt.lower():
            response_text = self._generate_negative_tests()
        elif "security" in prompt.lower():
            response_text = self._generate_security_tests()
        elif "performance" in prompt.lower():
            response_text = self._generate_performance_tests()
        elif "stateful" in prompt.lower():
            response_text = self._generate_stateful_tests()
        else:
            response_text = self._generate_generic_tests()
        
        return LLMResponse(
            content=response_text,
            model=self.config.model,
            usage={
                "prompt_tokens": len(prompt.split()),
                "completion_tokens": len(response_text.split()),
                "total_tokens": len(prompt.split()) + len(response_text.split())
            },
            raw_response={"mocked": True, "counter": self.response_counter},
            finish_reason="stop",
            provider=self.config.provider
        )
    
    def _generate_positive_tests(self) -> str:
        """Generate positive test cases"""
        tests = []
        for i in range(5):
            tests.append({
                "test_name": f"test_valid_request_{i+1}",
                "method": "POST",
                "endpoint": "/api/pets",
                "headers": {"Content-Type": "application/json"},
                "body": {
                    "name": f"Pet{i+1}",
                    "type": random.choice(["dog", "cat", "bird"]),
                    "age": random.randint(1, 15)
                },
                "expected_status": 201,
                "description": f"Valid pet creation test {i+1}"
            })
        return json.dumps(tests, indent=2)
    
    def _generate_negative_tests(self) -> str:
        """Generate negative test cases"""
        tests = []
        negative_scenarios = [
            {"name": "", "error": "Empty name field"},
            {"name": "A" * 256, "error": "Name too long"},
            {"age": -1, "error": "Negative age"},
            {"type": 123, "error": "Invalid type format"},
            {"name": None, "error": "Null name value"}
        ]
        
        for i, scenario in enumerate(negative_scenarios):
            tests.append({
                "test_name": f"test_invalid_request_{i+1}",
                "method": "POST",
                "endpoint": "/api/pets",
                "headers": {"Content-Type": "application/json"},
                "body": scenario,
                "expected_status": 400,
                "description": scenario.get("error", "Invalid request")
            })
        return json.dumps(tests, indent=2)
    
    def _generate_security_tests(self) -> str:
        """Generate security test cases"""
        tests = []
        security_payloads = [
            {"injection": "'; DROP TABLE pets; --"},
            {"xss": "<script>alert('XSS')</script>"},
            {"traversal": "../../../etc/passwd"},
            {"overflow": "A" * 10000},
            {"command": "; ls -la /"}
        ]
        
        for i, payload in enumerate(security_payloads):
            tests.append({
                "test_name": f"test_security_vulnerability_{i+1}",
                "method": "POST",
                "endpoint": "/api/pets",
                "headers": {"Content-Type": "application/json"},
                "body": {"name": list(payload.values())[0], "type": "cat"},
                "expected_status": 400,
                "description": f"Security test: {list(payload.keys())[0]}"
            })
        return json.dumps(tests, indent=2)
    
    def _generate_performance_tests(self) -> str:
        """Generate performance test cases"""
        tests = {
            "load_test_config": {
                "virtual_users": 100,
                "ramp_up_time": 30,
                "duration": 300,
                "think_time": 1
            },
            "scenarios": [
                {
                    "name": "create_pet_load",
                    "weight": 40,
                    "endpoint": "/api/pets",
                    "method": "POST"
                },
                {
                    "name": "get_pets_load",
                    "weight": 60,
                    "endpoint": "/api/pets",
                    "method": "GET"
                }
            ],
            "thresholds": {
                "response_time_p95": 500,
                "error_rate": 0.01,
                "requests_per_second": 100
            }
        }
        return json.dumps(tests, indent=2)
    
    def _generate_stateful_tests(self) -> str:
        """Generate stateful workflow tests"""
        workflows = {
            "workflows": [
                {
                    "name": "pet_lifecycle",
                    "steps": [
                        {"action": "create", "endpoint": "/api/pets", "method": "POST"},
                        {"action": "retrieve", "endpoint": "/api/pets/{id}", "method": "GET"},
                        {"action": "update", "endpoint": "/api/pets/{id}", "method": "PUT"},
                        {"action": "delete", "endpoint": "/api/pets/{id}", "method": "DELETE"}
                    ]
                }
            ]
        }
        return json.dumps(workflows, indent=2)
    
    def _generate_generic_tests(self) -> str:
        """Generate generic test cases"""
        return json.dumps([
            {
                "test_name": "test_generic_1",
                "method": "GET",
                "endpoint": "/api/health",
                "expected_status": 200
            }
        ], indent=2)
    
    async def generate_async(self, 
                            prompt: str,
                            system_prompt: Optional[str] = None,
                            **kwargs) -> LLMResponse:
        """Async version of generate"""
        return self.generate(prompt, system_prompt, **kwargs)
    
    def get_capabilities(self) -> List[ModelCapability]:
        """Return mock capabilities"""
        return [
            ModelCapability.TEXT_GENERATION,
            ModelCapability.CODE_GENERATION,
            ModelCapability.FUNCTION_CALLING
        ]
    
    def validate_config(self) -> bool:
        """Config is always valid for mock provider"""
        return True
    
    def estimate_tokens(self, text: str) -> int:
        """Simple token estimation"""
        return len(text.split())
    
    def get_model_info(self) -> Dict[str, Any]:
        """Return mock model information"""
        return {
            "provider": "mock",
            "model": self.config.model or "mock-model",
            "context_length": 100000,
            "capabilities": [cap.value for cap in self.get_capabilities()],
            "response_time": "instant",
            "deterministic": True
        }