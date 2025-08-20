"""
Performance tests for AI agents in the Sentinel platform.

This module tests the performance characteristics of AI agents,
including response times, throughput, and resource usage.
"""

import asyncio
import pytest
import time
from typing import List, Dict, Any
from unittest.mock import Mock, AsyncMock, patch
import random
from concurrent.futures import ThreadPoolExecutor

from sentinel_backend.orchestration_service.agents.base_agent import BaseAgent
from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.orchestration_service.agents.security_injection_agent import SecurityInjectionAgent
from sentinel_backend.orchestration_service.agents.performance_planner_agent import PerformancePlannerAgent


class TestAgentPerformance:
    """Test suite for AI agent performance."""
    
    @pytest.fixture
    def mock_llm_provider(self):
        """Create a mock LLM provider with realistic delays."""
        provider = AsyncMock()
        
        async def mock_generate(prompt, **kwargs):
            # Simulate realistic LLM response time (0.5-2 seconds)
            await asyncio.sleep(random.uniform(0.5, 2.0))
            return {
                "content": "Mocked LLM response",
                "tokens_used": random.randint(100, 500)
            }
        
        provider.generate = mock_generate
        return provider
    
    @pytest.fixture
    def sample_openapi_spec(self):
        """Create a sample OpenAPI spec for testing."""
        return {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "responses": {"200": {"description": "Success"}}
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/users/{id}": {
                    "get": {"summary": "Get user by ID"},
                    "put": {"summary": "Update user"},
                    "delete": {"summary": "Delete user"}
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_single_agent_response_time(self, mock_llm_provider, sample_openapi_spec):
        """Test response time for a single agent execution."""
        agent = FunctionalPositiveAgent(llm_provider=mock_llm_provider)
        
        start_time = time.time()
        result = await agent.execute(sample_openapi_spec)
        elapsed = time.time() - start_time
        
        assert elapsed < 5.0, f"Single agent took too long: {elapsed}s"
        assert result is not None
        assert "test_cases" in result or "error" not in str(result).lower()
    
    @pytest.mark.asyncio
    async def test_concurrent_agent_execution(self, mock_llm_provider, sample_openapi_spec):
        """Test performance with multiple agents running concurrently."""
        agents = [
            FunctionalPositiveAgent(llm_provider=mock_llm_provider),
            FunctionalNegativeAgent(llm_provider=mock_llm_provider),
            SecurityInjectionAgent(llm_provider=mock_llm_provider),
        ]
        
        start_time = time.time()
        tasks = [agent.execute(sample_openapi_spec) for agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time
        
        # Concurrent execution should be faster than sequential
        assert elapsed < 6.0, f"Concurrent execution took too long: {elapsed}s"
        
        # All agents should complete successfully
        errors = [r for r in results if isinstance(r, Exception)]
        assert len(errors) == 0, f"Agents failed: {errors}"
    
    @pytest.mark.asyncio
    async def test_agent_throughput(self, mock_llm_provider, sample_openapi_spec):
        """Test agent throughput under load."""
        agent = FunctionalPositiveAgent(llm_provider=mock_llm_provider)
        num_executions = 10
        
        start_time = time.time()
        tasks = [agent.execute(sample_openapi_spec) for _ in range(num_executions)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time
        
        throughput = num_executions / elapsed
        
        assert throughput > 0.5, f"Throughput too low: {throughput} executions/second"
        
        # Check success rate
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        success_rate = (success_count / num_executions) * 100
        assert success_rate >= 90, f"Success rate too low: {success_rate}%"
    
    @pytest.mark.asyncio
    async def test_agent_memory_efficiency(self, mock_llm_provider):
        """Test agent memory usage during execution."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create and execute multiple agents
        for _ in range(5):
            agent = FunctionalPositiveAgent(llm_provider=mock_llm_provider)
            spec = {"paths": {f"/endpoint{i}": {} for i in range(10)}}
            await agent.execute(spec)
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable (less than 100MB for 5 agents)
        assert memory_increase < 100, f"Memory usage increased too much: {memory_increase}MB"
    
    @pytest.mark.asyncio
    async def test_agent_scaling(self, mock_llm_provider, sample_openapi_spec):
        """Test agent performance scaling with increasing load."""
        agent_counts = [1, 5, 10, 20]
        results = []
        
        for count in agent_counts:
            agents = [FunctionalPositiveAgent(llm_provider=mock_llm_provider) 
                     for _ in range(count)]
            
            start_time = time.time()
            tasks = [agent.execute(sample_openapi_spec) for agent in agents]
            await asyncio.gather(*tasks, return_exceptions=True)
            elapsed = time.time() - start_time
            
            results.append({
                "count": count,
                "time": elapsed,
                "avg_time_per_agent": elapsed / count
            })
        
        # Check that average time per agent doesn't degrade too much
        for i in range(1, len(results)):
            degradation = results[i]["avg_time_per_agent"] / results[0]["avg_time_per_agent"]
            assert degradation < 2.0, f"Performance degraded too much at {results[i]['count']} agents: {degradation}x"
    
    @pytest.mark.asyncio
    async def test_agent_retry_performance(self, sample_openapi_spec):
        """Test agent performance with retry logic."""
        # Mock provider that fails intermittently
        provider = AsyncMock()
        call_count = 0
        
        async def mock_generate_with_failures(prompt, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count % 3 == 0:  # Fail every 3rd call
                raise Exception("Simulated LLM failure")
            await asyncio.sleep(0.1)
            return {"content": "Success"}
        
        provider.generate = mock_generate_with_failures
        
        agent = FunctionalPositiveAgent(llm_provider=provider)
        
        start_time = time.time()
        # Execute multiple times to trigger retries
        tasks = [agent.execute(sample_openapi_spec) for _ in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.time() - start_time
        
        # Should complete within reasonable time despite retries
        assert elapsed < 10.0, f"Retry handling took too long: {elapsed}s"
    
    @pytest.mark.asyncio
    async def test_agent_caching_performance(self, mock_llm_provider):
        """Test performance improvement with caching."""
        agent = FunctionalPositiveAgent(llm_provider=mock_llm_provider)
        
        # Same spec to test caching
        spec = {
            "paths": {
                "/cached": {
                    "get": {"summary": "Cached endpoint"}
                }
            }
        }
        
        # First execution (cache miss)
        start_time = time.time()
        result1 = await agent.execute(spec)
        first_time = time.time() - start_time
        
        # Second execution (potential cache hit)
        start_time = time.time()
        result2 = await agent.execute(spec)
        second_time = time.time() - start_time
        
        # If caching is implemented, second execution should be faster
        # This test assumes caching is implemented in the agent
        if hasattr(agent, '_cache'):
            assert second_time <= first_time, "Caching did not improve performance"
    
    @pytest.mark.asyncio
    async def test_large_spec_performance(self, mock_llm_provider):
        """Test agent performance with large OpenAPI specifications."""
        # Create a large spec with many endpoints
        large_spec = {
            "openapi": "3.0.0",
            "paths": {}
        }
        
        for i in range(100):
            large_spec["paths"][f"/endpoint{i}"] = {
                "get": {"summary": f"Get endpoint {i}"},
                "post": {"summary": f"Post endpoint {i}"},
                "put": {"summary": f"Put endpoint {i}"},
                "delete": {"summary": f"Delete endpoint {i}"}
            }
        
        agent = PerformancePlannerAgent(llm_provider=mock_llm_provider)
        
        start_time = time.time()
        result = await agent.execute(large_spec)
        elapsed = time.time() - start_time
        
        # Should handle large specs within reasonable time
        assert elapsed < 30.0, f"Large spec processing took too long: {elapsed}s"
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_agent_timeout_handling(self):
        """Test agent behavior with timeout scenarios."""
        # Mock provider with long delay
        slow_provider = AsyncMock()
        
        async def slow_generate(prompt, **kwargs):
            await asyncio.sleep(10)  # Very slow response
            return {"content": "Too late"}
        
        slow_provider.generate = slow_generate
        
        agent = FunctionalPositiveAgent(llm_provider=slow_provider)
        
        # Set a timeout for the test
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                agent.execute({"paths": {"/test": {}}}),
                timeout=2.0
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])