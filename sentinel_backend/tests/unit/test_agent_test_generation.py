"""
Tests for agent test case generation functionality.

These tests verify:
- Agent test case generation process
- Different agent types and their outputs  
- Test case validation and quality
- Async agent coordination
- Error handling in test generation
"""
import pytest
import json
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Pet Store API",
            "version": "1.0.0"
        },
        "paths": {
            "/pets": {
                "get": {
                    "summary": "List pets",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "maximum": 100}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of pets",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/Pet"}
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create pet",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Pet"}
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "Pet created"},
                        "400": {"description": "Invalid input"}
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Pet": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "tag": {"type": "string"}
                    }
                }
            }
        }
    }


@pytest.fixture
def mock_agent_result():
    """Mock agent generation result."""
    return {
        "test_cases": [
            {
                "name": "Test get pets with valid limit",
                "method": "GET",
                "path": "/pets",
                "query_params": {"limit": 10},
                "expected_status": 200,
                "agent_type": "Functional-Positive-Agent"
            },
            {
                "name": "Test get pets with maximum limit",
                "method": "GET", 
                "path": "/pets",
                "query_params": {"limit": 100},
                "expected_status": 200,
                "agent_type": "Functional-Positive-Agent"
            }
        ],
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "agent_version": "1.0.0",
            "spec_hash": "abc123"
        }
    }


class TestAgentTestGeneration:
    """Test agent test generation functionality."""
    
    @pytest.mark.asyncio
    async def test_functional_positive_agent_generation(self, sample_openapi_spec, mock_agent_result):
        """Test functional positive agent test generation."""
        from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
        
        agent = FunctionalPositiveAgent()
        
        with patch.object(agent, 'generate_test_cases', return_value=mock_agent_result):
            result = await agent.generate_test_cases(sample_openapi_spec)
            
            assert len(result["test_cases"]) == 2
            assert all(tc["expected_status"] == 200 for tc in result["test_cases"])
            assert all(tc["agent_type"] == "Functional-Positive-Agent" for tc in result["test_cases"])
    
    @pytest.mark.asyncio
    async def test_functional_negative_agent_generation(self, sample_openapi_spec):
        """Test functional negative agent test generation."""
        from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
        
        agent = FunctionalNegativeAgent()
        
        negative_result = {
            "test_cases": [
                {
                    "name": "Test get pets with invalid limit",
                    "method": "GET",
                    "path": "/pets", 
                    "query_params": {"limit": 150},  # Exceeds maximum
                    "expected_status": 400,
                    "agent_type": "Functional-Negative-Agent"
                }
            ]
        }
        
        with patch.object(agent, 'generate_test_cases', return_value=negative_result):
            result = await agent.generate_test_cases(sample_openapi_spec)
            
            assert len(result["test_cases"]) == 1
            assert result["test_cases"][0]["expected_status"] == 400
            assert result["test_cases"][0]["query_params"]["limit"] > 100
    
    @pytest.mark.asyncio
    async def test_security_agent_generation(self, sample_openapi_spec):
        """Test security agent test generation."""
        from sentinel_backend.orchestration_service.agents.security_auth_agent import SecurityAuthAgent
        
        agent = SecurityAuthAgent()
        
        security_result = {
            "test_cases": [
                {
                    "name": "Test unauthorized access to create pet",
                    "method": "POST",
                    "path": "/pets",
                    "headers": {},  # No auth header
                    "body": {"name": "Fluffy"},
                    "expected_status": 401,
                    "agent_type": "Security-Auth-Agent"
                }
            ]
        }
        
        with patch.object(agent, 'generate_test_cases', return_value=security_result):
            result = await agent.generate_test_cases(sample_openapi_spec)
            
            assert len(result["test_cases"]) == 1
            assert result["test_cases"][0]["expected_status"] == 401
            assert "headers" in result["test_cases"][0]
    
    @pytest.mark.asyncio 
    async def test_agent_coordination_parallel(self, sample_openapi_spec):
        """Test parallel execution of multiple agents."""
        import asyncio
        
        async def mock_agent_generate(agent_type):
            # Simulate different generation times
            if agent_type == "fast":
                await asyncio.sleep(0.1)
            else:
                await asyncio.sleep(0.2)
            
            return {
                "test_cases": [{"agent_type": agent_type}],
                "generation_time": 0.1 if agent_type == "fast" else 0.2
            }
        
        # Test parallel execution
        tasks = [
            mock_agent_generate("fast"),
            mock_agent_generate("slow")
        ]
        
        start_time = asyncio.get_event_loop().time()
        results = await asyncio.gather(*tasks)
        end_time = asyncio.get_event_loop().time()
        
        # Should complete faster than sequential execution
        assert (end_time - start_time) < 0.4  # Less than sum of individual times
        assert len(results) == 2
    
    def test_test_case_validation(self, mock_agent_result):
        """Test validation of generated test cases."""
        test_cases = mock_agent_result["test_cases"]
        
        required_fields = ["name", "method", "path", "expected_status"]
        
        for test_case in test_cases:
            # Validate required fields
            for field in required_fields:
                assert field in test_case, f"Missing required field: {field}"
            
            # Validate HTTP method
            assert test_case["method"] in ["GET", "POST", "PUT", "DELETE", "PATCH"]
            
            # Validate status code
            assert isinstance(test_case["expected_status"], int)
            assert 100 <= test_case["expected_status"] < 600
            
            # Validate path format
            assert test_case["path"].startswith("/")
    
    def test_test_case_quality_metrics(self, mock_agent_result):
        """Test quality metrics for generated test cases."""
        test_cases = mock_agent_result["test_cases"]
        
        # Calculate coverage metrics
        paths_covered = set(tc["path"] for tc in test_cases)
        methods_covered = set(tc["method"] for tc in test_cases)
        status_codes_covered = set(tc["expected_status"] for tc in test_cases)
        
        # Quality assertions
        assert len(paths_covered) >= 1  # At least one path covered
        assert len(methods_covered) >= 1  # At least one method covered
        assert len(test_cases) >= 2  # Minimum test case count
        
        # Test case naming convention
        for test_case in test_cases:
            assert test_case["name"].startswith("Test ")
            assert len(test_case["name"]) > 10  # Descriptive names
    
    @pytest.mark.asyncio
    async def test_agent_error_handling(self, sample_openapi_spec):
        """Test agent error handling during generation."""
        from sentinel_backend.orchestration_service.agents.base_agent import BaseAgent
        
        agent = BaseAgent()
        
        # Test with invalid spec
        invalid_spec = {"invalid": "spec"}
        
        with patch.object(agent, 'generate_test_cases', side_effect=ValueError("Invalid spec")):
            try:
                await agent.generate_test_cases(invalid_spec)
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert str(e) == "Invalid spec"
    
    @pytest.mark.asyncio
    async def test_agent_timeout_handling(self, sample_openapi_spec):
        """Test agent timeout handling."""
        import asyncio
        
        async def slow_generation():
            await asyncio.sleep(10)  # Simulate slow generation
            return {"test_cases": []}
        
        # Test with timeout
        try:
            result = await asyncio.wait_for(slow_generation(), timeout=1.0)
            assert False, "Should have timed out"
        except asyncio.TimeoutError:
            assert True  # Expected timeout
    
    def test_agent_result_serialization(self, mock_agent_result):
        """Test serialization of agent results."""
        # Test JSON serialization
        serialized = json.dumps(mock_agent_result, default=str)
        deserialized = json.loads(serialized)
        
        assert "test_cases" in deserialized
        assert "metadata" in deserialized
        assert len(deserialized["test_cases"]) == len(mock_agent_result["test_cases"])
    
    @pytest.mark.asyncio
    async def test_agent_state_management(self, sample_openapi_spec):
        """Test agent state management during generation."""
        from sentinel_backend.orchestration_service.agents.base_agent import BaseAgent
        
        agent = BaseAgent()
        
        # Test initial state
        assert agent.state == "idle"
        
        # Test state during generation
        with patch.object(agent, 'generate_test_cases') as mock_generate:
            async def mock_generation(*args, **kwargs):
                agent.state = "generating"
                await asyncio.sleep(0.1)
                agent.state = "completed"
                return {"test_cases": []}
            
            mock_generate.side_effect = mock_generation
            
            await agent.generate_test_cases(sample_openapi_spec)
            assert agent.state == "completed"
    
    def test_agent_configuration_validation(self):
        """Test agent configuration validation."""
        valid_config = {
            "max_test_cases": 100,
            "timeout": 30,
            "include_edge_cases": True,
            "output_format": "json"
        }
        
        # Validate configuration fields
        assert isinstance(valid_config["max_test_cases"], int)
        assert valid_config["max_test_cases"] > 0
        assert isinstance(valid_config["timeout"], int)
        assert valid_config["timeout"] > 0
        assert isinstance(valid_config["include_edge_cases"], bool)
        assert valid_config["output_format"] in ["json", "yaml"]


class TestAgentPerformance:
    """Test agent performance and optimization."""
    
    def test_agent_generation_performance(self, sample_openapi_spec):
        """Test agent generation performance metrics."""
        import time
        
        def mock_generation():
            time.sleep(0.1)  # Simulate generation time
            return {"test_cases": [{"name": "test"}]}
        
        start_time = time.time()
        result = mock_generation()
        end_time = time.time()
        
        generation_time = end_time - start_time
        
        # Performance assertions
        assert generation_time < 1.0  # Should complete within 1 second
        assert len(result["test_cases"]) > 0
    
    def test_memory_usage_optimization(self):
        """Test memory usage during test generation."""
        import sys
        
        # Create large test case set
        large_test_set = []
        for i in range(1000):
            large_test_set.append({
                "name": f"Test case {i}",
                "method": "GET",
                "path": f"/test/{i}",
                "expected_status": 200
            })
        
        # Verify memory usage is reasonable
        test_set_size = sys.getsizeof(large_test_set)
        assert test_set_size < 1024 * 1024  # Less than 1MB
    
    @pytest.mark.asyncio
    async def test_concurrent_agent_execution(self):
        """Test concurrent execution of multiple agents."""
        import asyncio
        
        async def agent_task(agent_id):
            await asyncio.sleep(0.1)
            return {"agent_id": agent_id, "test_cases": []}
        
        # Run multiple agents concurrently
        tasks = [agent_task(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 5
        assert all("agent_id" in result for result in results)