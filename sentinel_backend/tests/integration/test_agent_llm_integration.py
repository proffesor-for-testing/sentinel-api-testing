"""
Integration tests for Agent LLM functionality
"""

import pytest
import asyncio
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from sentinel_backend.orchestration_service.agents.base_agent import BaseAgent, AgentTask, AgentResult
from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.llm_providers.base_provider import LLMProvider, LLMResponse, Message


@pytest.fixture
def mock_api_spec():
    """Mock API specification for testing"""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
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
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "Success"},
                        "404": {"description": "Not found"}
                    }
                }
            }
        }
    }


@pytest.fixture
def agent_task():
    """Mock agent task"""
    return AgentTask(
        task_id="test_task_001",
        spec_id=1,
        agent_type="test-agent",
        parameters={}
    )


class TestBaseAgentLLMIntegration:
    """Test BaseAgent LLM integration"""
    
    def test_agent_without_llm(self):
        """Test agent works without LLM configured"""
        with patch.dict(os.environ, {"SENTINEL_APP_LLM_PROVIDER": "none"}):
            agent = FunctionalPositiveAgent()
            assert agent.llm_enabled == False
            assert agent.llm_provider is None
    
    def test_agent_with_llm_no_key(self):
        """Test agent handles missing API key gracefully"""
        with patch.dict(os.environ, {
            "SENTINEL_APP_LLM_PROVIDER": "anthropic",
            "SENTINEL_APP_LLM_MODEL": "claude-sonnet-4"
        }, clear=True):
            agent = FunctionalPositiveAgent()
            # Should not enable LLM without API key
            assert agent.llm_enabled == False
    
    @patch('sentinel_backend.llm_providers.LLMProviderFactory.create_provider')
    def test_agent_with_llm_configured(self, mock_create_provider):
        """Test agent initializes with LLM when properly configured"""
        # Mock the provider
        mock_provider = Mock()
        mock_provider.config = Mock(provider=LLMProvider.ANTHROPIC, model="claude-sonnet-4")
        mock_create_provider.return_value = mock_provider
        
        with patch.dict(os.environ, {
            "SENTINEL_APP_LLM_PROVIDER": "anthropic",
            "SENTINEL_APP_ANTHROPIC_API_KEY": "test-key",
            "SENTINEL_APP_LLM_MODEL": "claude-sonnet-4"
        }):
            with patch('sentinel_backend.config.settings.get_application_settings') as mock_settings:
                mock_settings.return_value = Mock(
                    llm_provider="anthropic",
                    llm_model="claude-sonnet-4",
                    anthropic_api_key="test-key",
                    llm_temperature=0.7,
                    llm_max_tokens=2000,
                    llm_top_p=1.0,
                    llm_timeout=60,
                    llm_max_retries=3,
                    llm_cache_enabled=True,
                    llm_cache_ttl=3600,
                    llm_fallback_enabled=False,
                    ollama_base_url="http://localhost:11434",
                    vllm_base_url=None
                )
                
                agent = FunctionalPositiveAgent()
                assert agent.llm_enabled == True
                assert agent.llm_provider == mock_provider


@pytest.mark.asyncio
class TestFunctionalPositiveAgentWithLLM:
    """Test FunctionalPositiveAgent with LLM enhancement"""
    
    async def test_generate_without_llm(self, mock_api_spec, agent_task):
        """Test test generation without LLM"""
        with patch.dict(os.environ, {"SENTINEL_APP_LLM_PROVIDER": "none"}):
            agent = FunctionalPositiveAgent()
            result = await agent.execute(agent_task, mock_api_spec)
            
            assert result.status == "success"
            assert len(result.test_cases) > 0
            assert result.metadata["llm_enhanced"] == False
    
    @patch('sentinel_backend.orchestration_service.agents.base_agent.BaseLLMProvider')
    async def test_generate_with_llm_enhancement(self, mock_provider_class, mock_api_spec, agent_task):
        """Test test generation with LLM enhancement"""
        # Mock LLM provider
        mock_provider = AsyncMock()
        mock_provider.config = Mock(provider=LLMProvider.ANTHROPIC, model="claude-sonnet-4")
        mock_provider.generate = AsyncMock(return_value=LLMResponse(
            content='{"name": "Enhanced User", "email": "enhanced@example.com", "age": 30}',
            model="claude-sonnet-4",
            provider=LLMProvider.ANTHROPIC,
            usage={"total_tokens": 50, "cost": 0.001},
            metadata={},
            created_at=datetime.now()
        ))
        
        with patch('sentinel_backend.llm_providers.LLMProviderFactory.create_provider', return_value=mock_provider):
            with patch.dict(os.environ, {
                "SENTINEL_APP_LLM_PROVIDER": "anthropic",
                "SENTINEL_APP_ANTHROPIC_API_KEY": "test-key"
            }):
                with patch('sentinel_backend.config.settings.get_application_settings') as mock_settings:
                    mock_settings.return_value = Mock(
                        llm_provider="anthropic",
                        llm_model="claude-sonnet-4",
                        anthropic_api_key="test-key",
                        llm_temperature=0.7,
                        llm_max_tokens=2000,
                        llm_top_p=1.0,
                        llm_timeout=60,
                        llm_max_retries=3,
                        llm_cache_enabled=True,
                        llm_cache_ttl=3600,
                        llm_fallback_enabled=False,
                        ollama_base_url="http://localhost:11434",
                        vllm_base_url=None
                    )
                    
                    agent = FunctionalPositiveAgent()
                    agent.llm_enabled = True
                    agent.llm_provider = mock_provider
                    
                    result = await agent.execute(agent_task, mock_api_spec)
                    
                    assert result.status == "success"
                    assert len(result.test_cases) > 0
                    assert result.metadata["llm_enhanced"] == True
                    assert result.metadata["llm_provider"] == LLMProvider.ANTHROPIC
    
    async def test_creative_variant_generation(self):
        """Test generating creative test case variants with LLM"""
        mock_provider = AsyncMock()
        mock_provider.generate = AsyncMock(return_value=LLMResponse(
            content='{"endpoint": "/users", "method": "POST", "body": {"name": "Creative User", "email": "creative@test.com"}}',
            model="claude-sonnet-4",
            provider=LLMProvider.ANTHROPIC,
            usage={"total_tokens": 60, "cost": 0.002},
            metadata={},
            created_at=datetime.now()
        ))
        
        agent = FunctionalPositiveAgent()
        agent.llm_enabled = True
        agent.llm_provider = mock_provider
        
        original_test = {
            "endpoint": "/users",
            "method": "POST",
            "body": {"name": "Test User", "email": "test@example.com"}
        }
        
        variant = await agent.generate_creative_variant(original_test, "realistic")
        
        assert variant is not None
        assert variant["endpoint"] == "/users"
        assert variant["method"] == "POST"
        assert "Creative User" in str(variant)


@pytest.mark.asyncio
class TestFunctionalNegativeAgentWithLLM:
    """Test FunctionalNegativeAgent with LLM enhancement"""
    
    async def test_llm_negative_test_generation(self, mock_api_spec, agent_task):
        """Test LLM-enhanced negative test generation"""
        mock_provider = AsyncMock()
        mock_provider.config = Mock(provider=LLMProvider.ANTHROPIC, model="claude-sonnet-4")
        mock_provider.generate = AsyncMock(return_value=LLMResponse(
            content='[{"description": "SQL Injection test", "body": {"name": "\'; DROP TABLE users; --"}, "expected_status": 400}]',
            model="claude-sonnet-4",
            provider=LLMProvider.ANTHROPIC,
            usage={"total_tokens": 80, "cost": 0.003},
            metadata={},
            created_at=datetime.now()
        ))
        
        with patch('sentinel_backend.llm_providers.LLMProviderFactory.create_provider', return_value=mock_provider):
            with patch('sentinel_backend.config.settings.get_application_settings') as mock_settings:
                mock_settings.return_value = Mock(
                    llm_provider="anthropic",
                    llm_model="claude-sonnet-4",
                    anthropic_api_key="test-key",
                    security_max_bola_vectors=12,
                    security_max_auth_scenarios=4,
                    test_execution_timeout=600,
                    llm_temperature=0.7,
                    llm_max_tokens=2000,
                    llm_top_p=1.0,
                    llm_timeout=60,
                    llm_max_retries=3,
                    llm_cache_enabled=True,
                    llm_cache_ttl=3600,
                    llm_fallback_enabled=False,
                    ollama_base_url="http://localhost:11434",
                    vllm_base_url=None
                )
                
                agent = FunctionalNegativeAgent()
                agent.llm_enabled = True
                agent.llm_provider = mock_provider
                
                result = await agent.execute(agent_task, mock_api_spec)
                
                assert result.status == "success"
                assert len(result.test_cases) > 0
                # Check for LLM-generated tests
                llm_tests = [t for t in result.test_cases if "[LLM]" in t.get("test_name", "")]
                assert len(llm_tests) > 0


class TestAgentLLMHelperMethods:
    """Test agent LLM helper methods"""
    
    @pytest.mark.asyncio
    async def test_enhance_with_llm(self):
        """Test enhance_with_llm helper method"""
        mock_provider = AsyncMock()
        mock_provider.generate = AsyncMock(return_value=LLMResponse(
            content='{"enhanced": true, "data": "Enhanced content"}',
            model="claude-sonnet-4",
            provider=LLMProvider.ANTHROPIC,
            usage={"total_tokens": 40, "cost": 0.001},
            metadata={},
            created_at=datetime.now()
        ))
        
        agent = BaseAgent("test-agent")
        agent.llm_enabled = True
        agent.llm_provider = mock_provider
        
        original_data = {"data": "Original content"}
        enhanced = await agent.enhance_with_llm(
            original_data,
            "Enhance this data",
            system_prompt="You are a test assistant"
        )
        
        assert enhanced is not None
        assert enhanced["enhanced"] == True
        assert "Enhanced content" in str(enhanced)
    
    @pytest.mark.asyncio
    async def test_enhance_with_llm_disabled(self):
        """Test enhance_with_llm returns original when LLM disabled"""
        agent = BaseAgent("test-agent")
        agent.llm_enabled = False
        
        original_data = {"data": "Original content"}
        enhanced = await agent.enhance_with_llm(original_data, "Enhance this")
        
        assert enhanced == original_data
    
    @pytest.mark.asyncio
    async def test_enhance_with_llm_failure(self):
        """Test enhance_with_llm handles failures gracefully"""
        mock_provider = AsyncMock()
        mock_provider.generate = AsyncMock(side_effect=Exception("LLM error"))
        
        agent = BaseAgent("test-agent")
        agent.llm_enabled = True
        agent.llm_provider = mock_provider
        
        original_data = {"data": "Original content"}
        enhanced = await agent.enhance_with_llm(original_data, "Enhance this")
        
        # Should return original data on failure
        assert enhanced == original_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])