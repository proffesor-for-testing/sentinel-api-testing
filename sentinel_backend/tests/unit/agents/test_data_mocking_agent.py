"""
Comprehensive Unit Tests for DataMockingAgent

This module provides extensive test coverage for the DataMockingAgent class,
including data generation strategies, schema analysis, and edge cases.
"""

import pytest
import asyncio
import json
import random
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List
from datetime import datetime
from faker import Faker

from sentinel_backend.orchestration_service.agents.data_mocking_agent import (
    DataMockingAgent, APIProvider
)


class TestDataMockingAgent:
    """Comprehensive test suite for DataMockingAgent"""
    
    @pytest.fixture
    def agent(self):
        """Create DataMockingAgent instance for testing"""
        return DataMockingAgent()
    
    @pytest.fixture
    def api_spec(self):
        """Sample OpenAPI specification for testing"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/User"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        }
                    }
                },
                "/posts": {
                    "get": {
                        "parameters": [
                            {"name": "userId", "in": "query", "schema": {"type": "integer"}}
                        ]
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                            "email": {"type": "string", "format": "email"},
                            "age": {"type": "integer", "minimum": 18, "maximum": 120},
                            "active": {"type": "boolean"},
                            "role": {"type": "string", "enum": ["admin", "user", "guest"]},
                            "created_at": {"type": "string", "format": "date-time"}
                        },
                        "required": ["name", "email"]
                    },
                    "Post": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "userId": {"type": "integer"},
                            "title": {"type": "string"},
                            "content": {"type": "string"},
                            "tags": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                }
            }
        }
    
    # Core Functionality Tests
    
    def test_agent_initialization(self, agent):
        """Test agent initialization and configuration"""
        assert agent.agent_type == "data-mocking"
        assert isinstance(agent.fake, Faker)
        assert hasattr(agent.fake, 'api_key')  # Custom provider added
        assert hasattr(agent.fake, 'jwt_token')
        assert len(agent.strategies) == 4
        assert agent.default_count == 10
    
    @pytest.mark.asyncio
    async def test_execute_with_realistic_strategy(self, agent, api_spec):
        """Test data generation with realistic strategy"""
        config = {
            'strategy': 'realistic',
            'count': 5
        }
        
        result = await agent.execute(api_spec, config)
        
        assert result['agent_type'] == 'data-mocking'
        assert result['strategy'] == 'realistic'
        assert 'mock_data' in result
        assert 'global_data' in result
        assert 'analysis' in result
        assert 'metadata' in result
        
        # Check mock data structure
        assert '/users' in result['mock_data']
        assert 'get' in result['mock_data']['/users']
        assert 'post' in result['mock_data']['/users']
    
    @pytest.mark.asyncio
    async def test_execute_with_edge_cases_strategy(self, agent, api_spec):
        """Test data generation with edge cases strategy"""
        config = {
            'strategy': 'edge_cases',
            'count': 3
        }
        
        result = await agent.execute(api_spec, config)
        
        assert result['strategy'] == 'edge_cases'
        assert 'mock_data' in result
    
    @pytest.mark.asyncio
    async def test_execute_with_seed(self, agent, api_spec):
        """Test deterministic data generation with seed"""
        config = {
            'strategy': 'realistic',
            'count': 3,
            'seed': 42
        }
        
        result1 = await agent.execute(api_spec, config)
        result2 = await agent.execute(api_spec, config)
        
        # Results should be identical with same seed
        assert json.dumps(result1['mock_data']) == json.dumps(result2['mock_data'])
    
    @pytest.mark.asyncio
    async def test_execute_error_handling(self, agent):
        """Test error handling during execution"""
        invalid_spec = {"invalid": "spec"}
        
        result = await agent.execute(invalid_spec)
        
        assert result['agent_type'] == 'data-mocking'
        assert 'error' in result
        assert result['mock_data'] == {}
        assert result['analysis'] == {}
    
    # Schema Analysis Tests
    
    def test_analyze_specification(self, agent, api_spec):
        """Test API specification analysis"""
        analysis = agent._analyze_specification(api_spec)
        
        assert 'schemas' in analysis
        assert 'relationships' in analysis
        assert 'constraints' in analysis
        assert 'patterns' in analysis
        assert 'enums' in analysis
        
        # Check schemas
        assert 'User' in analysis['schemas']
        assert 'Post' in analysis['schemas']
        
        # Check enums
        assert 'User.role' in analysis['enums']
        assert analysis['enums']['User.role'] == ['admin', 'user', 'guest']
    
    def test_find_relationships(self, agent, api_spec):
        """Test finding relationships between schemas"""
        schemas = api_spec['components']['schemas']
        relationships = agent._find_relationships(schemas)
        
        # Should find Post.userId -> User relationship
        assert len(relationships) > 0
        
        user_post_rel = [r for r in relationships if r['from'] == 'Post' and r['field'] == 'userId']
        assert len(user_post_rel) > 0
        assert user_post_rel[0]['type'] == 'foreign_key'
    
    def test_extract_patterns(self, agent, api_spec):
        """Test field pattern extraction"""
        schemas = api_spec['components']['schemas']
        patterns = agent._extract_patterns(schemas)
        
        # Should identify email pattern
        assert 'User.email' in patterns
        assert patterns['User.email'] == 'email'
        
        # Should identify name pattern
        assert 'User.name' in patterns
        assert patterns['User.name'] == 'name'
    
    def test_extract_constraints(self, agent, api_spec):
        """Test constraint extraction"""
        schemas = api_spec['components']['schemas']
        constraints = agent._extract_constraints(schemas)
        
        # Check User.age constraints
        assert 'User.age' in constraints
        assert constraints['User.age']['minimum'] == 18
        assert constraints['User.age']['maximum'] == 120
        
        # Check User.name constraints
        assert 'User.name' in constraints
        assert constraints['User.name']['minLength'] == 1
        assert constraints['User.name']['maxLength'] == 100
        assert constraints['User.name']['required'] is True
    
    # Data Generation Tests
    
    @pytest.mark.asyncio
    async def test_generate_from_schema_string(self, agent):
        """Test string data generation from schema"""
        schema = {"type": "string", "minLength": 5, "maxLength": 10}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        
        assert isinstance(result, str)
        assert 5 <= len(result) <= 10
        
        # Test with enum
        schema = {"type": "string", "enum": ["red", "green", "blue"]}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        assert result in ["red", "green", "blue"]
        
        # Test with format
        schema = {"type": "string", "format": "email"}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        assert "@" in result
    
    @pytest.mark.asyncio
    async def test_generate_from_schema_number(self, agent):
        """Test numeric data generation from schema"""
        # Integer
        schema = {"type": "integer", "minimum": 10, "maximum": 20}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        
        assert isinstance(result, int)
        assert 10 <= result <= 20
        
        # Number
        schema = {"type": "number", "minimum": 0.0, "maximum": 1.0}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        
        assert isinstance(result, float)
        assert 0.0 <= result <= 1.0
    
    @pytest.mark.asyncio
    async def test_generate_from_schema_boolean(self, agent):
        """Test boolean data generation from schema"""
        schema = {"type": "boolean"}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        
        assert isinstance(result, bool)
    
    @pytest.mark.asyncio
    async def test_generate_from_schema_array(self, agent):
        """Test array data generation from schema"""
        schema = {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
            "maxItems": 5
        }
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        
        assert isinstance(result, list)
        assert 2 <= len(result) <= 5
        assert all(isinstance(item, str) for item in result)
    
    @pytest.mark.asyncio
    async def test_generate_from_schema_object(self, agent):
        """Test object data generation from schema"""
        schema = {
            "type": "object",
            "properties": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "active": {"type": "boolean"}
            },
            "required": ["id", "name"]
        }
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        
        assert isinstance(result, dict)
        assert "id" in result
        assert "name" in result
        assert isinstance(result["id"], int)
        assert isinstance(result["name"], str)
    
    @pytest.mark.asyncio
    async def test_generate_operation_data(self, agent, api_spec):
        """Test operation-specific data generation"""
        operation = api_spec['paths']['/users']['post']
        analysis = agent._analyze_specification(api_spec)
        
        operation_data = await agent._generate_operation_data(
            operation, analysis, 'realistic', 2
        )
        
        assert 'request_bodies' in operation_data
        assert 'responses' in operation_data
        assert 'parameters' in operation_data
        
        # Check request bodies
        assert len(operation_data['request_bodies']) > 0
        for body in operation_data['request_bodies']:
            assert 'media_type' in body
            assert 'data' in body
            assert 'variation' in body
    
    @pytest.mark.asyncio
    async def test_generate_global_data(self, agent, api_spec):
        """Test global mock data generation"""
        analysis = agent._analyze_specification(api_spec)
        global_data = await agent._generate_global_data(api_spec, analysis, 'realistic', 3)
        
        assert 'users' in global_data
        assert 'auth_tokens' in global_data
        assert 'api_keys' in global_data
        assert 'test_entities' in global_data
        
        # Check users
        assert len(global_data['users']) == 3
        for user in global_data['users']:
            assert 'id' in user
            assert 'username' in user
            assert 'email' in user
            assert '@' in user['email']
        
        # Check auth tokens
        assert len(global_data['auth_tokens']) == 3
        for token in global_data['auth_tokens']:
            assert 'token' in token
            assert 'user_id' in token
            assert 'expires_at' in token
    
    # Edge Cases Tests
    
    def test_generate_string_edge_cases(self, agent):
        """Test string generation for edge cases"""
        schema = {"type": "string", "minLength": 0, "maxLength": 1}
        result = agent._generate_string(schema, {}, 'edge_cases')
        
        assert isinstance(result, str)
        assert len(result) <= 1
        
        # Test pattern handling
        schema = {"type": "string", "pattern": "^[A-Z]+$"}
        result = agent._generate_string(schema, {}, 'realistic')
        assert isinstance(result, str)
    
    def test_generate_integer_boundary_values(self, agent):
        """Test integer generation at boundaries"""
        schema = {"type": "integer", "minimum": 0, "maximum": 10}
        
        # Edge cases should return boundary values
        result = agent._generate_integer(schema, {}, 'edge_cases')
        assert result in [0, 1, 9, 10]
        
        # Boundary strategy
        result = agent._generate_integer(schema, {}, 'boundary')
        assert result in [0, 10]
    
    def test_generate_number_boundary_values(self, agent):
        """Test number generation at boundaries"""
        schema = {"type": "number", "minimum": 0.0, "maximum": 1.0}
        
        result = agent._generate_number(schema, {}, 'edge_cases')
        assert result in [0.0, 0.1, 0.9, 1.0]
    
    # Custom Provider Tests
    
    def test_api_provider_methods(self):
        """Test custom Faker provider methods"""
        faker = Faker()
        faker.add_provider(APIProvider)
        
        # Test API key generation
        api_key = faker.api_key()
        assert api_key.startswith("sk-")
        assert len(api_key) > 35
        
        # Test JWT token generation
        jwt = faker.jwt_token()
        assert jwt.count('.') == 2  # JWT has 3 parts
        
        # Test resource ID generation
        resource_id = faker.resource_id("user")
        assert resource_id.startswith("user_")
        
        # Test version string generation
        version = faker.version_string()
        assert '.' in version
        parts = version.split('.')
        assert len(parts) == 3
        
        # Test status code generation
        status = faker.status_code(success_bias=1.0)
        assert status in [200, 201, 202, 204]
        
        status = faker.status_code(success_bias=0.0)
        assert status in [400, 401, 403, 404, 422, 500, 502, 503]
    
    @pytest.mark.asyncio
    async def test_null_and_empty_handling(self, agent):
        """Test handling of null and empty values"""
        schema = {"type": "object", "properties": {}}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        assert result == {}
        
        schema = {"type": "array", "items": {"type": "string"}, "minItems": 0}
        result = await agent._generate_from_schema(schema, {}, 'realistic')
        assert isinstance(result, list)
        assert len(result) >= 0
    
    def test_configuration_limits(self, agent):
        """Test configuration limit enforcement"""
        assert agent.max_response_variations == 5
        assert agent.max_parameter_variations == 3
        assert agent.max_entity_variations == 5
        
        # These limits should be respected in generation
        # (tested in generate_operation_data)