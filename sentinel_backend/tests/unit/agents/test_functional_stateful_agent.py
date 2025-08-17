"""
Comprehensive Unit Tests for FunctionalStatefulAgent

This module provides extensive test coverage for the FunctionalStatefulAgent class,
including SODG (Semantic Operation Dependency Graph) testing, workflow generation,
and state management testing.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List
from dataclasses import dataclass

from sentinel_backend.orchestration_service.agents.functional_stateful_agent import (
    FunctionalStatefulAgent, DependencyType, ExtractRule, InjectRule,
    OperationNode, OperationEdge, StatefulTestScenario
)
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


class TestFunctionalStatefulAgent:
    """Comprehensive test suite for FunctionalStatefulAgent"""
    
    @pytest.fixture
    def agent(self):
        """Create FunctionalStatefulAgent instance for testing"""
        return FunctionalStatefulAgent()
    
    @pytest.fixture
    def agent_task(self):
        """Sample agent task for testing"""
        return AgentTask(
            task_id="test-stateful-789",
            spec_id=1,
            agent_type="Functional-Stateful-Agent",
            parameters={}
        )
    
    @pytest.fixture
    def api_spec_with_relationships(self):
        """API specification with resource relationships for stateful testing"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "post": {
                        "operationId": "createUser",
                        "summary": "Create a new user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/UserInput"}
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            }
                        }
                    },
                    "get": {
                        "operationId": "listUsers",
                        "summary": "List all users",
                        "responses": {"200": {}}
                    }
                },
                "/users/{userId}": {
                    "get": {
                        "operationId": "getUser",
                        "summary": "Get user by ID",
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {}}
                    },
                    "put": {
                        "operationId": "updateUser",
                        "summary": "Update user",
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/UserInput"}
                                }
                            }
                        },
                        "responses": {"200": {}}
                    },
                    "delete": {
                        "operationId": "deleteUser",
                        "summary": "Delete user",
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {"204": {}}
                    }
                },
                "/users/{userId}/posts": {
                    "post": {
                        "operationId": "createPost",
                        "summary": "Create post for user",
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/PostInput"}
                                }
                            }
                        },
                        "responses": {"201": {}}
                    },
                    "get": {
                        "operationId": "getUserPosts",
                        "summary": "Get posts for user",
                        "parameters": [
                            {"name": "userId", "in": "path", "required": True, "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {}}
                    }
                },
                "/posts": {
                    "get": {
                        "operationId": "listPosts",
                        "summary": "List all posts",
                        "parameters": [
                            {"name": "userId", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {}}
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "email": {"type": "string"}
                        }
                    },
                    "UserInput": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "email": {"type": "string"}
                        },
                        "required": ["name", "email"]
                    },
                    "PostInput": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "content": {"type": "string"}
                        },
                        "required": ["title", "content"]
                    }
                }
            }
        }
    
    # Core Functionality Tests
    
    def test_agent_initialization(self, agent):
        """Test agent initialization and configuration"""
        assert agent.agent_type == "Functional-Stateful-Agent"
        assert agent.sodg == {}
        assert agent.logger is not None
    
    @pytest.mark.asyncio
    async def test_execute_success(self, agent, agent_task, api_spec_with_relationships):
        """Test successful execution of stateful test generation"""
        result = await agent.execute(agent_task, api_spec_with_relationships)
        
        assert isinstance(result, AgentResult)
        assert result.task_id == agent_task.task_id
        assert result.agent_type == "Functional-Stateful-Agent"
        assert result.status == "success"
        assert len(result.test_cases) > 0
        assert result.metadata is not None
        assert "total_operations" in result.metadata
        assert "workflow_patterns" in result.metadata
    
    @pytest.mark.asyncio
    async def test_execute_error_handling(self, agent, agent_task):
        """Test error handling during execution"""
        invalid_spec = {"invalid": "spec"}
        
        result = await agent.execute(agent_task, invalid_spec)
        
        assert result.status == "failed"
        assert result.error_message is not None
    
    # SODG Building Tests
    
    def test_build_sodg(self, agent, api_spec_with_relationships):
        """Test building Semantic Operation Dependency Graph"""
        sodg = agent._build_sodg(api_spec_with_relationships)
        
        assert len(sodg) > 0
        
        # Check node creation
        assert "createUser" in sodg or "post_users" in sodg
        
        # Check that nodes have proper structure
        for node_id, node in sodg.items():
            assert isinstance(node, OperationNode)
            assert node.operation_id is not None
            assert node.path is not None
            assert node.method is not None
            assert isinstance(node.dependencies, list)
            assert isinstance(node.dependents, list)
    
    def test_generate_operation_id(self, agent, api_spec_with_relationships):
        """Test operation ID generation"""
        endpoint = {
            "path": "/users",
            "method": "POST",
            "operation": {"operationId": "createUser"}
        }
        
        op_id = agent._generate_operation_id(endpoint)
        assert op_id == "createUser"
        
        # Test without operationId
        endpoint_no_id = {
            "path": "/users/{id}/posts",
            "method": "GET",
            "operation": {}
        }
        
        op_id = agent._generate_operation_id(endpoint_no_id)
        assert op_id == "get_posts"
    
    def test_identify_dependency_resource_id(self, agent):
        """Test identifying resource ID dependencies"""
        from_node = OperationNode(
            operation_id="createUser",
            path="/users",
            method="POST",
            operation_spec={},
            dependencies=[],
            dependents=[]
        )
        
        to_node = OperationNode(
            operation_id="getUser",
            path="/users/{id}",
            method="GET",
            operation_spec={},
            dependencies=[],
            dependents=[]
        )
        
        edge = agent._identify_dependency(from_node, to_node)
        
        assert edge is not None
        assert edge.dependency_type == DependencyType.RESOURCE_ID
        assert len(edge.extract_rules) > 0
        assert len(edge.inject_rules) > 0
    
    def test_identify_dependency_update(self, agent):
        """Test identifying update dependencies"""
        from_node = OperationNode(
            operation_id="createUser",
            path="/users",
            method="POST",
            operation_spec={},
            dependencies=[],
            dependents=[]
        )
        
        to_node = OperationNode(
            operation_id="updateUser",
            path="/users/{id}",
            method="PUT",
            operation_spec={},
            dependencies=[],
            dependents=[]
        )
        
        edge = agent._identify_dependency(from_node, to_node)
        
        assert edge is not None
        assert edge.dependency_type == DependencyType.UPDATE_REFERENCE
    
    def test_identify_dependency_parent_child(self, agent):
        """Test identifying parent-child dependencies"""
        from_node = OperationNode(
            operation_id="createUser",
            path="/users",
            method="POST",
            operation_spec={},
            dependencies=[],
            dependents=[]
        )
        
        to_node = OperationNode(
            operation_id="createPost",
            path="/users/{userId}/posts",
            method="POST",
            operation_spec={},
            dependencies=[],
            dependents=[]
        )
        
        edge = agent._identify_dependency(from_node, to_node)
        
        assert edge is not None
        assert edge.dependency_type == DependencyType.PARENT_CHILD
    
    def test_identify_dependency_filter(self, agent):
        """Test identifying filter reference dependencies"""
        from_node = OperationNode(
            operation_id="createUser",
            path="/users",
            method="POST",
            operation_spec={},
            dependencies=[],
            dependents=[]
        )
        
        to_node = OperationNode(
            operation_id="listPosts",
            path="/posts",
            method="GET",
            operation_spec={
                "parameters": [
                    {"name": "userId", "in": "query", "schema": {"type": "integer"}}
                ]
            },
            dependencies=[],
            dependents=[]
        )
        
        edge = agent._identify_dependency(from_node, to_node)
        
        assert edge is not None
        assert edge.dependency_type == DependencyType.FILTER_REFERENCE
    
    # Workflow Pattern Tests
    
    def test_identify_workflow_patterns(self, agent, api_spec_with_relationships):
        """Test identifying workflow patterns in API"""
        agent.sodg = agent._build_sodg(api_spec_with_relationships)
        patterns = agent._identify_workflow_patterns()
        
        assert len(patterns) > 0
        
        # Check for different pattern types
        pattern_types = [p["type"] for p in patterns]
        
        # Should find CRUD patterns
        crud_types = ["create_read", "create_update", "create_delete", "full_crud"]
        assert any(pt in pattern_types for pt in crud_types)
    
    def test_find_crud_patterns(self, agent, api_spec_with_relationships):
        """Test finding CRUD workflow patterns"""
        agent.sodg = agent._build_sodg(api_spec_with_relationships)
        crud_patterns = agent._find_crud_patterns()
        
        assert len(crud_patterns) > 0
        
        # Should find user CRUD operations
        user_patterns = [p for p in crud_patterns if p["resource"] == "users"]
        assert len(user_patterns) > 0
        
        # Check pattern structure
        for pattern in crud_patterns:
            assert "type" in pattern
            assert "resource" in pattern
            assert "operations" in pattern
            assert "description" in pattern
    
    def test_find_parent_child_patterns(self, agent, api_spec_with_relationships):
        """Test finding parent-child workflow patterns"""
        agent.sodg = agent._build_sodg(api_spec_with_relationships)
        parent_child_patterns = agent._find_parent_child_patterns()
        
        # Should find user -> post relationship
        if len(parent_child_patterns) > 0:
            pattern = parent_child_patterns[0]
            assert "parent_resource" in pattern
            assert "child_resource" in pattern
            assert "operations" in pattern
    
    # Scenario Generation Tests
    
    @pytest.mark.asyncio
    async def test_generate_scenarios_for_pattern(self, agent, api_spec_with_relationships):
        """Test generating scenarios for workflow patterns"""
        agent.sodg = agent._build_sodg(api_spec_with_relationships)
        
        pattern = {
            "type": "create_read",
            "resource": "users",
            "operations": list(agent.sodg.values())[:2],
            "description": "Create and read user workflow"
        }
        
        scenarios = await agent._generate_scenarios_for_pattern(
            pattern, api_spec_with_relationships
        )
        
        assert len(scenarios) > 0
        
        for scenario in scenarios:
            assert isinstance(scenario, StatefulTestScenario)
            assert scenario.scenario_id is not None
            assert scenario.description is not None
            assert len(scenario.operations) > 0
    
    @pytest.mark.asyncio
    async def test_generate_crud_scenario(self, agent, api_spec_with_relationships):
        """Test generating CRUD workflow scenario"""
        agent.sodg = agent._build_sodg(api_spec_with_relationships)
        
        pattern = {
            "type": "full_crud",
            "resource": "users",
            "operations": list(agent.sodg.values())[:3],
            "description": "Full CRUD workflow"
        }
        
        scenario = await agent._generate_crud_scenario(pattern, api_spec_with_relationships)
        
        assert scenario is not None
        assert isinstance(scenario, StatefulTestScenario)
        assert len(scenario.operations) > 0
        
        # Check operation structure
        for op in scenario.operations:
            assert "operation_id" in op
            assert "method" in op
            assert "path" in op
            assert "extract_rules" in op
            assert "inject_rules" in op
    
    def test_convert_scenario_to_test_case(self, agent):
        """Test converting scenario to test case format"""
        scenario = StatefulTestScenario(
            scenario_id="test_scenario",
            description="Test workflow",
            operations=[
                {
                    "operation_id": "createUser",
                    "method": "POST",
                    "path": "/users",
                    "extract_rules": [],
                    "inject_rules": []
                }
            ],
            state_variables={},
            cleanup_operations=[]
        )
        
        test_case = agent._convert_scenario_to_test_case(scenario)
        
        assert test_case["test_type"] == "functional-stateful"
        assert test_case["method"] == "STATEFUL"
        assert test_case["endpoint"] == "multi-step"
        assert len(test_case["assertions"]) > 0
        assert test_case["assertions"][0]["type"] == "stateful_workflow"
    
    # Data Generation Tests
    
    def test_generate_request_body_for_operation(self, agent, api_spec_with_relationships):
        """Test generating request body for operations"""
        operation_node = OperationNode(
            operation_id="createUser",
            path="/users",
            method="POST",
            operation_spec={
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UserInput"}
                        }
                    }
                }
            },
            dependencies=[],
            dependents=[]
        )
        
        body = agent._generate_request_body_for_operation(
            operation_node, api_spec_with_relationships
        )
        
        assert body is not None
        assert isinstance(body, dict)
        assert "name" in body
        assert "email" in body
    
    def test_generate_realistic_property_value(self, agent):
        """Test generating realistic property values"""
        # Email property
        value = agent._generate_realistic_property_value("email", {"type": "string"})
        assert "@" in value
        assert ".com" in value
        
        # Name property
        value = agent._generate_realistic_property_value("firstName", {"type": "string"})
        assert value == "Stateful"
        
        # Age property
        value = agent._generate_realistic_property_value("age", {"type": "integer"})
        assert value == 25
        
        # Price property
        value = agent._generate_realistic_property_value("price", {"type": "number"})
        assert value == 99.99
    
    def test_get_expected_status_for_operation(self, agent):
        """Test determining expected status codes"""
        operation_node = OperationNode(
            operation_id="createUser",
            path="/users",
            method="POST",
            operation_spec={
                "responses": {
                    "201": {"description": "Created"},
                    "400": {"description": "Bad Request"}
                }
            },
            dependencies=[],
            dependents=[]
        )
        
        status = agent._get_expected_status_for_operation(operation_node)
        assert status == 201
        
        # Test with default
        operation_node.operation_spec = {"responses": {}}
        operation_node.method = "DELETE"
        status = agent._get_expected_status_for_operation(operation_node)
        assert status == 204
    
    def test_generate_assertions_for_operation(self, agent):
        """Test generating assertions for operations"""
        operation_node = OperationNode(
            operation_id="createUser",
            path="/users",
            method="POST",
            operation_spec={
                "responses": {
                    "201": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"}
                            }
                        }
                    }
                }
            },
            dependencies=[],
            dependents=[]
        )
        
        assertions = agent._generate_assertions_for_operation(operation_node)
        
        assert len(assertions) > 0
        
        # Should have status code assertion
        status_assertions = [a for a in assertions if a["type"] == "status_code"]
        assert len(status_assertions) > 0
        assert status_assertions[0]["expected"] == 201
        
        # POST should have ID field assertion
        id_assertions = [a for a in assertions if a["type"] == "response_field_exists"]
        assert len(id_assertions) > 0
    
    # LLM Enhancement Tests
    
    @pytest.mark.asyncio
    async def test_generate_llm_workflows(self, agent, api_spec_with_relationships):
        """Test LLM-enhanced workflow generation"""
        with patch.object(agent, 'llm_enabled', True):
            with patch.object(agent, 'enhance_with_llm', new_callable=AsyncMock) as mock_llm:
                # Setup mock response
                mock_llm.return_value = {
                    "description": "Complex user lifecycle workflow",
                    "operations": [
                        {"operation_id": "createUser", "method": "POST", "path": "/users"},
                        {"operation_id": "updateUser", "method": "PUT", "path": "/users/{id}"}
                    ],
                    "state_variables": {"user_id": None},
                    "cleanup_operations": []
                }
                
                patterns = [{"type": "crud", "operations": []}]
                scenarios = await agent._generate_llm_workflows(patterns, api_spec_with_relationships)
                
                assert len(scenarios) > 0
                assert mock_llm.called
    
    # Edge Cases and Error Handling
    
    def test_handle_empty_paths(self, agent):
        """Test handling empty paths in specification"""
        empty_spec = {"paths": {}}
        sodg = agent._build_sodg(empty_spec)
        
        assert sodg == {}
    
    def test_handle_circular_dependencies(self, agent):
        """Test handling potential circular dependencies"""
        # Create nodes that could form a cycle
        node1 = OperationNode("op1", "/resource1", "POST", {}, [], [])
        node2 = OperationNode("op2", "/resource2", "POST", {}, [], [])
        
        # Test that dependency identification doesn't create cycles
        edge1 = agent._identify_dependency(node1, node2)
        edge2 = agent._identify_dependency(node2, node1)
        
        # Should not create bidirectional dependencies for same type
        if edge1 and edge2:
            assert edge1.dependency_type != edge2.dependency_type
    
    def test_path_parameter_extraction(self, agent):
        """Test extraction of path parameters"""
        assert agent._has_path_parameters("/users/{id}")
        assert agent._has_path_parameters("/users/{userId}/posts/{postId}")
        assert not agent._has_path_parameters("/users")
        assert not agent._has_path_parameters("/")
    
    def test_resource_name_extraction(self, agent):
        """Test extraction of resource names from paths"""
        assert agent._extract_resource_name("/users") == "users"
        assert agent._extract_resource_name("/users/{id}") == "users"
        assert agent._extract_resource_name("/users/{id}/posts") == "posts"
        assert agent._extract_resource_name("/") is None