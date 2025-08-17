"""
Comprehensive Unit Tests for PerformancePlannerAgent

This module provides extensive test coverage for the PerformancePlannerAgent class,
including load testing, stress testing, and performance scenario generation.
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from typing import Dict, Any, List

from sentinel_backend.orchestration_service.agents.performance_planner_agent import (
    PerformancePlannerAgent
)
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


class TestPerformancePlannerAgent:
    """Comprehensive test suite for PerformancePlannerAgent"""
    
    @pytest.fixture
    def agent(self):
        """Create PerformancePlannerAgent instance for testing"""
        return PerformancePlannerAgent()
    
    @pytest.fixture
    def agent_task(self):
        """Sample agent task for testing"""
        return AgentTask(
            task_id="test-perf-101",
            spec_id=1,
            agent_type="Performance-Planner-Agent",
            parameters={}
        )
    
    @pytest.fixture
    def api_spec(self):
        """Sample OpenAPI specification for performance testing"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {}}
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
                        },
                        "responses": {"201": {}}
                    }
                },
                "/search": {
                    "get": {
                        "summary": "Search endpoint",
                        "parameters": [
                            {"name": "q", "in": "query", "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {}}
                    }
                },
                "/upload": {
                    "post": {
                        "summary": "File upload",
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "file": {"type": "string", "format": "binary"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {}}
                    }
                },
                "/auth/login": {
                    "post": {
                        "summary": "User login",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {}, "401": {}}
                    }
                },
                "/reports/export": {
                    "get": {
                        "summary": "Export report",
                        "responses": {"200": {}}
                    }
                }
            }
        }
    
    # Core Functionality Tests
    
    def test_agent_initialization(self, agent):
        """Test agent initialization and configuration"""
        assert agent.agent_type == "Performance-Planner-Agent"
        assert agent.default_users == 10
        assert agent.max_users == 1000
        assert agent.test_duration == 60
        assert agent.ramp_up_time == 30
        assert agent.think_time == 1
    
    @pytest.mark.asyncio
    async def test_execute_success(self, agent, agent_task, api_spec):
        """Test successful execution of performance test generation"""
        result = await agent.execute(agent_task, api_spec)
        
        assert isinstance(result, AgentResult)
        assert result.task_id == agent_task.task_id
        assert result.agent_type == "Performance-Planner-Agent"
        assert result.status == "success"
        assert len(result.test_cases) > 0
        assert result.metadata is not None
        assert "test_types" in result.metadata
        assert "Load" in result.metadata["test_types"]
    
    @pytest.mark.asyncio
    async def test_execute_error_handling(self, agent, agent_task):
        """Test error handling during execution"""
        invalid_spec = {"invalid": "spec"}
        
        result = await agent.execute(agent_task, invalid_spec)
        
        assert result.status == "failed"
        assert result.error_message is not None
        assert len(result.test_cases) == 0
    
    # API Analysis Tests
    
    def test_analyze_api_performance_characteristics(self, agent, api_spec):
        """Test API performance characteristics analysis"""
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        
        assert "total_endpoints" in analysis
        assert "read_endpoints" in analysis
        assert "write_endpoints" in analysis
        assert "critical_paths" in analysis
        assert "data_intensive_operations" in analysis
        assert "authentication_required" in analysis
        assert "estimated_complexity" in analysis
        assert "recommended_load_patterns" in analysis
        
        # Check counts
        assert analysis["total_endpoints"] == 6
        assert analysis["read_endpoints"] == 3  # GET endpoints
        assert analysis["write_endpoints"] == 3  # POST endpoints
        
        # Should identify critical paths
        assert len(analysis["critical_paths"]) > 0
        critical_paths = [cp["path"] for cp in analysis["critical_paths"]]
        assert "/auth/login" in critical_paths or "/search" in critical_paths
        
        # Should identify data-intensive operations
        assert len(analysis["data_intensive_operations"]) > 0
        data_ops = [op["path"] for op in analysis["data_intensive_operations"]]
        assert "/upload" in data_ops or "/reports/export" in data_ops
    
    def test_is_critical_path(self, agent, api_spec):
        """Test critical path identification"""
        # Login endpoint should be critical
        assert agent._is_critical_path(
            "/auth/login", "POST", 
            api_spec["paths"]["/auth/login"]["post"]
        )
        
        # Search endpoint should be critical
        assert agent._is_critical_path(
            "/search", "GET",
            api_spec["paths"]["/search"]["get"]
        )
        
        # Regular endpoint might not be critical
        regular_op = {"summary": "Regular operation"}
        assert not agent._is_critical_path("/regular", "GET", regular_op)
    
    def test_is_data_intensive(self, agent, api_spec):
        """Test data-intensive operation identification"""
        # Upload endpoint should be data-intensive
        assert agent._is_data_intensive(
            "/upload", "POST",
            api_spec["paths"]["/upload"]["post"]
        )
        
        # Export endpoint should be data-intensive
        assert agent._is_data_intensive(
            "/reports/export", "GET",
            api_spec["paths"]["/reports/export"]["get"]
        )
        
        # Regular endpoint should not be data-intensive
        assert not agent._is_data_intensive(
            "/users", "GET",
            api_spec["paths"]["/users"]["get"]
        )
    
    def test_requires_authentication(self, agent, api_spec):
        """Test authentication requirement detection"""
        # Login endpoint has security requirement
        assert agent._requires_authentication(
            api_spec["paths"]["/auth/login"]["post"]
        )
        
        # Regular endpoint without security
        assert not agent._requires_authentication(
            api_spec["paths"]["/users"]["get"]
        )
        
        # Test with 401 response
        op_with_401 = {"responses": {"401": {}}}
        assert agent._requires_authentication(op_with_401)
    
    def test_estimate_api_complexity(self, agent):
        """Test API complexity estimation"""
        # Low complexity
        analysis = {
            "total_endpoints": 3,
            "critical_paths": [],
            "data_intensive_operations": []
        }
        assert agent._estimate_api_complexity(analysis) == "low"
        
        # Medium complexity
        analysis = {
            "total_endpoints": 10,
            "critical_paths": [1, 2],
            "data_intensive_operations": [1]
        }
        assert agent._estimate_api_complexity(analysis) == "medium"
        
        # High complexity
        analysis = {
            "total_endpoints": 20,
            "critical_paths": [1, 2, 3, 4],
            "data_intensive_operations": [1, 2, 3]
        }
        assert agent._estimate_api_complexity(analysis) == "high"
    
    # Load Test Generation Tests
    
    def test_generate_load_test_scenarios(self, agent, api_spec):
        """Test load test scenario generation"""
        path = "/users"
        method = "get"
        operation = api_spec["paths"]["/users"]["get"]
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        
        test_cases = agent._generate_load_test_scenarios(path, method, operation, analysis)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_type"] == "performance-planner"
            assert test_case["test_subtype"] == "load-test"
            assert "performance_config" in test_case
            assert "k6_script" in test_case
            assert "jmeter_config" in test_case
            
            config = test_case["performance_config"]
            assert config["test_type"] == "load"
            assert "duration" in config
            assert "virtual_users" in config
            assert "success_criteria" in config
    
    def test_generate_stress_test_scenarios(self, agent, api_spec):
        """Test stress test scenario generation"""
        path = "/users"
        method = "post"
        operation = api_spec["paths"]["/users"]["post"]
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        
        test_cases = agent._generate_stress_test_scenarios(path, method, operation, analysis)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "stress-test"
            config = test_case["performance_config"]
            assert config["test_type"] == "stress"
            assert "max_virtual_users" in config
            assert "breaking_point_detection" in config
            assert "recovery_validation" in config
    
    def test_generate_spike_test_scenarios(self, agent, api_spec):
        """Test spike test scenario generation"""
        path = "/search"
        method = "get"
        operation = api_spec["paths"]["/search"]["get"]
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        
        test_cases = agent._generate_spike_test_scenarios(path, method, operation, analysis)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "spike-test"
            config = test_case["performance_config"]
            assert config["test_type"] == "spike"
            assert "baseline_users" in config
            assert "spike_users" in config
            assert "spike_duration" in config
            assert "recovery_time" in config
    
    def test_generate_system_wide_tests(self, agent, api_spec):
        """Test system-wide performance test generation"""
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        test_cases = agent._generate_system_wide_tests(api_spec, analysis)
        
        assert len(test_cases) > 0
        
        for test_case in test_cases:
            assert test_case["test_subtype"] == "system-wide"
            assert "workflow" in test_case
            config = test_case["performance_config"]
            assert config["test_type"] == "system-wide"
            assert "workflow_name" in config
            assert "concurrent_workflows" in config
    
    # Load Profile Tests
    
    def test_get_load_profiles_for_operation(self, agent, api_spec):
        """Test load profile generation for operations"""
        # Critical path operation
        path = "/auth/login"
        method = "post"
        operation = api_spec["paths"]["/auth/login"]["post"]
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        
        profiles = agent._get_load_profiles_for_operation(path, method, operation, analysis)
        
        assert len(profiles) > 0
        
        # Should have critical profile
        critical_profiles = [p for p in profiles if p["category"] == "critical"]
        assert len(critical_profiles) > 0
        
        for profile in profiles:
            assert "name" in profile
            assert "duration" in profile
            assert "virtual_users" in profile
            assert "success_criteria" in profile
    
    def test_get_stress_profiles_for_operation(self, agent, api_spec):
        """Test stress profile generation"""
        path = "/users"
        method = "get"
        operation = api_spec["paths"]["/users"]["get"]
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        
        profiles = agent._get_stress_profiles_for_operation(path, method, operation, analysis)
        
        assert len(profiles) > 0
        
        for profile in profiles:
            assert "max_virtual_users" in profile
            assert "breaking_point_detection" in profile
            assert profile["max_virtual_users"] >= agent.default_users
    
    def test_get_spike_profiles_for_operation(self, agent, api_spec):
        """Test spike profile generation"""
        path = "/search"
        method = "get"
        operation = api_spec["paths"]["/search"]["get"]
        analysis = agent._analyze_api_performance_characteristics(api_spec)
        
        profiles = agent._get_spike_profiles_for_operation(path, method, operation, analysis)
        
        assert len(profiles) > 0
        
        for profile in profiles:
            assert "baseline_users" in profile
            assert "spike_users" in profile
            assert profile["spike_users"] > profile["baseline_users"]
    
    # Script Generation Tests
    
    def test_generate_k6_script(self, agent):
        """Test k6 script generation"""
        profile = {
            "virtual_users": 10,
            "duration": "60s",
            "ramp_up_time": "30s",
            "ramp_down_time": "30s",
            "think_time": "1s",
            "expected_response_time": "500ms",
            "success_criteria": {
                "response_time_p95": "1s",
                "error_rate": "1%"
            }
        }
        
        script = agent._generate_k6_script("/users", "GET", {}, profile)
        
        assert "import http from 'k6/http'" in script
        assert "export let options" in script
        assert "stages" in script
        assert "thresholds" in script
        assert "http.get" in script
        assert "check(response" in script
    
    def test_generate_k6_stress_script(self, agent):
        """Test k6 stress test script generation"""
        profile = {
            "max_virtual_users": 100,
            "breaking_point_detection": {
                "response_time_threshold": "5s",
                "error_rate_threshold": "10%"
            }
        }
        
        script = agent._generate_k6_stress_script("/users", "POST", {}, profile)
        
        assert "stages" in script
        assert str(profile["max_virtual_users"]) in script
        assert "http.post" in script
    
    def test_generate_k6_spike_script(self, agent):
        """Test k6 spike test script generation"""
        profile = {
            "baseline_users": 10,
            "spike_users": 100,
            "spike_duration": "2m",
            "recovery_time": "5m",
            "success_criteria": {
                "error_rate_during_spike": "5%"
            }
        }
        
        script = agent._generate_k6_spike_script("/search", "GET", {}, profile)
        
        assert str(profile["baseline_users"]) in script
        assert str(profile["spike_users"]) in script
        assert profile["spike_duration"] in script
    
    def test_generate_k6_workflow_script(self, agent):
        """Test k6 workflow script generation"""
        workflow = {
            "name": "User Journey",
            "concurrent_workflows": 5,
            "duration": "10m",
            "steps": [
                {"action": "login", "weight": 0.8},
                {"action": "browse", "weight": 0.9},
                {"action": "purchase", "weight": 0.3}
            ],
            "success_criteria": {
                "error_rate": "2%"
            }
        }
        
        script = agent._generate_k6_workflow_script(workflow)
        
        assert "User Journey workflow" in script
        assert "Math.random()" in script
        for step in workflow["steps"]:
            assert step["action"] in script
            assert str(step["weight"]) in script
    
    def test_generate_jmeter_config(self, agent):
        """Test JMeter configuration generation"""
        profile = {
            "virtual_users": 20,
            "ramp_up_time": "60s",
            "duration": "300s",
            "expected_response_time": "1000ms"
        }
        
        config = agent._generate_jmeter_config("/users", "GET", {}, profile)
        
        assert "test_plan" in config
        assert "thread_group" in config["test_plan"]
        assert config["test_plan"]["thread_group"]["threads"] == 20
        assert "http_request" in config["test_plan"]
        assert "assertions" in config["test_plan"]
    
    # Helper Method Tests
    
    def test_generate_performance_headers(self, agent):
        """Test performance test header generation"""
        headers = agent._generate_performance_headers()
        
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "application/json"
        assert "Sentinel-Performance-Test" in headers["User-Agent"]
    
    def test_generate_performance_query_params(self, agent):
        """Test performance-optimized query parameter generation"""
        operation = {
            "parameters": [
                {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                {"name": "offset", "in": "query", "schema": {"type": "integer"}},
                {"name": "sort", "in": "query", "schema": {"type": "string"}}
            ]
        }
        
        params = agent._generate_performance_query_params(operation)
        
        assert "limit" in params
        assert params["limit"] == 10  # Small for performance
        assert "offset" in params
        assert "sort" in params
    
    def test_generate_valid_path_params(self, agent):
        """Test valid path parameter generation"""
        path = "/users/{id}/posts/{postId}"
        operation = {
            "parameters": [
                {"name": "id", "in": "path", "schema": {"type": "integer"}},
                {"name": "postId", "in": "path", "schema": {"type": "integer"}}
            ]
        }
        
        params = agent._generate_valid_path_params(path, operation)
        
        assert "id" in params
        assert "postId" in params
        assert isinstance(params["id"], int)
        assert isinstance(params["postId"], int)
    
    def test_generate_request_body(self, agent):
        """Test request body generation for performance tests"""
        operation = {
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "count": {"type": "integer"}
                            },
                            "required": ["name"]
                        }
                    }
                }
            }
        }
        
        body = agent._generate_request_body(operation)
        
        assert body is not None
        assert "name" in body
        assert isinstance(body["name"], str)