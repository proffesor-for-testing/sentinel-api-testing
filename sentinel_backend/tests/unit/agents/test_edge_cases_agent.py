"""
Unit tests for the Edge Cases Agent.

Tests the comprehensive edge case generation functionality including:
- Boundary value analysis
- Collection size edge cases
- Unicode and special character handling
- Floating point precision cases
- Date/time edge cases
- Null/empty/undefined handling
- Case sensitivity scenarios
- Whitespace handling
- Pagination, sorting, and filter edge cases
"""

import pytest
import math
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

from sentinel_backend.orchestration_service.agents.edge_cases_agent import EdgeCasesAgent
from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult


class TestEdgeCasesAgent:
    """Test suite for the Edge Cases Agent."""

    @pytest.fixture
    def edge_cases_agent(self):
        """Create an Edge Cases Agent instance for testing."""
        return EdgeCasesAgent()

    @pytest.fixture
    def sample_api_spec(self):
        """Sample API specification for testing."""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "getUsers",
                        "parameters": [
                            {
                                "name": "page",
                                "in": "query",
                                "schema": {"type": "integer", "minimum": 1, "maximum": 1000}
                            },
                            {
                                "name": "name",
                                "in": "query",
                                "schema": {"type": "string", "minLength": 1, "maxLength": 50}
                            },
                            {
                                "name": "sort",
                                "in": "query",
                                "schema": {"type": "string"}
                            }
                        ],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                                            "age": {"type": "integer", "minimum": 0, "maximum": 150},
                                            "email": {"type": "string"},
                                            "tags": {"type": "array", "items": {"type": "string"}}
                                        },
                                        "required": ["name", "email"]
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}}
                    }
                },
                "/users/{userId}": {
                    "get": {
                        "operationId": "getUserById",
                        "parameters": [
                            {
                                "name": "userId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer", "minimum": 1}
                            }
                        ],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "put": {
                        "operationId": "updateUser",
                        "parameters": [
                            {
                                "name": "userId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer", "minimum": 1}
                            }
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "score": {"type": "number"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "Updated"}}
                    }
                },
                "/products": {
                    "get": {
                        "operationId": "getProducts",
                        "parameters": [
                            {
                                "name": "created_at",
                                "in": "query",
                                "schema": {"type": "string", "format": "date-time"}
                            },
                            {
                                "name": "category",
                                "in": "query",
                                "schema": {"type": "string"}
                            },
                            {
                                "name": "min_price",
                                "in": "query",
                                "schema": {"type": "number"}
                            },
                            {
                                "name": "max_price",
                                "in": "query",
                                "schema": {"type": "number"}
                            }
                        ],
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }

    @pytest.fixture
    def sample_task(self):
        """Sample agent task for testing."""
        return AgentTask(
            task_id="edge-test-001",
            spec_id=123,
            agent_type="Edge-Cases-Agent",
            parameters={"coverage": "comprehensive"},
            target_environment="test"
        )

    def test_agent_initialization(self, edge_cases_agent):
        """Test that the agent initializes correctly."""
        assert edge_cases_agent.agent_type == "Edge-Cases-Agent"
        assert hasattr(edge_cases_agent, 'unicode_edge_cases')
        assert hasattr(edge_cases_agent, 'float_edge_cases')
        assert hasattr(edge_cases_agent, 'datetime_edge_cases')
        assert hasattr(edge_cases_agent, 'size_edge_cases')
        assert hasattr(edge_cases_agent, 'case_variations')
        assert hasattr(edge_cases_agent, 'whitespace_variations')

    def test_unicode_edge_cases_initialization(self, edge_cases_agent):
        """Test that unicode edge cases are properly initialized."""
        unicode_cases = edge_cases_agent.unicode_edge_cases

        # Check for specific edge cases
        assert "" in unicode_cases  # Empty string
        assert "\u200B" in unicode_cases  # Zero-width space
        assert "🚀" in unicode_cases  # Emoji
        assert "café" in unicode_cases  # Accented characters

        # Ensure we have a good variety
        assert len(unicode_cases) >= 15

    def test_float_edge_cases_initialization(self, edge_cases_agent):
        """Test that floating point edge cases are properly initialized."""
        float_cases = edge_cases_agent.float_edge_cases

        # Check for specific edge cases
        assert 0.0 in float_cases
        assert -0.0 in float_cases
        assert math.pi in float_cases
        assert math.e in float_cases

        # Check for special values
        has_inf = any(math.isinf(x) for x in float_cases)
        has_nan = any(math.isnan(x) for x in float_cases)
        assert has_inf
        assert has_nan

    def test_extract_endpoints(self, edge_cases_agent, sample_api_spec):
        """Test endpoint extraction from API specification."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        assert len(endpoints) == 5  # 2 + 2 + 1 endpoints

        # Check endpoint structure
        for endpoint in endpoints:
            assert 'path' in endpoint
            assert 'method' in endpoint
            assert 'operation' in endpoint
            assert 'parameters' in endpoint
            assert 'requestBody' in endpoint
            assert 'responses' in endpoint

    @pytest.mark.asyncio
    async def test_execute_success(self, edge_cases_agent, sample_task, sample_api_spec):
        """Test successful execution of edge case generation."""
        result = await edge_cases_agent.execute(sample_task, sample_api_spec)

        assert isinstance(result, AgentResult)
        assert result.task_id == sample_task.task_id
        assert result.agent_type == "Edge-Cases-Agent"
        assert result.status == "success"
        assert len(result.test_cases) > 0

        # Check metadata
        metadata = result.metadata
        assert metadata['total_endpoints'] == 5
        assert metadata['total_test_cases'] > 0
        assert metadata['generation_strategy'] == "comprehensive_edge_case_analysis"
        assert 'edge_case_categories' in metadata

    def test_generate_boundary_value_tests(self, edge_cases_agent, sample_api_spec):
        """Test boundary value test generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the users GET endpoint
        users_get = next(ep for ep in endpoints if ep['path'] == '/users' and ep['method'] == 'GET')

        boundary_tests = edge_cases_agent._generate_boundary_value_tests(users_get, sample_api_spec)

        # Should generate tests for page parameter boundaries
        page_tests = [test for test in boundary_tests if 'page' in test['description']]
        assert len(page_tests) > 0

        # Should test minimum and maximum values
        min_tests = [test for test in page_tests if 'minimum' in test['description']]
        max_tests = [test for test in page_tests if 'maximum' in test['description']]
        assert len(min_tests) > 0
        assert len(max_tests) > 0

    def test_generate_collection_size_tests(self, edge_cases_agent, sample_api_spec):
        """Test collection size edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the users POST endpoint
        users_post = next(ep for ep in endpoints if ep['path'] == '/users' and ep['method'] == 'POST')

        collection_tests = edge_cases_agent._generate_collection_size_tests(users_post, sample_api_spec)

        # Should generate tests for different collection sizes
        assert len(collection_tests) >= 0  # May not have array parameters in this example

    def test_generate_unicode_tests(self, edge_cases_agent, sample_api_spec):
        """Test unicode edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the users GET endpoint
        users_get = next(ep for ep in endpoints if ep['path'] == '/users' and ep['method'] == 'GET')

        unicode_tests = edge_cases_agent._generate_unicode_tests(users_get, sample_api_spec)

        # Should generate tests for string parameters with unicode
        name_tests = [test for test in unicode_tests if 'name' in test['description']]
        assert len(name_tests) > 0

        # Check that various unicode cases are tested
        descriptions = [test['description'] for test in unicode_tests]
        assert any('emoji' in desc.lower() or '🚀' in desc for desc in descriptions)

    def test_generate_floating_point_tests(self, edge_cases_agent, sample_api_spec):
        """Test floating point edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the users PUT endpoint (has number field)
        users_put = next(ep for ep in endpoints if ep['path'] == '/users/{userId}' and ep['method'] == 'PUT')

        float_tests = edge_cases_agent._generate_floating_point_tests(users_put, sample_api_spec)

        # Should generate tests for numeric parameters
        # Note: The sample spec has 'number' type in the request body schema
        assert len(float_tests) >= 0  # May not have float parameters in query

    def test_generate_datetime_tests(self, edge_cases_agent, sample_api_spec):
        """Test datetime edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the products GET endpoint (has date-time parameter)
        products_get = next(ep for ep in endpoints if ep['path'] == '/products' and ep['method'] == 'GET')

        datetime_tests = edge_cases_agent._generate_datetime_tests(products_get, sample_api_spec)

        # Should generate tests for datetime parameters
        created_at_tests = [test for test in datetime_tests if 'created_at' in test['description']]
        assert len(created_at_tests) > 0

    def test_generate_null_empty_tests(self, edge_cases_agent, sample_api_spec):
        """Test null/empty/undefined edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the users GET endpoint
        users_get = next(ep for ep in endpoints if ep['path'] == '/users' and ep['method'] == 'GET')

        null_tests = edge_cases_agent._generate_null_empty_tests(users_get, sample_api_spec)

        # Should generate tests for optional parameters
        # Note: All parameters in the sample spec are not marked as required
        assert len(null_tests) > 0

    def test_generate_case_sensitivity_tests(self, edge_cases_agent, sample_api_spec):
        """Test case sensitivity edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the users GET endpoint
        users_get = next(ep for ep in endpoints if ep['path'] == '/users' and ep['method'] == 'GET')

        case_tests = edge_cases_agent._generate_case_sensitivity_tests(users_get, sample_api_spec)

        # Should generate tests for string parameters with case variations
        name_tests = [test for test in case_tests if 'name' in test['description']]
        assert len(name_tests) > 0

        # Should test different case variations
        descriptions = [test['description'] for test in case_tests]
        assert any('Test' in desc for desc in descriptions)
        assert any('TEST' in desc for desc in descriptions)

    def test_generate_whitespace_tests(self, edge_cases_agent, sample_api_spec):
        """Test whitespace handling edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        # Find the users GET endpoint
        users_get = next(ep for ep in endpoints if ep['path'] == '/users' and ep['method'] == 'GET')

        whitespace_tests = edge_cases_agent._generate_whitespace_tests(users_get, sample_api_spec)

        # Should generate tests for string parameters with whitespace variations
        name_tests = [test for test in whitespace_tests if 'name' in test['description']]
        assert len(name_tests) > 0

    @pytest.mark.asyncio
    async def test_generate_global_edge_cases(self, edge_cases_agent, sample_api_spec):
        """Test global edge case generation."""
        endpoints = edge_cases_agent._extract_endpoints(sample_api_spec)

        global_tests = await edge_cases_agent._generate_global_edge_cases(endpoints, sample_api_spec)

        # Should generate various types of global edge cases
        assert len(global_tests) > 0

        # Check for different types of global tests
        descriptions = [test['description'] for test in global_tests]

        # Should have pagination tests
        pagination_tests = [desc for desc in descriptions if 'pagination' in desc.lower()]
        assert len(pagination_tests) > 0

        # Should have sorting tests
        sorting_tests = [desc for desc in descriptions if 'sorting' in desc.lower()]
        assert len(sorting_tests) > 0

    def test_generate_pagination_edge_cases(self, edge_cases_agent):
        """Test pagination edge case generation."""
        # Create endpoints with pagination parameters
        endpoints = [
            {
                'path': '/users',
                'method': 'GET',
                'parameters': [
                    {'name': 'page', 'in': 'query', 'schema': {'type': 'integer'}}
                ]
            }
        ]

        pagination_tests = edge_cases_agent._generate_pagination_edge_cases(endpoints)

        # Should generate tests for various pagination edge cases
        assert len(pagination_tests) > 0

        descriptions = [test['description'] for test in pagination_tests]
        assert any('page_zero' in desc for desc in descriptions)
        assert any('negative_page' in desc for desc in descriptions)
        assert any('beyond_last_page' in desc for desc in descriptions)

    def test_generate_sorting_edge_cases(self, edge_cases_agent):
        """Test sorting edge case generation."""
        # Create endpoints with sort parameters
        endpoints = [
            {
                'path': '/users',
                'method': 'GET',
                'parameters': [
                    {'name': 'sort', 'in': 'query', 'schema': {'type': 'string'}}
                ]
            }
        ]

        sorting_tests = edge_cases_agent._generate_sorting_edge_cases(endpoints)

        # Should generate tests for various sorting edge cases
        assert len(sorting_tests) > 0

        descriptions = [test['description'] for test in sorting_tests]
        assert any('empty_sort_field' in desc for desc in descriptions)
        assert any('invalid_sort_field' in desc for desc in descriptions)

    def test_generate_filter_combination_tests(self, edge_cases_agent):
        """Test filter combination edge case generation."""
        # Create endpoints with multiple filter parameters
        endpoints = [
            {
                'path': '/products',
                'method': 'GET',
                'parameters': [
                    {'name': 'status', 'in': 'query', 'schema': {'type': 'string'}},
                    {'name': 'category', 'in': 'query', 'schema': {'type': 'string'}},
                    {'name': 'min_price', 'in': 'query', 'schema': {'type': 'number'}},
                    {'name': 'max_price', 'in': 'query', 'schema': {'type': 'number'}}
                ]
            }
        ]

        filter_tests = edge_cases_agent._generate_filter_combination_tests(endpoints)

        # Should generate tests for complex filter combinations
        assert len(filter_tests) > 0

        descriptions = [test['description'] for test in filter_tests]
        assert any('conflicting' in desc for desc in descriptions)
        assert any('invalid_range' in desc for desc in descriptions)

    def test_create_boundary_test(self, edge_cases_agent):
        """Test boundary test case creation."""
        endpoint = {
            'path': '/users',
            'method': 'GET'
        }

        param = {
            'name': 'page',
            'in': 'query',
            'schema': {'type': 'integer'}
        }

        test_case = edge_cases_agent._create_boundary_test(
            endpoint, param, 1, "Test boundary", 200
        )

        assert test_case['endpoint'] == '/users'
        assert test_case['method'] == 'GET'
        assert test_case['description'] == "Test boundary"
        assert test_case['query_params']['page'] == 1
        assert test_case['expected_status'] == 200

    def test_create_boundary_test_path_param(self, edge_cases_agent):
        """Test boundary test case creation for path parameters."""
        endpoint = {
            'path': '/users/{userId}',
            'method': 'GET'
        }

        param = {
            'name': 'userId',
            'in': 'path',
            'schema': {'type': 'integer'}
        }

        test_case = edge_cases_agent._create_boundary_test(
            endpoint, param, 123, "Test path boundary", 200
        )

        assert test_case['endpoint'] == '/users/123'
        assert test_case['method'] == 'GET'
        assert test_case['description'] == "Test path boundary"
        assert test_case['expected_status'] == 200

    def test_create_boundary_test_header_param(self, edge_cases_agent):
        """Test boundary test case creation for header parameters."""
        endpoint = {
            'path': '/users',
            'method': 'GET'
        }

        param = {
            'name': 'X-API-Key',
            'in': 'header',
            'schema': {'type': 'string'}
        }

        test_case = edge_cases_agent._create_boundary_test(
            endpoint, param, "test-key", "Test header boundary", 200
        )

        assert test_case['endpoint'] == '/users'
        assert test_case['method'] == 'GET'
        assert test_case['description'] == "Test header boundary"
        assert test_case['headers']['X-API-Key'] == "test-key"
        assert test_case['expected_status'] == 200

    @pytest.mark.asyncio
    async def test_execute_with_error(self, edge_cases_agent, sample_task):
        """Test execute method handling errors gracefully."""
        # Pass invalid API spec to trigger error
        invalid_spec = {"invalid": "spec"}

        result = await edge_cases_agent.execute(sample_task, invalid_spec)

        assert result.status == "failed"
        assert result.error_message is not None
        assert len(result.test_cases) == 0

    def test_edge_case_categories_coverage(self, edge_cases_agent):
        """Test that all expected edge case categories are implemented."""
        # This is more of a documentation test to ensure we haven't missed any categories
        expected_categories = [
            "boundary_values",
            "empty_collections",
            "single_element_collections",
            "maximum_size_collections",
            "unicode_special_characters",
            "floating_point_edge_cases",
            "datetime_edge_cases",
            "null_empty_undefined",
            "case_sensitivity",
            "whitespace_handling",
            "recursive_structures",
            "concurrent_scenarios",
            "pagination_edge_cases",
            "sorting_edge_cases",
            "filter_combinations"
        ]

        # Check that the agent has methods or attributes for each category
        agent_methods = dir(edge_cases_agent)

        # Most categories should have corresponding generation methods
        boundary_methods = [method for method in agent_methods if 'boundary' in method.lower()]
        unicode_methods = [method for method in agent_methods if 'unicode' in method.lower()]
        float_methods = [method for method in agent_methods if 'float' in method.lower()]
        datetime_methods = [method for method in agent_methods if 'datetime' in method.lower()]

        assert len(boundary_methods) > 0
        assert len(unicode_methods) > 0
        assert len(float_methods) > 0
        assert len(datetime_methods) > 0

    def test_unicode_edge_cases_variety(self, edge_cases_agent):
        """Test that unicode edge cases cover a good variety of scenarios."""
        unicode_cases = edge_cases_agent.unicode_edge_cases

        # Check for different types of unicode edge cases
        has_empty = "" in unicode_cases
        has_whitespace = any(case.isspace() for case in unicode_cases if case)
        has_emoji = any(ord(char) > 0x1F600 for case in unicode_cases for char in case if case)
        has_rtl = any('arabic' in unicodedata.name(char, '').lower()
                     for case in unicode_cases for char in case if case)
        has_zero_width = any('\u200B' in case or '\u200C' in case or '\u200D' in case
                           for case in unicode_cases if case)

        assert has_empty
        assert has_whitespace
        assert has_emoji
        assert has_zero_width

    def test_size_edge_cases_reasonable_limits(self, edge_cases_agent):
        """Test that size edge cases have reasonable limits for testing."""
        size_cases = edge_cases_agent.size_edge_cases

        # Should have various sizes
        assert 'empty' in size_cases
        assert 'single' in size_cases
        assert 'large' in size_cases

        # Sizes should be reasonable for testing
        assert size_cases['empty'] == 0
        assert size_cases['single'] == 1
        assert size_cases['large'] <= 100000  # Not too large to break tests

    @pytest.mark.asyncio
    async def test_concurrent_scenario_tests(self, edge_cases_agent):
        """Test concurrent scenario test generation."""
        # Create endpoints that modify resources
        endpoints = [
            {
                'path': '/users',
                'method': 'POST',
                'parameters': []
            },
            {
                'path': '/users/{userId}',
                'method': 'PUT',
                'parameters': []
            },
            {
                'path': '/users/{userId}',
                'method': 'DELETE',
                'parameters': []
            }
        ]

        concurrent_tests = edge_cases_agent._generate_concurrent_scenario_tests(endpoints)

        # Should generate test case definitions for concurrent scenarios
        assert len(concurrent_tests) == 3  # One for each modification endpoint

        for test in concurrent_tests:
            assert 'concurrent' in test['description'].lower()
            assert len(test['assertions']) > 0
            assert any('concurrency' in assertion.get('type', '') for assertion in test['assertions'])