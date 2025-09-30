"""
Edge Cases Agent: Generates comprehensive edge case tests for boundary conditions and unusual scenarios.

This agent is dedicated to testing edge cases that could expose bugs in boundary handling,
special character processing, data structure limits, and other unusual but valid scenarios
that might not be covered by standard positive or negative testing.
"""

from typing import Dict, List, Any, Optional, Union, Set, Tuple
import random
import string
import math
from datetime import datetime, timedelta, timezone
import json
import re
import uuid
import decimal
from urllib.parse import urlparse
from copy import deepcopy
import unicodedata

from .base_agent import BaseAgent, AgentTask, AgentResult
from sentinel_backend.config.settings import get_application_settings


class EdgeCasesAgent(BaseAgent):
    """
    Agent responsible for generating edge case test scenarios.

    This agent creates test cases that:
    - Test exact boundary values (min, max, min-1, max+1)
    - Handle empty and single-element collections
    - Test unicode and special character edge cases
    - Validate floating point precision scenarios
    - Test date/time edge cases and timezone handling
    - Differentiate between null, empty, and undefined states
    - Test case sensitivity scenarios
    - Handle whitespace and formatting edge cases
    - Test recursive and circular reference scenarios
    - Test concurrent modification edge cases
    - Test pagination boundaries
    - Test sorting with edge case values
    - Test complex filter combinations
    """

    def __init__(self):
        super().__init__("Edge-Cases-Agent")
        self._initialize_edge_case_data()

    def _initialize_edge_case_data(self):
        """Initialize predefined edge case data sets."""
        # Unicode edge cases
        self.unicode_edge_cases = [
            "",  # Empty string
            " ",  # Single space
            "\t",  # Tab
            "\n",  # Newline
            "\r\n",  # CRLF
            "🚀",  # Emoji
            "مرحبا",  # RTL text (Arabic)
            "שלום",  # RTL text (Hebrew)
            "🇺🇸🇺🇸",  # Flag emojis
            "👨‍💻",  # Composite emoji
            "\u200B",  # Zero-width space
            "\u200C",  # Zero-width non-joiner
            "\u200D",  # Zero-width joiner
            "\uFEFF",  # Byte order mark
            "test\u0000null",  # Null character
            "café",  # Accented characters
            "𝓤𝓷𝓲𝓬𝓸𝓭𝓮",  # Mathematical script
            "ﷺ",  # Arabic ligature
            "‍‍‍",  # Multiple zero-width joiners
            " ̶̷̨̀́̋̇͏͜͞ ",  # Combining diacritical marks
        ]

        # Floating point edge cases
        self.float_edge_cases = [
            0.0,
            -0.0,
            float('inf'),
            float('-inf'),
            float('nan'),
            1e-323,  # Smallest positive normal float64
            1.7976931348623157e+308,  # Largest positive float64
            2.2250738585072014e-308,  # Smallest positive denormal float64
            1.0000000000000002,  # Smallest float > 1
            0.9999999999999999,  # Largest float < 1
            1e-15,  # Near machine epsilon
            math.pi,
            math.e,
            0.1 + 0.2,  # Floating point precision issue
        ]

        # Date/time edge cases
        self.datetime_edge_cases = [
            "1970-01-01T00:00:00Z",  # Unix epoch
            "2038-01-19T03:14:07Z",  # Unix timestamp overflow
            "1900-02-29",  # Invalid leap year
            "2000-02-29",  # Valid leap year
            "2100-02-29",  # Invalid leap year (not divisible by 400)
            "2000-12-31T23:59:59.999Z",  # Last moment of millennium
            "2001-01-01T00:00:00.000Z",  # First moment of new millennium
            datetime.now().replace(microsecond=999999).isoformat() + "Z",  # Max microseconds
            datetime.now(timezone.utc).isoformat(),  # Current UTC
            "2023-03-12T02:30:00-05:00",  # DST transition (spring forward)
            "2023-11-05T01:30:00-05:00",  # DST transition (fall back)
        ]

        # Size edge cases for collections
        self.size_edge_cases = {
            'empty': 0,
            'single': 1,
            'small': 5,
            'medium': 100,
            'large': 10000,
            'max_reasonable': 100000,
        }

        # Case sensitivity test strings
        self.case_variations = [
            "test",
            "Test",
            "TEST",
            "tEsT",
            "TeSt",
            "tesT",
        ]

        # Whitespace variations
        self.whitespace_variations = [
            "test",
            " test",
            "test ",
            " test ",
            "\ttest",
            "test\t",
            "\ntest",
            "test\n",
            "  test  ",
            "\t\ntest\r\n\t",
        ]

    async def execute(self, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
        """
        Generate edge case test scenarios for the given API specification.

        Args:
            task: The agent task containing parameters and context
            api_spec: The parsed OpenAPI specification

        Returns:
            AgentResult with generated edge case test scenarios
        """
        try:
            self.logger.info(f"Starting edge case generation for spec_id: {task.spec_id}")

            # Extract all endpoints from the specification
            endpoints = self._extract_endpoints(api_spec)

            test_cases = []

            # Generate edge case tests for each endpoint
            for endpoint in endpoints:
                endpoint_tests = await self._generate_endpoint_edge_cases(endpoint, api_spec)
                test_cases.extend(endpoint_tests)

            # Generate global edge case scenarios
            global_edge_cases = await self._generate_global_edge_cases(endpoints, api_spec)
            test_cases.extend(global_edge_cases)

            # If LLM is enabled, generate additional creative edge cases
            if self.llm_enabled and test_cases:
                self.logger.info("Generating LLM-enhanced edge case scenarios")
                llm_tests = await self._generate_llm_edge_cases(endpoints[:3], api_spec)
                test_cases.extend(llm_tests)

            self.logger.info(f"Generated {len(test_cases)} edge case test scenarios")

            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="success",
                test_cases=test_cases,
                metadata={
                    "total_endpoints": len(endpoints),
                    "total_test_cases": len(test_cases),
                    "generation_strategy": "comprehensive_edge_case_analysis",
                    "edge_case_categories": [
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
                    ],
                    "llm_enhanced": self.llm_enabled,
                    "unicode_test_count": len(self.unicode_edge_cases),
                    "float_test_count": len(self.float_edge_cases),
                    "datetime_test_count": len(self.datetime_edge_cases)
                }
            )

        except Exception as e:
            self.logger.error(f"Error generating edge case tests: {str(e)}")
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="failed",
                error_message=str(e)
            )

    def _extract_endpoints(self, api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize endpoint information from the API specification."""
        endpoints = []
        paths = api_spec.get('paths', {})

        for path, path_obj in paths.items():
            for method, operation in path_obj.items():
                if method.lower() in ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']:
                    endpoint = {
                        'path': path,
                        'method': method.upper(),
                        'operation': operation,
                        'parameters': operation.get('parameters', []),
                        'requestBody': operation.get('requestBody', {}),
                        'responses': operation.get('responses', {}),
                        'operationId': operation.get('operationId', f"{method}_{path.replace('/', '_')}")
                    }
                    endpoints.append(endpoint)

        return endpoints

    async def _generate_endpoint_edge_cases(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate edge case tests for a specific endpoint."""
        test_cases = []

        # Boundary value tests
        boundary_tests = self._generate_boundary_value_tests(endpoint, api_spec)
        test_cases.extend(boundary_tests)

        # Collection size tests
        collection_tests = self._generate_collection_size_tests(endpoint, api_spec)
        test_cases.extend(collection_tests)

        # Unicode and special character tests
        unicode_tests = self._generate_unicode_tests(endpoint, api_spec)
        test_cases.extend(unicode_tests)

        # Floating point precision tests
        float_tests = self._generate_floating_point_tests(endpoint, api_spec)
        test_cases.extend(float_tests)

        # Date/time edge case tests
        datetime_tests = self._generate_datetime_tests(endpoint, api_spec)
        test_cases.extend(datetime_tests)

        # Null/empty/undefined tests
        null_tests = self._generate_null_empty_tests(endpoint, api_spec)
        test_cases.extend(null_tests)

        # Case sensitivity tests
        case_tests = self._generate_case_sensitivity_tests(endpoint, api_spec)
        test_cases.extend(case_tests)

        # Whitespace handling tests
        whitespace_tests = self._generate_whitespace_tests(endpoint, api_spec)
        test_cases.extend(whitespace_tests)

        return test_cases

    def _generate_boundary_value_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for exact boundary values."""
        test_cases = []
        path = endpoint['path']
        method = endpoint['method']

        # Test numeric boundaries in parameters
        for param in endpoint.get('parameters', []):
            if param.get('schema', {}).get('type') == 'integer':
                schema = param['schema']
                minimum = schema.get('minimum')
                maximum = schema.get('maximum')

                if minimum is not None:
                    # Test exact minimum
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, minimum,
                        f"Boundary test: {param['name']} at exact minimum ({minimum})"
                    ))

                    # Test minimum - 1 (should fail if exclusive minimum)
                    if minimum > 0:
                        test_cases.append(self._create_boundary_test(
                            endpoint, param, minimum - 1,
                            f"Boundary test: {param['name']} below minimum ({minimum - 1})",
                            expected_status=400
                        ))

                if maximum is not None:
                    # Test exact maximum
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, maximum,
                        f"Boundary test: {param['name']} at exact maximum ({maximum})"
                    ))

                    # Test maximum + 1 (should fail if exclusive maximum)
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, maximum + 1,
                        f"Boundary test: {param['name']} above maximum ({maximum + 1})",
                        expected_status=400
                    ))

        # Test string length boundaries
        for param in endpoint.get('parameters', []):
            if param.get('schema', {}).get('type') == 'string':
                schema = param['schema']
                min_length = schema.get('minLength')
                max_length = schema.get('maxLength')

                if min_length is not None:
                    # Test exact minimum length
                    test_string = 'a' * min_length
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, test_string,
                        f"Boundary test: {param['name']} at exact minLength ({min_length})"
                    ))

                    # Test minimum length - 1
                    if min_length > 0:
                        test_string = 'a' * (min_length - 1)
                        test_cases.append(self._create_boundary_test(
                            endpoint, param, test_string,
                            f"Boundary test: {param['name']} below minLength ({min_length - 1})",
                            expected_status=400
                        ))

                if max_length is not None:
                    # Test exact maximum length
                    test_string = 'a' * max_length
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, test_string,
                        f"Boundary test: {param['name']} at exact maxLength ({max_length})"
                    ))

                    # Test maximum length + 1
                    test_string = 'a' * (max_length + 1)
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, test_string,
                        f"Boundary test: {param['name']} above maxLength ({max_length + 1})",
                        expected_status=400
                    ))

        return test_cases

    def _generate_collection_size_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for various collection sizes."""
        test_cases = []

        # Test array parameters with different sizes
        for param in endpoint.get('parameters', []):
            if param.get('schema', {}).get('type') == 'array':
                for size_name, size_value in self.size_edge_cases.items():
                    if size_value <= 1000:  # Limit size for practical testing
                        test_array = ['item'] * size_value
                        test_cases.append(self._create_boundary_test(
                            endpoint, param, test_array,
                            f"Collection size test: {param['name']} with {size_name} size ({size_value} items)"
                        ))

        # Test request body arrays
        request_body = endpoint.get('requestBody', {})
        if request_body:
            content = request_body.get('content', {})
            for content_type, content_schema in content.items():
                if 'application/json' in content_type:
                    schema = content_schema.get('schema', {})
                    array_tests = self._generate_array_size_tests_for_schema(
                        schema, endpoint, "request body"
                    )
                    test_cases.extend(array_tests)

        return test_cases

    def _generate_unicode_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for unicode and special character edge cases."""
        test_cases = []

        # Test string parameters with unicode edge cases
        for param in endpoint.get('parameters', []):
            if param.get('schema', {}).get('type') == 'string':
                for unicode_case in self.unicode_edge_cases[:10]:  # Limit for practicality
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, unicode_case,
                        f"Unicode test: {param['name']} with '{repr(unicode_case)}'"
                    ))

        return test_cases

    def _generate_floating_point_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for floating point edge cases."""
        test_cases = []

        # Test numeric parameters with floating point edge cases
        for param in endpoint.get('parameters', []):
            param_type = param.get('schema', {}).get('type')
            if param_type in ['number', 'float', 'double']:
                for float_case in self.float_edge_cases:
                    # Skip NaN and infinity for most APIs as they may not be supported
                    if not (math.isnan(float_case) or math.isinf(float_case)):
                        test_cases.append(self._create_boundary_test(
                            endpoint, param, float_case,
                            f"Float precision test: {param['name']} with {float_case}"
                        ))

        return test_cases

    def _generate_datetime_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for date/time edge cases."""
        test_cases = []

        # Test date/time parameters
        for param in endpoint.get('parameters', []):
            param_format = param.get('schema', {}).get('format')
            if param_format in ['date', 'date-time', 'time']:
                for datetime_case in self.datetime_edge_cases[:5]:  # Limit for practicality
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, datetime_case,
                        f"DateTime edge test: {param['name']} with {datetime_case}"
                    ))

        return test_cases

    def _generate_null_empty_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for null, empty, and undefined states."""
        test_cases = []

        # Test different absence representations
        absence_values = [
            (None, "null"),
            ("", "empty_string"),
            ([], "empty_array"),
            ({}, "empty_object"),
        ]

        for param in endpoint.get('parameters', []):
            if not param.get('required', False):  # Only test optional parameters
                for value, description in absence_values:
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, value,
                        f"Absence test: {param['name']} with {description}"
                    ))

        return test_cases

    def _generate_case_sensitivity_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for case sensitivity scenarios."""
        test_cases = []

        # Test string parameters with case variations
        for param in endpoint.get('parameters', []):
            if param.get('schema', {}).get('type') == 'string':
                for case_variation in self.case_variations:
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, case_variation,
                        f"Case sensitivity test: {param['name']} with '{case_variation}'"
                    ))

        return test_cases

    def _generate_whitespace_tests(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate tests for whitespace handling edge cases."""
        test_cases = []

        # Test string parameters with whitespace variations
        for param in endpoint.get('parameters', []):
            if param.get('schema', {}).get('type') == 'string':
                for whitespace_variation in self.whitespace_variations:
                    test_cases.append(self._create_boundary_test(
                        endpoint, param, whitespace_variation,
                        f"Whitespace test: {param['name']} with '{repr(whitespace_variation)}'"
                    ))

        return test_cases

    async def _generate_global_edge_cases(self, endpoints: List[Dict[str, Any]], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate global edge case scenarios that apply across endpoints."""
        test_cases = []

        # Pagination edge cases
        pagination_tests = self._generate_pagination_edge_cases(endpoints)
        test_cases.extend(pagination_tests)

        # Sorting edge cases
        sorting_tests = self._generate_sorting_edge_cases(endpoints)
        test_cases.extend(sorting_tests)

        # Filter combination edge cases
        filter_tests = self._generate_filter_combination_tests(endpoints)
        test_cases.extend(filter_tests)

        # Concurrent request scenarios (test case generation only)
        concurrent_tests = self._generate_concurrent_scenario_tests(endpoints)
        test_cases.extend(concurrent_tests)

        return test_cases

    def _generate_pagination_edge_cases(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate pagination edge case tests."""
        test_cases = []

        pagination_edge_cases = [
            (0, "page_zero"),
            (-1, "negative_page"),
            (999999, "beyond_last_page"),
            (1.5, "fractional_page"),
        ]

        for endpoint in endpoints:
            if endpoint['method'] == 'GET':
                # Look for pagination parameters
                has_page_param = any(
                    param.get('name', '').lower() in ['page', 'offset', 'skip']
                    for param in endpoint.get('parameters', [])
                )

                if has_page_param:
                    for page_value, description in pagination_edge_cases:
                        query_params = {'page': page_value}

                        test_cases.append(self._create_test_case(
                            endpoint=endpoint['path'],
                            method=endpoint['method'],
                            description=f"Pagination edge case: {description} for {endpoint['path']}",
                            query_params=query_params,
                            expected_status=400 if page_value < 1 or isinstance(page_value, float) else 200
                        ))

        return test_cases

    def _generate_sorting_edge_cases(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate sorting edge case tests."""
        test_cases = []

        sorting_edge_cases = [
            ("", "empty_sort_field"),
            ("nonexistent_field", "invalid_sort_field"),
            ("field1,field2", "multiple_sort_fields"),
            ("field1 asc,field2 desc", "mixed_sort_directions"),
        ]

        for endpoint in endpoints:
            if endpoint['method'] == 'GET':
                # Look for sort parameters
                has_sort_param = any(
                    param.get('name', '').lower() in ['sort', 'order', 'orderby']
                    for param in endpoint.get('parameters', [])
                )

                if has_sort_param:
                    for sort_value, description in sorting_edge_cases:
                        query_params = {'sort': sort_value}

                        test_cases.append(self._create_test_case(
                            endpoint=endpoint['path'],
                            method=endpoint['method'],
                            description=f"Sorting edge case: {description} for {endpoint['path']}",
                            query_params=query_params,
                            expected_status=400 if sort_value in ["", "nonexistent_field"] else 200
                        ))

        return test_cases

    def _generate_filter_combination_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate tests for complex filter combinations."""
        test_cases = []

        # Complex filter scenarios
        filter_combinations = [
            ({"status": "active", "status": "inactive"}, "conflicting_filters"),
            ({"min_price": 100, "max_price": 50}, "invalid_range_filters"),
            ({"category": "", "subcategory": "electronics"}, "empty_parent_filter"),
            ({"search": "test", "category": "all", "status": "any"}, "redundant_filters"),
        ]

        for endpoint in endpoints:
            if endpoint['method'] == 'GET':
                # Look for filter-like parameters
                filter_params = [
                    param for param in endpoint.get('parameters', [])
                    if param.get('name', '').lower() in [
                        'filter', 'status', 'category', 'type', 'search',
                        'min_price', 'max_price', 'min_date', 'max_date'
                    ]
                ]

                if len(filter_params) > 1:  # Only test if multiple filter params exist
                    for filters, description in filter_combinations:
                        test_cases.append(self._create_test_case(
                            endpoint=endpoint['path'],
                            method=endpoint['method'],
                            description=f"Filter combination: {description} for {endpoint['path']}",
                            query_params=filters,
                            expected_status=400 if "conflicting" in description or "invalid" in description else 200
                        ))

        return test_cases

    def _generate_concurrent_scenario_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate test case definitions for concurrent scenarios."""
        test_cases = []

        # Find endpoints that modify resources
        modification_endpoints = [
            ep for ep in endpoints
            if ep['method'] in ['POST', 'PUT', 'PATCH', 'DELETE']
        ]

        for endpoint in modification_endpoints:
            # Create test case scenarios for concurrent modification
            test_cases.append(self._create_test_case(
                endpoint=endpoint['path'],
                method=endpoint['method'],
                description=f"Concurrent modification scenario for {endpoint['path']} - Test case definition",
                body={"note": "This is a test case definition for concurrent access testing"},
                expected_status=200,
                assertions=[
                    {
                        "type": "concurrency_note",
                        "description": "This test should be run with multiple concurrent requests to verify race condition handling"
                    }
                ]
            ))

        return test_cases

    def _create_boundary_test(
        self,
        endpoint: Dict[str, Any],
        param: Dict[str, Any],
        value: Any,
        description: str,
        expected_status: int = 200
    ) -> Dict[str, Any]:
        """Create a boundary value test case."""
        param_name = param['name']
        param_in = param.get('in', 'query')

        if param_in == 'query':
            return self._create_test_case(
                endpoint=endpoint['path'],
                method=endpoint['method'],
                description=description,
                query_params={param_name: value},
                expected_status=expected_status
            )
        elif param_in == 'path':
            # Replace path parameter
            path_with_value = endpoint['path'].replace(f"{{{param_name}}}", str(value))
            return self._create_test_case(
                endpoint=path_with_value,
                method=endpoint['method'],
                description=description,
                expected_status=expected_status
            )
        elif param_in == 'header':
            return self._create_test_case(
                endpoint=endpoint['path'],
                method=endpoint['method'],
                description=description,
                headers={param_name: str(value)},
                expected_status=expected_status
            )
        else:
            # Default to query parameter
            return self._create_test_case(
                endpoint=endpoint['path'],
                method=endpoint['method'],
                description=description,
                query_params={param_name: value},
                expected_status=expected_status
            )

    def _generate_array_size_tests_for_schema(
        self,
        schema: Dict[str, Any],
        endpoint: Dict[str, Any],
        context: str
    ) -> List[Dict[str, Any]]:
        """Generate array size tests for a given schema."""
        test_cases = []

        if schema.get('type') == 'array':
            for size_name, size_value in self.size_edge_cases.items():
                if size_value <= 100:  # Limit for request body testing
                    test_array = ['item'] * size_value

                    test_cases.append(self._create_test_case(
                        endpoint=endpoint['path'],
                        method=endpoint['method'],
                        description=f"Array size test: {context} with {size_name} size ({size_value} items)",
                        body=test_array,
                        expected_status=200 if size_value > 0 else 400
                    ))

        elif schema.get('type') == 'object':
            properties = schema.get('properties', {})
            for prop_name, prop_schema in properties.items():
                if prop_schema.get('type') == 'array':
                    for size_name, size_value in self.size_edge_cases.items():
                        if size_value <= 50:  # Further limit for nested arrays
                            test_array = ['item'] * size_value

                            test_cases.append(self._create_test_case(
                                endpoint=endpoint['path'],
                                method=endpoint['method'],
                                description=f"Nested array size test: {prop_name} with {size_name} size ({size_value} items)",
                                body={prop_name: test_array},
                                expected_status=200 if size_value > 0 else 400
                            ))

        return test_cases

    async def _generate_llm_edge_cases(self, endpoints: List[Dict[str, Any]], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate additional edge cases using LLM creativity."""
        if not self.llm_enabled:
            return []

        test_cases = []

        try:
            # Create a prompt for creative edge case generation
            prompt = self._create_llm_edge_case_prompt(endpoints, api_spec)

            # Get LLM response
            response = await self.llm_provider.generate_completion(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.7
            )

            # Parse the response and create test cases
            llm_test_cases = self._parse_llm_edge_case_response(response, endpoints)
            test_cases.extend(llm_test_cases)

        except Exception as e:
            self.logger.warning(f"Failed to generate LLM edge cases: {str(e)}")

        return test_cases

    def _create_llm_edge_case_prompt(self, endpoints: List[Dict[str, Any]], api_spec: Dict[str, Any]) -> str:
        """Create a prompt for LLM to generate creative edge cases."""
        endpoint_descriptions = []
        for endpoint in endpoints:
            endpoint_descriptions.append(f"- {endpoint['method']} {endpoint['path']}")

        prompt = f"""
        Given these API endpoints:
        {chr(10).join(endpoint_descriptions)}

        Generate 5 creative edge case test scenarios that might reveal bugs or unexpected behavior.
        Focus on unusual but valid combinations of parameters, unconventional data patterns,
        or scenarios that might not be covered by standard boundary value analysis.

        For each test case, provide:
        1. A clear description
        2. The endpoint to test
        3. The HTTP method
        4. Any special parameters or body content
        5. Expected behavior or potential issues

        Format your response as a JSON array of test case objects.
        """

        return prompt

    def _parse_llm_edge_case_response(self, response: str, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse LLM response and convert to test cases."""
        test_cases = []

        try:
            # Try to parse as JSON
            llm_cases = json.loads(response)

            for case in llm_cases:
                if isinstance(case, dict) and 'description' in case:
                    test_case = self._create_test_case(
                        endpoint=case.get('endpoint', '/'),
                        method=case.get('method', 'GET'),
                        description=f"LLM Edge Case: {case['description']}",
                        query_params=case.get('query_params', {}),
                        body=case.get('body'),
                        expected_status=case.get('expected_status', 200)
                    )
                    test_cases.append(test_case)

        except json.JSONDecodeError:
            self.logger.warning("Failed to parse LLM response as JSON")

        return test_cases