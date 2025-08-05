"""
Functional-Negative-Agent: Generates tests to trigger errors and validate failure paths.

This agent focuses on creating test cases that should fail under various conditions,
validating that the API properly handles invalid inputs and edge cases using a hybrid
approach of deterministic Boundary Value Analysis and LLM-powered creative generation.
"""

from typing import Dict, List, Any, Optional, Union
import random
import string
from datetime import datetime, timedelta
import json
import re

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
                    ]
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
        Generate negative test cases for a specific endpoint.
        
        Args:
            endpoint: The endpoint definition from the API spec
            api_spec: The full API specification for context
            
        Returns:
            List of negative test cases for this endpoint
        """
        test_cases = []
        
        # Stage 1: Deterministic Boundary Value Analysis
        bva_tests = await self._generate_bva_tests(endpoint, api_spec)
        test_cases.extend(bva_tests)
        
        # Stage 2: Creative Invalid Data Generation
        creative_tests = await self._generate_creative_invalid_tests(endpoint, api_spec)
        test_cases.extend(creative_tests)
        
        # Stage 3: Structural Malformation Tests
        structural_tests = await self._generate_structural_malformation_tests(endpoint, api_spec)
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
    
    def _get_wrong_type_value(self, expected_type: str) -> Any:
        """Get a value of the wrong type for testing."""
        wrong_type_map = {
            "string": 12345,  # Number instead of string
            "integer": "not_a_number",  # String instead of integer
            "number": "not_a_number",  # String instead of number
            "boolean": "not_a_boolean",  # String instead of boolean
            "array": {"not": "an_array"},  # Object instead of array
            "object": "not_an_object"  # String instead of object
        }
        return wrong_type_map.get(expected_type)
    
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
