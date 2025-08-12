"""
Functional-Positive-Agent: Generates valid, "happy path" test cases.

This agent focuses on creating test cases that should succeed under normal conditions,
validating that the API works correctly for valid inputs and expected usage patterns.
"""

from typing import Dict, List, Any, Optional
import random
import string
from datetime import datetime, timedelta

from .base_agent import BaseAgent, AgentTask, AgentResult
from sentinel_backend.config.settings import get_application_settings


class FunctionalPositiveAgent(BaseAgent):
    """
    Agent responsible for generating positive functional test cases.
    
    This agent creates test cases that:
    - Use valid data according to the API specification
    - Follow expected usage patterns
    - Should result in successful responses (2xx status codes)
    - Cover the main functionality of each endpoint
    """
    
    def __init__(self):
        super().__init__("Functional-Positive-Agent")
    
    async def execute(self, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
        """
        Generate positive functional test cases for the given API specification.
        
        Args:
            task: The agent task containing parameters and context
            api_spec: The parsed OpenAPI specification
            
        Returns:
            AgentResult with generated test cases
        """
        try:
            self.logger.info(f"Starting positive test generation for spec_id: {task.spec_id}")
            
            # Extract all endpoints from the specification
            endpoints = self._extract_endpoints(api_spec)
            
            test_cases = []
            
            # Generate test cases for each endpoint
            for endpoint in endpoints:
                endpoint_tests = await self._generate_endpoint_tests(endpoint, api_spec)
                test_cases.extend(endpoint_tests)
            
            # If LLM is enabled, enhance some test cases with creative variants
            if self.llm_enabled and test_cases:
                self.logger.info("Enhancing test cases with LLM-generated variants")
                enhanced_count = min(5, len(test_cases) // 3)  # Enhance up to 1/3 of tests, max 5
                for i in range(enhanced_count):
                    original_test = test_cases[i]
                    variant = await self.generate_creative_variant(original_test, "realistic")
                    if variant:
                        variant["description"] = f"[LLM Enhanced] {variant.get('description', 'Creative variant')}"
                        test_cases.append(variant)
            
            self.logger.info(f"Generated {len(test_cases)} positive test cases")
            
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="success",
                test_cases=test_cases,
                metadata={
                    "total_endpoints": len(endpoints),
                    "total_test_cases": len(test_cases),
                    "generation_strategy": "schema_based_with_realistic_data",
                    "llm_enhanced": self.llm_enabled,
                    "llm_provider": getattr(self.llm_provider.config, 'provider', 'none') if self.llm_provider else 'none',
                    "llm_model": getattr(self.llm_provider.config, 'model', 'none') if self.llm_provider else 'none'
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error generating positive test cases: {str(e)}")
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="failed",
                error_message=str(e)
            )
    
    async def _generate_endpoint_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate positive test cases for a specific endpoint.
        
        Args:
            endpoint: The endpoint definition from the API spec
            api_spec: The full API specification for context
            
        Returns:
            List of test cases for this endpoint
        """
        test_cases = []
        path = endpoint["path"]
        method = endpoint["method"]
        operation = endpoint["operation"]
        
        # Generate basic positive test case
        basic_test = await self._generate_basic_positive_test(endpoint, api_spec)
        if basic_test:
            test_cases.append(basic_test)
        
        # Generate test cases with different parameter combinations
        if method in ["GET", "DELETE"]:
            param_tests = await self._generate_parameter_variation_tests(endpoint, api_spec)
            test_cases.extend(param_tests)
        
        # Generate test cases with different request body variations
        if method in ["POST", "PUT", "PATCH"]:
            body_tests = await self._generate_body_variation_tests(endpoint, api_spec)
            test_cases.extend(body_tests)
        
        return test_cases
    
    async def _generate_basic_positive_test(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a basic positive test case for an endpoint.
        
        This creates a straightforward test with valid, realistic data.
        """
        path = endpoint["path"]
        method = endpoint["method"]
        operation = endpoint["operation"]
        
        # Build test case components
        headers = self._generate_headers(operation)
        query_params = self._generate_query_parameters(endpoint["parameters"])
        path_params = self._generate_path_parameters(endpoint["parameters"])
        
        # Replace path parameters in the URL
        actual_path = self._substitute_path_parameters(path, path_params)
        
        # Generate request body if needed
        body = None
        if method in ["POST", "PUT", "PATCH"] and endpoint["requestBody"]:
            body = self._generate_request_body(endpoint["requestBody"], api_spec)
            
            # Optionally enhance body with LLM for more realistic data
            if self.llm_enabled and body:
                enhanced_body = await self.enhance_with_llm(
                    body,
                    "Make this test data more realistic and business-appropriate while maintaining the same structure",
                    system_prompt="You are generating test data for API testing. Return valid JSON that matches the original structure.",
                    temperature=0.5
                )
                if isinstance(enhanced_body, dict):
                    body = enhanced_body
        
        # Determine expected status code
        expected_status = self._get_expected_success_status(operation["responses"], method)
        
        # Create description
        summary = operation.get("summary", f"{method} {path}")
        description = f"Positive test: {summary}"
        
        # Generate assertions based on response schema
        assertions = self._generate_response_assertions(operation["responses"], expected_status)
        
        return self._create_test_case(
            endpoint=actual_path,
            method=method,
            description=description,
            headers=headers,
            query_params=query_params,
            body=body,
            expected_status=expected_status,
            assertions=assertions
        )
    
    def _create_test_case(
        self,
        endpoint: str,
        method: str,
        description: str,
        headers: Dict[str, str],
        query_params: Dict[str, Any],
        body: Optional[Dict[str, Any]],
        expected_status: int,
        assertions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a standardized test case with configuration-based settings."""
        app_settings = get_application_settings()
        test_timeout = getattr(app_settings, 'test_execution_timeout', 600)
        
        return {
            'test_name': description,
            'test_type': 'functional-positive',
            'method': method.upper(),
            'path': endpoint,
            'headers': headers,
            'query_params': query_params,
            'body': body,
            'timeout': test_timeout,
            'expected_status_codes': [expected_status],
            'assertions': assertions,
            'tags': ['functional', 'positive', f'{method.lower()}-method']
        }
    
    async def _generate_parameter_variation_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate test cases with different parameter combinations.
        
        This is particularly useful for GET endpoints with optional parameters.
        """
        test_cases = []
        parameters = endpoint["parameters"]
        
        # Find optional query parameters
        optional_params = [
            p for p in parameters 
            if p.get("in") == "query" and not p.get("required", False)
        ]
        
        if len(optional_params) > 1:
            # Test with only required parameters (minimal case)
            minimal_test = await self._generate_minimal_parameter_test(endpoint, api_spec)
            if minimal_test:
                test_cases.append(minimal_test)
            
            # Test with all parameters (maximal case)
            maximal_test = await self._generate_maximal_parameter_test(endpoint, api_spec)
            if maximal_test:
                test_cases.append(maximal_test)
        
        return test_cases
    
    async def _generate_body_variation_tests(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate test cases with different request body variations.
        
        This creates tests with minimal required fields and full object examples.
        """
        test_cases = []
        
        if not endpoint["requestBody"]:
            return test_cases
        
        # Generate minimal body test (only required fields)
        minimal_test = await self._generate_minimal_body_test(endpoint, api_spec)
        if minimal_test:
            test_cases.append(minimal_test)
        
        return test_cases
    
    def _generate_headers(self, operation: Dict[str, Any]) -> Dict[str, str]:
        """Generate appropriate headers for the request."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Add any required headers from the operation
        parameters = operation.get("parameters", [])
        for param in parameters:
            if param.get("in") == "header" and param.get("required", False):
                headers[param["name"]] = self._generate_parameter_value(param)
        
        return headers
    
    def _generate_query_parameters(self, parameters: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate query parameters from the parameter definitions."""
        query_params = {}
        
        for param in parameters:
            if param.get("in") == "query":
                # Always include required parameters, sometimes include optional ones
                if param.get("required", False) or random.random() < 0.7:
                    query_params[param["name"]] = self._generate_parameter_value(param)
        
        return query_params
    
    def _generate_path_parameters(self, parameters: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate path parameters from the parameter definitions."""
        path_params = {}
        
        for param in parameters:
            if param.get("in") == "path":
                path_params[param["name"]] = self._generate_parameter_value(param)
        
        return path_params
    
    def _generate_parameter_value(self, param: Dict[str, Any]) -> Any:
        """Generate a realistic value for a parameter based on its schema."""
        schema = param.get("schema", {})
        
        # Use example if provided
        if "example" in param:
            return param["example"]
        if "example" in schema:
            return schema["example"]
        
        # Generate based on parameter name and type
        param_name = param["name"].lower()
        param_type = schema.get("type", "string")
        
        # Generate realistic values based on common parameter names
        if "id" in param_name:
            return self._generate_realistic_id()
        elif "email" in param_name:
            return "test@example.com"
        elif "name" in param_name:
            return "Test Name"
        elif "date" in param_name:
            return datetime.now().isoformat()
        elif "limit" in param_name or "size" in param_name:
            return 10
        elif "offset" in param_name or "page" in param_name:
            return 0
        
        # Fall back to schema-based generation
        return self._get_schema_example(schema)
    
    def _generate_realistic_id(self) -> str:
        """Generate a realistic-looking ID."""
        # Mix of common ID formats
        formats = [
            lambda: str(random.randint(1, 10000)),  # Numeric ID
            lambda: ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),  # Short alphanumeric
            lambda: f"usr_{random.randint(1000, 9999)}",  # Prefixed numeric
            lambda: ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))  # UUID-like
        ]
        return random.choice(formats)()
    
    def _substitute_path_parameters(self, path: str, path_params: Dict[str, Any]) -> str:
        """Replace path parameter placeholders with actual values."""
        actual_path = path
        for param_name, param_value in path_params.items():
            actual_path = actual_path.replace(f"{{{param_name}}}", str(param_value))
        return actual_path
    
    def _generate_request_body(
        self, 
        request_body: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Generate a request body based on the request body schema."""
        content = request_body.get("content", {})
        
        # Look for JSON content type
        json_content = content.get("application/json", {})
        if not json_content:
            # Try the first available content type
            if content:
                json_content = list(content.values())[0]
        
        schema = json_content.get("schema", {})
        if not schema:
            return None
        
        # Resolve schema references
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
        """Generate a realistic object based on schema with enhanced data generation."""
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
    
    def _get_expected_success_status(self, responses: Dict[str, Any], method: str) -> int:
        """Determine the expected success status code for a method."""
        # Look for success responses (2xx)
        success_codes = [code for code in responses.keys() if code.startswith('2')]
        
        if success_codes:
            # Return the first success code found
            return int(success_codes[0])
        
        # Default success codes by method
        method_defaults = {
            "GET": 200,
            "POST": 201,
            "PUT": 200,
            "PATCH": 200,
            "DELETE": 204
        }
        
        return method_defaults.get(method, 200)
    
    def _generate_response_assertions(
        self, 
        responses: Dict[str, Any], 
        expected_status: int
    ) -> List[Dict[str, Any]]:
        """Generate assertions to validate the response."""
        assertions = []
        
        # Basic status code assertion
        assertions.append({
            "type": "status_code",
            "expected": expected_status
        })
        
        # Look for response schema to generate content assertions
        response_def = responses.get(str(expected_status), {})
        content = response_def.get("content", {})
        
        if content:
            json_content = content.get("application/json", {})
            if json_content and "schema" in json_content:
                assertions.append({
                    "type": "response_schema",
                    "schema": json_content["schema"]
                })
        
        return assertions
    
    async def _generate_minimal_parameter_test(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Generate a test with only required parameters."""
        # Implementation similar to basic test but only with required parameters
        # This is a simplified version for the MVP
        return None
    
    async def _generate_maximal_parameter_test(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Generate a test with all available parameters."""
        # Implementation similar to basic test but with all parameters
        # This is a simplified version for the MVP
        return None
    
    async def _generate_minimal_body_test(
        self, 
        endpoint: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Generate a test with minimal request body (only required fields)."""
        # Implementation for minimal body test
        # This is a simplified version for the MVP
        return None
