"""
Security Authentication Agent for Sentinel Platform

This agent specializes in testing authentication and authorization vulnerabilities,
with a primary focus on Broken Object Level Authorization (BOLA) attacks.
"""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import re
import random
from .base_agent import BaseAgent
from config.settings import get_application_settings

# Get configuration
app_settings = get_application_settings()
logger = logging.getLogger(__name__)

class SecurityAuthAgent(BaseAgent):
    """
    Agent specialized in testing authentication and authorization vulnerabilities.
    
    Primary focus areas:
    - Broken Object Level Authorization (BOLA)
    - Broken Function Level Authorization
    - Incorrect role enforcement
    - Authentication bypass attempts
    """
    
    def __init__(self):
        super().__init__()
        self.agent_type = "security-auth"
        self.description = "Security agent focused on authentication and authorization vulnerabilities"
        
        # Configuration-driven settings
        self.max_bola_vectors = getattr(app_settings, 'security_max_bola_vectors', 12)
        self.max_auth_scenarios = getattr(app_settings, 'security_max_auth_scenarios', 4)
        self.default_test_timeout = getattr(app_settings, 'security_test_timeout', 30)
        self.enable_aggressive_testing = getattr(app_settings, 'security_enable_aggressive_testing', False)
    
    def generate_test_cases(self, spec_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate security test cases focused on authentication and authorization.
        
        Args:
            spec_data: Parsed OpenAPI specification
            
        Returns:
            List of test cases targeting auth vulnerabilities
        """
        test_cases = []
        
        try:
            # Extract paths and operations from spec
            paths = spec_data.get('paths', {})
            
            for path, operations in paths.items():
                for method, operation_spec in operations.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        # Generate BOLA test cases
                        test_cases.extend(self._generate_bola_tests(path, method, operation_spec))
                        
                        # Generate function-level authorization tests
                        test_cases.extend(self._generate_function_auth_tests(path, method, operation_spec))
                        
                        # Generate authentication bypass tests
                        test_cases.extend(self._generate_auth_bypass_tests(path, method, operation_spec))
            
            logger.info(f"Generated {len(test_cases)} security authentication test cases")
            return test_cases
            
        except Exception as e:
            logger.error(f"Error generating security auth test cases: {str(e)}")
            return []
    
    def _generate_bola_tests(self, path: str, method: str, operation_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate Broken Object Level Authorization (BOLA) test cases.
        
        BOLA occurs when an application doesn't properly verify that a user
        should have access to a specific object/resource.
        """
        test_cases = []
        
        # Check if this endpoint has path parameters (potential object identifiers)
        path_params = self._extract_path_parameters(path, operation_spec)
        
        if not path_params:
            return test_cases
        
        # Generate test cases for each path parameter
        for param in path_params:
            param_name = param.get('name', '')
            
            # Skip non-ID parameters
            if not self._is_likely_object_id(param_name):
                continue
            
            # Generate BOLA attack vectors
            bola_vectors = self._generate_bola_vectors(param_name, param)
            
            for vector in bola_vectors:
                test_case = {
                    'test_name': f"BOLA Test: {method.upper()} {path} - {vector['description']}",
                    'test_type': 'security-auth',
                    'test_subtype': 'bola',
                    'method': method.upper(),
                    'path': path,
                    'headers': self._get_auth_headers_variants(vector['auth_scenario']),
                    'path_params': {param_name: vector['value']},
                    'query_params': {},
                    'body': self._generate_request_body(operation_spec) if method.upper() in ['POST', 'PUT', 'PATCH'] else None,
                    'expected_status_codes': vector['expected_status'],
                    'security_check': {
                        'type': 'bola',
                        'parameter': param_name,
                        'attack_vector': vector['description'],
                        'expected_behavior': vector['expected_behavior']
                    },
                    'tags': ['security', 'bola', 'authorization', f'{method.lower()}-method']
                }
                test_cases.append(test_case)
        
        return test_cases
    
    def _generate_function_auth_tests(self, path: str, method: str, operation_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate function-level authorization test cases.
        
        Tests whether users can access functions/endpoints they shouldn't have access to.
        """
        test_cases = []
        
        # Determine if this is a sensitive operation
        sensitive_operations = self._identify_sensitive_operations(path, method, operation_spec)
        
        if not sensitive_operations:
            return test_cases
        
        # Generate test cases with different authorization levels
        auth_scenarios = [
            {'name': 'no_auth', 'headers': {}, 'expected_status': [401, 403]},
            {'name': 'invalid_token', 'headers': {'Authorization': 'Bearer invalid_token_12345'}, 'expected_status': [401, 403]},
            {'name': 'expired_token', 'headers': {'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDAwMDB9.invalid'}, 'expected_status': [401, 403]},
            {'name': 'low_privilege_user', 'headers': {'Authorization': 'Bearer user_token', 'X-User-Role': 'user'}, 'expected_status': [403]},
        ]
        
        for scenario in auth_scenarios:
            for operation_type in sensitive_operations:
                test_case = {
                    'test_name': f"Function Auth Test: {method.upper()} {path} - {scenario['name']} accessing {operation_type}",
                    'test_type': 'security-auth',
                    'test_subtype': 'function-level-auth',
                    'method': method.upper(),
                    'path': path,
                    'headers': scenario['headers'],
                    'path_params': self._generate_valid_path_params(path, operation_spec),
                    'query_params': {},
                    'body': self._generate_request_body(operation_spec) if method.upper() in ['POST', 'PUT', 'PATCH'] else None,
                    'expected_status_codes': scenario['expected_status'],
                    'security_check': {
                        'type': 'function-level-authorization',
                        'operation_type': operation_type,
                        'auth_scenario': scenario['name'],
                        'expected_behavior': f"Should deny access with {scenario['expected_status']} status"
                    },
                    'tags': ['security', 'function-auth', 'authorization', f'{method.lower()}-method']
                }
                test_cases.append(test_case)
        
        return test_cases
    
    def _generate_auth_bypass_tests(self, path: str, method: str, operation_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate authentication bypass test cases.
        
        Tests various techniques to bypass authentication mechanisms.
        """
        test_cases = []
        
        # Check if endpoint requires authentication
        requires_auth = self._requires_authentication(operation_spec)
        
        if not requires_auth:
            return test_cases
        
        # Generate bypass techniques
        bypass_techniques = self._get_bypass_techniques()
        
        for technique in bypass_techniques:
            test_case = {
                'test_name': f"Auth Bypass Test: {method.upper()} {path} - {technique['description']}",
                'test_type': 'security-auth',
                'test_subtype': 'auth-bypass',
                'method': method.upper(),
                'path': path,
                'headers': technique['headers'],
                'path_params': self._generate_valid_path_params(path, operation_spec),
                'query_params': {},
                'body': self._generate_request_body(operation_spec) if method.upper() in ['POST', 'PUT', 'PATCH'] else None,
                'expected_status_codes': [401, 403],
                'security_check': {
                    'type': 'authentication-bypass',
                    'technique': technique['name'],
                    'description': technique['description'],
                    'expected_behavior': 'Should maintain authentication requirements and deny access'
                },
                'tags': ['security', 'auth-bypass', 'authentication', f'{method.lower()}-method']
            }
            test_cases.append(test_case)
        
        return test_cases
    
    def _extract_path_parameters(self, path: str, operation_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract path parameters from the operation specification."""
        parameters = operation_spec.get('parameters', [])
        path_params = [param for param in parameters if param.get('in') == 'path']
        
        # Also extract from path string
        path_param_names = re.findall(r'\{([^}]+)\}', path)
        for param_name in path_param_names:
            if not any(p.get('name') == param_name for p in path_params):
                path_params.append({
                    'name': param_name,
                    'in': 'path',
                    'required': True,
                    'schema': {'type': 'string'}
                })
        
        return path_params
    
    def _is_likely_object_id(self, param_name: str) -> bool:
        """Determine if a parameter is likely an object identifier."""
        id_patterns = ['id', 'uuid', 'key', 'identifier', 'ref']
        param_lower = param_name.lower()
        
        return any(pattern in param_lower for pattern in id_patterns)
    
    def _generate_bola_vectors(self, param_name: str, param_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate BOLA attack vectors for a parameter."""
        vectors = []
        
        # Determine parameter type
        param_type = param_spec.get('schema', {}).get('type', 'string')
        
        if param_type == 'integer':
            # Integer-based IDs
            base_vectors = self._get_integer_bola_vectors()
        else:
            # String-based IDs
            base_vectors = self._get_string_bola_vectors()
        
        # Add authentication scenarios to each vector
        auth_scenarios = [
            {'auth_scenario': 'no_auth', 'expected_status': [401, 403]},
            {'auth_scenario': 'different_user', 'expected_status': [403, 404]},
            {'auth_scenario': 'invalid_token', 'expected_status': [401, 403]},
        ]
        
        for vector in base_vectors:
            for auth in auth_scenarios:
                vectors.append({
                    **vector,
                    **auth,
                    'expected_behavior': f"Should deny access to {vector['description']} with {auth['auth_scenario']}"
                })
        
        return vectors
    
    def _get_auth_headers_variants(self, auth_scenario: str) -> Dict[str, str]:
        """Get authentication headers for different scenarios."""
        headers = {}
        
        if auth_scenario == 'no_auth':
            return headers
        elif auth_scenario == 'different_user':
            headers['Authorization'] = 'Bearer different_user_token_12345'
        elif auth_scenario == 'invalid_token':
            headers['Authorization'] = 'Bearer invalid_token_67890'
        
        return headers
    
    def _identify_sensitive_operations(self, path: str, method: str, operation_spec: Dict[str, Any]) -> List[str]:
        """Identify if this is a sensitive operation that requires special authorization."""
        sensitive_ops = []
        
        # Check path patterns
        sensitive_path_patterns = [
            'admin', 'management', 'config', 'settings', 'users', 'accounts',
            'delete', 'remove', 'update', 'modify', 'create', 'add'
        ]
        
        path_lower = path.lower()
        for pattern in sensitive_path_patterns:
            if pattern in path_lower:
                sensitive_ops.append(f"{pattern}_operation")
        
        # Check HTTP method
        if method.upper() in ['DELETE', 'PUT', 'PATCH']:
            sensitive_ops.append(f"{method.lower()}_operation")
        
        # Check operation description/summary
        summary = operation_spec.get('summary', '').lower()
        description = operation_spec.get('description', '').lower()
        
        sensitive_keywords = ['delete', 'remove', 'admin', 'manage', 'configure', 'update', 'modify']
        for keyword in sensitive_keywords:
            if keyword in summary or keyword in description:
                sensitive_ops.append(f"{keyword}_function")
        
        return list(set(sensitive_ops))  # Remove duplicates
    
    def _requires_authentication(self, operation_spec: Dict[str, Any]) -> bool:
        """Determine if an operation requires authentication."""
        # Check for security requirements
        security = operation_spec.get('security', [])
        if security:
            return True
        
        # Check responses for auth-related status codes
        responses = operation_spec.get('responses', {})
        auth_status_codes = ['401', '403']
        
        return any(code in responses for code in auth_status_codes)
    
    def _generate_valid_path_params(self, path: str, operation_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Generate valid path parameters for testing."""
        path_params = {}
        parameters = operation_spec.get('parameters', [])
        
        for param in parameters:
            if param.get('in') == 'path':
                param_name = param.get('name')
                param_type = param.get('schema', {}).get('type', 'string')
                
                if param_type == 'integer':
                    path_params[param_name] = 123
                else:
                    path_params[param_name] = 'test-id-123'
        
        # Extract from path pattern
        path_param_names = re.findall(r'\{([^}]+)\}', path)
        for param_name in path_param_names:
            if param_name not in path_params:
                path_params[param_name] = 'test-value'
        
        return path_params
    
    def _generate_request_body(self, operation_spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a basic request body for testing."""
        request_body = operation_spec.get('requestBody', {})
        if not request_body:
            return None
        
        content = request_body.get('content', {})
        json_content = content.get('application/json', {})
        schema = json_content.get('schema', {})
        
        if not schema:
            return {'test': 'data'}
        
        return self._generate_data_from_schema(schema)
    
    def _generate_data_from_schema(self, schema: Dict[str, Any]) -> Any:
        """Generate test data from a JSON schema."""
        schema_type = schema.get('type', 'object')
        
        if schema_type == 'object':
            properties = schema.get('properties', {})
            required = schema.get('required', [])
            
            data = {}
            for prop_name, prop_schema in properties.items():
                if prop_name in required:
                    data[prop_name] = self._generate_data_from_schema(prop_schema)
            
            return data
        elif schema_type == 'string':
            return 'test-string'
        elif schema_type == 'integer':
            return 123
        elif schema_type == 'number':
            return 123.45
        elif schema_type == 'boolean':
            return True
        elif schema_type == 'array':
            items_schema = schema.get('items', {'type': 'string'})
            return [self._generate_data_from_schema(items_schema)]
        else:
            return 'test-value'
    
    def _get_bypass_techniques(self) -> List[Dict[str, Any]]:
        """Get authentication bypass techniques based on configuration."""
        techniques = [
            {
                'name': 'header_manipulation',
                'headers': {'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1'},
                'description': 'IP spoofing via proxy headers'
            },
            {
                'name': 'user_agent_bypass',
                'headers': {'User-Agent': 'Internal-Service/1.0'},
                'description': 'Internal service user agent'
            },
            {
                'name': 'referer_bypass',
                'headers': {'Referer': 'https://localhost/admin'},
                'description': 'Admin referer bypass attempt'
            },
            {
                'name': 'method_override',
                'headers': {'X-HTTP-Method-Override': 'GET'},
                'description': 'HTTP method override bypass'
            },
            {
                'name': 'content_type_bypass',
                'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                'description': 'Content-Type manipulation'
            }
        ]
        
        if self.enable_aggressive_testing:
            # Add more aggressive techniques for comprehensive testing
            techniques.extend([
                {
                    'name': 'host_header_injection',
                    'headers': {'Host': 'evil.com'},
                    'description': 'Host header injection attempt'
                },
                {
                    'name': 'origin_bypass',
                    'headers': {'Origin': 'https://trusted-domain.com'},
                    'description': 'Origin header bypass attempt'
                }
            ])
        
        return techniques
    
    def _get_integer_bola_vectors(self) -> List[Dict[str, Any]]:
        """Get integer-based BOLA attack vectors."""
        return [
            {'value': 1, 'description': 'Access first resource'},
            {'value': 999999, 'description': 'Access high-numbered resource'},
            {'value': -1, 'description': 'Negative ID access'},
            {'value': 0, 'description': 'Zero ID access'},
        ]
    
    def _get_string_bola_vectors(self) -> List[Dict[str, Any]]:
        """Get string-based BOLA attack vectors."""
        return [
            {'value': 'admin', 'description': 'Admin user access'},
            {'value': 'test', 'description': 'Test user access'},
            {'value': '00000000-0000-0000-0000-000000000001', 'description': 'First UUID access'},
            {'value': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'description': 'Pattern UUID access'},
            {'value': '../admin', 'description': 'Path traversal attempt'},
            {'value': 'null', 'description': 'Null string access'},
        ]
