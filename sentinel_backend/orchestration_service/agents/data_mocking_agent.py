"""
Intelligent Data Mocking Agent

This agent generates realistic, contextually appropriate test data for API testing.
It analyzes API specifications to understand data requirements and generates
mock data that respects constraints, relationships, and business logic.
"""

import json
import random
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from faker import Faker
from faker.providers import BaseProvider
import uuid

from .base_agent import BaseAgent
from sentinel_backend.config.settings import get_application_settings

# Get configuration
app_settings = get_application_settings()


class APIProvider(BaseProvider):
    """Custom Faker provider for API-specific data generation"""
    
    def api_key(self) -> str:
        """Generate a realistic API key"""
        return f"sk-{self.random_element(['test', 'dev', 'prod'])}-{''.join(self.random_choices('abcdefghijklmnopqrstuvwxyz0123456789', length=32))}"
    
    def jwt_token(self) -> str:
        """Generate a realistic JWT token structure"""
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        payload_data = {
            "sub": str(self.random_int(1000, 9999)),
            "name": self.generator.name(),
            "iat": int(datetime.now().timestamp()),
            "exp": int((datetime.now() + timedelta(hours=24)).timestamp())
        }
        payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        signature = ''.join(self.random_choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_', length=43))
        return f"{header}.{payload}.{signature}"
    
    def resource_id(self, prefix: str = "res") -> str:
        """Generate a resource ID with optional prefix"""
        return f"{prefix}_{uuid.uuid4().hex[:12]}"
    
    def version_string(self) -> str:
        """Generate a semantic version string"""
        major = self.random_int(1, 5)
        minor = self.random_int(0, 20)
        patch = self.random_int(0, 50)
        return f"{major}.{minor}.{patch}"
    
    def status_code(self, success_bias: float = 0.8) -> int:
        """Generate HTTP status codes with configurable success bias"""
        if self.random.random() < success_bias:
            return self.random_element([200, 201, 202, 204])
        else:
            return self.random_element([400, 401, 403, 404, 422, 500, 502, 503])


class DataMockingAgent(BaseAgent):
    """
    Intelligent Data Mocking Agent
    
    Generates realistic test data based on API specifications, including:
    - Schema-aware data generation
    - Relationship-aware data consistency
    - Business logic constraints
    - Realistic edge cases and variations
    """
    
    def __init__(self):
        super().__init__("data-mocking")
        self.agent_type = "data-mocking"
        self.fake = Faker()
        self.fake.add_provider(APIProvider)
        
        # Data generation strategies
        self.strategies = {
            'realistic': self._generate_realistic_data,
            'edge_cases': self._generate_edge_cases,
            'invalid': self._generate_invalid_data,
            'boundary': self._generate_boundary_data
        }
        
        # Configuration-driven settings
        self.default_count = getattr(app_settings, 'data_mocking_default_count', 10)
        self.max_response_variations = getattr(app_settings, 'data_mocking_max_response_variations', 5)
        self.max_parameter_variations = getattr(app_settings, 'data_mocking_max_parameter_variations', 3)
        self.max_entity_variations = getattr(app_settings, 'data_mocking_max_entity_variations', 5)
        self.faker_locale = getattr(app_settings, 'data_mocking_faker_locale', 'en_US')
        self.realistic_data_bias = getattr(app_settings, 'data_mocking_realistic_bias', 0.8)
        
        # Field pattern mappings
        self.field_patterns = {
            'email': lambda: self.fake.email(),
            'phone': lambda: self.fake.phone_number(),
            'name': lambda: self.fake.name(),
            'first_name': lambda: self.fake.first_name(),
            'last_name': lambda: self.fake.last_name(),
            'address': lambda: self.fake.address(),
            'city': lambda: self.fake.city(),
            'country': lambda: self.fake.country(),
            'company': lambda: self.fake.company(),
            'url': lambda: self.fake.url(),
            'username': lambda: self.fake.user_name(),
            'password': lambda: self.fake.password(length=12),
            'description': lambda: self.fake.text(max_nb_chars=200),
            'title': lambda: self.fake.sentence(nb_words=4),
            'uuid': lambda: str(uuid.uuid4()),
            'id': lambda: self.fake.resource_id(),
            'token': lambda: self.fake.jwt_token(),
            'api_key': lambda: self.fake.api_key(),
            'version': lambda: self.fake.version_string(),
            'timestamp': lambda: self.fake.iso8601(),
            'date': lambda: self.fake.date(),
            'time': lambda: self.fake.time(),
        }
    
    async def execute(self, specification: Dict, config: Dict = None) -> Dict:
        """
        Generate mock data based on API specification
        
        Args:
            specification: Parsed API specification
            config: Configuration options for data generation
            
        Returns:
            Dictionary containing generated mock data and metadata
        """
        config = config or {}
        strategy = config.get('strategy', 'realistic')
        count = config.get('count', self.default_count)
        seed = config.get('seed')
        
        if seed:
            Faker.seed(seed)
            random.seed(seed)
        
        try:
            # Analyze specification
            analysis = self._analyze_specification(specification)
            
            # Generate mock data for each endpoint
            mock_data = {}
            for path, methods in specification.get('paths', {}).items():
                mock_data[path] = {}
                
                for method, operation in methods.items():
                    if method.lower() in ['get', 'post', 'put', 'patch', 'delete']:
                        mock_data[path][method] = await self._generate_operation_data(
                            operation, analysis, strategy, count
                        )
            
            # Generate global mock data
            global_data = await self._generate_global_data(specification, analysis, strategy, count)
            
            return {
                'agent_type': self.agent_type,
                'strategy': strategy,
                'mock_data': mock_data,
                'global_data': global_data,
                'analysis': analysis,
                'metadata': {
                    'total_endpoints': len([
                        (path, method) 
                        for path, methods in specification.get('paths', {}).items()
                        for method in methods.keys()
                        if method.lower() in ['get', 'post', 'put', 'patch', 'delete']
                    ]),
                    'schemas_analyzed': len(analysis.get('schemas', {})),
                    'data_relationships': len(analysis.get('relationships', [])),
                    'generation_timestamp': datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            return {
                'agent_type': self.agent_type,
                'error': f"Data mocking failed: {str(e)}",
                'mock_data': {},
                'analysis': {}
            }
    
    def _analyze_specification(self, specification: Dict) -> Dict:
        """Analyze API specification to understand data requirements"""
        analysis = {
            'schemas': {},
            'relationships': [],
            'constraints': {},
            'patterns': {},
            'enums': {}
        }
        
        # Analyze schemas
        components = specification.get('components', {})
        schemas = components.get('schemas', {})
        
        for schema_name, schema_def in schemas.items():
            analysis['schemas'][schema_name] = self._analyze_schema(schema_def)
        
        # Analyze relationships between schemas
        analysis['relationships'] = self._find_relationships(schemas)
        
        # Analyze field patterns
        analysis['patterns'] = self._extract_patterns(schemas)
        
        # Analyze enums and constraints
        analysis['constraints'] = self._extract_constraints(schemas)
        analysis['enums'] = self._extract_enums(schemas)
        
        return analysis
    
    def _analyze_schema(self, schema: Dict) -> Dict:
        """Analyze individual schema definition"""
        return {
            'type': schema.get('type', 'object'),
            'properties': schema.get('properties', {}),
            'required': schema.get('required', []),
            'constraints': {
                'minLength': schema.get('minLength'),
                'maxLength': schema.get('maxLength'),
                'minimum': schema.get('minimum'),
                'maximum': schema.get('maximum'),
                'pattern': schema.get('pattern'),
                'format': schema.get('format')
            }
        }
    
    def _find_relationships(self, schemas: Dict) -> List[Dict]:
        """Find relationships between schemas"""
        relationships = []
        
        for schema_name, schema_def in schemas.items():
            properties = schema_def.get('properties', {})
            
            for prop_name, prop_def in properties.items():
                # Check for references to other schemas
                if '$ref' in prop_def:
                    ref_schema = prop_def['$ref'].split('/')[-1]
                    relationships.append({
                        'from': schema_name,
                        'to': ref_schema,
                        'field': prop_name,
                        'type': 'reference'
                    })
                
                # Check for foreign key patterns
                if prop_name.endswith('_id') or prop_name.endswith('Id'):
                    potential_ref = prop_name.replace('_id', '').replace('Id', '')
                    if potential_ref.capitalize() in schemas:
                        relationships.append({
                            'from': schema_name,
                            'to': potential_ref.capitalize(),
                            'field': prop_name,
                            'type': 'foreign_key'
                        })
        
        return relationships
    
    def _extract_patterns(self, schemas: Dict) -> Dict:
        """Extract field naming patterns for intelligent data generation"""
        patterns = {}
        
        for schema_name, schema_def in schemas.items():
            properties = schema_def.get('properties', {})
            
            for prop_name, prop_def in properties.items():
                prop_type = prop_def.get('type', 'string')
                prop_format = prop_def.get('format')
                
                # Map field names to generation patterns
                for pattern, generator in self.field_patterns.items():
                    if pattern in prop_name.lower():
                        patterns[f"{schema_name}.{prop_name}"] = pattern
                        break
                
                # Map formats to patterns
                if prop_format:
                    patterns[f"{schema_name}.{prop_name}"] = prop_format
        
        return patterns
    
    def _extract_constraints(self, schemas: Dict) -> Dict:
        """Extract validation constraints"""
        constraints = {}
        
        for schema_name, schema_def in schemas.items():
            properties = schema_def.get('properties', {})
            
            for prop_name, prop_def in properties.items():
                field_key = f"{schema_name}.{prop_name}"
                constraints[field_key] = {
                    'type': prop_def.get('type'),
                    'format': prop_def.get('format'),
                    'minLength': prop_def.get('minLength'),
                    'maxLength': prop_def.get('maxLength'),
                    'minimum': prop_def.get('minimum'),
                    'maximum': prop_def.get('maximum'),
                    'pattern': prop_def.get('pattern'),
                    'required': prop_name in schema_def.get('required', [])
                }
        
        return constraints
    
    def _extract_enums(self, schemas: Dict) -> Dict:
        """Extract enum values for constrained fields"""
        enums = {}
        
        for schema_name, schema_def in schemas.items():
            properties = schema_def.get('properties', {})
            
            for prop_name, prop_def in properties.items():
                if 'enum' in prop_def:
                    field_key = f"{schema_name}.{prop_name}"
                    enums[field_key] = prop_def['enum']
        
        return enums
    
    async def _generate_operation_data(self, operation: Dict, analysis: Dict, strategy: str, count: int) -> Dict:
        """Generate mock data for a specific operation"""
        operation_data = {
            'request_bodies': [],
            'responses': {},
            'parameters': []
        }
        
        # Generate request body data
        request_body = operation.get('requestBody', {})
        if request_body:
            content = request_body.get('content', {})
            for media_type, media_def in content.items():
                schema = media_def.get('schema', {})
                for i in range(count):
                    mock_body = await self._generate_from_schema(schema, analysis, strategy)
                    operation_data['request_bodies'].append({
                        'media_type': media_type,
                        'data': mock_body,
                        'variation': i
                    })
        
        # Generate response data
        responses = operation.get('responses', {})
        for status_code, response_def in responses.items():
            content = response_def.get('content', {})
            operation_data['responses'][status_code] = []
            
            for media_type, media_def in content.items():
                schema = media_def.get('schema', {})
                for i in range(min(count, self.max_response_variations)):  # Configurable response variations
                    mock_response = await self._generate_from_schema(schema, analysis, strategy)
                    operation_data['responses'][status_code].append({
                        'media_type': media_type,
                        'data': mock_response,
                        'variation': i
                    })
        
        # Generate parameter data
        parameters = operation.get('parameters', [])
        for param in parameters:
            param_schema = param.get('schema', {})
            for i in range(min(count, self.max_parameter_variations)):  # Configurable parameter variations
                mock_param = await self._generate_from_schema(param_schema, analysis, strategy)
                operation_data['parameters'].append({
                    'name': param.get('name'),
                    'in': param.get('in'),
                    'value': mock_param,
                    'variation': i
                })
        
        return operation_data
    
    async def _generate_global_data(self, specification: Dict, analysis: Dict, strategy: str, count: int) -> Dict:
        """Generate global mock data (users, auth tokens, etc.)"""
        global_data = {
            'users': [],
            'auth_tokens': [],
            'api_keys': [],
            'test_entities': {}
        }
        
        # Generate test users
        for i in range(count):
            user = {
                'id': self.fake.resource_id('user'),
                'username': self.fake.user_name(),
                'email': self.fake.email(),
                'first_name': self.fake.first_name(),
                'last_name': self.fake.last_name(),
                'role': self.fake.random_element(['admin', 'user', 'moderator']),
                'created_at': self.fake.iso8601(),
                'active': self.fake.boolean(chance_of_getting_true=80)
            }
            global_data['users'].append(user)
        
        # Generate auth tokens
        for i in range(count):
            token = {
                'token': self.fake.jwt_token(),
                'user_id': global_data['users'][i % len(global_data['users'])]['id'],
                'expires_at': (datetime.now() + timedelta(hours=24)).isoformat(),
                'scopes': self.fake.random_elements(['read', 'write', 'admin'], length=2)
            }
            global_data['auth_tokens'].append(token)
        
        # Generate API keys
        for i in range(min(count, 5)):
            api_key = {
                'key': self.fake.api_key(),
                'name': f"Test Key {i+1}",
                'user_id': global_data['users'][i % len(global_data['users'])]['id'],
                'created_at': self.fake.iso8601(),
                'last_used': self.fake.iso8601() if self.fake.boolean() else None
            }
            global_data['api_keys'].append(api_key)
        
        # Generate test entities for each schema
        for schema_name in analysis.get('schemas', {}):
            global_data['test_entities'][schema_name] = []
            for i in range(min(count, self.max_entity_variations)):
                entity = await self._generate_from_schema_name(schema_name, analysis, strategy)
                global_data['test_entities'][schema_name].append(entity)
        
        return global_data
    
    async def _generate_from_schema(self, schema: Dict, analysis: Dict, strategy: str) -> Any:
        """Generate data from a schema definition"""
        if not schema:
            return None
        
        schema_type = schema.get('type', 'object')
        
        if schema_type == 'object':
            return await self._generate_object(schema, analysis, strategy)
        elif schema_type == 'array':
            return await self._generate_array(schema, analysis, strategy)
        elif schema_type == 'string':
            return self._generate_string(schema, analysis, strategy)
        elif schema_type == 'integer':
            return self._generate_integer(schema, analysis, strategy)
        elif schema_type == 'number':
            return self._generate_number(schema, analysis, strategy)
        elif schema_type == 'boolean':
            return self._generate_boolean(schema, analysis, strategy)
        else:
            return None
    
    async def _generate_from_schema_name(self, schema_name: str, analysis: Dict, strategy: str) -> Dict:
        """Generate data from a named schema"""
        schema_def = analysis.get('schemas', {}).get(schema_name, {})
        return await self._generate_from_schema(schema_def, analysis, strategy)
    
    async def _generate_object(self, schema: Dict, analysis: Dict, strategy: str) -> Dict:
        """Generate object data"""
        obj = {}
        properties = schema.get('properties', {})
        required = schema.get('required', [])
        
        for prop_name, prop_schema in properties.items():
            # Always generate required fields
            if prop_name in required or self.fake.boolean(chance_of_getting_true=70):
                obj[prop_name] = await self._generate_from_schema(prop_schema, analysis, strategy)
        
        return obj
    
    async def _generate_array(self, schema: Dict, analysis: Dict, strategy: str) -> List:
        """Generate array data"""
        items_schema = schema.get('items', {})
        min_items = schema.get('minItems', 1)
        max_items = schema.get('maxItems', 5)
        
        length = random.randint(min_items, max_items)
        return [
            await self._generate_from_schema(items_schema, analysis, strategy)
            for _ in range(length)
        ]
    
    def _generate_string(self, schema: Dict, analysis: Dict, strategy: str) -> str:
        """Generate string data"""
        format_type = schema.get('format')
        pattern = schema.get('pattern')
        enum_values = schema.get('enum')
        min_length = schema.get('minLength', 1)
        max_length = schema.get('maxLength', 50)
        
        if enum_values:
            return self.fake.random_element(enum_values)
        
        if format_type == 'email':
            return self.fake.email()
        elif format_type == 'uri':
            return self.fake.url()
        elif format_type == 'date':
            return self.fake.date()
        elif format_type == 'date-time':
            return self.fake.iso8601()
        elif format_type == 'uuid':
            return str(uuid.uuid4())
        elif pattern:
            # Simple pattern matching for common cases
            if 'email' in pattern.lower():
                return self.fake.email()
            elif 'phone' in pattern.lower():
                return self.fake.phone_number()
            else:
                # Generate random string matching length constraints
                length = random.randint(min_length, min(max_length, 20))
                return self.fake.lexify('?' * length)
        else:
            # Generate based on length constraints
            if strategy == 'edge_cases':
                if random.choice([True, False]):
                    return 'a' * min_length  # Minimum length
                else:
                    return 'a' * max_length  # Maximum length
            else:
                length = random.randint(min_length, min(max_length, 20))
                return self.fake.text(max_nb_chars=length).replace('\n', ' ')
    
    def _generate_integer(self, schema: Dict, analysis: Dict, strategy: str) -> int:
        """Generate integer data"""
        minimum = schema.get('minimum', 0)
        maximum = schema.get('maximum', 1000)
        
        if strategy == 'edge_cases':
            return random.choice([minimum, maximum, minimum + 1, maximum - 1])
        elif strategy == 'boundary':
            return random.choice([minimum, maximum])
        else:
            return random.randint(minimum, maximum)
    
    def _generate_number(self, schema: Dict, analysis: Dict, strategy: str) -> float:
        """Generate number data"""
        minimum = schema.get('minimum', 0.0)
        maximum = schema.get('maximum', 1000.0)
        
        if strategy == 'edge_cases':
            return random.choice([minimum, maximum, minimum + 0.1, maximum - 0.1])
        elif strategy == 'boundary':
            return random.choice([minimum, maximum])
        else:
            return round(random.uniform(minimum, maximum), 2)
    
    def _generate_boolean(self, schema: Dict, analysis: Dict, strategy: str) -> bool:
        """Generate boolean data"""
        if strategy == 'edge_cases':
            return random.choice([True, False])
        else:
            return self.fake.boolean()
    
    def _generate_realistic_data(self, schema: Dict, analysis: Dict) -> Any:
        """Generate realistic, production-like data"""
        return self.strategies['realistic'](schema, analysis, 'realistic')
    
    def _generate_edge_cases(self, schema: Dict, analysis: Dict) -> Any:
        """Generate edge case data (boundary values, empty strings, etc.)"""
        return self.strategies['edge_cases'](schema, analysis, 'edge_cases')
    
    def _generate_invalid_data(self, schema: Dict, analysis: Dict) -> Any:
        """Generate invalid data for negative testing"""
        return self.strategies['invalid'](schema, analysis, 'invalid')
    
    def _generate_boundary_data(self, schema: Dict, analysis: Dict) -> Any:
        """Generate boundary value data"""
        return self.strategies['boundary'](schema, analysis, 'boundary')
