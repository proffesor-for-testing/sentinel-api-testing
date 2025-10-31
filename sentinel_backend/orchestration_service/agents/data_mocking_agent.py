"""
Data Mocking Agent - Schema-aware test data generation

This agent generates realistic, edge-case, and boundary-value test data
based on OpenAPI specifications. It uses Faker for realistic data and
implements custom strategies for edge cases and performance optimization.

Performance target: 10,000+ records per second
"""

import random
import string
import json
import re
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from faker import Faker
from faker.providers import BaseProvider
import logging

from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult

logger = logging.getLogger(__name__)


class APIProvider(BaseProvider):
    """Custom Faker provider for API-specific data generation"""

    def api_key(self, prefix: str = "sk-") -> str:
        """Generate realistic API key"""
        chars = string.ascii_letters + string.digits
        return prefix + ''.join(random.choices(chars, k=40))

    def jwt_token(self) -> str:
        """Generate realistic JWT token structure"""
        header = self.random_element(['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'])
        payload_chars = string.ascii_letters + string.digits + '-_'
        payload = ''.join(random.choices(payload_chars, k=100))
        signature = ''.join(random.choices(payload_chars, k=43))
        return f"{header}.{payload}.{signature}"

    def resource_id(self, resource_type: str = "res") -> str:
        """Generate resource ID with prefix"""
        return f"{resource_type}_{self.random_int(100000, 999999)}"

    def version_string(self) -> str:
        """Generate semantic version string"""
        major = self.random_int(0, 10)
        minor = self.random_int(0, 20)
        patch = self.random_int(0, 50)
        return f"{major}.{minor}.{patch}"

    def status_code(self, success_bias: float = 0.8) -> int:
        """Generate HTTP status code with configurable success bias"""
        if random.random() < success_bias:
            return random.choice([200, 201, 202, 204])
        else:
            return random.choice([400, 401, 403, 404, 422, 500, 502, 503])


class DataMockingAgent:
    """
    Agent for generating schema-aware test data from API specifications

    Strategies:
    - realistic: Faker-based realistic data
    - edge_cases: Boundary values and edge cases
    - boundary: Exact boundary values
    - random: Completely random valid data
    """

    def __init__(self):
        self.agent_type = "data-mocking"
        self.fake = Faker()
        self.fake.add_provider(APIProvider)

        # Configuration
        self.default_count = 10
        self.max_response_variations = 5
        self.max_parameter_variations = 3
        self.max_entity_variations = 5

        # Strategy mapping
        self.strategies = {
            'realistic': self._generate_realistic,
            'edge_cases': self._generate_edge_cases,
            'boundary': self._generate_boundary,
            'random': self._generate_random
        }

        # Statistics tracking
        self.statistics = {
            'objects_generated': 0,
            'fields_generated': 0,
            'faker_calls': 0,
            'fallback_calls': 0
        }

    async def execute(self, task: AgentTask, api_spec: Dict[str, Any], db_session=None) -> AgentResult:
        """
        Main execution method - generates mock data for API specification

        Args:
            task: The agent task containing parameters and context
            api_spec: OpenAPI specification dictionary
            db_session: Optional database session for trajectory tracking

        Returns:
            AgentResult with generated mock data sets in test_cases field
        """
        # Extract configuration from task parameters
        config = task.parameters if hasattr(task, 'parameters') else {}
        strategy = config.get('strategy', 'realistic')
        count = config.get('count', self.default_count)
        seed = config.get('seed')
        paths = config.get('paths')

        # Set seed for deterministic generation
        if seed is not None:
            random.seed(seed)
            Faker.seed(seed)

        try:
            # Analyze API specification
            analysis = self._analyze_specification(api_spec)

            # Generate mock data for each path/operation
            mock_data = {}

            paths_to_process = paths or api_spec.get('paths', {}).keys()

            for path in paths_to_process:
                if path not in api_spec.get('paths', {}):
                    continue

                path_item = api_spec['paths'][path]
                mock_data[path] = {}

                for method in ['get', 'post', 'put', 'patch', 'delete']:
                    if method in path_item:
                        operation = path_item[method]
                        mock_data[path][method] = await self._generate_operation_data(
                            operation, analysis, strategy, count
                        )

            # Generate global reusable data
            global_data = await self._generate_global_data(api_spec, analysis, strategy, count)

            # Convert mock data to test case format
            test_cases = []
            for path, methods in mock_data.items():
                for method, operation_data in methods.items():
                    test_cases.append({
                        'path': path,
                        'method': method.upper(),
                        'operation_data': operation_data,
                        'global_data': global_data,
                        'analysis': analysis
                    })

            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="success",
                test_cases=test_cases,
                metadata={
                    'generated_at': datetime.utcnow().isoformat(),
                    'strategy': strategy,
                    'count': count,
                    'seed': seed,
                    'paths_processed': len(mock_data),
                    'statistics': self.statistics
                },
                error_message=None
            )

        except Exception as e:
            logger.error(f"Error in DataMockingAgent execution: {e}", exc_info=True)
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="failed",
                test_cases=[],
                metadata={'error': True, 'error_details': str(e)},
                error_message=str(e)
            )

    def _analyze_specification(self, api_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze API specification to extract schemas, relationships, and constraints"""
        analysis = {
            'schemas': {},
            'relationships': [],
            'constraints': {},
            'patterns': {},
            'enums': {}
        }

        # Extract schemas
        schemas = api_spec.get('components', {}).get('schemas', {})
        analysis['schemas'] = schemas

        # Find relationships between schemas
        analysis['relationships'] = self._find_relationships(schemas)

        # Extract field patterns (email, phone, etc.)
        analysis['patterns'] = self._extract_patterns(schemas)

        # Extract constraints (min/max, lengths, etc.)
        analysis['constraints'] = self._extract_constraints(schemas)

        # Extract enum values
        for schema_name, schema in schemas.items():
            if 'properties' in schema:
                for field_name, field_schema in schema['properties'].items():
                    if 'enum' in field_schema:
                        key = f"{schema_name}.{field_name}"
                        analysis['enums'][key] = field_schema['enum']

        return analysis

    def _find_relationships(self, schemas: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find foreign key relationships between schemas"""
        relationships = []

        for schema_name, schema in schemas.items():
            if 'properties' not in schema:
                continue

            for field_name, field_schema in schema['properties'].items():
                # Look for fields like userId, postId, etc.
                if field_name.endswith('Id') and field_schema.get('type') == 'integer':
                    related_entity = field_name[:-2].capitalize()
                    if related_entity in schemas:
                        relationships.append({
                            'from': schema_name,
                            'to': related_entity,
                            'field': field_name,
                            'type': 'foreign_key'
                        })

        return relationships

    def _extract_patterns(self, schemas: Dict[str, Any]) -> Dict[str, str]:
        """Extract common field patterns (email, phone, name, etc.)"""
        patterns = {}

        pattern_keywords = {
            'email': 'email',
            'phone': 'phone',
            'name': 'name',
            'username': 'username',
            'password': 'password',
            'url': 'url',
            'date': 'date',
            'time': 'time',
            'uuid': 'uuid',
            'ip': 'ip'
        }

        for schema_name, schema in schemas.items():
            if 'properties' not in schema:
                continue

            for field_name, field_schema in schema['properties'].items():
                field_lower = field_name.lower()

                # Check format first
                if 'format' in field_schema:
                    key = f"{schema_name}.{field_name}"
                    patterns[key] = field_schema['format']
                    continue

                # Check field name for patterns
                for keyword, pattern_type in pattern_keywords.items():
                    if keyword in field_lower:
                        key = f"{schema_name}.{field_name}"
                        patterns[key] = pattern_type
                        break

        return patterns

    def _extract_constraints(self, schemas: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract validation constraints for fields"""
        constraints = {}

        for schema_name, schema in schemas.items():
            if 'properties' not in schema:
                continue

            required_fields = set(schema.get('required', []))

            for field_name, field_schema in schema['properties'].items():
                field_constraints = {}
                key = f"{schema_name}.{field_name}"

                # String constraints
                if 'minLength' in field_schema:
                    field_constraints['minLength'] = field_schema['minLength']
                if 'maxLength' in field_schema:
                    field_constraints['maxLength'] = field_schema['maxLength']
                if 'pattern' in field_schema:
                    field_constraints['pattern'] = field_schema['pattern']

                # Number constraints
                if 'minimum' in field_schema:
                    field_constraints['minimum'] = field_schema['minimum']
                if 'maximum' in field_schema:
                    field_constraints['maximum'] = field_schema['maximum']

                # Array constraints
                if 'minItems' in field_schema:
                    field_constraints['minItems'] = field_schema['minItems']
                if 'maxItems' in field_schema:
                    field_constraints['maxItems'] = field_schema['maxItems']

                # Required
                if field_name in required_fields:
                    field_constraints['required'] = True

                if field_constraints:
                    constraints[key] = field_constraints

        return constraints

    async def _generate_operation_data(
        self,
        operation: Dict[str, Any],
        analysis: Dict[str, Any],
        strategy: str,
        count: int
    ) -> Dict[str, Any]:
        """Generate data for a specific API operation"""
        operation_data = {
            'request_bodies': [],
            'responses': [],
            'parameters': []
        }

        # Generate request bodies
        if 'requestBody' in operation:
            content = operation['requestBody'].get('content', {})
            for media_type, media_schema in content.items():
                if 'schema' in media_schema:
                    for i in range(min(count, self.max_response_variations)):
                        body_data = await self._generate_from_schema(
                            media_schema['schema'], analysis, strategy
                        )
                        operation_data['request_bodies'].append({
                            'media_type': media_type,
                            'data': body_data,
                            'variation': i + 1
                        })

        # Generate response data
        if 'responses' in operation:
            for status_code, response in operation['responses'].items():
                if 'content' in response:
                    content = response['content']
                    for media_type, media_schema in content.items():
                        if 'schema' in media_schema:
                            for i in range(min(count, self.max_response_variations)):
                                response_data = await self._generate_from_schema(
                                    media_schema['schema'], analysis, strategy
                                )
                                operation_data['responses'].append({
                                    'status_code': status_code,
                                    'media_type': media_type,
                                    'data': response_data,
                                    'variation': i + 1
                                })

        # Generate parameter data
        if 'parameters' in operation:
            for param in operation['parameters']:
                if 'schema' in param:
                    for i in range(min(count, self.max_parameter_variations)):
                        param_data = await self._generate_from_schema(
                            param['schema'], analysis, strategy
                        )
                        operation_data['parameters'].append({
                            'name': param['name'],
                            'in': param['in'],
                            'data': param_data,
                            'variation': i + 1
                        })

        return operation_data

    async def _generate_from_schema(
        self,
        schema: Dict[str, Any],
        analysis: Dict[str, Any],
        strategy: str
    ) -> Any:
        """Generate data from JSON Schema"""
        # Handle $ref
        if '$ref' in schema:
            ref_path = schema['$ref'].split('/')
            ref_schema = analysis['schemas'].get(ref_path[-1], {})
            return await self._generate_from_schema(ref_schema, analysis, strategy)

        schema_type = schema.get('type', 'string')

        if schema_type == 'string':
            return self._generate_string(schema, analysis, strategy)
        elif schema_type == 'integer':
            return self._generate_integer(schema, analysis, strategy)
        elif schema_type == 'number':
            return self._generate_number(schema, analysis, strategy)
        elif schema_type == 'boolean':
            return self._generate_boolean(schema, analysis, strategy)
        elif schema_type == 'array':
            return await self._generate_array(schema, analysis, strategy)
        elif schema_type == 'object':
            return await self._generate_object(schema, analysis, strategy)
        else:
            return None

    def _generate_string(self, schema: Dict[str, Any], analysis: Dict[str, Any], strategy: str) -> str:
        """Generate string data based on schema and strategy"""
        # Check for enum
        if 'enum' in schema:
            return random.choice(schema['enum'])

        # Check format
        format_type = schema.get('format')
        if format_type == 'email':
            return self.fake.email()
        elif format_type == 'uri' or format_type == 'url':
            return self.fake.url()
        elif format_type == 'date':
            return self.fake.date()
        elif format_type == 'date-time':
            return self.fake.iso8601()
        elif format_type == 'uuid':
            return str(self.fake.uuid4())

        # Get length constraints
        min_len = schema.get('minLength', 0)
        max_len = schema.get('maxLength', 100)

        # Strategy-based generation
        if strategy == 'edge_cases':
            # Return boundary values
            return random.choice([
                'a' * min_len,  # Minimum length
                'a' * (min_len + 1),  # Just above minimum
                'a' * (max_len - 1),  # Just below maximum
                'a' * max_len  # Maximum length
            ])
        elif strategy == 'boundary':
            return random.choice(['a' * min_len, 'a' * max_len])
        else:
            # Realistic generation
            if 'pattern' in schema:
                # For patterns, generate a simple valid string
                return 'A' * random.randint(max(min_len, 1), min(max_len, 20))

            length = random.randint(max(min_len, 5), min(max_len, 50))
            return self.fake.text(max_nb_chars=length).strip()

    def _generate_integer(self, schema: Dict[str, Any], analysis: Dict[str, Any], strategy: str) -> int:
        """Generate integer data based on schema and strategy"""
        minimum = schema.get('minimum', 0)
        maximum = schema.get('maximum', 1000000)

        if strategy == 'edge_cases':
            return random.choice([
                minimum,
                minimum + 1,
                maximum - 1,
                maximum
            ])
        elif strategy == 'boundary':
            return random.choice([minimum, maximum])
        else:
            return random.randint(minimum, maximum)

    def _generate_number(self, schema: Dict[str, Any], analysis: Dict[str, Any], strategy: str) -> float:
        """Generate number (float) data based on schema and strategy"""
        minimum = schema.get('minimum', 0.0)
        maximum = schema.get('maximum', 1000000.0)

        if strategy == 'edge_cases':
            return random.choice([
                minimum,
                minimum + 0.1,
                maximum - 0.1,
                maximum
            ])
        elif strategy == 'boundary':
            return random.choice([minimum, maximum])
        else:
            return random.uniform(minimum, maximum)

    def _generate_boolean(self, schema: Dict[str, Any], analysis: Dict[str, Any], strategy: str) -> bool:
        """Generate boolean data"""
        return random.choice([True, False])

    async def _generate_array(self, schema: Dict[str, Any], analysis: Dict[str, Any], strategy: str) -> List[Any]:
        """Generate array data based on schema and strategy"""
        min_items = schema.get('minItems', 0)
        max_items = schema.get('maxItems', 10)

        if strategy == 'edge_cases':
            count = random.choice([min_items, min_items + 1, max_items - 1, max_items])
        elif strategy == 'boundary':
            count = random.choice([min_items, max_items])
        else:
            count = random.randint(max(min_items, 1), min(max_items, 5))

        items_schema = schema.get('items', {'type': 'string'})
        result = []

        for _ in range(count):
            item = await self._generate_from_schema(items_schema, analysis, strategy)
            result.append(item)

        return result

    async def _generate_object(self, schema: Dict[str, Any], analysis: Dict[str, Any], strategy: str) -> Dict[str, Any]:
        """Generate object data based on schema and strategy"""
        result = {}

        properties = schema.get('properties', {})
        required_fields = set(schema.get('required', []))

        for field_name, field_schema in properties.items():
            # Always generate required fields
            if field_name in required_fields or random.random() > 0.3:
                result[field_name] = await self._generate_from_schema(
                    field_schema, analysis, strategy
                )

        return result

    async def _generate_global_data(
        self,
        api_spec: Dict[str, Any],
        analysis: Dict[str, Any],
        strategy: str,
        count: int
    ) -> Dict[str, Any]:
        """Generate global reusable test data (users, tokens, etc.)"""
        global_data = {
            'users': [],
            'auth_tokens': [],
            'api_keys': [],
            'test_entities': {}
        }

        # Generate test users
        for i in range(count):
            user = {
                'id': i + 1,
                'username': self.fake.user_name(),
                'email': self.fake.email(),
                'password': self.fake.password(),
                'first_name': self.fake.first_name(),
                'last_name': self.fake.last_name(),
                'created_at': self.fake.iso8601()
            }
            global_data['users'].append(user)

        # Generate auth tokens
        for i in range(count):
            token = {
                'token': self.fake.jwt_token(),
                'user_id': i + 1,
                'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
                'scope': random.choice(['read', 'write', 'admin'])
            }
            global_data['auth_tokens'].append(token)

        # Generate API keys
        for i in range(count):
            api_key = {
                'key': self.fake.api_key(),
                'user_id': i + 1,
                'name': f"API Key {i + 1}",
                'created_at': self.fake.iso8601()
            }
            global_data['api_keys'].append(api_key)

        # Generate entities for each schema
        for schema_name in analysis['schemas'].keys():
            entities = []
            for i in range(min(count, self.max_entity_variations)):
                entity_schema = analysis['schemas'][schema_name]
                entity = await self._generate_from_schema(entity_schema, analysis, strategy)
                entities.append(entity)
            global_data['test_entities'][schema_name] = entities

        return global_data

    def _generate_realistic(self, schema: Dict[str, Any], analysis: Dict[str, Any]) -> Any:
        """Realistic data generation strategy"""
        return self._generate_from_schema(schema, analysis, 'realistic')

    def _generate_edge_cases(self, schema: Dict[str, Any], analysis: Dict[str, Any]) -> Any:
        """Edge cases data generation strategy"""
        return self._generate_from_schema(schema, analysis, 'edge_cases')

    def _generate_boundary(self, schema: Dict[str, Any], analysis: Dict[str, Any]) -> Any:
        """Boundary values data generation strategy"""
        return self._generate_from_schema(schema, analysis, 'boundary')

    def _generate_random(self, schema: Dict[str, Any], analysis: Dict[str, Any]) -> Any:
        """Random data generation strategy"""
        return self._generate_from_schema(schema, analysis, 'random')
