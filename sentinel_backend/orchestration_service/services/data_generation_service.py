"""
Data Generation Service - Utility for generating realistic test data

This service provides data generation capabilities for use by other agents.
It generates ONLY data (not test cases), which can be consumed by functional,
security, and other testing agents.

Key Architectural Change:
- OLD: DataMockingAgent generated "test cases with mock data"
- NEW: DataGenerationService generates "data only" for use by other agents
"""

import random
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from faker import Faker
from faker.providers import BaseProvider


class APIProvider(BaseProvider):
    """Custom Faker provider for API-specific data generation"""

    def api_key(self) -> str:
        """Generate a realistic API key"""
        return f"sk-{self.random_element(['test', 'dev', 'prod'])}-{''.join(self.random_choices('abcdefghijklmnopqrstuvwxyz0123456789', length=32))}"

    def jwt_token(self) -> str:
        """Generate a realistic JWT token structure"""
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
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


class DataGenerationService:
    """
    Utility service for generating realistic test data.

    This service is NOT an agent - it's a utility used by agents to generate data.
    It does not create test cases, only data that matches schemas and constraints.

    OPTIMIZED: Uses singleton pattern to avoid repeated Faker() initialization (50-100ms overhead).
    """

    _instance = None
    _faker = None

    def __new__(cls, locale: str = 'en_US', seed: Optional[int] = None):
        """Singleton pattern - reuse single instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._faker = Faker(locale)
            cls._faker.add_provider(APIProvider)
            if seed is not None:
                Faker.seed(seed)
        return cls._instance

    def __init__(self, locale: str = 'en_US', seed: Optional[int] = None):
        """
        Initialize the data generation service (singleton).

        Args:
            locale: Faker locale for data generation
            seed: Optional seed for reproducible data generation
        """
        if not hasattr(self, 'fake'):
            self.fake = self._faker

        if seed is not None:
            self.set_seed(seed)

        # Field pattern mappings for intelligent data generation
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
            'description': lambda: self.fake.text(max_nb_chars=200) if random.random() > 0.1 else self.fake.text(max_nb_chars=50),
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

    def set_seed(self, seed: int) -> None:
        """Set seed for reproducible data generation"""
        Faker.seed(seed)
        random.seed(seed)

    def generate_realistic_data(self, schema: Dict[str, Any], strategy: str = "realistic") -> Any:
        """
        Generate data matching a JSON schema.

        Args:
            schema: JSON schema definition
            strategy: Generation strategy - "realistic", "boundary", "edge_case", "invalid"

        Returns:
            Generated data (NOT a test case!)

        Raises:
            ValueError: If strategy is invalid
        """
        if not schema:
            return None

        valid_strategies = ["realistic", "boundary", "edge_case", "invalid"]
        if strategy not in valid_strategies:
            raise ValueError(f"Invalid strategy '{strategy}'. Must be one of {valid_strategies}")

        schema_type = schema.get('type', 'object')

        if strategy == "realistic":
            return self._generate_by_type(schema, schema_type)
        elif strategy == "boundary":
            return self._generate_boundary_data_for_schema(schema, schema_type)
        elif strategy == "edge_case":
            # Return first edge case from list
            edge_cases = self.generate_edge_case_data(schema)
            return edge_cases[0] if edge_cases else None
        elif strategy == "invalid":
            return self._generate_invalid_data_for_schema(schema, schema_type)

    def _generate_by_type(self, schema: Dict[str, Any], schema_type: str) -> Any:
        """Generate data based on schema type"""
        if schema_type == 'object':
            return self._generate_object(schema)
        elif schema_type == 'array':
            return self._generate_array(schema)
        elif schema_type == 'string':
            return self._generate_string(schema)
        elif schema_type == 'integer':
            return self._generate_integer(schema)
        elif schema_type == 'number':
            return self._generate_number(schema)
        elif schema_type == 'boolean':
            return self._generate_boolean(schema)
        else:
            return None

    def generate_boundary_values(self, param_type: str, constraints: Dict[str, Any]) -> List[Any]:
        """
        Generate boundary values for a parameter.

        Args:
            param_type: Type of parameter (string, integer, number, array, etc.)
            constraints: Constraints dict with min/max values

        Returns:
            List of boundary values
        """
        boundary_values = []

        if param_type == 'integer':
            minimum = constraints.get('minimum', 0)
            maximum = constraints.get('maximum', 100)

            boundary_values = [
                minimum,           # Minimum value
                maximum,           # Maximum value
                minimum - 1,       # Below minimum
                maximum + 1,       # Above maximum
                minimum + 1,       # Just above minimum
                maximum - 1,       # Just below maximum
            ]

        elif param_type == 'number':
            minimum = constraints.get('minimum', 0.0)
            maximum = constraints.get('maximum', 100.0)

            boundary_values = [
                minimum,           # Minimum value
                maximum,           # Maximum value
                minimum - 0.1,     # Below minimum
                maximum + 0.1,     # Above maximum
                minimum + 0.1,     # Just above minimum
                maximum - 0.1,     # Just below maximum
            ]

        elif param_type == 'string':
            min_length = constraints.get('minLength', 0)
            max_length = constraints.get('maxLength', 100)

            boundary_values = [
                'a' * min_length,       # Minimum length
                'a' * max_length,       # Maximum length
                'a' * (min_length - 1) if min_length > 0 else '',  # Below minimum
                'a' * (max_length + 1), # Above maximum
                'a' * (min_length + 1), # Just above minimum
                'a' * (max_length - 1) if max_length > 0 else '',  # Just below maximum
            ]

        elif param_type == 'array':
            min_items = constraints.get('minItems', 0)
            max_items = constraints.get('maxItems', 10)

            boundary_values = [
                ['item'] * min_items,       # Minimum items
                ['item'] * max_items,       # Maximum items
                ['item'] * (min_items - 1) if min_items > 0 else [],  # Below minimum
                ['item'] * (max_items + 1), # Above maximum
                ['item'] * (min_items + 1), # Just above minimum
                ['item'] * (max_items - 1) if max_items > 0 else [],  # Just below maximum
            ]

        return boundary_values

    def generate_edge_case_data(self, schema: Dict[str, Any]) -> List[Any]:
        """
        Generate edge case data (empty, null, special chars, etc.).

        Args:
            schema: JSON schema definition

        Returns:
            List of edge case values
        """
        schema_type = schema.get('type', 'object')
        edge_cases = []

        if schema_type == 'string':
            edge_cases = [
                '',                    # Empty string
                ' ',                   # Whitespace
                '  ',                  # Multiple spaces
                '\n',                  # Newline
                '\t',                  # Tab
                '   leading spaces',   # Leading spaces
                'trailing spaces   ',  # Trailing spaces
                '<script>alert("xss")</script>',  # XSS attempt
                "'; DROP TABLE users--",           # SQL injection
                '../../../etc/passwd',             # Path traversal
                '${7*7}',             # Template injection
                '{{7*7}}',            # Template injection
                '%00',                # Null byte
                '\x00',               # Null character
                '🚀💻🎉',              # Unicode/emoji
                'a' * 1000,           # Very long string
                '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',  # Special chars
            ]

        elif schema_type == 'integer':
            edge_cases = [
                0,
                -1,
                1,
                -2147483648,  # Min 32-bit int
                2147483647,   # Max 32-bit int
                -9223372036854775808,  # Min 64-bit int
                9223372036854775807,   # Max 64-bit int
            ]

        elif schema_type == 'number':
            edge_cases = [
                0.0,
                -0.0,
                0.1,
                -0.1,
                1.7976931348623157e+308,  # Max float
                2.2250738585072014e-308,   # Min positive float
                float('inf'),              # Infinity
                float('-inf'),             # Negative infinity
                float('nan'),              # NaN
            ]

        elif schema_type == 'boolean':
            edge_cases = [True, False]

        elif schema_type == 'array':
            edge_cases = [
                [],                    # Empty array
                [None],                # Array with null
                [''],                  # Array with empty string
                [' '],                 # Array with whitespace
                ['a'] * 1000,          # Very large array
            ]

        elif schema_type == 'object':
            edge_cases = [
                {},                    # Empty object
                {'key': None},         # Object with null value
                {'key': ''},           # Object with empty string
                {'': 'value'},         # Empty key
                {' ': 'value'},        # Whitespace key
            ]

        return edge_cases

    def _generate_object(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate object data based on schema"""
        obj = {}
        properties = schema.get('properties', {})
        required = schema.get('required', [])

        for prop_name, prop_schema in properties.items():
            # Always generate required fields, randomly generate optional fields
            if prop_name in required or random.random() < 0.7:
                obj[prop_name] = self._generate_by_type(prop_schema, prop_schema.get('type', 'string'))

        return obj

    def _generate_array(self, schema: Dict[str, Any]) -> List[Any]:
        """Generate array data based on schema"""
        items_schema = schema.get('items', {})
        min_items = schema.get('minItems', 1)
        max_items = schema.get('maxItems', 5)

        length = random.randint(min_items, max_items)
        items_type = items_schema.get('type', 'string')

        return [
            self._generate_by_type(items_schema, items_type)
            for _ in range(length)
        ]

    def _generate_string(self, schema: Dict[str, Any]) -> str:
        """Generate string data based on schema"""
        format_type = schema.get('format')
        pattern = schema.get('pattern')
        enum_values = schema.get('enum')
        min_length = schema.get('minLength', 1)
        max_length = schema.get('maxLength', 50)

        # Handle enum
        if enum_values:
            return random.choice(enum_values)

        # Handle format
        if format_type == 'email':
            return self.fake.email()
        elif format_type == 'uri' or format_type == 'url':
            return self.fake.url()
        elif format_type == 'date':
            return self.fake.date()
        elif format_type == 'date-time':
            return self.fake.iso8601()
        elif format_type == 'uuid':
            return str(uuid.uuid4())
        elif format_type == 'ipv4':
            return self.fake.ipv4()
        elif format_type == 'ipv6':
            return self.fake.ipv6()

        # Handle pattern (basic support)
        if pattern:
            if 'email' in pattern.lower():
                return self.fake.email()
            elif 'phone' in pattern.lower():
                return self.fake.phone_number()
            # For complex patterns, generate a string that might match
            # This is simplified - full regex generation would be complex
            length = random.randint(min_length, min(max_length, 20))
            return self.fake.lexify('?' * length)

        # Default string generation
        # Faker.text() requires at least 5 characters
        length = random.randint(max(min_length, 5), max(max_length, 20))
        return self.fake.text(max_nb_chars=length).replace('\n', ' ').strip()

    def _generate_integer(self, schema: Dict[str, Any]) -> int:
        """Generate integer data based on schema"""
        minimum = schema.get('minimum', 0)
        maximum = schema.get('maximum', 1000)

        return random.randint(minimum, maximum)

    def _generate_number(self, schema: Dict[str, Any]) -> float:
        """Generate number (float) data based on schema"""
        minimum = schema.get('minimum', 0.0)
        maximum = schema.get('maximum', 1000.0)

        return round(random.uniform(minimum, maximum), 2)

    def _generate_boolean(self, schema: Dict[str, Any]) -> bool:
        """Generate boolean data based on schema"""
        return self.fake.boolean()

    def _generate_boundary_data_for_schema(self, schema: Dict[str, Any], schema_type: str) -> Any:
        """Generate boundary data for a specific schema"""
        if schema_type == 'integer':
            minimum = schema.get('minimum', 0)
            maximum = schema.get('maximum', 100)
            return random.choice([minimum, maximum, minimum + 1, maximum - 1])

        elif schema_type == 'number':
            minimum = schema.get('minimum', 0.0)
            maximum = schema.get('maximum', 100.0)
            return random.choice([minimum, maximum, minimum + 0.1, maximum - 0.1])

        elif schema_type == 'string':
            min_length = schema.get('minLength', 1)
            max_length = schema.get('maxLength', 50)
            return random.choice(['a' * min_length, 'a' * max_length])

        elif schema_type == 'array':
            items_schema = schema.get('items', {})
            min_items = schema.get('minItems', 0)
            max_items = schema.get('maxItems', 10)
            length = random.choice([min_items, max_items])
            items_type = items_schema.get('type', 'string')
            return [self._generate_by_type(items_schema, items_type) for _ in range(length)]

        else:
            return self._generate_by_type(schema, schema_type)

    def _generate_invalid_data_for_schema(self, schema: Dict[str, Any], schema_type: str) -> Any:
        """Generate invalid data that violates schema constraints"""
        if schema_type == 'integer':
            # Return a string instead of integer, or violate constraints
            minimum = schema.get('minimum', 0)
            maximum = schema.get('maximum', 100)
            return random.choice([
                "not_an_integer",
                None,
                minimum - 100,  # Way below minimum
                maximum + 100,  # Way above maximum
            ])

        elif schema_type == 'number':
            return random.choice(["not_a_number", None, "NaN", "Infinity"])

        elif schema_type == 'string':
            min_length = schema.get('minLength', 1)
            max_length = schema.get('maxLength', 50)
            return random.choice([
                None,
                123,  # Wrong type
                '',   # Too short (if minLength > 0)
                'a' * (max_length + 100),  # Way too long
            ])

        elif schema_type == 'boolean':
            return random.choice([None, "true", "false", 1, 0])

        elif schema_type == 'array':
            return random.choice([None, "not_an_array", {}, 123])

        elif schema_type == 'object':
            return random.choice([None, "not_an_object", [], 123])

        return None
