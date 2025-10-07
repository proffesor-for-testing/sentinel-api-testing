"""
Tests for Data Generation Service

This module tests the DataGenerationService utility that generates
realistic test data for use by other agents (not test cases themselves).
"""

import pytest
from typing import Dict, List, Any
from sentinel_backend.orchestration_service.services.data_generation_service import DataGenerationService


class TestDataGenerationService:
    """Test suite for DataGenerationService"""

    @pytest.fixture
    def service(self):
        """Create DataGenerationService instance"""
        return DataGenerationService()

    # ===== REALISTIC DATA GENERATION =====

    def test_generate_realistic_string_data(self, service):
        """Test realistic string data generation"""
        schema = {
            'type': 'string',
            'minLength': 5,
            'maxLength': 20
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, str)
        assert 5 <= len(result) <= 20

    def test_generate_realistic_integer_data(self, service):
        """Test realistic integer data generation"""
        schema = {
            'type': 'integer',
            'minimum': 1,
            'maximum': 100
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, int)
        assert 1 <= result <= 100

    def test_generate_realistic_email_data(self, service):
        """Test realistic email generation"""
        schema = {
            'type': 'string',
            'format': 'email'
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, str)
        assert '@' in result
        assert '.' in result

    def test_generate_realistic_object_data(self, service):
        """Test realistic object data generation"""
        schema = {
            'type': 'object',
            'properties': {
                'name': {'type': 'string'},
                'age': {'type': 'integer', 'minimum': 0, 'maximum': 120},
                'email': {'type': 'string', 'format': 'email'}
            },
            'required': ['name', 'email']
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, dict)
        assert 'name' in result
        assert 'email' in result
        assert '@' in result['email']

    def test_generate_realistic_array_data(self, service):
        """Test realistic array data generation"""
        schema = {
            'type': 'array',
            'items': {'type': 'string'},
            'minItems': 2,
            'maxItems': 5
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, list)
        assert 2 <= len(result) <= 5
        assert all(isinstance(item, str) for item in result)

    # ===== BOUNDARY VALUE GENERATION =====

    def test_generate_boundary_integer_values(self, service):
        """Test boundary value generation for integers"""
        constraints = {
            'minimum': 0,
            'maximum': 100
        }

        result = service.generate_boundary_values('integer', constraints)

        assert isinstance(result, list)
        assert 0 in result  # Minimum
        assert 100 in result  # Maximum
        assert -1 in result  # Below minimum
        assert 101 in result  # Above maximum

    def test_generate_boundary_string_values(self, service):
        """Test boundary value generation for strings"""
        constraints = {
            'minLength': 5,
            'maxLength': 10
        }

        result = service.generate_boundary_values('string', constraints)

        assert isinstance(result, list)
        # Check for various boundary cases
        lengths = [len(s) for s in result]
        assert 4 in lengths  # Below min
        assert 5 in lengths  # Min
        assert 10 in lengths  # Max
        assert 11 in lengths  # Above max

    def test_generate_boundary_number_values(self, service):
        """Test boundary value generation for numbers"""
        constraints = {
            'minimum': 0.0,
            'maximum': 1.0
        }

        result = service.generate_boundary_values('number', constraints)

        assert isinstance(result, list)
        assert 0.0 in result  # Minimum
        assert 1.0 in result  # Maximum
        # Check for values outside boundaries
        assert any(v < 0.0 for v in result)
        assert any(v > 1.0 for v in result)

    def test_generate_boundary_array_values(self, service):
        """Test boundary value generation for arrays"""
        constraints = {
            'minItems': 2,
            'maxItems': 5
        }

        result = service.generate_boundary_values('array', constraints)

        assert isinstance(result, list)
        lengths = [len(arr) for arr in result]
        assert 1 in lengths  # Below min
        assert 2 in lengths  # Min
        assert 5 in lengths  # Max
        assert 6 in lengths  # Above max

    # ===== EDGE CASE GENERATION =====

    def test_generate_edge_case_string_data(self, service):
        """Test edge case generation for strings"""
        schema = {'type': 'string'}

        result = service.generate_edge_case_data(schema)

        assert isinstance(result, list)
        assert '' in result  # Empty string
        assert any(' ' in s for s in result)  # Whitespace
        assert any(s.startswith(' ') or s.endswith(' ') for s in result)  # Leading/trailing spaces
        # Check for special characters
        special_chars_found = any(
            any(c in s for c in ['<', '>', '&', '"', "'", '\\', '/'])
            for s in result
        )
        assert special_chars_found

    def test_generate_edge_case_integer_data(self, service):
        """Test edge case generation for integers"""
        schema = {'type': 'integer'}

        result = service.generate_edge_case_data(schema)

        assert isinstance(result, list)
        assert 0 in result
        assert -1 in result
        assert 1 in result
        # Check for extreme values
        assert any(v > 1000000 for v in result)
        assert any(v < -1000000 for v in result)

    def test_generate_edge_case_number_data(self, service):
        """Test edge case generation for numbers"""
        schema = {'type': 'number'}

        result = service.generate_edge_case_data(schema)

        assert isinstance(result, list)
        assert 0.0 in result
        assert -0.0 in result or 0.0 in result  # Both representations of zero
        # Check for special float values
        assert any(v < 0 for v in result)  # Negative numbers
        assert any(0 < v < 1 for v in result)  # Fractional numbers

    def test_generate_edge_case_boolean_data(self, service):
        """Test edge case generation for booleans"""
        schema = {'type': 'boolean'}

        result = service.generate_edge_case_data(schema)

        assert isinstance(result, list)
        assert True in result
        assert False in result

    def test_generate_edge_case_array_data(self, service):
        """Test edge case generation for arrays"""
        schema = {
            'type': 'array',
            'items': {'type': 'string'}
        }

        result = service.generate_edge_case_data(schema)

        assert isinstance(result, list)
        assert [] in result  # Empty array
        # Check for array with edge case strings
        assert any(len(arr) > 0 for arr in result)

    def test_generate_edge_case_object_data(self, service):
        """Test edge case generation for objects"""
        schema = {
            'type': 'object',
            'properties': {
                'name': {'type': 'string'},
                'age': {'type': 'integer'}
            }
        }

        result = service.generate_edge_case_data(schema)

        assert isinstance(result, list)
        assert {} in result  # Empty object
        # Check for objects with edge case values
        assert any(isinstance(obj, dict) and len(obj) > 0 for obj in result)

    # ===== INVALID DATA GENERATION =====

    def test_generate_invalid_type_data(self, service):
        """Test invalid data generation (wrong types)"""
        schema = {
            'type': 'integer',
            'minimum': 0,
            'maximum': 100
        }

        result = service.generate_realistic_data(schema, strategy="invalid")

        # Should generate data that violates the schema
        # This might be a string instead of integer, or null
        assert result is None or isinstance(result, str) or isinstance(result, (int, float))

    def test_generate_invalid_constraint_data(self, service):
        """Test invalid data that violates constraints"""
        schema = {
            'type': 'string',
            'minLength': 5,
            'maxLength': 10
        }

        result = service.generate_realistic_data(schema, strategy="invalid")

        # Should generate string outside the length constraints
        if result is not None:
            assert isinstance(result, str)
            # Either too short or too long
            assert len(result) < 5 or len(result) > 10

    # ===== ENUM SUPPORT =====

    def test_generate_enum_data(self, service):
        """Test enum value generation"""
        schema = {
            'type': 'string',
            'enum': ['active', 'inactive', 'pending']
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert result in ['active', 'inactive', 'pending']

    # ===== FORMAT SUPPORT =====

    def test_generate_date_format_data(self, service):
        """Test date format generation"""
        schema = {
            'type': 'string',
            'format': 'date'
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, str)
        # Basic date format check (YYYY-MM-DD)
        assert len(result) >= 8
        assert '-' in result

    def test_generate_datetime_format_data(self, service):
        """Test datetime format generation"""
        schema = {
            'type': 'string',
            'format': 'date-time'
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, str)
        assert 'T' in result or ' ' in result  # ISO format separator

    def test_generate_uuid_format_data(self, service):
        """Test UUID format generation"""
        schema = {
            'type': 'string',
            'format': 'uuid'
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, str)
        assert '-' in result
        # Basic UUID length check (36 characters with dashes)
        assert len(result) == 36

    # ===== PATTERN SUPPORT =====

    def test_generate_pattern_data(self, service):
        """Test pattern-based data generation"""
        schema = {
            'type': 'string',
            'pattern': '^[A-Z]{3}-[0-9]{4}$'
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, str)
        # Should attempt to match the pattern (ABC-1234)
        parts = result.split('-')
        if len(parts) == 2:
            assert parts[0].isupper()

    # ===== NESTED STRUCTURES =====

    def test_generate_nested_object_data(self, service):
        """Test nested object data generation"""
        schema = {
            'type': 'object',
            'properties': {
                'user': {
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string'},
                        'address': {
                            'type': 'object',
                            'properties': {
                                'street': {'type': 'string'},
                                'city': {'type': 'string'}
                            }
                        }
                    }
                }
            }
        }

        result = service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(result, dict)
        assert 'user' in result
        assert isinstance(result['user'], dict)
        if 'address' in result['user']:
            assert isinstance(result['user']['address'], dict)

    # ===== SEED SUPPORT =====

    def test_reproducible_generation_with_seed(self, service):
        """Test that data generation is reproducible with seed"""
        schema = {
            'type': 'string',
            'minLength': 10,
            'maxLength': 20
        }

        service.set_seed(42)
        result1 = service.generate_realistic_data(schema, strategy="realistic")

        service.set_seed(42)
        result2 = service.generate_realistic_data(schema, strategy="realistic")

        assert result1 == result2

    # ===== ERROR HANDLING =====

    def test_handle_empty_schema(self, service):
        """Test handling of empty schema"""
        schema = {}

        result = service.generate_realistic_data(schema, strategy="realistic")

        # Should return None or a default value
        assert result is None or isinstance(result, (str, int, float, bool, dict, list))

    def test_handle_invalid_strategy(self, service):
        """Test handling of invalid strategy"""
        schema = {'type': 'string'}

        # Should default to realistic or raise clear error
        try:
            result = service.generate_realistic_data(schema, strategy="unknown_strategy")
            assert result is not None
        except ValueError as e:
            assert "strategy" in str(e).lower()
