"""
Comprehensive TDD Tests for DataGenerationService

This test suite ensures:
1. Data generation ONLY (not test case generation)
2. Realistic data patterns based on field names
3. Boundary value generation for constraints
4. Edge case data generation
5. Reproducible data with seed
6. NO test case generation (utility service only)
"""

import pytest
from typing import Dict, List, Any
import re
from datetime import datetime

from sentinel_backend.orchestration_service.services.data_generation_service import (
    DataGenerationService,
    APIProvider
)


class TestDataGenerationService:
    """Test suite for DataGenerationService utility"""

    @pytest.fixture
    def data_service(self):
        """Create DataGenerationService instance"""
        return DataGenerationService()

    @pytest.fixture
    def seeded_service(self):
        """Create DataGenerationService with fixed seed for reproducibility"""
        return DataGenerationService(seed=12345)

    # ==================== INITIALIZATION TESTS ====================

    def test_service_initialization(self, data_service):
        """MUST initialize with Faker and custom providers"""
        assert data_service.fake is not None
        assert hasattr(data_service.fake, 'email')
        assert hasattr(data_service.fake, 'api_key')  # Custom provider method

    def test_service_with_seed_is_reproducible(self):
        """MUST generate same data with same seed"""
        service1 = DataGenerationService(seed=42)
        service2 = DataGenerationService(seed=42)

        data1 = service1.generate_realistic_data({"type": "string"})
        data2 = service2.generate_realistic_data({"type": "string"})

        assert data1 == data2, "Same seed must produce same data"

    def test_service_without_seed_is_random(self, data_service):
        """MUST generate different data each time without seed"""
        data1 = data_service.generate_realistic_data({"type": "string"})
        data2 = data_service.generate_realistic_data({"type": "string"})

        # Very unlikely to be the same (but not impossible)
        # Generate multiple and check they're not all identical
        data_list = [
            data_service.generate_realistic_data({"type": "string"})
            for _ in range(5)
        ]

        unique_values = len(set(data_list))
        assert unique_values > 1, "Should generate varied data without seed"

    # ==================== REALISTIC DATA GENERATION ====================

    def test_generates_realistic_email(self, data_service):
        """MUST generate valid email addresses for email fields"""
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string", "format": "email"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        assert "email" in data
        # Email format validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        assert re.match(email_pattern, data["email"]), f"Invalid email: {data['email']}"

    def test_generates_realistic_phone_number(self, data_service):
        """MUST generate realistic phone numbers"""
        schema = {
            "type": "object",
            "properties": {
                "phone": {"type": "string"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        assert "phone" in data
        assert len(data["phone"]) > 0
        # Should contain digits
        assert any(c.isdigit() for c in data["phone"]), "Phone should contain digits"

    def test_generates_realistic_name(self, data_service):
        """MUST generate realistic names"""
        schema = {
            "type": "object",
            "properties": {
                "first_name": {"type": "string"},
                "last_name": {"type": "string"},
                "full_name": {"type": "string"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        assert "first_name" in data
        assert "last_name" in data
        assert len(data["first_name"]) > 0
        assert len(data["last_name"]) > 0

    def test_generates_realistic_url(self, data_service):
        """MUST generate valid URLs"""
        schema = {
            "type": "object",
            "properties": {
                "url": {"type": "string", "format": "uri"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        assert "url" in data
        # URL should start with http:// or https://
        assert data["url"].startswith(('http://', 'https://')), f"Invalid URL: {data['url']}"

    def test_generates_api_key(self, data_service):
        """MUST generate realistic API keys"""
        # Use custom provider method
        api_key = data_service.fake.api_key()

        assert api_key.startswith('sk-'), "API key should start with 'sk-'"
        assert len(api_key) > 30, "API key should be sufficiently long"
        # Should contain alphanumeric characters
        assert any(c.isalnum() for c in api_key)

    def test_generates_jwt_token(self, data_service):
        """MUST generate realistic JWT token structure"""
        jwt = data_service.fake.jwt_token()

        # JWT has 3 parts separated by dots
        parts = jwt.split('.')
        assert len(parts) == 3, f"JWT should have 3 parts, got {len(parts)}"

        # Each part should be base64-like
        for part in parts:
            assert len(part) > 0
            assert all(c.isalnum() or c in '-_=' for c in part)

    # ==================== TYPE-SPECIFIC DATA GENERATION ====================

    def test_generates_string_data(self, data_service):
        """MUST generate string data"""
        schema = {"type": "string"}

        data = data_service.generate_realistic_data(schema)

        assert isinstance(data, str)
        assert len(data) > 0

    def test_generates_integer_data(self, data_service):
        """MUST generate integer data"""
        schema = {"type": "integer"}

        data = data_service.generate_realistic_data(schema)

        assert isinstance(data, int)

    def test_generates_number_data(self, data_service):
        """MUST generate number (float) data"""
        schema = {"type": "number"}

        data = data_service.generate_realistic_data(schema)

        assert isinstance(data, (int, float))

    def test_generates_boolean_data(self, data_service):
        """MUST generate boolean data"""
        schema = {"type": "boolean"}

        data = data_service.generate_realistic_data(schema)

        assert isinstance(data, bool)

    def test_generates_array_data(self, data_service):
        """MUST generate array data"""
        schema = {
            "type": "array",
            "items": {"type": "string"}
        }

        data = data_service.generate_realistic_data(schema)

        assert isinstance(data, list)
        assert all(isinstance(item, str) for item in data)

    def test_generates_object_data(self, data_service):
        """MUST generate object data with properties"""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name"]
        }

        data = data_service.generate_realistic_data(schema)

        assert isinstance(data, dict)
        assert "name" in data, "Required field must be present"
        assert isinstance(data["name"], str)

    # ==================== CONSTRAINT HANDLING ====================

    def test_respects_integer_constraints(self, data_service):
        """MUST respect min/max constraints for integers"""
        schema = {
            "type": "integer",
            "minimum": 10,
            "maximum": 50
        }

        for _ in range(10):
            data = data_service.generate_realistic_data(schema)
            assert 10 <= data <= 50, f"Integer {data} outside bounds [10, 50]"

    def test_respects_string_length_constraints(self, data_service):
        """MUST respect minLength/maxLength for strings"""
        schema = {
            "type": "string",
            "minLength": 5,
            "maxLength": 20
        }

        for _ in range(10):
            data = data_service.generate_realistic_data(schema)
            assert 5 <= len(data) <= 20, f"String length {len(data)} outside bounds [5, 20]"

    def test_respects_array_length_constraints(self, data_service):
        """MUST respect minItems/maxItems for arrays"""
        schema = {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
            "maxItems": 5
        }

        data = data_service.generate_realistic_data(schema)

        assert 2 <= len(data) <= 5, f"Array length {len(data)} outside bounds [2, 5]"

    def test_respects_enum_values(self, data_service):
        """MUST select from enum values"""
        schema = {
            "type": "string",
            "enum": ["red", "green", "blue"]
        }

        for _ in range(10):
            data = data_service.generate_realistic_data(schema)
            assert data in ["red", "green", "blue"], f"Value {data} not in enum"

    # ==================== BOUNDARY VALUE GENERATION ====================

    def test_generates_integer_boundary_values(self, data_service):
        """MUST generate boundary values for integers"""
        boundary_values = data_service.generate_boundary_values(
            'integer',
            {'minimum': 10, 'maximum': 100}
        )

        assert len(boundary_values) >= 4, "Should generate multiple boundary values"

        # Must include minimum and maximum
        assert 10 in boundary_values, "Must include minimum boundary"
        assert 100 in boundary_values, "Must include maximum boundary"

        # Should include out-of-bounds values for negative testing
        assert 9 in boundary_values or any(v < 10 for v in boundary_values), "Should include below-minimum value"
        assert 101 in boundary_values or any(v > 100 for v in boundary_values), "Should include above-maximum value"

    def test_generates_string_boundary_values(self, data_service):
        """MUST generate boundary values for strings"""
        boundary_values = data_service.generate_boundary_values(
            'string',
            {'minLength': 3, 'maxLength': 10}
        )

        assert len(boundary_values) > 0

        lengths = [len(v) for v in boundary_values]

        # Should include min and max lengths
        assert 3 in lengths, "Must include minimum length"
        assert 10 in lengths, "Must include maximum length"

    def test_generates_number_boundary_values(self, data_service):
        """MUST generate boundary values for numbers"""
        boundary_values = data_service.generate_boundary_values(
            'number',
            {'minimum': 0.0, 'maximum': 1.0}
        )

        assert len(boundary_values) >= 4

        # Must include boundaries
        assert 0.0 in boundary_values, "Must include minimum"
        assert 1.0 in boundary_values, "Must include maximum"

    # ==================== EDGE CASE DATA GENERATION ====================

    def test_generates_edge_case_data(self, data_service):
        """MUST generate edge case data"""
        schema = {"type": "string"}

        edge_cases = data_service.generate_edge_case_data(schema)

        assert len(edge_cases) > 0, "Must generate edge cases"
        assert isinstance(edge_cases, list), "Edge cases must be a list"

    def test_edge_cases_include_special_values(self, data_service):
        """MUST include special values in edge cases"""
        schema = {"type": "string"}

        edge_cases = data_service.generate_edge_case_data(schema)

        # Should include various edge cases like empty, special chars, etc.
        edge_case_strings = [str(ec) for ec in edge_cases]

        # Should have some variety
        assert len(set(edge_case_strings)) > 1, "Should generate varied edge cases"

    # ==================== STRATEGY-BASED GENERATION ====================

    def test_realistic_strategy_generates_realistic_data(self, data_service):
        """'realistic' strategy MUST generate realistic-looking data"""
        schema = {
            "type": "object",
            "properties": {
                "email": {"type": "string"},
                "age": {"type": "integer", "minimum": 18, "maximum": 100}
            }
        }

        data = data_service.generate_realistic_data(schema, strategy="realistic")

        assert isinstance(data, dict)
        # Email should look realistic (contain @)
        if "email" in data:
            assert "@" in data["email"]

    def test_boundary_strategy_generates_boundary_data(self, data_service):
        """'boundary' strategy MUST generate boundary values"""
        schema = {
            "type": "integer",
            "minimum": 10,
            "maximum": 50
        }

        data = data_service.generate_realistic_data(schema, strategy="boundary")

        # Boundary data should be at extremes
        assert data in [10, 50, 9, 51, 11, 49], f"Expected boundary value, got {data}"

    def test_edge_case_strategy_generates_edge_data(self, data_service):
        """'edge_case' strategy MUST generate edge case data"""
        schema = {"type": "string"}

        data = data_service.generate_realistic_data(schema, strategy="edge_case")

        # Edge case data should be unusual/extreme
        assert data is not None

    def test_invalid_strategy_raises_error(self, data_service):
        """MUST raise ValueError for invalid strategy"""
        schema = {"type": "string"}

        with pytest.raises(ValueError) as exc_info:
            data_service.generate_realistic_data(schema, strategy="unknown_strategy")

        assert "Invalid strategy" in str(exc_info.value)

    # ==================== UTILITY SERVICE TESTS (NOT TEST CASE GENERATION) ====================

    def test_service_generates_data_not_test_cases(self, data_service):
        """CRITICAL: Service MUST generate data ONLY, not test cases"""
        schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        # Should be raw data, not a test case structure
        assert "test_name" not in data, "Should NOT generate test case structure"
        assert "endpoint" not in data, "Should NOT generate test case structure"
        assert "method" not in data, "Should NOT generate test case structure"
        assert "expected_status" not in data, "Should NOT generate test case structure"

        # Should only have schema properties
        assert isinstance(data, dict)

    def test_service_output_is_consumable_by_agents(self, data_service):
        """Service output MUST be usable by agents for test case generation"""
        schema = {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"}
            },
            "required": ["username", "password"]
        }

        data = data_service.generate_realistic_data(schema)

        # Data should be in format agents can use as request body
        assert isinstance(data, dict)
        assert "username" in data
        assert "password" in data
        assert isinstance(data["username"], str)
        assert isinstance(data["password"], str)

    # ==================== FIELD PATTERN RECOGNITION ====================

    def test_recognizes_email_field_pattern(self, data_service):
        """MUST recognize and generate email for email-like fields"""
        schema = {
            "type": "object",
            "properties": {
                "user_email": {"type": "string"},
                "contact_email": {"type": "string"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        # Fields with 'email' in name should generate email addresses
        for key, value in data.items():
            if 'email' in key.lower():
                assert '@' in value, f"Field {key} should contain email with @"

    def test_recognizes_id_field_pattern(self, data_service):
        """MUST recognize and generate IDs for id-like fields"""
        schema = {
            "type": "object",
            "properties": {
                "user_id": {"type": "string"},
                "product_id": {"type": "string"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        # ID fields should have ID-like values
        for key, value in data.items():
            if 'id' in key.lower():
                assert len(value) > 0
                # IDs are often alphanumeric
                assert any(c.isalnum() for c in value)

    def test_recognizes_timestamp_field_pattern(self, data_service):
        """MUST recognize and generate timestamps for timestamp-like fields"""
        schema = {
            "type": "object",
            "properties": {
                "created_at": {"type": "string"},
                "timestamp": {"type": "string"}
            }
        }

        data = data_service.generate_realistic_data(schema)

        # Timestamp fields should have datetime-like values
        if "created_at" in data or "timestamp" in data:
            # Should contain date-like patterns
            timestamp = data.get("created_at") or data.get("timestamp")
            assert any(c.isdigit() for c in timestamp), "Timestamp should contain numbers"

    # ==================== COMPLEX SCHEMA HANDLING ====================

    def test_handles_nested_objects(self, data_service):
        """MUST handle nested object schemas"""
        schema = {
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "email": {"type": "string"}
                    }
                }
            }
        }

        data = data_service.generate_realistic_data(schema)

        assert "user" in data
        assert isinstance(data["user"], dict)
        assert "name" in data["user"] or "email" in data["user"]

    def test_handles_arrays_of_objects(self, data_service):
        """MUST handle arrays containing objects"""
        schema = {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"}
                }
            }
        }

        data = data_service.generate_realistic_data(schema)

        assert isinstance(data, list)
        if len(data) > 0:
            assert isinstance(data[0], dict)

    def test_handles_required_vs_optional_fields(self, data_service):
        """MUST include required fields, may include optional fields"""
        schema = {
            "type": "object",
            "properties": {
                "required_field": {"type": "string"},
                "optional_field": {"type": "string"}
            },
            "required": ["required_field"]
        }

        # Test multiple times due to randomness
        results = [data_service.generate_realistic_data(schema) for _ in range(10)]

        # All must have required field
        for data in results:
            assert "required_field" in data, "Required field must always be present"

        # Optional field should appear sometimes (but not necessarily always)
        # This is acceptable behavior for realistic data generation

    # ==================== ERROR HANDLING ====================

    def test_handles_empty_schema_gracefully(self, data_service):
        """MUST handle empty schema without crashing"""
        data = data_service.generate_realistic_data({})

        # Should return None or empty dict, not crash
        assert data is None or data == {}

    def test_handles_none_schema_gracefully(self, data_service):
        """MUST handle None schema without crashing"""
        data = data_service.generate_realistic_data(None)

        assert data is None

    def test_handles_unknown_type_gracefully(self, data_service):
        """MUST handle unknown types gracefully"""
        schema = {"type": "unknown_type"}

        data = data_service.generate_realistic_data(schema)

        # Should return None or handle gracefully
        # Should NOT crash
        assert True  # If we get here, no crash occurred
