"""
Unit tests for Specification Service.

Tests specification upload, parsing, validation, and management functionality.
"""
import pytest
from fastapi.testclient import TestClient
from fastapi import status
import json

from spec_service.app_factory import (
    create_spec_app, 
    create_test_spec_app, 
    SpecConfig,
    parse_openapi_spec,
    calculate_llm_readiness_score
)


class TestSpecServiceHelpers:
    """Test helper functions."""
    
    @pytest.mark.unit
    def test_parse_openapi_spec_json(self):
        """Test parsing JSON OpenAPI spec."""
        spec_json = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {}
        })
        
        result = parse_openapi_spec(spec_json)
        assert result["openapi"] == "3.0.0"
        assert result["info"]["title"] == "Test API"
    
    @pytest.mark.unit
    def test_parse_openapi_spec_yaml(self):
        """Test parsing YAML OpenAPI spec."""
        spec_yaml = """
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths: {}
"""
        result = parse_openapi_spec(spec_yaml)
        assert result["openapi"] == "3.0.0"
        assert result["info"]["title"] == "Test API"
    
    @pytest.mark.unit
    def test_parse_invalid_spec(self):
        """Test parsing invalid specification."""
        with pytest.raises(ValueError, match="Not a valid OpenAPI"):
            parse_openapi_spec("not a valid spec")
    
    @pytest.mark.unit
    def test_parse_non_openapi_spec(self):
        """Test parsing non-OpenAPI JSON."""
        with pytest.raises(ValueError, match="Not a valid OpenAPI"):
            parse_openapi_spec('{"some": "json"}')
    
    @pytest.mark.unit
    def test_llm_readiness_score_basic(self):
        """Test LLM readiness score calculation."""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0",
                "description": "A test API"
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }
        
        score = calculate_llm_readiness_score(spec)
        assert 0.0 <= score <= 1.0
        assert score > 0.3  # Should have decent score with basic documentation
    
    @pytest.mark.unit
    def test_llm_readiness_score_comprehensive(self):
        """Test LLM readiness score with comprehensive spec."""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0",
                "description": "A comprehensive test API"
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "description": "Retrieve all users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {"description": "Success"}}
                    },
                    "post": {
                        "summary": "Create user",
                        "description": "Create a new user",
                        "requestBody": {"content": {"application/json": {"schema": {}}}},
                        "responses": {"201": {"description": "Created"}}
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {"id": {"type": "integer"}}
                    }
                }
            },
            "security": [{"bearerAuth": []}]
        }
        
        score = calculate_llm_readiness_score(spec)
        assert score > 0.6  # Should have high score with comprehensive documentation


class TestSpecService:
    """Test Specification Service endpoints."""
    
    @pytest.fixture
    def app(self):
        """Create test app."""
        return create_spec_app()
    
    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return TestClient(app)
    
    @pytest.fixture
    def sample_spec(self):
        """Sample OpenAPI specification."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Sample API",
                "version": "1.0.0",
                "description": "A sample API for testing"
            },
            "paths": {
                "/items": {
                    "get": {
                        "summary": "List items",
                        "responses": {
                            "200": {
                                "description": "Successful response",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    
    @pytest.mark.unit
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "service" in data
        assert data["service"] == "Sentinel Spec Service"
    
    @pytest.mark.unit
    def test_health_endpoint(self, client):
        """Test health endpoint."""
        response = client.get("/health")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
    
    @pytest.mark.unit
    def test_upload_specification_success(self, client, sample_spec):
        """Test successful specification upload."""
        response = client.post("/api/v1/specifications", json={
            "raw_spec": json.dumps(sample_spec),
            "source_filename": "sample.yaml"
        })
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == 1
        assert data["parsed_spec"]["info"]["title"] == "Sample API"
        assert data["source_filename"] == "sample.yaml"
        assert data["llm_readiness_score"] > 0
    
    @pytest.mark.unit
    def test_upload_invalid_specification(self, client):
        """Test uploading invalid specification."""
        response = client.post("/api/v1/specifications", json={
            "raw_spec": "not a valid spec"
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Not a valid OpenAPI" in response.json()["detail"]
    
    @pytest.mark.unit
    def test_upload_non_openapi_spec(self, client):
        """Test uploading non-OpenAPI JSON."""
        response = client.post("/api/v1/specifications", json={
            "raw_spec": '{"some": "json", "without": "openapi"}'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Not a valid OpenAPI" in response.json()["detail"]
    
    @pytest.mark.unit
    def test_list_specifications(self, client, sample_spec):
        """Test listing specifications."""
        # Upload multiple specs
        for i in range(3):
            client.post("/api/v1/specifications", json={
                "raw_spec": json.dumps(sample_spec),
                "source_filename": f"spec_{i}.yaml"
            })
        
        response = client.get("/api/v1/specifications")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 3
        assert all("id" in spec for spec in data)
    
    @pytest.mark.unit
    def test_list_specifications_with_pagination(self, client, sample_spec):
        """Test listing specifications with pagination."""
        # Upload 5 specs
        for i in range(5):
            client.post("/api/v1/specifications", json={
                "raw_spec": json.dumps(sample_spec)
            })
        
        # Get first 2
        response = client.get("/api/v1/specifications?skip=0&limit=2")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 2
        
        # Get next 2
        response = client.get("/api/v1/specifications?skip=2&limit=2")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 2
    
    @pytest.mark.unit
    def test_get_specification_by_id(self, client, sample_spec):
        """Test getting specification by ID."""
        # Upload a spec
        upload_response = client.post("/api/v1/specifications", json={
            "raw_spec": json.dumps(sample_spec),
            "source_filename": "test.yaml"
        })
        spec_id = upload_response.json()["id"]
        
        # Get by ID
        response = client.get(f"/api/v1/specifications/{spec_id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == spec_id
        assert data["source_filename"] == "test.yaml"
    
    @pytest.mark.unit
    def test_get_nonexistent_specification(self, client):
        """Test getting non-existent specification."""
        response = client.get("/api/v1/specifications/999")
        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()
    
    @pytest.mark.unit
    def test_update_specification(self, client, sample_spec):
        """Test updating a specification."""
        # Upload initial spec
        upload_response = client.post("/api/v1/specifications", json={
            "raw_spec": json.dumps(sample_spec),
            "source_filename": "v1.yaml"
        })
        spec_id = upload_response.json()["id"]
        
        # Update spec
        updated_spec = sample_spec.copy()
        updated_spec["info"]["version"] = "2.0.0"
        
        response = client.put(f"/api/v1/specifications/{spec_id}", json={
            "raw_spec": json.dumps(updated_spec),
            "source_filename": "v2.yaml"
        })
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["version"] == "2.0.0"
        assert data["source_filename"] == "v2.yaml"
        assert data["updated_at"] != data["created_at"]
    
    @pytest.mark.unit
    def test_delete_specification(self, client, sample_spec):
        """Test deleting a specification."""
        # Upload a spec
        upload_response = client.post("/api/v1/specifications", json={
            "raw_spec": json.dumps(sample_spec)
        })
        spec_id = upload_response.json()["id"]
        
        # Delete it
        response = client.delete(f"/api/v1/specifications/{spec_id}")
        assert response.status_code == status.HTTP_200_OK
        assert "deleted successfully" in response.json()["message"]
        
        # Verify it's gone
        response = client.get(f"/api/v1/specifications/{spec_id}")
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.unit
    def test_validate_specification(self, client, sample_spec):
        """Test specification validation."""
        # Upload a spec
        upload_response = client.post("/api/v1/specifications", json={
            "raw_spec": json.dumps(sample_spec)
        })
        spec_id = upload_response.json()["id"]
        
        # Validate it
        response = client.post(f"/api/v1/specifications/{spec_id}/validate")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is True
        assert len(data["errors"]) == 0
    
    @pytest.mark.unit
    def test_validate_incomplete_specification(self, client):
        """Test validation of incomplete specification."""
        # First upload a minimal valid spec (with openapi field)
        minimal_spec = {"openapi": "3.0.0"}  # Missing info but has openapi field
        
        upload_response = client.post("/api/v1/specifications", json={
            "raw_spec": json.dumps(minimal_spec)
        })
        
        # Check if upload was successful
        assert upload_response.status_code == status.HTTP_200_OK
        spec_id = upload_response.json()["id"]
        
        # Validate it
        response = client.post(f"/api/v1/specifications/{spec_id}/validate")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is False  # Should be invalid due to missing info
        assert len(data["errors"]) > 0
        assert any("Missing 'info'" in error for error in data["errors"])
    
    @pytest.mark.unit
    def test_specification_with_project_id(self, client, sample_spec):
        """Test specification with project ID."""
        # Upload specs for different projects
        for project_id in [1, 1, 2]:
            client.post("/api/v1/specifications", json={
                "raw_spec": json.dumps(sample_spec),
                "project_id": project_id
            })
        
        # List specs for project 1
        response = client.get("/api/v1/specifications?project_id=1")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 2
        
        # List specs for project 2
        response = client.get("/api/v1/specifications?project_id=2")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1


class TestSpecServiceWithTestData:
    """Test with predefined test data."""
    
    @pytest.fixture
    def test_specifications(self):
        """Predefined test specifications."""
        return {
            1: {
                "id": 1,
                "raw_spec": {"openapi": "3.0.0", "info": {"title": "API 1"}},
                "parsed_spec": {"openapi": "3.0.0", "info": {"title": "API 1"}},
                "version": "1.0.0",
                "created_at": "2024-01-01T00:00:00",
                "updated_at": "2024-01-01T00:00:00",
                "llm_readiness_score": 0.5
            },
            2: {
                "id": 2,
                "raw_spec": {"openapi": "3.0.0", "info": {"title": "API 2"}},
                "parsed_spec": {"openapi": "3.0.0", "info": {"title": "API 2"}},
                "version": "2.0.0",
                "created_at": "2024-01-02T00:00:00",
                "updated_at": "2024-01-02T00:00:00",
                "llm_readiness_score": 0.7
            }
        }
    
    @pytest.fixture
    def app_with_data(self, test_specifications):
        """Create app with test data."""
        return create_test_spec_app(test_specifications)
    
    @pytest.fixture
    def client(self, app_with_data):
        """Create test client."""
        return TestClient(app_with_data)
    
    @pytest.mark.unit
    def test_list_predefined_specifications(self, client):
        """Test listing predefined specifications."""
        response = client.get("/api/v1/specifications")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 2
        assert data[0]["parsed_spec"]["info"]["title"] == "API 1"
        assert data[1]["parsed_spec"]["info"]["title"] == "API 2"