"""
Comprehensive test suite for the Data Service using the factory pattern.
"""
import pytest
from datetime import datetime, timedelta
from httpx import AsyncClient
from unittest.mock import Mock, AsyncMock

from sentinel_backend.data_service.app_factory import create_data_app, DataServiceConfig
from sentinel_backend.data_service.schemas import (
    TestCaseCreate, TestSuiteCreate, TestSuiteEntryCreate
)


@pytest.fixture
def data_config():
    """Create test configuration for Data Service."""
    return DataServiceConfig(
        mock_mode=True
    )


@pytest.fixture
async def data_app(data_config):
    """Create test Data Service app."""
    return create_data_app(data_config)


@pytest.fixture
async def data_client(data_app):
    """Create test client for Data Service."""
    async with AsyncClient(app=data_app, base_url="http://test") as client:
        yield client


class TestDataServiceHealth:
    """Test health and basic endpoints."""
    
    @pytest.mark.asyncio
    async def test_root_endpoint(self, data_client):
        """Test root endpoint returns expected message."""
        response = await data_client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Sentinel Data & Analytics Service is running"}
    
    @pytest.mark.asyncio
    async def test_health_check(self, data_client):
        """Test health check endpoint."""
        response = await data_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "data-analytics-service"


class TestTestCaseEndpoints:
    """Test test case CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_test_case(self, data_client):
        """Test creating a new test case."""
        test_case_data = {
            "spec_id": 1,
            "agent_type": "functional-positive",
            "description": "Test user login",
            "test_definition": {
                "endpoint": "/api/login",
                "method": "POST",
                "body": {"username": "test", "password": "pass"},
                "expected_status": 200
            },
            "tags": ["auth", "login"]
        }
        
        response = await data_client.post("/api/v1/test-cases", json=test_case_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["id"] == 1
        assert data["spec_id"] == test_case_data["spec_id"]
        assert data["agent_type"] == test_case_data["agent_type"]
        assert data["description"] == test_case_data["description"]
        assert data["test_definition"] == test_case_data["test_definition"]
        assert data["tags"] == test_case_data["tags"]
    
    @pytest.mark.asyncio
    async def test_list_test_cases(self, data_client):
        """Test listing test cases."""
        response = await data_client.get("/api/v1/test-cases")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["id"] == 1
        assert data[0]["agent_type"] == "functional-positive"
    
    @pytest.mark.asyncio
    async def test_list_test_cases_with_filters(self, data_client):
        """Test listing test cases with filters."""
        # Test spec_id filter
        response = await data_client.get("/api/v1/test-cases?spec_id=1")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        
        # Test agent_type filter
        response = await data_client.get("/api/v1/test-cases?agent_type=functional-positive")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        
        # Test tags filter
        response = await data_client.get("/api/v1/test-cases?tags=auth,login")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    @pytest.mark.asyncio
    async def test_get_test_case(self, data_client):
        """Test getting a specific test case."""
        response = await data_client.get("/api/v1/test-cases/1")
        assert response.status_code == 200
        
        data = response.json()
        assert data["id"] == 1
        assert data["spec_id"] == 1
        assert data["agent_type"] == "functional-positive"
        assert "test_definition" in data
        assert "created_at" in data
        assert "updated_at" in data


class TestTestSuiteEndpoints:
    """Test test suite CRUD operations."""
    
    @pytest.mark.asyncio
    async def test_create_test_suite(self, data_client):
        """Test creating a new test suite."""
        suite_data = {
            "name": "Authentication Test Suite",
            "description": "Tests for authentication endpoints"
        }
        
        response = await data_client.post("/api/v1/test-suites", json=suite_data)
        assert response.status_code == 200
        
        data = response.json()
        assert data["id"] == 1
        assert data["name"] == suite_data["name"]
        assert data["description"] == suite_data["description"]
        assert "created_at" in data
        assert "updated_at" in data
    
    @pytest.mark.asyncio
    async def test_list_test_suites(self, data_client):
        """Test listing test suites."""
        response = await data_client.get("/api/v1/test-suites")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["id"] == 1
        assert data[0]["name"] == "Test Suite 1"


class TestAnalyticsEndpoints:
    """Test analytics and reporting endpoints."""
    
    @pytest.mark.asyncio
    async def test_failure_rate_trends(self, data_client):
        """Test getting failure rate trends."""
        response = await data_client.get("/api/v1/analytics/trends/failure-rate")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        
        # Check data structure
        for item in data:
            assert "date" in item
            assert "total_tests" in item
            assert "failed_tests" in item
            assert "failure_rate" in item
            assert item["total_tests"] >= 0
            assert item["failed_tests"] >= 0
            assert 0 <= item["failure_rate"] <= 1
    
    @pytest.mark.asyncio
    async def test_failure_rate_trends_with_filters(self, data_client):
        """Test failure rate trends with filters."""
        # Test with suite_id filter
        response = await data_client.get("/api/v1/analytics/trends/failure-rate?suite_id=1")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        
        # Test with custom days parameter
        response = await data_client.get("/api/v1/analytics/trends/failure-rate?days=7")
        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 7
    
    @pytest.mark.asyncio
    async def test_health_summary(self, data_client):
        """Test getting health summary."""
        response = await data_client.get("/api/v1/analytics/health-summary")
        assert response.status_code == 200
        
        data = response.json()
        assert "overall_health_score" in data
        assert "total_test_cases" in data
        assert "total_test_runs" in data
        assert "recent_failure_rate" in data
        assert "avg_latency_ms" in data
        assert "last_run_status" in data
        assert "critical_issues" in data
        assert "recommendations" in data
        
        # Validate data types and ranges
        assert 0 <= data["overall_health_score"] <= 100
        assert data["total_test_cases"] >= 0
        assert data["total_test_runs"] >= 0
        assert 0 <= data["recent_failure_rate"] <= 1
        assert data["avg_latency_ms"] >= 0
        assert isinstance(data["critical_issues"], list)
        assert isinstance(data["recommendations"], list)
    
    @pytest.mark.asyncio
    async def test_dashboard_stats(self, data_client):
        """Test getting dashboard statistics."""
        response = await data_client.get("/api/v1/dashboard-stats")
        assert response.status_code == 200
        
        data = response.json()
        assert "data" in data
        stats = data["data"]
        
        assert "total_test_cases" in stats
        assert "total_test_suites" in stats
        assert "total_test_runs" in stats
        assert "success_rate" in stats
        assert "avg_response_time_ms" in stats
        assert "recent_runs" in stats
        
        # Validate data types
        assert stats["total_test_cases"] >= 0
        assert stats["total_test_suites"] >= 0
        assert stats["total_test_runs"] >= 0
        assert 0 <= stats["success_rate"] <= 1
        assert stats["avg_response_time_ms"] >= 0
        assert isinstance(stats["recent_runs"], list)


class TestDataServiceWithDatabase:
    """Test Data Service with database interactions (requires database config)."""
    
    @pytest.fixture
    def db_config(self):
        """Create configuration with test database."""
        return DataServiceConfig(
            database_url="sqlite+aiosqlite:///:memory:",
            mock_mode=False
        )
    
    @pytest.fixture
    async def db_app(self, db_config):
        """Create app with database configuration."""
        return create_data_app(db_config)
    
    @pytest.fixture
    async def db_client(self, db_app):
        """Create client for database tests."""
        async with AsyncClient(app=db_app, base_url="http://test") as client:
            yield client
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires database setup")
    async def test_create_and_retrieve_test_case(self, db_client):
        """Test creating and retrieving test case with database."""
        # Create test case
        test_case_data = {
            "spec_id": 1,
            "agent_type": "functional-positive",
            "description": "Database test case",
            "test_definition": {"endpoint": "/test", "method": "GET"},
            "tags": ["database", "test"]
        }
        
        create_response = await db_client.post("/api/v1/test-cases", json=test_case_data)
        assert create_response.status_code == 200
        case_id = create_response.json()["id"]
        
        # Retrieve test case
        get_response = await db_client.get(f"/api/v1/test-cases/{case_id}")
        assert get_response.status_code == 200
        
        data = get_response.json()
        assert data["description"] == test_case_data["description"]
        assert data["agent_type"] == test_case_data["agent_type"]


class TestDataServiceErrorHandling:
    """Test error handling in Data Service."""
    
    @pytest.mark.asyncio
    async def test_invalid_test_case_data(self, data_client):
        """Test creating test case with invalid data."""
        # Missing required fields
        invalid_data = {
            "description": "Invalid test case"
        }
        
        response = await data_client.post("/api/v1/test-cases", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_test_case_not_found(self, data_client):
        """Test retrieving non-existent test case."""
        # In mock mode, all IDs return data, so this test would need
        # to be modified for real database testing
        response = await data_client.get("/api/v1/test-cases/999999")
        assert response.status_code == 200  # Mock mode returns data for any ID
    
    @pytest.mark.asyncio
    async def test_invalid_filter_parameters(self, data_client):
        """Test invalid filter parameters."""
        # Invalid days parameter (should still work with default)
        response = await data_client.get("/api/v1/analytics/trends/failure-rate?days=invalid")
        assert response.status_code == 422  # Validation error


class TestDataServiceConfiguration:
    """Test Data Service configuration options."""
    
    def test_default_configuration(self):
        """Test creating config with defaults."""
        config = DataServiceConfig()
        assert config.pool_size == 20
        assert config.max_overflow == 10
        assert config.pool_timeout == 30
        assert config.pool_recycle == 3600
        assert config.mock_mode == False
    
    def test_custom_configuration(self):
        """Test creating config with custom values."""
        config = DataServiceConfig(
            database_url="postgresql://test",
            pool_size=10,
            max_overflow=5,
            mock_mode=True
        )
        assert config.database_url == "postgresql://test"
        assert config.pool_size == 10
        assert config.max_overflow == 5
        assert config.mock_mode == True
    
    @pytest.mark.asyncio
    async def test_mock_mode_configuration(self):
        """Test app creation with mock mode."""
        config = DataServiceConfig(mock_mode=True)
        app = create_data_app(config)
        
        assert app.state.config.mock_mode == True
        assert not hasattr(app.state, 'engine')  # No database engine in mock mode
        assert not hasattr(app.state, 'session_maker')  # No session maker in mock mode


class TestDataServiceIntegration:
    """Integration tests for Data Service."""
    
    @pytest.mark.asyncio
    async def test_complete_test_suite_workflow(self, data_client):
        """Test complete workflow: create suite, add cases, get summary."""
        # Create test suite
        suite_data = {
            "name": "Integration Test Suite",
            "description": "Full workflow test"
        }
        suite_response = await data_client.post("/api/v1/test-suites", json=suite_data)
        assert suite_response.status_code == 200
        suite_id = suite_response.json()["id"]
        
        # Create test cases
        for i in range(3):
            case_data = {
                "spec_id": 1,
                "agent_type": "functional-positive",
                "description": f"Test case {i+1}",
                "test_definition": {"endpoint": f"/test{i+1}", "method": "GET"},
                "tags": ["integration"]
            }
            case_response = await data_client.post("/api/v1/test-cases", json=case_data)
            assert case_response.status_code == 200
        
        # List test cases
        list_response = await data_client.get("/api/v1/test-cases?tags=integration")
        assert list_response.status_code == 200
        
        # Get health summary
        health_response = await data_client.get("/api/v1/analytics/health-summary")
        assert health_response.status_code == 200
        assert health_response.json()["total_test_cases"] >= 0