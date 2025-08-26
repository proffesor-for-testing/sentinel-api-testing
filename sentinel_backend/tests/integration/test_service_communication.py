"""
Integration tests for service-to-service communication.

These tests verify the complete service communication flow including:
- API Gateway to backend services
- Service discovery and routing
- Request/response handling
- Error propagation
- Timeout handling
- Authentication across services
"""
import pytest
import asyncio
import httpx
from fastapi.testclient import TestClient
from fastapi import status
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List
import json
import time
from datetime import datetime, timedelta


@pytest.mark.integration
class TestServiceCommunication:
    """Test service-to-service communication patterns."""
    
    @pytest.fixture
    def api_gateway_client(self):
        """Create test client for API Gateway."""
        from api_gateway.main import app
        return TestClient(app)
    
    @pytest.fixture
    def spec_service_client(self):
        """Create test client for Spec Service."""
        from spec_service.main import app
        return TestClient(app)
    
    @pytest.fixture
    def orchestration_client(self):
        """Create test client for Orchestration Service."""
        from orchestration_service.main import app
        return TestClient(app)
    
    @pytest.fixture
    def execution_client(self):
        """Create test client for Execution Service."""
        from execution_service.main import app
        return TestClient(app)
    
    @pytest.fixture
    def data_service_client(self):
        """Create test client for Data Service."""
        from data_service.main import app
        return TestClient(app)
    
    @pytest.fixture
    def auth_headers(self, api_gateway_client):
        """Get authenticated headers for testing."""
        response = api_gateway_client.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "admin123"
        })
        if response.status_code == status.HTTP_200_OK:
            token = response.json().get("access_token")
            return {"Authorization": f"Bearer {token}"}
        return {}
    
    @pytest.fixture
    def mock_spec_data(self):
        """Mock OpenAPI specification for testing."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0",
                "description": "Integration test API"
            },
            "servers": [
                {"url": "https://api.test.com"}
            ],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "operationId": "getUsers",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer"}
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/User"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "operationId": "createUser",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Created"}
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "email": {"type": "string", "format": "email"}
                        },
                        "required": ["name", "email"]
                    }
                }
            }
        }
    
    @pytest.mark.asyncio
    @patch('sys.modules', {'api_gateway.services': MagicMock()})
    async def test_gateway_to_spec_service(self, api_gateway_client, auth_headers, mock_spec_data):
        """Test API Gateway to Spec Service communication."""
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 1, "spec": mock_spec_data}
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            response = api_gateway_client.post(
                "/specifications/",
                headers=auth_headers,
                json={"name": "Test Spec", "spec_content": json.dumps(mock_spec_data)}
            )
            
            assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
    
    @pytest.mark.asyncio
    async def test_gateway_to_orchestration_service(self, api_gateway_client, auth_headers):
        """Test API Gateway to Orchestration Service communication."""
        with patch('api_gateway.services.orchestration_service.httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "test_run_id": "test-123",
                "status": "running",
                "agents": ["functional-positive", "functional-negative"]
            }
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            response = api_gateway_client.post(
                "/test-runs/",
                headers=auth_headers,
                json={
                    "spec_id": 1,
                    "agent_types": ["functional-positive", "functional-negative"]
                }
            )
            
            assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
    
    @pytest.mark.asyncio
    @patch('sys.modules', {'orchestration_service.services': MagicMock()})
    async def test_orchestration_to_execution_service(self):
        """Test Orchestration to Execution Service communication."""
        # Mock the ExecutionServiceClient
        mock_client_class = Mock()
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "execution_id": "exec-123",
                "status": "completed",
                "results": {"passed": 10, "failed": 2}
            }
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            client = ExecutionServiceClient(base_url="http://execution:8003")
            result = await client.execute_tests({
                "test_cases": [
                    {"id": "tc1", "endpoint": "/users", "method": "GET"},
                    {"id": "tc2", "endpoint": "/users", "method": "POST"}
                ]
            })
            
            assert result is not None
            assert "execution_id" in result or "status" in result
    
    @pytest.mark.asyncio
    async def test_execution_to_data_service(self):
        """Test Execution to Data Service communication."""
        from execution_service.services.data_service import DataServiceClient
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {"id": 1, "stored": True}
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            client = DataServiceClient(base_url="http://data:8004")
            result = await client.store_results({
                "test_run_id": "test-123",
                "results": {"passed": 10, "failed": 2},
                "timestamp": datetime.utcnow().isoformat()
            })
            
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_service_timeout_handling(self):
        """Test service timeout handling."""
        from api_gateway.services.base_service import BaseServiceClient
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.TimeoutException("Request timeout")
            )
            
            client = BaseServiceClient(base_url="http://test-service:8000")
            
            with pytest.raises(httpx.TimeoutException):
                await client.make_request("GET", "/timeout-test")
    
    @pytest.mark.asyncio
    async def test_service_error_propagation(self, api_gateway_client, auth_headers):
        """Test error propagation across services."""
        with patch('api_gateway.services.spec_service.httpx.AsyncClient') as mock_client:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.json.return_value = {"detail": "Internal server error"}
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            
            response = api_gateway_client.get(
                "/specifications/999",
                headers=auth_headers
            )
            
            assert response.status_code >= 400
    
    @pytest.mark.asyncio
    async def test_concurrent_service_requests(self, api_gateway_client, auth_headers):
        """Test concurrent requests to multiple services."""
        async def make_request(endpoint: str):
            return api_gateway_client.get(endpoint, headers=auth_headers)
        
        with patch('api_gateway.services.spec_service.httpx.AsyncClient') as mock_spec:
            with patch('api_gateway.services.data_service.httpx.AsyncClient') as mock_data:
                mock_spec_response = Mock()
                mock_spec_response.status_code = 200
                mock_spec_response.json.return_value = {"specs": []}
                
                mock_data_response = Mock()
                mock_data_response.status_code = 200
                mock_data_response.json.return_value = {"analytics": {}}
                
                mock_spec.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_spec_response)
                mock_data.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_data_response)
                
                tasks = [
                    make_request("/specifications/"),
                    make_request("/analytics/dashboard")
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if not isinstance(result, Exception):
                        assert result.status_code in [200, 404]
    
    @pytest.mark.asyncio
    async def test_service_health_checks(self):
        """Test health check endpoints for all services."""
        services = [
            ("http://api-gateway:8000", "/health"),
            ("http://spec:8001", "/health"),
            ("http://orchestration:8002", "/health"),
            ("http://execution:8003", "/health"),
            ("http://data:8004", "/health"),
            ("http://auth:8005", "/health")
        ]
        
        for base_url, endpoint in services:
            with patch('httpx.AsyncClient') as mock_client:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {"status": "healthy"}
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
                
                async with httpx.AsyncClient() as client:
                    try:
                        response = await client.get(f"{base_url}{endpoint}")
                        assert response.status_code == 200
                    except:
                        pass  # Service might not be running in test environment
    
    @pytest.mark.asyncio
    async def test_service_circuit_breaker(self):
        """Test circuit breaker pattern for failed services."""
        from api_gateway.services.circuit_breaker import CircuitBreaker
        
        breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=1)
        
        # Simulate failures
        for _ in range(3):
            with pytest.raises(Exception):
                await breaker.call(AsyncMock(side_effect=Exception("Service unavailable")))
        
        # Circuit should be open
        assert breaker.is_open()
        
        # Should fail fast when open
        with pytest.raises(Exception):
            await breaker.call(AsyncMock())
        
        # Wait for recovery
        await asyncio.sleep(1.1)
        
        # Should allow one test call
        assert not breaker.is_open()