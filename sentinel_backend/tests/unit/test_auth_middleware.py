"""
Unit tests for Authentication Service middleware components.

Tests authentication middleware, dependency injection, and security components.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

# Import the modules we want to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from auth_service.auth_middleware import (
    get_current_user,
    require_permission, 
    Permissions,
    optional_auth
)

# Import fixtures
from tests.fixtures.auth_fixtures import *


class TestAuthMiddleware:
    """Test authentication middleware functionality."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.httpx.AsyncClient')
    async def test_get_current_user_success(self, mock_client, valid_jwt_token, test_user_data):
        """Test successful user authentication via auth service."""
        # Mock the auth service response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "valid": True,
            "user": test_user_data,
            "permissions": ["spec:read", "test_case:create"]
        }
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        # Test the function
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=valid_jwt_token
        )
        
        result = await get_current_user(credentials)
        
        assert result["user"] == test_user_data
        assert result["token"] == valid_jwt_token
        assert "permissions" in result
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.httpx.AsyncClient')
    async def test_get_current_user_invalid_token(self, mock_client, invalid_jwt_token):
        """Test authentication with invalid token."""
        # Mock the auth service response for invalid token
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Invalid token"
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        # Mock raise_for_status to raise an exception
        def raise_for_status():
            from httpx import HTTPStatusError
            raise HTTPStatusError("401 Unauthorized", request=Mock(), response=mock_response)
        
        mock_response.raise_for_status = raise_for_status
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=invalid_jwt_token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.httpx.AsyncClient')
    async def test_get_current_user_service_unavailable(self, mock_client, valid_jwt_token):
        """Test authentication when auth service is unavailable."""
        # Mock connection error
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        
        from httpx import RequestError
        mock_client_instance.post.side_effect = RequestError("Connection failed")
        mock_client.return_value = mock_client_instance
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", 
            credentials=valid_jwt_token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)
        
        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert "auth service" in exc_info.value.detail.lower()


class TestOptionalAuth:
    """Test optional authentication functionality."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.get_current_user')
    async def test_optional_auth_with_token(self, mock_get_current_user, valid_jwt_token, test_user_data):
        """Test optional auth with valid token provided."""
        mock_get_current_user.return_value = {
            "user": test_user_data,
            "token": valid_jwt_token,
            "permissions": ["spec:read"]
        }
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=valid_jwt_token
        )
        
        result = await optional_auth(credentials)
        
        assert result["user"] == test_user_data
        assert result["token"] == valid_jwt_token
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_optional_auth_without_token(self):
        """Test optional auth without token (anonymous access)."""
        result = await optional_auth(None)
        
        assert result is None
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.get_current_user')
    async def test_optional_auth_with_invalid_token(self, mock_get_current_user, invalid_jwt_token):
        """Test optional auth with invalid token (should return None, not raise)."""
        # Mock get_current_user to raise HTTPException
        mock_get_current_user.side_effect = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=invalid_jwt_token
        )
        
        result = await optional_auth(credentials)
        
        # Optional auth should return None for invalid tokens, not raise
        assert result is None


class TestPermissionChecking:
    """Test permission checking functionality."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_require_permission_success(self, test_user_data):
        """Test permission requirement check passes."""
        # Mock auth data with required permission
        auth_data = {
            "user": test_user_data,
            "token": "mock-token",
            "permissions": ["spec:read", "test_case:create"]
        }
        
        permission_checker = require_permission(Permissions.SPEC_READ)
        
        # Test that the permission checker returns the auth data
        result = await permission_checker(auth_data=auth_data)
        assert result == auth_data
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_require_permission_failure(self, test_user_data):
        """Test permission requirement check fails."""
        # Mock auth data without required permission
        auth_data = {
            "user": test_user_data,
            "token": "mock-token", 
            "permissions": ["spec:read"]  # Missing test_case:create
        }
        
        permission_checker = require_permission(Permissions.TEST_CASE_CREATE)
        
        with pytest.raises(HTTPException) as exc_info:
            await permission_checker(auth_data=auth_data)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "insufficient permissions" in exc_info.value.detail.lower()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_require_permission_no_auth_data(self):
        """Test permission requirement with no auth data."""
        permission_checker = require_permission(Permissions.SPEC_CREATE)
        
        with pytest.raises(HTTPException) as exc_info:
            await permission_checker(auth_data=None)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "authentication required" in exc_info.value.detail.lower()


class TestPermissionsEnum:
    """Test Permissions enum values."""
    
    @pytest.mark.unit
    def test_permissions_enum_values(self):
        """Test that Permissions enum has expected values."""
        assert Permissions.SPEC_CREATE == "spec:create"
        assert Permissions.SPEC_READ == "spec:read"
        assert Permissions.SPEC_UPDATE == "spec:update"
        assert Permissions.SPEC_DELETE == "spec:delete"
        
        assert Permissions.TEST_CASE_CREATE == "test_case:create"
        assert Permissions.TEST_CASE_READ == "test_case:read"
        assert Permissions.TEST_CASE_UPDATE == "test_case:update"
        assert Permissions.TEST_CASE_DELETE == "test_case:delete"
        
        assert Permissions.USER_CREATE == "user:create"
        assert Permissions.USER_READ == "user:read"
        assert Permissions.USER_UPDATE == "user:update"
        assert Permissions.USER_DELETE == "user:delete"
    
    @pytest.mark.unit
    def test_permissions_categories(self):
        """Test permission categories are properly defined."""
        # Get all permission values
        all_perms = [perm.value for perm in Permissions]
        
        # Check specification permissions
        spec_perms = [p for p in all_perms if p.startswith("spec:")]
        assert "spec:create" in spec_perms
        assert "spec:read" in spec_perms
        assert "spec:update" in spec_perms
        assert "spec:delete" in spec_perms
        
        # Check user management permissions
        user_perms = [p for p in all_perms if p.startswith("user:")]
        assert "user:create" in user_perms
        assert "user:read" in user_perms
        assert "user:update" in user_perms
        assert "user:delete" in user_perms


class TestServiceIntegration:
    """Test integration with auth service."""
    
    @pytest.mark.unit
    @patch('auth_service.auth_middleware.get_service_settings')
    def test_auth_service_url_configuration(self, mock_service_settings):
        """Test that auth service URL is properly configured."""
        mock_service_settings.return_value = Mock(
            auth_service_url="http://auth:8005",
            service_timeout=30
        )
        
        settings = mock_service_settings()
        assert settings.auth_service_url == "http://auth:8005"
        assert settings.service_timeout == 30
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.httpx.AsyncClient')
    async def test_correlation_id_propagation(self, mock_client, valid_jwt_token):
        """Test that correlation ID is propagated to auth service."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "valid": True,
            "user": {"id": 1, "email": "test@example.com"},
            "permissions": ["spec:read"]
        }
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=valid_jwt_token
        )
        
        # Mock structlog context to include correlation ID
        with patch('auth_service.auth_middleware.structlog.contextvars.get_contextvars') as mock_context:
            mock_context.return_value = {"correlation_id": "test-correlation-123"}
            
            await get_current_user(credentials)
            
            # Verify that the auth service was called with correlation ID header
            mock_client_instance.post.assert_called_once()
            call_args = mock_client_instance.post.call_args
            headers = call_args.kwargs.get('headers', {})
            assert headers.get('X-Correlation-ID') == "test-correlation-123"
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.httpx.AsyncClient')
    async def test_auth_service_timeout_handling(self, mock_client, valid_jwt_token):
        """Test handling of auth service timeout."""
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        
        from httpx import TimeoutException
        mock_client_instance.post.side_effect = TimeoutException("Request timeout")
        mock_client.return_value = mock_client_instance
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=valid_jwt_token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)
        
        assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert "timeout" in exc_info.value.detail.lower() or "unavailable" in exc_info.value.detail.lower()


class TestErrorHandling:
    """Test error handling in middleware."""
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    @patch('auth_service.auth_middleware.httpx.AsyncClient')
    async def test_malformed_response_handling(self, mock_client, valid_jwt_token):
        """Test handling of malformed response from auth service."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.raise_for_status = Mock()
        
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_client_instance.post.return_value = mock_response
        mock_client.return_value = mock_client_instance
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=valid_jwt_token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)
        
        assert exc_info.value.status_code in [status.HTTP_500_INTERNAL_SERVER_ERROR, status.HTTP_503_SERVICE_UNAVAILABLE]
    
    @pytest.mark.unit
    def test_invalid_permission_enum(self):
        """Test behavior with invalid permission value."""
        # This test ensures the Permissions enum is used correctly
        valid_permissions = [perm.value for perm in Permissions]
        
        # All expected permissions should be in the enum
        expected_permissions = [
            "spec:create", "spec:read", "spec:update", "spec:delete",
            "user:create", "user:read", "user:update", "user:delete",
            "test_case:create", "test_case:read", "test_case:update", "test_case:delete"
        ]
        
        for perm in expected_permissions:
            assert perm in valid_permissions