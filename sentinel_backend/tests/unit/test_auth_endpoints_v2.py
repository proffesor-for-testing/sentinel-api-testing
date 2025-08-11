"""
Improved unit tests for Authentication Service API endpoints.

This version uses proper dependency injection and mocking strategies
that work well with FastAPI's architecture.
"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from fastapi import status
import json
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Import test helpers
from tests.helpers.auth_helpers import AuthTestHelper, MockAuthService


class TestAuthEndpointsV2:
    """Improved auth endpoint tests using proper mocking."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment."""
        self.auth_helper = AuthTestHelper()
        self.mock_auth_service = MockAuthService()
        
        # Create test users
        self.admin_user = {
            "id": 1,
            "email": "admin@sentinel.com",
            "full_name": "Admin User",
            "role": "admin",
            "is_active": True
        }
        
        self.test_user = {
            "id": 2,
            "email": "test@sentinel.com",
            "full_name": "Test User",
            "role": "tester",
            "is_active": True
        }
        
    @pytest.fixture
    def client_with_mocked_auth(self):
        """Create a test client with properly mocked authentication."""
        with patch('auth_service.main.users_db', self.mock_auth_service.users):
            # Import app after patching
            from auth_service.main import app
            
            # Override dependencies
            from auth_service.main import get_current_user, require_permission
            
            # Create mock functions that use our mock service
            async def mock_get_current_user(credentials):
                token = credentials.credentials
                user = self.mock_auth_service.verify_token(token)
                if not user:
                    from fastapi import HTTPException
                    raise HTTPException(status_code=401, detail="Invalid token")
                return user
            
            def mock_require_permission(permission):
                async def permission_checker(credentials):
                    user = await mock_get_current_user(credentials)
                    # For testing, admin has all permissions
                    if user.get("role") == "admin":
                        return user
                    from fastapi import HTTPException
                    raise HTTPException(status_code=403, detail="Insufficient permissions")
                return permission_checker
            
            # Override the dependencies
            app.dependency_overrides[get_current_user] = mock_get_current_user
            
            # For permission-based endpoints, we need to override each permission dependency
            from auth_service.main import Permission
            for perm in Permission:
                app.dependency_overrides[require_permission(perm)] = mock_require_permission(perm)
            
            client = TestClient(app)
            yield client
            
            # Clean up overrides
            app.dependency_overrides.clear()
    
    @pytest.mark.unit
    def test_login_success(self, client_with_mocked_auth):
        """Test successful login."""
        response = client_with_mocked_auth.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "admin123"
        })
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "admin@sentinel.com"
    
    @pytest.mark.unit
    def test_login_invalid_credentials(self, client_with_mocked_auth):
        """Test login with invalid credentials."""
        response = client_with_mocked_auth.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "wrong_password"
        })
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid credentials" in response.json()["detail"]
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_register_user_as_admin(self, client_with_mocked_auth):
        """Test user registration by admin."""
        # Get admin token
        admin_token = self.mock_auth_service.create_access_token(self.admin_user)
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        response = client_with_mocked_auth.post(
            "/auth/register",
            json={
                "email": "newuser@sentinel.com",
                "full_name": "New User",
                "password": "password123",
                "role": "tester"
            },
            headers=headers
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "newuser@sentinel.com"
        assert data["role"] == "tester"
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_get_profile(self, client_with_mocked_auth):
        """Test getting user profile."""
        # Get user token
        user_token = self.mock_auth_service.create_access_token(self.test_user)
        headers = {"Authorization": f"Bearer {user_token}"}
        
        response = client_with_mocked_auth.get("/auth/profile", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == self.test_user["email"]
        assert data["full_name"] == self.test_user["full_name"]
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_update_profile(self, client_with_mocked_auth):
        """Test updating user profile."""
        user_token = self.mock_auth_service.create_access_token(self.test_user)
        headers = {"Authorization": f"Bearer {user_token}"}
        
        response = client_with_mocked_auth.put(
            "/auth/profile",
            json={"full_name": "Updated Name"},
            headers=headers
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["full_name"] == "Updated Name"
    
    @pytest.mark.unit
    @pytest.mark.auth
    def test_list_users_as_admin(self, client_with_mocked_auth):
        """Test listing all users as admin."""
        admin_token = self.mock_auth_service.create_access_token(self.admin_user)
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        response = client_with_mocked_auth.get("/auth/users", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3  # At least the default users
    
    @pytest.mark.unit
    def test_validate_token(self, client_with_mocked_auth):
        """Test token validation."""
        user_token = self.mock_auth_service.create_access_token(self.test_user)
        headers = {"Authorization": f"Bearer {user_token}"}
        
        response = client_with_mocked_auth.post("/auth/validate", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is True
        assert data["user"]["email"] == self.test_user["email"]
    
    @pytest.mark.unit
    def test_invalid_token(self, client_with_mocked_auth):
        """Test with invalid token."""
        headers = {"Authorization": "Bearer invalid_token"}
        
        response = client_with_mocked_auth.get("/auth/profile", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    @pytest.mark.unit
    def test_expired_token(self, client_with_mocked_auth):
        """Test with expired token."""
        expired_token = self.auth_helper.create_expired_token(self.test_user)
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        response = client_with_mocked_auth.get("/auth/profile", headers=headers)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED