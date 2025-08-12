"""
Unit tests using the testable auth app factory.

This demonstrates how to properly test FastAPI applications
using the factory pattern for better testability.
"""
import pytest
from fastapi.testclient import TestClient
from fastapi import status
import bcrypt

from sentinel_backend.auth_service.app_factory import create_auth_app, create_test_app_with_users, AuthConfig


class TestAuthWithFactory:
    """Test authentication using app factory pattern."""
    
    @pytest.fixture
    def test_users(self):
        """Create test users with hashed passwords."""
        users = {}
        
        # Admin user
        admin_password = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
        users["admin@test.com"] = {
            "id": 1,
            "email": "admin@test.com",
            "full_name": "Admin User",
            "role": "admin",
            "is_active": True,
            "hashed_password": admin_password.decode('utf-8')
        }
        
        # Regular user
        user_password = bcrypt.hashpw(b"user123", bcrypt.gensalt())
        users["user@test.com"] = {
            "id": 2,
            "email": "user@test.com",
            "full_name": "Regular User",
            "role": "tester",
            "is_active": True,
            "hashed_password": user_password.decode('utf-8')
        }
        
        # Inactive user
        inactive_password = bcrypt.hashpw(b"inactive123", bcrypt.gensalt())
        users["inactive@test.com"] = {
            "id": 3,
            "email": "inactive@test.com",
            "full_name": "Inactive User",
            "role": "viewer",
            "is_active": False,
            "hashed_password": inactive_password.decode('utf-8')
        }
        
        return users
    
    @pytest.fixture
    def app_with_users(self, test_users):
        """Create app with test users."""
        return create_test_app_with_users(test_users)
    
    @pytest.fixture
    def client(self, app_with_users):
        """Create test client."""
        return TestClient(app_with_users)
    
    @pytest.mark.unit
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data
        assert "version" in data
    
    @pytest.mark.unit
    def test_login_success(self, client):
        """Test successful login."""
        response = client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "admin123"
        })
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "admin@test.com"
        assert "hashed_password" not in data["user"]
    
    @pytest.mark.unit
    def test_login_invalid_email(self, client):
        """Test login with invalid email."""
        response = client.post("/auth/login", json={
            "email": "nonexistent@test.com",
            "password": "password"
        })
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid credentials" in response.json()["detail"]
    
    @pytest.mark.unit
    def test_login_invalid_password(self, client):
        """Test login with invalid password."""
        response = client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "wrongpassword"
        })
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid credentials" in response.json()["detail"]
    
    @pytest.mark.unit
    def test_login_inactive_user(self, client):
        """Test login with inactive user."""
        response = client.post("/auth/login", json={
            "email": "inactive@test.com",
            "password": "inactive123"
        })
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "disabled" in response.json()["detail"].lower()
    
    @pytest.mark.unit
    def test_get_profile_authenticated(self, client):
        """Test getting profile with valid token."""
        # First login
        login_response = client.post("/auth/login", json={
            "email": "user@test.com",
            "password": "user123"
        })
        token = login_response.json()["access_token"]
        
        # Get profile
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("/auth/profile", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "user@test.com"
        assert data["full_name"] == "Regular User"
        assert "hashed_password" not in data
    
    @pytest.mark.unit
    def test_get_profile_unauthenticated(self, client):
        """Test getting profile without token."""
        response = client.get("/auth/profile")
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.unit
    def test_register_user_as_admin(self, client):
        """Test user registration by admin."""
        # Login as admin
        login_response = client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "admin123"
        })
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Register new user
        response = client.post("/auth/register", json={
            "email": "newuser@test.com",
            "full_name": "New User",
            "password": "newpass123",
            "role": "tester"
        }, headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == "newuser@test.com"
        assert data["role"] == "tester"
        assert "hashed_password" not in data
        
        # Verify new user can login
        login_response = client.post("/auth/login", json={
            "email": "newuser@test.com",
            "password": "newpass123"
        })
        assert login_response.status_code == status.HTTP_200_OK
    
    @pytest.mark.unit
    def test_register_user_as_non_admin(self, client):
        """Test that non-admin cannot register users."""
        # Login as regular user
        login_response = client.post("/auth/login", json={
            "email": "user@test.com",
            "password": "user123"
        })
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Try to register new user
        response = client.post("/auth/register", json={
            "email": "newuser@test.com",
            "full_name": "New User",
            "password": "newpass123",
            "role": "tester"
        }, headers=headers)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Permission denied" in response.json()["detail"]
    
    @pytest.mark.unit
    def test_list_users_as_admin(self, client):
        """Test listing users as admin."""
        # Login as admin
        login_response = client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "admin123"
        })
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # List users
        response = client.get("/auth/users", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 3  # At least our test users
        
        # Check no passwords are exposed
        for user in data:
            assert "hashed_password" not in user
    
    @pytest.mark.unit
    def test_list_users_as_viewer(self, client):
        """Test that viewer cannot list users."""
        # Create a viewer user first
        admin_login = client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "admin123"
        })
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        client.post("/auth/register", json={
            "email": "viewer@test.com",
            "full_name": "Viewer User",
            "password": "viewer123",
            "role": "viewer"
        }, headers=admin_headers)
        
        # Login as viewer
        viewer_login = client.post("/auth/login", json={
            "email": "viewer@test.com",
            "password": "viewer123"
        })
        viewer_token = viewer_login.json()["access_token"]
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
        
        # Try to list users
        response = client.get("/auth/users", headers=viewer_headers)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Permission denied" in response.json()["detail"]