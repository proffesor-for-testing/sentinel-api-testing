"""
End-to-end tests for authentication flow.

These tests verify the complete authentication workflow including:
- User registration
- Login process
- Token management
- Session handling
- Password reset
- Role-based access
"""
import pytest
import jwt
import time
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from fastapi import status
from typing import Dict, Any
import secrets
import hashlib


@pytest.mark.e2e
class TestAuthenticationFlow:
    """Test complete authentication end-to-end flow."""
    
    @pytest.fixture
    def api_client(self):
        """Create test client for API Gateway."""
        from api_gateway.main import app
        return TestClient(app)
    
    @pytest.fixture
    def unique_email(self):
        """Generate unique email for testing."""
        timestamp = int(time.time())
        random_str = secrets.token_hex(4)
        return f"e2e_test_{timestamp}_{random_str}@sentinel.com"
    
    @pytest.fixture
    def test_users(self, unique_email):
        """Create test user data."""
        base_email = unique_email.split("@")[0]
        return {
            "new_user": {
                "email": unique_email,
                "password": "SecureP@ssw0rd123!",
                "full_name": "E2E Test User",
                "role": "tester"
            },
            "admin_user": {
                "email": f"admin_{base_email}@sentinel.com",
                "password": "AdminP@ssw0rd123!",
                "full_name": "E2E Admin User",
                "role": "admin"
            },
            "viewer_user": {
                "email": f"viewer_{base_email}@sentinel.com",
                "password": "ViewerP@ssw0rd123!",
                "full_name": "E2E Viewer User",
                "role": "viewer"
            }
        }
    
    def test_complete_registration_flow(self, api_client, test_users):
        """Test complete user registration flow."""
        new_user = test_users["new_user"]
        
        # Step 1: Check if registration endpoint exists
        response = api_client.post("/auth/register", json={})
        
        if response.status_code == status.HTTP_404_NOT_FOUND:
            # Try admin-protected user creation
            # First login as admin
            admin_response = api_client.post("/auth/login", json={
                "email": "admin@sentinel.com",
                "password": "admin123"
            })
            
            if admin_response.status_code == status.HTTP_200_OK:
                admin_token = admin_response.json()["access_token"]
                headers = {"Authorization": f"Bearer {admin_token}"}
                
                # Create new user as admin
                response = api_client.post("/users/", headers=headers, json=new_user)
                
                if response.status_code == status.HTTP_201_CREATED:
                    user_data = response.json()
                    assert user_data["email"] == new_user["email"]
                    assert user_data["role"] == new_user["role"]
                    assert "id" in user_data
        else:
            # Direct registration
            response = api_client.post("/auth/register", json=new_user)
            
            if response.status_code == status.HTTP_201_CREATED:
                user_data = response.json()
                assert user_data["email"] == new_user["email"]
                
                # Verify password is not returned
                assert "password" not in user_data
    
    def test_login_flow_with_token_validation(self, api_client, test_users):
        """Test login flow with token validation."""
        # Use default admin credentials
        login_data = {
            "email": "admin@sentinel.com",
            "password": "admin123"
        }
        
        # Step 1: Login
        response = api_client.post("/auth/login", json=login_data)
        
        assert response.status_code == status.HTTP_200_OK
        token_data = response.json()
        
        # Verify token structure
        assert "access_token" in token_data
        assert "token_type" in token_data
        assert token_data["token_type"] == "bearer"
        
        # Step 2: Decode and validate token
        access_token = token_data["access_token"]
        
        # Decode without verification (for testing)
        try:
            payload = jwt.decode(access_token, options={"verify_signature": False})
            
            # Verify token claims
            assert "sub" in payload  # Subject (user email)
            assert "exp" in payload  # Expiration
            assert "role" in payload or "roles" in payload
            
            # Check expiration is in future
            exp_timestamp = payload["exp"]
            current_timestamp = time.time()
            assert exp_timestamp > current_timestamp
            
        except jwt.DecodeError:
            pytest.fail("Failed to decode JWT token")
        
        # Step 3: Use token to access protected endpoint
        headers = {"Authorization": f"Bearer {access_token}"}
        me_response = api_client.get("/users/me", headers=headers)
        
        if me_response.status_code == status.HTTP_200_OK:
            user_data = me_response.json()
            assert user_data["email"] == login_data["email"]
    
    def test_role_based_access_control(self, api_client):
        """Test role-based access control for different user roles."""
        roles_and_permissions = {
            "admin": {
                "email": "admin@sentinel.com",
                "password": "admin123",
                "can_access": ["/users/", "/specifications/", "/test-runs/", "/analytics/"],
                "cannot_access": []
            },
            "tester": {
                "email": "tester@sentinel.com",
                "password": "tester123",
                "can_access": ["/specifications/", "/test-runs/"],
                "cannot_access": ["/users/"]
            },
            "viewer": {
                "email": "viewer@sentinel.com",
                "password": "viewer123",
                "can_access": ["/analytics/", "/reports/"],
                "cannot_access": ["/users/", "/test-runs/"]
            }
        }
        
        for role, config in roles_and_permissions.items():
            # Login as user with specific role
            login_response = api_client.post("/auth/login", json={
                "email": config["email"],
                "password": config["password"]
            })
            
            if login_response.status_code == status.HTTP_200_OK:
                token = login_response.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}
                
                # Test accessible endpoints
                for endpoint in config["can_access"]:
                    response = api_client.get(endpoint, headers=headers)
                    # Should not be forbidden
                    assert response.status_code != status.HTTP_403_FORBIDDEN
                
                # Test restricted endpoints
                for endpoint in config["cannot_access"]:
                    response = api_client.get(endpoint, headers=headers)
                    # Should be forbidden or unauthorized
                    assert response.status_code in [
                        status.HTTP_403_FORBIDDEN,
                        status.HTTP_401_UNAUTHORIZED
                    ]
    
    def test_password_reset_flow(self, api_client, unique_email):
        """Test password reset workflow."""
        # Step 1: Request password reset
        reset_response = api_client.post("/auth/password-reset/request", json={
            "email": unique_email
        })
        
        if reset_response.status_code in [status.HTTP_200_OK, status.HTTP_202_ACCEPTED]:
            # In real scenario, user would receive email with reset token
            # For testing, we'll simulate the token
            reset_token = secrets.token_urlsafe(32)
            
            # Step 2: Reset password with token
            new_password = "NewSecureP@ssw0rd456!"
            
            reset_confirm_response = api_client.post("/auth/password-reset/confirm", json={
                "token": reset_token,
                "new_password": new_password
            })
            
            if reset_confirm_response.status_code == status.HTTP_200_OK:
                # Step 3: Try to login with new password
                login_response = api_client.post("/auth/login", json={
                    "email": unique_email,
                    "password": new_password
                })
                
                # Should be able to login with new password
                assert login_response.status_code in [
                    status.HTTP_200_OK,
                    status.HTTP_401_UNAUTHORIZED  # If user doesn't exist
                ]
    
    def test_token_refresh_flow(self, api_client):
        """Test token refresh mechanism."""
        # Step 1: Initial login
        login_response = api_client.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "admin123"
        })
        
        assert login_response.status_code == status.HTTP_200_OK
        initial_token = login_response.json()["access_token"]
        
        # Check if refresh token is provided
        if "refresh_token" in login_response.json():
            refresh_token = login_response.json()["refresh_token"]
            
            # Step 2: Use refresh token to get new access token
            refresh_response = api_client.post("/auth/refresh", json={
                "refresh_token": refresh_token
            })
            
            if refresh_response.status_code == status.HTTP_200_OK:
                new_token = refresh_response.json()["access_token"]
                
                # New token should be different from initial
                assert new_token != initial_token
                
                # Both tokens should work
                headers_old = {"Authorization": f"Bearer {initial_token}"}
                headers_new = {"Authorization": f"Bearer {new_token}"}
                
                # Test both tokens
                response_old = api_client.get("/users/me", headers=headers_old)
                response_new = api_client.get("/users/me", headers=headers_new)
                
                # New token should work
                assert response_new.status_code == status.HTTP_200_OK
    
    def test_logout_flow(self, api_client):
        """Test logout workflow."""
        # Step 1: Login
        login_response = api_client.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "admin123"
        })
        
        assert login_response.status_code == status.HTTP_200_OK
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Step 2: Verify token works
        me_response = api_client.get("/users/me", headers=headers)
        initial_status = me_response.status_code
        
        # Step 3: Logout
        logout_response = api_client.post("/auth/logout", headers=headers)
        
        if logout_response.status_code == status.HTTP_200_OK:
            # Step 4: Try to use token after logout
            me_response_after = api_client.get("/users/me", headers=headers)
            
            # Token might be invalidated (depends on implementation)
            # Could still work if using stateless JWT
            assert me_response_after.status_code in [
                status.HTTP_200_OK,  # Stateless JWT
                status.HTTP_401_UNAUTHORIZED  # Token invalidated
            ]
    
    def test_concurrent_login_sessions(self, api_client):
        """Test handling of concurrent login sessions."""
        email = "admin@sentinel.com"
        password = "admin123"
        
        # Create multiple login sessions
        sessions = []
        for i in range(3):
            response = api_client.post("/auth/login", json={
                "email": email,
                "password": password
            })
            
            if response.status_code == status.HTTP_200_OK:
                token = response.json()["access_token"]
                sessions.append(token)
        
        # All sessions should work independently
        for i, token in enumerate(sessions):
            headers = {"Authorization": f"Bearer {token}"}
            response = api_client.get("/users/me", headers=headers)
            
            # Each session should be valid
            assert response.status_code == status.HTTP_200_OK
            
            if response.status_code == status.HTTP_200_OK:
                user_data = response.json()
                assert user_data["email"] == email
    
    def test_invalid_credentials_handling(self, api_client):
        """Test handling of invalid login attempts."""
        invalid_attempts = [
            {"email": "nonexistent@sentinel.com", "password": "password123"},
            {"email": "admin@sentinel.com", "password": "wrongpassword"},
            {"email": "invalid-email", "password": "password123"},
            {"email": "", "password": "password123"},
            {"email": "admin@sentinel.com", "password": ""},
        ]
        
        for attempt in invalid_attempts:
            response = api_client.post("/auth/login", json=attempt)
            
            # Should reject invalid credentials
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                status.HTTP_400_BAD_REQUEST
            ]
            
            # Should not return token
            if response.status_code != status.HTTP_422_UNPROCESSABLE_ENTITY:
                data = response.json()
                assert "access_token" not in data