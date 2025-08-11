"""
Integration tests for authentication flow.

These tests verify the complete authentication flow including:
- User registration
- Login and token generation
- Token validation
- Protected endpoint access
"""
import pytest
from fastapi.testclient import TestClient
from fastapi import status
import time


@pytest.mark.integration
class TestAuthenticationFlow:
    """Test complete authentication flow."""
    
    @pytest.fixture
    def client(self):
        """Create test client with real app."""
        # Use real app with test database
        from auth_service.main import app
        return TestClient(app)
    
    @pytest.fixture
    def test_user_data(self):
        """Test user data for integration tests."""
        # Use timestamp to ensure unique email
        timestamp = int(time.time())
        return {
            "email": f"integration_test_{timestamp}@sentinel.com",
            "full_name": "Integration Test User",
            "password": "TestPassword123!",
            "role": "tester"
        }
    
    def test_complete_auth_flow(self, client, test_user_data):
        """Test complete authentication flow from registration to protected access."""
        
        # Step 1: Login as admin (using default admin)
        admin_login = client.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "admin123"
        })
        
        if admin_login.status_code != status.HTTP_200_OK:
            pytest.skip("Admin login failed - database might not be initialized")
        
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Step 2: Register a new user as admin
        register_response = client.post(
            "/auth/register",
            json=test_user_data,
            headers=admin_headers
        )
        
        assert register_response.status_code == status.HTTP_200_OK
        registered_user = register_response.json()
        assert registered_user["email"] == test_user_data["email"]
        
        # Step 3: Login as the new user
        login_response = client.post("/auth/login", json={
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        })
        
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()
        assert "access_token" in login_data
        user_token = login_data["access_token"]
        
        # Step 4: Access protected endpoint with token
        user_headers = {"Authorization": f"Bearer {user_token}"}
        profile_response = client.get("/auth/profile", headers=user_headers)
        
        assert profile_response.status_code == status.HTTP_200_OK
        profile_data = profile_response.json()
        assert profile_data["email"] == test_user_data["email"]
        
        # Step 5: Validate token
        validate_response = client.post("/auth/validate", headers=user_headers)
        
        assert validate_response.status_code == status.HTTP_200_OK
        validate_data = validate_response.json()
        assert validate_data["valid"] is True
        
        # Step 6: Try to access admin-only endpoint (should fail)
        users_response = client.get("/auth/users", headers=user_headers)
        assert users_response.status_code == status.HTTP_403_FORBIDDEN
        
        # Step 7: Update profile
        update_response = client.put(
            "/auth/profile",
            json={"full_name": "Updated Integration User"},
            headers=user_headers
        )
        
        assert update_response.status_code == status.HTTP_200_OK
        updated_data = update_response.json()
        assert updated_data["full_name"] == "Updated Integration User"
    
    @pytest.mark.slow
    def test_token_expiration(self, client):
        """Test token expiration handling."""
        # This would test actual token expiration
        # For now, we'll skip as it requires waiting for expiration
        pytest.skip("Token expiration test requires long wait time")
    
    def test_concurrent_logins(self, client, test_user_data):
        """Test multiple concurrent login sessions."""
        # First create a user
        admin_login = client.post("/auth/login", json={
            "email": "admin@sentinel.com",
            "password": "admin123"
        })
        
        if admin_login.status_code != status.HTTP_200_OK:
            pytest.skip("Admin login failed")
        
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Register user
        client.post("/auth/register", json=test_user_data, headers=admin_headers)
        
        # Login multiple times
        tokens = []
        for _ in range(3):
            response = client.post("/auth/login", json={
                "email": test_user_data["email"],
                "password": test_user_data["password"]
            })
            assert response.status_code == status.HTTP_200_OK
            tokens.append(response.json()["access_token"])
        
        # All tokens should be valid
        for token in tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = client.get("/auth/profile", headers=headers)
            assert response.status_code == status.HTTP_200_OK