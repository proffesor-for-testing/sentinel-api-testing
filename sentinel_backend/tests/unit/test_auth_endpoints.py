"""
Unit tests for Authentication Service API endpoints.

Tests all authentication endpoints including login, registration, profile management,
user management, and token validation using FastAPI TestClient.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import status
import json
from datetime import datetime

# Import fixtures
from tests.fixtures.auth_fixtures import *


@pytest.fixture
def auth_app():
    """Create test FastAPI app instance for authentication service."""
    # Patch require_permission before importing the app
    with patch('auth_service.main.require_permission') as mock_require_permission:
        
        # Mock require_permission to always return a function that returns admin_user_data
        def mock_permission(permission):
            async def permission_checker():
                return {
                    "user": {
                        "id": 1,
                        "email": "admin@sentinel.com",
                        "full_name": "Test Admin",
                        "role": "admin",
                        "is_active": True
                    },
                    "permissions": [
                        "user:create", "user:read", "user:update", "user:delete",
                        "spec:create", "spec:read", "spec:update", "spec:delete",
                        "test_case:create", "test_case:read", "test_case:update", "test_case:delete"
                    ]
                }
            return permission_checker
        
        mock_require_permission.side_effect = mock_permission
        
        with patch('auth_service.main.setup_logging'), \
             patch('auth_service.main.setup_tracing'), \
             patch('auth_service.main.Instrumentator'):
            
            # Mock the settings
            with patch('auth_service.main.get_security_settings') as mock_sec, \
                 patch('auth_service.main.get_application_settings') as mock_app:
                
                # Setup mock settings
                mock_sec.return_value = Mock(
                    jwt_secret_key="test-secret",
                    jwt_algorithm="HS256", 
                    jwt_expiration_hours=24,
                    default_admin_email="admin@sentinel.com",
                    default_admin_password="admin123",
                    cors_origins=["http://localhost:3000"],
                    cors_allow_credentials=True,
                    cors_allow_methods=["*"],
                    cors_allow_headers=["*"]
                )
                mock_app.return_value = Mock(app_version="1.0.0-test")
                
                # Clear any module cache and reimport
                import sys
                if 'auth_service.main' in sys.modules:
                    del sys.modules['auth_service.main']
                
                from auth_service.main import app
                return app


def create_test_token(user_data: dict, secret_key: str = "test-secret") -> str:
    """Create a test JWT token for authentication."""
    import jwt
    from datetime import datetime, timedelta
    
    payload = {
        "sub": user_data["email"],
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


@pytest.fixture
def client(auth_app):
    """Create test client for authentication service."""
    client = TestClient(auth_app)
    # Clear any dependency overrides after each test
    yield client
    client.app.dependency_overrides.clear()


@pytest.fixture
def admin_headers(admin_user_data):
    """Create authorization headers for admin user."""
    token = create_test_token(admin_user_data)
    return {"Authorization": f"Bearer {token}"}


class TestRootEndpoint:
    """Test root endpoint of authentication service."""
    
    @pytest.mark.unit
    def test_root_endpoint(self, client):
        """Test root endpoint returns service information."""
        response = client.get("/")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["message"] == "Sentinel Authentication Service is running"
        assert data["version"] == "1.0.0"
        assert "endpoints" in data


class TestUserRegistration:
    """Test user registration endpoint."""
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_register_user_success(self, mock_users_db, client, user_create_request_data, admin_user_data, admin_headers, hashed_password):
        """Test successful user registration by admin."""
        # Setup mocks - admin must exist in users_db for auth to work
        admin_with_password = {**admin_user_data, "hashed_password": hashed_password}
        mock_users_db.__contains__ = Mock(side_effect=lambda email: email == admin_user_data["email"])
        mock_users_db.__getitem__ = Mock(return_value=admin_with_password)
        mock_users_db.get = Mock(return_value=admin_with_password)
        mock_users_db.__len__ = Mock(return_value=1)
        mock_users_db.__setitem__ = Mock()
        
        response = client.post("/auth/register", json=user_create_request_data, headers=admin_headers)
        
        if response.status_code != status.HTTP_200_OK:
            print(f"Response status: {response.status_code}")
            print(f"Response body: {response.json()}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == user_create_request_data["email"]
        assert data["full_name"] == user_create_request_data["full_name"]
        assert data["role"] == user_create_request_data["role"]
        assert "hashed_password" not in data
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_register_user_duplicate_email(self, mock_users_db, client, user_create_request_data, admin_user_data):
        """Test user registration with duplicate email."""
        # Setup mocks
        mock_users_db.__contains__ = Mock(return_value=True)
        
        from auth_service.main import require_permission, Permission as Permissions
        
        def mock_dependency():
            return admin_user_data
        
        client.app.dependency_overrides[require_permission(Permissions.USER_CREATE)] = mock_dependency
        
        response = client.post("/auth/register", json=user_create_request_data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["detail"].lower()
    
    @pytest.mark.unit
    def test_register_user_invalid_data(self, client):
        """Test user registration with invalid data."""
        invalid_data = {
            "email": "invalid-email",  # Invalid email format
            "full_name": "",  # Empty name
            "password": "123",  # Weak password  
            "role": "invalid_role"  # Invalid role
        }
        
        response = client.post("/auth/register", json=invalid_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestUserLogin:
    """Test user login endpoint."""
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_login_success(self, mock_users_db, client, login_request_data, test_user_data, hashed_password):
        """Test successful user login."""
        # Setup mock user database
        user_data = {**test_user_data, "hashed_password": hashed_password}
        mock_users_db.get = Mock(return_value=user_data)
        
        response = client.post("/auth/login", json=login_request_data)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["token_type"] == "bearer"
        assert "access_token" in data
        assert len(data["access_token"]) > 0
        assert data["user"]["email"] == test_user_data["email"]
        assert "hashed_password" not in data["user"]
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_login_invalid_credentials(self, mock_users_db, client, invalid_login_request_data):
        """Test login with invalid credentials."""
        mock_users_db.get = Mock(return_value=None)
        
        response = client.post("/auth/login", json=invalid_login_request_data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "invalid" in response.json()["detail"].lower()
    
    @pytest.mark.unit 
    @patch('auth_service.main.users_db')
    def test_login_inactive_user(self, mock_users_db, client, login_request_data, inactive_user_data, hashed_password):
        """Test login with inactive user account."""
        user_data = {**inactive_user_data, "hashed_password": hashed_password}
        mock_users_db.get = Mock(return_value=user_data)
        
        response = client.post("/auth/login", json=login_request_data)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "disabled" in response.json()["detail"].lower()
    
    @pytest.mark.unit
    def test_login_invalid_data_format(self, client):
        """Test login with invalid request data format."""
        invalid_data = {
            "email": "not-an-email",
            "password": ""
        }
        
        response = client.post("/auth/login", json=invalid_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestUserProfile:
    """Test user profile endpoints."""
    
    @pytest.mark.unit
    def test_get_profile_success(self, client, test_user_data):
        """Test getting current user profile."""
        from auth_service.main import get_current_user
        
        def mock_dependency():
            return test_user_data
        
        client.app.dependency_overrides[get_current_user] = mock_dependency
        
        response = client.get("/auth/profile")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == test_user_data["email"]
        assert data["full_name"] == test_user_data["full_name"]
        assert "hashed_password" not in data
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_update_profile_success(self, mock_users_db, client, test_user_data, user_update_request_data):
        """Test updating current user profile."""
        mock_users_db.__getitem__ = Mock(return_value=test_user_data.copy())
        mock_users_db.__setitem__ = Mock()
        
        from auth_service.main import get_current_user
        
        def mock_dependency():
            return test_user_data
        
        client.app.dependency_overrides[get_current_user] = mock_dependency
        
        response = client.put("/auth/profile", json={"full_name": "Updated Name"})
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["full_name"] == "Updated Name"
    
    @pytest.mark.unit
    def test_update_profile_admin_only_fields(self, client, test_user_data):
        """Test non-admin user cannot update role/active status."""
        from auth_service.main import get_current_user
        
        def mock_dependency():
            return test_user_data  # tester role
        
        client.app.dependency_overrides[get_current_user] = mock_dependency
        
        # Try to update role (should fail for non-admin)
        response = client.put("/auth/profile", json={
            "role": "admin",
            "is_active": False
        })
        
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUserManagement:
    """Test user management endpoints (admin only)."""
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_list_users_success(self, mock_users_db, client, admin_user_data):
        """Test listing all users (admin only)."""
        mock_users_db.values.return_value = [admin_user_data]
        
        from auth_service.main import require_permission, Permission as Permissions
        
        def mock_dependency():
            return admin_user_data
        
        client.app.dependency_overrides[require_permission(Permissions.USER_READ)] = mock_dependency
        
        response = client.get("/auth/users")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 0
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_get_user_by_id_success(self, mock_users_db, client, admin_user_data, test_user_data):
        """Test getting specific user by ID."""
        mock_users_db.values.return_value = [test_user_data]
        
        from auth_service.main import require_permission, Permission as Permissions
        
        def mock_dependency():
            return admin_user_data
        
        client.app.dependency_overrides[require_permission(Permissions.USER_READ)] = mock_dependency
        
        response = client.get(f"/auth/users/{test_user_data['id']}")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == test_user_data["id"]
        assert data["email"] == test_user_data["email"]
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')  
    def test_get_user_by_id_not_found(self, mock_users_db, client, admin_user_data):
        """Test getting non-existent user by ID."""
        mock_users_db.values.return_value = []
        
        from auth_service.main import require_permission, Permission as Permissions
        
        def mock_dependency():
            return admin_user_data
        
        client.app.dependency_overrides[require_permission(Permissions.USER_READ)] = mock_dependency
        
        response = client.get("/auth/users/9999")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_update_user_success(self, mock_users_db, client, admin_user_data, test_user_data):
        """Test updating user (admin only)."""
        # Mock finding the user
        mock_users_db.items.return_value = [(test_user_data["email"], test_user_data)]
        
        from auth_service.main import require_permission, Permission as Permissions
        
        def mock_dependency():
            return admin_user_data
        
        client.app.dependency_overrides[require_permission(Permissions.USER_UPDATE)] = mock_dependency
        
        update_data = {"full_name": "Updated Test User", "role": "manager"}
        response = client.put(f"/auth/users/{test_user_data['id']}", json=update_data)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["full_name"] == "Updated Test User"
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_delete_user_success(self, mock_users_db, client, admin_user_data, test_user_data):
        """Test deleting user (admin only)."""
        mock_users_db.items.return_value = [(test_user_data["email"], test_user_data)]
        mock_users_db.__delitem__ = Mock()
        
        from auth_service.main import require_permission, Permission as Permissions
        
        def mock_dependency():
            return admin_user_data
        
        client.app.dependency_overrides[require_permission(Permissions.USER_DELETE)] = mock_dependency
        
        response = client.delete(f"/auth/users/{test_user_data['id']}")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "deleted successfully" in data["message"]
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    def test_delete_user_self_deletion_prevented(self, mock_users_db, client, admin_user_data):
        """Test that users cannot delete their own account."""
        # Mock finding the admin user trying to delete themselves
        mock_users_db.items.return_value = [(admin_user_data["email"], admin_user_data)]
        
        from auth_service.main import require_permission, Permission as Permissions
        
        def mock_dependency():
            return admin_user_data
        
        client.app.dependency_overrides[require_permission(Permissions.USER_DELETE)] = mock_dependency
        
        response = client.delete(f"/auth/users/{admin_user_data['id']}")
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "cannot delete your own account" in response.json()["detail"].lower()


class TestTokenValidation:
    """Test token validation endpoint."""
    
    @pytest.mark.unit
    @patch('auth_service.main.ROLE_PERMISSIONS')
    def test_validate_token_success(self, mock_role_perms, client, test_user_data, role_permissions_map):
        """Test token validation with valid token."""
        mock_role_perms.__getitem__ = Mock(return_value=role_permissions_map["tester"])
        
        from auth_service.main import get_current_user
        
        def mock_dependency():
            return test_user_data
        
        client.app.dependency_overrides[get_current_user] = mock_dependency
        
        response = client.post("/auth/validate")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is True
        assert data["user"]["email"] == test_user_data["email"]
        assert "permissions" in data
        assert isinstance(data["permissions"], list)


class TestRolesList:
    """Test roles listing endpoint."""
    
    @pytest.mark.unit
    def test_list_roles(self, client):
        """Test listing all available roles and permissions."""
        response = client.get("/auth/roles")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "roles" in data
        assert isinstance(data["roles"], dict)
        
        # Check that all expected roles are present
        expected_roles = ["admin", "manager", "tester", "viewer"]
        for role in expected_roles:
            assert role in data["roles"]
            assert "name" in data["roles"][role]
            assert "permissions" in data["roles"][role]
            assert isinstance(data["roles"][role]["permissions"], list)


class TestCORSAndSecurityHeaders:
    """Test CORS and security middleware."""
    
    @pytest.mark.unit
    def test_cors_headers_present(self, client):
        """Test that CORS headers are present in responses."""
        response = client.options("/auth/login", headers={"Origin": "http://localhost:3000"})
        
        # CORS headers should be present
        assert "access-control-allow-origin" in [h.lower() for h in response.headers.keys()]
    
    @pytest.mark.unit
    def test_correlation_id_middleware(self, client):
        """Test that correlation ID middleware adds headers."""
        response = client.get("/")
        
        # Correlation ID should be added to response
        assert "x-correlation-id" in [h.lower() for h in response.headers.keys()]