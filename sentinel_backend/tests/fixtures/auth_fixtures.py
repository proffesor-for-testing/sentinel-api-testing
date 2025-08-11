"""
Authentication test fixtures and test data.
"""
import pytest
from datetime import datetime, timedelta
from typing import Dict, Any
import jwt
import bcrypt
from unittest.mock import Mock


@pytest.fixture
def mock_jwt_secret():
    """Mock JWT secret key for testing."""
    return "test-secret-key-for-testing-only"


@pytest.fixture
def test_user_data():
    """Test user data for authentication tests."""
    return {
        "id": 1,
        "email": "test@example.com",
        "full_name": "Test User",
        "role": "tester",
        "is_active": True,
        "created_at": datetime.utcnow(),
        "last_login": None
    }


@pytest.fixture  
def admin_user_data():
    """Admin user data for testing."""
    return {
        "id": 2,
        "email": "admin@sentinel.com",
        "full_name": "System Administrator", 
        "role": "admin",
        "is_active": True,
        "created_at": datetime.utcnow(),
        "last_login": datetime.utcnow()
    }


@pytest.fixture
def viewer_user_data():
    """Viewer user data for testing."""
    return {
        "id": 3,
        "email": "viewer@example.com",
        "full_name": "Read Only User",
        "role": "viewer", 
        "is_active": True,
        "created_at": datetime.utcnow(),
        "last_login": None
    }


@pytest.fixture
def inactive_user_data():
    """Inactive user data for testing."""
    return {
        "id": 4,
        "email": "inactive@example.com", 
        "full_name": "Inactive User",
        "role": "tester",
        "is_active": False,
        "created_at": datetime.utcnow(),
        "last_login": None
    }


@pytest.fixture
def test_password():
    """Test password for authentication tests."""
    return "TestPassword123!"


@pytest.fixture
def hashed_password(test_password):
    """Hashed version of test password."""
    return bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


@pytest.fixture
def valid_jwt_token(test_user_data, mock_jwt_secret):
    """Valid JWT token for testing."""
    payload = {
        "sub": test_user_data["email"],
        "user_id": test_user_data["id"],
        "role": test_user_data["role"],
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, mock_jwt_secret, algorithm="HS256")


@pytest.fixture
def expired_jwt_token(test_user_data, mock_jwt_secret):
    """Expired JWT token for testing."""
    payload = {
        "sub": test_user_data["email"],
        "user_id": test_user_data["id"], 
        "role": test_user_data["role"],
        "exp": datetime.utcnow() - timedelta(hours=1),
        "iat": datetime.utcnow() - timedelta(hours=2)
    }
    return jwt.encode(payload, mock_jwt_secret, algorithm="HS256")


@pytest.fixture
def invalid_jwt_token():
    """Invalid JWT token for testing."""
    # Create a properly formatted but invalid JWT token
    # This has valid base64 segments but invalid signature
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwidXNlcl9pZCI6MSwicm9sZSI6InRlc3RlciJ9.invalid_signature_part"


@pytest.fixture
def login_request_data(test_user_data, test_password):
    """Valid login request data."""
    return {
        "email": test_user_data["email"],
        "password": test_password
    }


@pytest.fixture
def invalid_login_request_data():
    """Invalid login request data."""
    return {
        "email": "nonexistent@example.com",
        "password": "wrongpassword"
    }


@pytest.fixture
def user_create_request_data():
    """User creation request data."""
    return {
        "email": "newuser@example.com",
        "full_name": "New Test User",
        "password": "NewPassword123!",
        "role": "tester"
    }


@pytest.fixture
def user_update_request_data():
    """User update request data."""
    return {
        "full_name": "Updated Full Name",
        "role": "manager",
        "is_active": True
    }


@pytest.fixture
def mock_users_db(test_user_data, admin_user_data, viewer_user_data, inactive_user_data, hashed_password):
    """Mock users database for testing."""
    return {
        test_user_data["email"]: {**test_user_data, "hashed_password": hashed_password},
        admin_user_data["email"]: {**admin_user_data, "hashed_password": hashed_password},
        viewer_user_data["email"]: {**viewer_user_data, "hashed_password": hashed_password},
        inactive_user_data["email"]: {**inactive_user_data, "hashed_password": hashed_password}
    }


@pytest.fixture
def mock_security_settings(mock_jwt_secret):
    """Mock security settings for testing."""
    mock_settings = Mock()
    mock_settings.jwt_secret_key = mock_jwt_secret
    mock_settings.jwt_algorithm = "HS256"
    mock_settings.jwt_expiration_hours = 24
    mock_settings.default_admin_email = "admin@sentinel.com"
    mock_settings.default_admin_password = "admin123"
    mock_settings.cors_origins = ["http://localhost:3000"]
    mock_settings.cors_allow_credentials = True
    mock_settings.cors_allow_methods = ["*"]
    mock_settings.cors_allow_headers = ["*"]
    return mock_settings


@pytest.fixture
def mock_app_settings():
    """Mock application settings for testing."""
    mock_settings = Mock()
    mock_settings.app_version = "1.0.0-test"
    mock_settings.debug = True
    mock_settings.log_level = "DEBUG"
    return mock_settings


@pytest.fixture
def role_permissions_map():
    """Role permissions mapping for testing."""
    return {
        "admin": [
            "spec:create", "spec:read", "spec:update", "spec:delete",
            "test_case:create", "test_case:read", "test_case:update", "test_case:delete", 
            "test_suite:create", "test_suite:read", "test_suite:update", "test_suite:delete",
            "test_run:create", "test_run:read", "test_run:cancel",
            "user:create", "user:read", "user:update", "user:delete",
            "analytics:read", "analytics:export"
        ],
        "manager": [
            "spec:create", "spec:read", "spec:update", "spec:delete",
            "test_case:create", "test_case:read", "test_case:update", "test_case:delete",
            "test_suite:create", "test_suite:read", "test_suite:update", "test_suite:delete", 
            "test_run:create", "test_run:read", "test_run:cancel",
            "user:read", "analytics:read", "analytics:export"
        ],
        "tester": [
            "spec:read",
            "test_case:create", "test_case:read", "test_case:update",
            "test_suite:create", "test_suite:read", "test_suite:update",
            "test_run:create", "test_run:read", "analytics:read"
        ],
        "viewer": [
            "spec:read", "test_case:read", "test_suite:read",
            "test_run:read", "analytics:read"
        ]
    }


@pytest.fixture
def mock_correlation_id():
    """Mock correlation ID for testing."""
    return "test-correlation-id-12345"


@pytest.fixture
def mock_request():
    """Mock FastAPI request for testing."""
    mock_req = Mock()
    mock_req.headers = {"X-Correlation-ID": "test-correlation-id-12345"}
    return mock_req


@pytest.fixture
def auth_headers(valid_jwt_token):
    """Authorization headers for testing."""
    return {"Authorization": f"Bearer {valid_jwt_token}"}


@pytest.fixture
def invalid_auth_headers():
    """Invalid authorization headers for testing."""
    return {"Authorization": "Bearer invalid-token"}


@pytest.fixture  
def missing_auth_headers():
    """Missing authorization headers for testing."""
    return {}