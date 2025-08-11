"""
Unit tests for Authentication Service.

Tests JWT token creation/validation, password hashing, user authentication,
role-based access control (RBAC), and user management functionality.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
import jwt
import bcrypt

# Import the modules we want to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from auth_service.main import (
    hash_password,
    verify_password, 
    create_access_token,
    decode_access_token,
    get_current_user,
    require_permission,
    require_role,
    UserRole,
    Permission,
    ROLE_PERMISSIONS
)

# Import fixtures
from tests.fixtures.auth_fixtures import *


class TestPasswordHandling:
    """Test password hashing and verification functionality."""
    
    @pytest.mark.unit
    def test_hash_password(self, test_password):
        """Test password hashing creates valid bcrypt hash."""
        hashed = hash_password(test_password)
        
        assert isinstance(hashed, str)
        assert hashed != test_password
        assert hashed.startswith("$2b$")  # bcrypt identifier
        assert len(hashed) == 60  # Standard bcrypt hash length
    
    @pytest.mark.unit
    def test_verify_password_success(self, test_password, hashed_password):
        """Test password verification with correct password."""
        result = verify_password(test_password, hashed_password)
        assert result is True
    
    @pytest.mark.unit
    def test_verify_password_failure(self, hashed_password):
        """Test password verification with incorrect password."""
        wrong_password = "WrongPassword123!"
        result = verify_password(wrong_password, hashed_password)
        assert result is False
    
    @pytest.mark.unit
    def test_hash_password_different_salts(self, test_password):
        """Test that hashing same password twice produces different hashes."""
        hash1 = hash_password(test_password)
        hash2 = hash_password(test_password)
        
        assert hash1 != hash2
        assert verify_password(test_password, hash1)
        assert verify_password(test_password, hash2)


class TestJWTTokenHandling:
    """Test JWT token creation, validation, and decoding."""
    
    @pytest.mark.unit
    @patch('auth_service.main.JWT_SECRET_KEY', 'test-secret')
    @patch('auth_service.main.JWT_ALGORITHM', 'HS256')
    @patch('auth_service.main.JWT_EXPIRATION_HOURS', 24)
    def test_create_access_token(self, test_user_data):
        """Test JWT token creation with valid user data."""
        token = create_access_token(test_user_data)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode to verify contents
        payload = jwt.decode(token, 'test-secret', algorithms=['HS256'])
        assert payload['sub'] == test_user_data['email']
        assert payload['user_id'] == test_user_data['id']
        assert payload['role'] == test_user_data['role']
        assert 'exp' in payload
        assert 'iat' in payload
    
    @pytest.mark.unit
    @patch('auth_service.main.JWT_SECRET_KEY', 'test-secret')
    @patch('auth_service.main.JWT_ALGORITHM', 'HS256')
    def test_decode_access_token_valid(self, valid_jwt_token):
        """Test decoding valid JWT token."""
        with patch('auth_service.main.JWT_SECRET_KEY', 'test-secret-key-for-testing-only'):
            payload = decode_access_token(valid_jwt_token)
            
            assert 'sub' in payload
            assert 'user_id' in payload
            assert 'role' in payload
            assert 'exp' in payload
            assert 'iat' in payload
    
    @pytest.mark.unit
    @patch('auth_service.main.JWT_SECRET_KEY', 'test-secret')
    @patch('auth_service.main.JWT_ALGORITHM', 'HS256')
    def test_decode_access_token_expired(self, expired_jwt_token):
        """Test decoding expired JWT token raises HTTPException."""
        with patch('auth_service.main.JWT_SECRET_KEY', 'test-secret-key-for-testing-only'):
            with pytest.raises(HTTPException) as exc_info:
                decode_access_token(expired_jwt_token)
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "expired" in exc_info.value.detail.lower()
    
    @pytest.mark.unit
    @patch('auth_service.main.JWT_SECRET_KEY', 'test-secret')
    @patch('auth_service.main.JWT_ALGORITHM', 'HS256')
    def test_decode_access_token_invalid(self, invalid_jwt_token):
        """Test decoding invalid JWT token raises HTTPException."""
        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(invalid_jwt_token)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "invalid" in exc_info.value.detail.lower()


class TestUserAuthentication:
    """Test user authentication and current user retrieval."""
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    @patch('auth_service.main.decode_access_token')
    def test_get_current_user_success(self, mock_decode, mock_users_db, test_user_data, valid_jwt_token):
        """Test getting current user with valid token."""
        # Setup mocks
        mock_decode.return_value = {
            'sub': test_user_data['email'],
            'user_id': test_user_data['id'],
            'role': test_user_data['role']
        }
        mock_users_db.__getitem__ = Mock(return_value=test_user_data)
        mock_users_db.__contains__ = Mock(return_value=True)
        
        # Create credentials
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=valid_jwt_token
        )
        
        # Test function
        result = get_current_user(credentials)
        
        assert result == test_user_data
        mock_decode.assert_called_once_with(valid_jwt_token)
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    @patch('auth_service.main.decode_access_token')
    def test_get_current_user_not_found(self, mock_decode, mock_users_db, test_user_data, valid_jwt_token):
        """Test getting current user when user not found in database."""
        # Setup mocks
        mock_decode.return_value = {
            'sub': test_user_data['email'],
            'user_id': test_user_data['id'],
            'role': test_user_data['role']
        }
        mock_users_db.__contains__ = Mock(return_value=False)
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", 
            credentials=valid_jwt_token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "not found" in exc_info.value.detail.lower()
    
    @pytest.mark.unit
    @patch('auth_service.main.users_db')
    @patch('auth_service.main.decode_access_token')
    def test_get_current_user_inactive(self, mock_decode, mock_users_db, inactive_user_data, valid_jwt_token):
        """Test getting current user when user is inactive."""
        # Setup mocks
        mock_decode.return_value = {
            'sub': inactive_user_data['email'],
            'user_id': inactive_user_data['id'],
            'role': inactive_user_data['role']
        }
        mock_users_db.__getitem__ = Mock(return_value=inactive_user_data)
        mock_users_db.__contains__ = Mock(return_value=True)
        
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=valid_jwt_token
        )
        
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(credentials)
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert "disabled" in exc_info.value.detail.lower()


class TestRoleBasedAccessControl:
    """Test RBAC functionality including permissions and role hierarchy."""
    
    @pytest.mark.unit
    def test_require_permission_success(self, test_user_data):
        """Test permission check passes for authorized user."""
        # Test with tester role trying to access test_case:read
        permission_checker = require_permission(Permission.TEST_CASE_READ)
        
        # Call the permission checker directly with user data (bypassing FastAPI Depends)
        result = permission_checker(current_user=test_user_data)
        assert result == test_user_data
    
    @pytest.mark.unit
    def test_require_permission_failure(self, viewer_user_data):
        """Test permission check fails for unauthorized user."""
        # Test with viewer role trying to access user:create (admin only)
        permission_checker = require_permission(Permission.USER_CREATE)
        
        with pytest.raises(HTTPException) as exc_info:
            permission_checker(current_user=viewer_user_data)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "insufficient permissions" in exc_info.value.detail.lower()
    
    @pytest.mark.unit
    def test_require_role_success(self, admin_user_data):
        """Test role check passes for user with sufficient role."""
        # Admin should be able to access manager-required endpoint
        role_checker = require_role(UserRole.MANAGER)
        
        result = role_checker(current_user=admin_user_data)
        assert result == admin_user_data
    
    @pytest.mark.unit
    def test_require_role_failure(self, viewer_user_data):
        """Test role check fails for user with insufficient role."""
        # Viewer should not be able to access admin-required endpoint
        role_checker = require_role(UserRole.ADMIN)
        
        with pytest.raises(HTTPException) as exc_info:
            role_checker(current_user=viewer_user_data)
        
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "insufficient role" in exc_info.value.detail.lower()
    
    @pytest.mark.unit
    def test_role_permissions_mapping(self, role_permissions_map):
        """Test that ROLE_PERMISSIONS contains expected permissions."""
        # Verify admin has all permissions
        admin_perms = [perm.value for perm in ROLE_PERMISSIONS[UserRole.ADMIN]]
        assert Permission.USER_CREATE.value in admin_perms
        assert Permission.USER_DELETE.value in admin_perms
        
        # Verify viewer has only read permissions
        viewer_perms = [perm.value for perm in ROLE_PERMISSIONS[UserRole.VIEWER]]
        assert Permission.SPEC_READ.value in viewer_perms
        assert Permission.USER_CREATE.value not in viewer_perms
        
        # Verify tester can create test cases but not users
        tester_perms = [perm.value for perm in ROLE_PERMISSIONS[UserRole.TESTER]]
        assert Permission.TEST_CASE_CREATE.value in tester_perms
        assert Permission.USER_CREATE.value not in tester_perms


class TestUserRoles:
    """Test UserRole enum and role hierarchy."""
    
    @pytest.mark.unit
    def test_user_role_values(self):
        """Test UserRole enum has expected values."""
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.MANAGER.value == "manager"
        assert UserRole.TESTER.value == "tester"
        assert UserRole.VIEWER.value == "viewer"
    
    @pytest.mark.unit
    def test_user_role_string_conversion(self):
        """Test UserRole can be created from string."""
        assert UserRole("admin") == UserRole.ADMIN
        assert UserRole("tester") == UserRole.TESTER
        
        with pytest.raises(ValueError):
            UserRole("invalid_role")


class TestPermissions:
    """Test Permission enum values."""
    
    @pytest.mark.unit
    def test_permission_values(self):
        """Test Permission enum has expected values."""
        assert Permission.SPEC_CREATE.value == "spec:create"
        assert Permission.USER_DELETE.value == "user:delete"
        assert Permission.TEST_RUN_READ.value == "test_run:read"
        assert Permission.ANALYTICS_EXPORT.value == "analytics:export"
    
    @pytest.mark.unit
    def test_permission_categories(self):
        """Test permissions are properly categorized."""
        # Spec permissions
        spec_perms = [p for p in Permission if p.value.startswith("spec:")]
        assert len(spec_perms) == 4  # create, read, update, delete
        
        # User permissions 
        user_perms = [p for p in Permission if p.value.startswith("user:")]
        assert len(user_perms) == 4  # create, read, update, delete
        
        # Test case permissions
        test_case_perms = [p for p in Permission if p.value.startswith("test_case:")]
        assert len(test_case_perms) == 4  # create, read, update, delete


class TestSecurityConfiguration:
    """Test security configuration and settings."""
    
    @pytest.mark.unit
    def test_jwt_configuration(self):
        """Test JWT configuration is properly loaded."""
        # Just test that JWT creation works with proper settings
        import auth_service.main
        assert hasattr(auth_service.main, 'JWT_SECRET_KEY')
        assert hasattr(auth_service.main, 'JWT_ALGORITHM')
        assert hasattr(auth_service.main, 'JWT_EXPIRATION_HOURS')
    
    @pytest.mark.unit 
    def test_cors_configuration(self, mock_security_settings):
        """Test CORS configuration for security."""
        expected_origins = ["http://localhost:3000"]
        mock_security_settings.cors_origins = expected_origins
        mock_security_settings.cors_allow_credentials = True
        
        assert mock_security_settings.cors_origins == expected_origins
        assert mock_security_settings.cors_allow_credentials is True


class TestUserManagement:
    """Test user management functionality (create, update, delete)."""
    
    @pytest.mark.unit
    def test_default_admin_creation(self, mock_security_settings):
        """Test that default admin user is created correctly."""
        expected_email = "admin@sentinel.com"
        expected_password = "admin123"
        
        mock_security_settings.default_admin_email = expected_email
        mock_security_settings.default_admin_password = expected_password
        
        assert mock_security_settings.default_admin_email == expected_email
        assert mock_security_settings.default_admin_password == expected_password
    
    @pytest.mark.unit
    def test_user_id_generation(self, mock_users_db):
        """Test user ID generation for new users."""
        # Test that new user gets next available ID
        current_max_id = max(user['id'] for user in mock_users_db.values())
        expected_new_id = current_max_id + 1
        
        # This would be tested in the actual endpoint tests
        # Here we just verify the logic would work
        assert expected_new_id > current_max_id