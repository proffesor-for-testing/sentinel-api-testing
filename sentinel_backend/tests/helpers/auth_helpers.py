"""
Authentication test helpers for easier testing.
"""
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from unittest.mock import Mock, AsyncMock
from fastapi import HTTPException, status


class AuthTestHelper:
    """Helper class for authentication testing."""
    
    def __init__(self, secret_key: str = "test-secret", algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.mock_users_db = {}
        
    def create_token(self, user_data: Dict[str, Any], expires_in: int = 3600) -> str:
        """Create a valid JWT token for testing."""
        payload = {
            "sub": user_data.get("email"),
            "exp": datetime.utcnow() + timedelta(seconds=expires_in),
            "iat": datetime.utcnow(),
            "user_id": user_data.get("id"),
            "role": user_data.get("role")
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_expired_token(self, user_data: Dict[str, Any]) -> str:
        """Create an expired JWT token for testing."""
        payload = {
            "sub": user_data.get("email"),
            "exp": datetime.utcnow() - timedelta(seconds=1),
            "iat": datetime.utcnow() - timedelta(hours=2),
            "user_id": user_data.get("id"),
            "role": user_data.get("role")
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def create_auth_headers(self, token: str) -> Dict[str, str]:
        """Create authorization headers with token."""
        return {"Authorization": f"Bearer {token}"}
    
    def add_user_to_mock_db(self, user_data: Dict[str, Any], password: str = "password123"):
        """Add a user to the mock database."""
        import bcrypt
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_with_password = {
            **user_data,
            "hashed_password": hashed.decode('utf-8')
        }
        self.mock_users_db[user_data["email"]] = user_with_password
        return user_with_password
    
    def create_mock_get_current_user(self, user_data: Dict[str, Any]):
        """Create a mock get_current_user function."""
        async def mock_get_current_user(credentials=None):
            return user_data
        return mock_get_current_user
    
    def create_mock_require_permission(self, user_data: Dict[str, Any]):
        """Create a mock require_permission function."""
        def mock_require_permission(permission):
            async def permission_checker(credentials=None):
                # Check if user has permission based on role
                role_permissions = {
                    "admin": ["user:create", "user:read", "user:update", "user:delete",
                             "spec:create", "spec:read", "spec:update", "spec:delete",
                             "test_case:create", "test_case:read", "test_case:update", "test_case:delete"],
                    "manager": ["spec:create", "spec:read", "spec:update",
                               "test_case:create", "test_case:read", "test_case:update",
                               "user:read"],
                    "tester": ["spec:read", "test_case:create", "test_case:read", "test_case:update"],
                    "viewer": ["spec:read", "test_case:read"]
                }
                
                user_role = user_data.get("role", "viewer")
                user_permissions = role_permissions.get(user_role, [])
                
                if hasattr(permission, 'value'):
                    permission = permission.value
                    
                if permission not in user_permissions:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"User does not have permission: {permission}"
                    )
                
                return user_data
            return permission_checker
        return mock_require_permission


class MockAuthService:
    """Mock authentication service for testing."""
    
    def __init__(self):
        self.users = {}
        self.tokens = {}
        self.helper = AuthTestHelper()
        
        # Add default test users
        self.add_default_users()
    
    def add_default_users(self):
        """Add default test users."""
        self.add_user({
            "id": 1,
            "email": "admin@sentinel.com",
            "full_name": "Admin User",
            "role": "admin",
            "is_active": True
        }, "admin123")
        
        self.add_user({
            "id": 2,
            "email": "tester@sentinel.com",
            "full_name": "Test User",
            "role": "tester",
            "is_active": True
        }, "tester123")
        
        self.add_user({
            "id": 3,
            "email": "viewer@sentinel.com",
            "full_name": "Viewer User",
            "role": "viewer",
            "is_active": True
        }, "viewer123")
    
    def add_user(self, user_data: Dict[str, Any], password: str):
        """Add a user to the mock service."""
        user_with_password = self.helper.add_user_to_mock_db(user_data, password)
        self.users[user_data["email"]] = user_with_password
        return user_with_password
    
    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user."""
        import bcrypt
        user = self.users.get(email)
        if not user:
            return None
        
        if not bcrypt.checkpw(password.encode('utf-8'), user["hashed_password"].encode('utf-8')):
            return None
        
        if not user.get("is_active", True):
            return None
        
        return {k: v for k, v in user.items() if k != "hashed_password"}
    
    def create_access_token(self, user_data: Dict[str, Any]) -> str:
        """Create an access token for a user."""
        token = self.helper.create_token(user_data)
        self.tokens[token] = user_data
        return token
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a token and return user data."""
        try:
            payload = jwt.decode(token, self.helper.secret_key, algorithms=[self.helper.algorithm])
            email = payload.get("sub")
            if email and email in self.users:
                user = self.users[email]
                return {k: v for k, v in user.items() if k != "hashed_password"}
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        return None