"""
Application factory for creating testable FastAPI instances.

This module provides a factory pattern for creating FastAPI applications
with configurable dependencies, making it easier to test.
"""
from typing import Optional, Dict, Any, Callable
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import jwt
import bcrypt
from datetime import datetime, timedelta
from enum import Enum


class Permission(str, Enum):
    """Permission constants."""
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    SPEC_CREATE = "spec:create"
    SPEC_READ = "spec:read"
    SPEC_UPDATE = "spec:update"
    SPEC_DELETE = "spec:delete"
    TEST_CASE_CREATE = "test_case:create"
    TEST_CASE_READ = "test_case:read"
    TEST_CASE_UPDATE = "test_case:update"
    TEST_CASE_DELETE = "test_case:delete"


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: str = "viewer"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class AuthConfig:
    """Configuration for authentication."""
    def __init__(self, 
                 jwt_secret: str = "secret",
                 jwt_algorithm: str = "HS256",
                 jwt_expiration_hours: int = 24,
                 users_db: Optional[Dict] = None):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiration_hours = jwt_expiration_hours
        self.users_db = users_db or {}


def create_auth_app(
    config: Optional[AuthConfig] = None,
    dependency_overrides: Optional[Dict[Callable, Callable]] = None
) -> FastAPI:
    """
    Create a FastAPI application with authentication.
    
    Args:
        config: Authentication configuration
        dependency_overrides: Optional dependency overrides for testing
    
    Returns:
        Configured FastAPI application
    """
    if config is None:
        config = AuthConfig()
    
    app = FastAPI(
        title="Sentinel Auth Service (Testable)",
        description="Testable authentication service",
        version="2.0.0"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Security
    security = HTTPBearer()
    
    # Helper functions
    def create_access_token(email: str) -> str:
        """Create JWT access token."""
        payload = {
            "sub": email,
            "exp": datetime.utcnow() + timedelta(hours=config.jwt_expiration_hours)
        }
        return jwt.encode(payload, config.jwt_secret, algorithm=config.jwt_algorithm)
    
    def decode_access_token(token: str) -> dict:
        """Decode JWT access token."""
        try:
            payload = jwt.decode(token, config.jwt_secret, algorithms=[config.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    # Dependencies
    async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
        """Get current user from token."""
        token = credentials.credentials
        payload = decode_access_token(token)
        
        email = payload.get("sub")
        if not email or email not in config.users_db:
            raise HTTPException(status_code=401, detail="User not found")
        
        user = config.users_db[email]
        if not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="User account is disabled")
        
        return user
    
    def require_permission(permission: Permission):
        """Require specific permission."""
        async def permission_checker(current_user: dict = Depends(get_current_user)) -> dict:
            # Role-based permissions
            role_permissions = {
                "admin": [p.value for p in Permission],  # Admin has all permissions
                "manager": [
                    Permission.SPEC_CREATE.value, Permission.SPEC_READ.value, 
                    Permission.SPEC_UPDATE.value, Permission.TEST_CASE_CREATE.value,
                    Permission.TEST_CASE_READ.value, Permission.TEST_CASE_UPDATE.value,
                    Permission.USER_READ.value
                ],
                "tester": [
                    Permission.SPEC_READ.value, Permission.TEST_CASE_CREATE.value,
                    Permission.TEST_CASE_READ.value, Permission.TEST_CASE_UPDATE.value
                ],
                "viewer": [Permission.SPEC_READ.value, Permission.TEST_CASE_READ.value]
            }
            
            user_role = current_user.get("role", "viewer")
            user_permissions = role_permissions.get(user_role, [])
            
            if permission.value not in user_permissions:
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission denied: {permission.value}"
                )
            
            return current_user
        
        return permission_checker
    
    # Apply dependency overrides if provided (for testing)
    if dependency_overrides:
        for dep, override in dependency_overrides.items():
            app.dependency_overrides[dep] = override
    
    # Routes
    @app.get("/")
    async def root():
        return {
            "message": "Sentinel Auth Service (Testable)",
            "version": "2.0.0"
        }
    
    @app.post("/auth/login")
    async def login(credentials: UserLogin):
        """Login endpoint."""
        user = config.users_db.get(credentials.email)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check password
        if not bcrypt.checkpw(credentials.password.encode('utf-8'), 
                            user["hashed_password"].encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if active
        if not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="Account disabled")
        
        token = create_access_token(credentials.email)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {k: v for k, v in user.items() if k != "hashed_password"}
        }
    
    @app.post("/auth/register")
    async def register(
        user_data: UserCreate,
        current_user: dict = Depends(require_permission(Permission.USER_CREATE))
    ):
        """Register new user (admin only)."""
        if user_data.email in config.users_db:
            raise HTTPException(status_code=400, detail="User already exists")
        
        hashed = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
        
        new_user = {
            "id": len(config.users_db) + 1,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "role": user_data.role,
            "is_active": True,
            "hashed_password": hashed.decode('utf-8')
        }
        
        config.users_db[user_data.email] = new_user
        
        return {k: v for k, v in new_user.items() if k != "hashed_password"}
    
    @app.get("/auth/profile")
    async def get_profile(current_user: dict = Depends(get_current_user)):
        """Get current user profile."""
        return {k: v for k, v in current_user.items() if k != "hashed_password"}
    
    @app.get("/auth/users")
    async def list_users(
        current_user: dict = Depends(require_permission(Permission.USER_READ))
    ):
        """List all users (requires permission)."""
        return [
            {k: v for k, v in user.items() if k != "hashed_password"}
            for user in config.users_db.values()
        ]
    
    return app


def create_test_app_with_users(users: Dict[str, Dict[str, Any]]) -> FastAPI:
    """
    Create a test app with predefined users.
    
    Args:
        users: Dictionary of users (email -> user data)
    
    Returns:
        Configured FastAPI app for testing
    """
    config = AuthConfig(
        jwt_secret="test-secret",
        jwt_algorithm="HS256",
        jwt_expiration_hours=1,
        users_db=users
    )
    
    return create_auth_app(config)