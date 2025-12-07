"""
Application factory for creating testable FastAPI instances.

This module provides a factory pattern for creating FastAPI applications
with configurable dependencies, making it easier to test.
"""
from typing import Optional, Dict, Any, Callable
from collections import defaultdict
import time
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import jwt
import bcrypt
from datetime import datetime, timedelta
from enum import Enum


class RateLimiter:
    """
    In-memory rate limiter for authentication endpoints.

    SECURITY: Protects against brute-force attacks on login endpoints.
    For production with multiple instances, use Redis-based rate limiting.
    """
    def __init__(self, requests_per_minute: int = 5, lockout_duration_seconds: int = 300):
        self.requests_per_minute = requests_per_minute
        self.lockout_duration = lockout_duration_seconds
        self.request_counts: Dict[str, list] = defaultdict(list)
        self.lockouts: Dict[str, float] = {}

    def _clean_old_requests(self, key: str) -> None:
        """Remove requests older than 1 minute."""
        current_time = time.time()
        self.request_counts[key] = [
            req_time for req_time in self.request_counts[key]
            if current_time - req_time < 60
        ]

    def is_rate_limited(self, identifier: str) -> tuple[bool, Optional[int]]:
        """
        Check if an identifier (IP or email) is rate limited.

        Returns:
            Tuple of (is_limited, seconds_until_unlock)
        """
        current_time = time.time()

        # Check if in lockout period
        if identifier in self.lockouts:
            unlock_time = self.lockouts[identifier]
            if current_time < unlock_time:
                return True, int(unlock_time - current_time)
            else:
                del self.lockouts[identifier]

        # Clean old requests
        self._clean_old_requests(identifier)

        # Check request count
        if len(self.request_counts[identifier]) >= self.requests_per_minute:
            # Trigger lockout
            self.lockouts[identifier] = current_time + self.lockout_duration
            return True, self.lockout_duration

        return False, None

    def record_request(self, identifier: str) -> None:
        """Record a request for rate limiting purposes."""
        self.request_counts[identifier].append(time.time())

    def record_failed_attempt(self, identifier: str) -> None:
        """Record a failed login attempt (counts as multiple requests)."""
        current_time = time.time()
        # Failed attempts count as 2 requests to be more aggressive
        self.request_counts[identifier].extend([current_time, current_time])

    def reset(self) -> None:
        """Reset all rate limiting state. Useful for testing."""
        self.request_counts.clear()
        self.lockouts.clear()


# Global rate limiter instance
_auth_rate_limiter = RateLimiter(requests_per_minute=5, lockout_duration_seconds=300)


def reset_rate_limiter() -> None:
    """Reset the global rate limiter. Useful for testing."""
    _auth_rate_limiter.reset()


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
                 jwt_secret: str = None,
                 jwt_algorithm: str = "HS256",
                 jwt_expiration_hours: int = 24,
                 users_db: Optional[Dict] = None):
        import os
        import secrets

        # SECURITY FIX: Require proper JWT secret in production
        if jwt_secret is None:
            jwt_secret = os.getenv("SENTINEL_SECURITY_JWT_SECRET_KEY")

        if not jwt_secret:
            # Generate secure random secret for development only
            if os.getenv("SENTINEL_ENVIRONMENT") == "production":
                raise ValueError("JWT secret key must be set via SENTINEL_SECURITY_JWT_SECRET_KEY in production")
            jwt_secret = secrets.token_urlsafe(32)

        # Validate minimum length
        if len(jwt_secret) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")

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
    
    # Add CORS middleware - SECURITY FIX: Use configured origins
    import os
    cors_origins = os.getenv("SENTINEL_SECURITY_CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")
    if os.getenv("SENTINEL_ENVIRONMENT") == "development":
        cors_origins = list(set(cors_origins + ["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000"]))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
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
    
    def get_client_ip(request: Request) -> str:
        """Extract client IP from request, handling proxies."""
        # Check for forwarded headers (when behind proxy/load balancer)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @app.post("/auth/login")
    async def login(request: Request, credentials: UserLogin):
        """Login endpoint with rate limiting."""
        client_ip = get_client_ip(request)

        # Check rate limiting by IP
        is_limited, wait_time = _auth_rate_limiter.is_rate_limited(client_ip)
        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts. Please try again in {wait_time} seconds.",
                headers={"Retry-After": str(wait_time)}
            )

        # Also check by email (to prevent distributed attacks on single account)
        is_limited, wait_time = _auth_rate_limiter.is_rate_limited(credentials.email)
        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many login attempts for this account. Please try again in {wait_time} seconds.",
                headers={"Retry-After": str(wait_time)}
            )

        # Record the login attempt
        _auth_rate_limiter.record_request(client_ip)
        _auth_rate_limiter.record_request(credentials.email)

        user = config.users_db.get(credentials.email)
        if not user:
            # Record failed attempt
            _auth_rate_limiter.record_failed_attempt(client_ip)
            _auth_rate_limiter.record_failed_attempt(credentials.email)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Check password
        if not bcrypt.checkpw(credentials.password.encode('utf-8'),
                            user["hashed_password"].encode('utf-8')):
            # Record failed attempt
            _auth_rate_limiter.record_failed_attempt(client_ip)
            _auth_rate_limiter.record_failed_attempt(credentials.email)
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
        jwt_secret="test-secret-key-for-testing-purposes-only-32chars",
        jwt_algorithm="HS256",
        jwt_expiration_hours=1,
        users_db=users
    )
    
    return create_auth_app(config)