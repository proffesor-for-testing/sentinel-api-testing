from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Dict, List, Optional, Any
from collections import defaultdict
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import structlog
import uuid
import time
from enum import Enum
from prometheus_fastapi_instrumentator import Instrumentator


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

    def is_rate_limited(self, identifier: str) -> tuple:
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


# Global rate limiter instance
_auth_rate_limiter = RateLimiter(requests_per_minute=5, lockout_duration_seconds=300)

# Import configuration
from sentinel_backend.config.settings import get_security_settings, get_application_settings
from sentinel_backend.config.logging_config import setup_logging
from sentinel_backend.config.tracing_config import setup_tracing

# Set up structured logging
setup_logging()

# Get configuration
security_settings = get_security_settings()
app_settings = get_application_settings()

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="Sentinel Authentication Service",
    description="Authentication and authorization service for the Sentinel platform",
    version="1.0.0"
)

# Instrument for Prometheus
Instrumentator().instrument(app).expose(app)

# Set up Jaeger tracing
setup_tracing(app, "auth-service")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=security_settings.cors_origins,
    allow_credentials=security_settings.cors_allow_credentials,
    allow_methods=security_settings.cors_allow_methods,
    allow_headers=security_settings.cors_allow_headers,
)

@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """
    Injects a correlation ID into every request and log context.
    """
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())

    # Bind the correlation ID to the logger context for this request
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

    response = await call_next(request)

    # Add the correlation ID to the response headers
    response.headers["X-Correlation-ID"] = correlation_id

    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Adds security headers to every response.

    SECURITY: These headers help protect against common web vulnerabilities.
    """
    response = await call_next(request)

    # HSTS - Force HTTPS connections
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # Content Security Policy - restrict resource loading
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "img-src 'self' fastapi.tiangolo.com; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )

    # Referrer Policy - control referrer information
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Permissions Policy - disable unnecessary browser features
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    return response

# Configuration from centralized settings
JWT_SECRET_KEY = security_settings.jwt_secret_key
JWT_ALGORITHM = security_settings.jwt_algorithm
JWT_EXPIRATION_HOURS = security_settings.jwt_expiration_hours

# Refresh token configuration
JWT_REFRESH_SECRET_KEY = getattr(security_settings, 'jwt_refresh_secret_key', JWT_SECRET_KEY + '-refresh')
JWT_REFRESH_EXPIRATION_DAYS = getattr(security_settings, 'jwt_refresh_expiration_days', 7)

security = HTTPBearer()

# Role definitions
class UserRole(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    TESTER = "tester"
    VIEWER = "viewer"

# Permission definitions
class Permission(str, Enum):
    # Specification permissions
    SPEC_CREATE = "spec:create"
    SPEC_READ = "spec:read"
    SPEC_UPDATE = "spec:update"
    SPEC_DELETE = "spec:delete"
    
    # Test case permissions
    TEST_CASE_CREATE = "test_case:create"
    TEST_CASE_READ = "test_case:read"
    TEST_CASE_UPDATE = "test_case:update"
    TEST_CASE_DELETE = "test_case:delete"
    
    # Test suite permissions
    TEST_SUITE_CREATE = "test_suite:create"
    TEST_SUITE_READ = "test_suite:read"
    TEST_SUITE_UPDATE = "test_suite:update"
    TEST_SUITE_DELETE = "test_suite:delete"
    
    # Test run permissions
    TEST_RUN_CREATE = "test_run:create"
    TEST_RUN_READ = "test_run:read"
    TEST_RUN_CANCEL = "test_run:cancel"
    
    # User management permissions
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Analytics permissions
    ANALYTICS_READ = "analytics:read"
    ANALYTICS_EXPORT = "analytics:export"

# Role-Permission mapping
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        # All permissions
        Permission.SPEC_CREATE, Permission.SPEC_READ, Permission.SPEC_UPDATE, Permission.SPEC_DELETE,
        Permission.TEST_CASE_CREATE, Permission.TEST_CASE_READ, Permission.TEST_CASE_UPDATE, Permission.TEST_CASE_DELETE,
        Permission.TEST_SUITE_CREATE, Permission.TEST_SUITE_READ, Permission.TEST_SUITE_UPDATE, Permission.TEST_SUITE_DELETE,
        Permission.TEST_RUN_CREATE, Permission.TEST_RUN_READ, Permission.TEST_RUN_CANCEL,
        Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE, Permission.USER_DELETE,
        Permission.ANALYTICS_READ, Permission.ANALYTICS_EXPORT
    ],
    UserRole.MANAGER: [
        # Most permissions except user management
        Permission.SPEC_CREATE, Permission.SPEC_READ, Permission.SPEC_UPDATE, Permission.SPEC_DELETE,
        Permission.TEST_CASE_CREATE, Permission.TEST_CASE_READ, Permission.TEST_CASE_UPDATE, Permission.TEST_CASE_DELETE,
        Permission.TEST_SUITE_CREATE, Permission.TEST_SUITE_READ, Permission.TEST_SUITE_UPDATE, Permission.TEST_SUITE_DELETE,
        Permission.TEST_RUN_CREATE, Permission.TEST_RUN_READ, Permission.TEST_RUN_CANCEL,
        Permission.USER_READ,  # Can view users but not manage them
        Permission.ANALYTICS_READ, Permission.ANALYTICS_EXPORT
    ],
    UserRole.TESTER: [
        # Testing-focused permissions
        Permission.SPEC_READ,
        Permission.TEST_CASE_CREATE, Permission.TEST_CASE_READ, Permission.TEST_CASE_UPDATE,
        Permission.TEST_SUITE_CREATE, Permission.TEST_SUITE_READ, Permission.TEST_SUITE_UPDATE,
        Permission.TEST_RUN_CREATE, Permission.TEST_RUN_READ,
        Permission.ANALYTICS_READ
    ],
    UserRole.VIEWER: [
        # Read-only permissions
        Permission.SPEC_READ,
        Permission.TEST_CASE_READ,
        Permission.TEST_SUITE_READ,
        Permission.TEST_RUN_READ,
        Permission.ANALYTICS_READ
    ]
}

# In-memory user store (replace with database in production)
users_db = {
    security_settings.default_admin_email: {
        "id": 1,
        "email": security_settings.default_admin_email,
        "full_name": "System Administrator",
        "hashed_password": bcrypt.hashpw(security_settings.default_admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
        "role": UserRole.ADMIN,
        "is_active": True,
        "created_at": datetime.utcnow(),
        "last_login": None
    }
}

# Request/Response Models
class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: UserRole = UserRole.VIEWER

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    """Request model for token refresh."""
    refresh_token: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

# Utility functions
def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(user_data: dict) -> str:
    """Create a JWT access token."""
    payload = {
        "sub": user_data["email"],
        "user_id": user_data["id"],
        "role": user_data["role"],
        "type": "access",
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_data: dict) -> str:
    """Create a JWT refresh token with longer expiry."""
    payload = {
        "sub": user_data["email"],
        "user_id": user_data["id"],
        "type": "refresh",
        "exp": datetime.utcnow() + timedelta(days=JWT_REFRESH_EXPIRATION_DAYS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_REFRESH_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_refresh_token(token: str) -> dict:
    """Decode and validate a JWT refresh token."""
    try:
        payload = jwt.decode(token, JWT_REFRESH_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get the current authenticated user from JWT token."""
    token = credentials.credentials
    payload = decode_access_token(token)
    
    user_email = payload.get("sub")
    if not user_email or user_email not in users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    user = users_db[user_email]
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )
    
    return user

def require_permission(permission: Permission):
    """Dependency to require a specific permission."""
    def permission_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = UserRole(current_user["role"])
        user_permissions = ROLE_PERMISSIONS.get(user_role, [])
        
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission}"
            )
        
        return current_user
    
    return permission_checker

def require_role(required_role: UserRole):
    """Dependency to require a specific role or higher."""
    role_hierarchy = {
        UserRole.VIEWER: 0,
        UserRole.TESTER: 1,
        UserRole.MANAGER: 2,
        UserRole.ADMIN: 3
    }
    
    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        user_role = UserRole(current_user["role"])
        
        if role_hierarchy[user_role] < role_hierarchy[required_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required: {required_role} or higher"
            )
        
        return current_user
    
    return role_checker

# API Endpoints
@app.get("/")
async def root():
    return {
        "message": "Sentinel Authentication Service is running",
        "version": "1.0.0",
        "endpoints": {
            "login": "/auth/login",
            "register": "/auth/register",
            "profile": "/auth/profile",
            "users": "/auth/users",
            "validate": "/auth/validate"
        }
    }

@app.post("/auth/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreate,
    current_user: dict = Depends(require_permission(Permission.USER_CREATE))
):
    """Register a new user (admin only)."""
    if user_data.email in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )
    
    # Create new user
    user_id = len(users_db) + 1
    hashed_password = hash_password(user_data.password)
    
    new_user = {
        "id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": hashed_password,
        "role": user_data.role,
        "is_active": True,
        "created_at": datetime.utcnow(),
        "last_login": None
    }
    
    users_db[user_data.email] = new_user
    
    logger.info(f"New user registered: {user_data.email} with role {user_data.role}")
    
    return UserResponse(**{k: v for k, v in new_user.items() if k != "hashed_password"})

def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check for forwarded headers (when behind proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.post("/auth/login", response_model=TokenResponse)
async def login_user(request: Request, login_data: UserLogin):
    """Authenticate user and return access token with rate limiting."""
    client_ip = get_client_ip(request)

    # Check rate limiting by IP
    is_limited, wait_time = _auth_rate_limiter.is_rate_limited(client_ip)
    if is_limited:
        logger.warning(f"Rate limited login attempt from IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts. Please try again in {wait_time} seconds.",
            headers={"Retry-After": str(wait_time)}
        )

    # Also check by email (to prevent distributed attacks on single account)
    is_limited, wait_time = _auth_rate_limiter.is_rate_limited(login_data.email)
    if is_limited:
        logger.warning(f"Rate limited login attempt for email: {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts for this account. Please try again in {wait_time} seconds.",
            headers={"Retry-After": str(wait_time)}
        )

    # Record the login attempt
    _auth_rate_limiter.record_request(client_ip)
    _auth_rate_limiter.record_request(login_data.email)

    user = users_db.get(login_data.email)

    if not user or not verify_password(login_data.password, user["hashed_password"]):
        # Record failed attempt
        _auth_rate_limiter.record_failed_attempt(client_ip)
        _auth_rate_limiter.record_failed_attempt(login_data.email)
        logger.warning(f"Failed login attempt for email: {login_data.email} from IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )

    # Update last login
    user["last_login"] = datetime.utcnow()

    # Create access and refresh tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    logger.info(f"User logged in: {login_data.email}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=JWT_EXPIRATION_HOURS * 3600,
        user=UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"})
    )

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh_access_token(request: Request, refresh_request: RefreshTokenRequest):
    """Refresh access token using a valid refresh token."""
    client_ip = get_client_ip(request)

    # Check rate limiting for refresh endpoint
    refresh_key = f"refresh:{client_ip}"
    is_limited, wait_time = _auth_rate_limiter.is_rate_limited(refresh_key)
    if is_limited:
        logger.warning(f"Rate limited refresh attempt from IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many refresh attempts. Please try again in {wait_time} seconds.",
            headers={"Retry-After": str(wait_time)}
        )

    _auth_rate_limiter.record_request(refresh_key)

    # Decode and validate refresh token
    payload = decode_refresh_token(refresh_request.refresh_token)
    user_email = payload.get("sub")

    if not user_email or user_email not in users_db:
        _auth_rate_limiter.record_failed_attempt(refresh_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    user = users_db[user_email]

    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )

    # Create new access and refresh tokens
    access_token = create_access_token(user)
    new_refresh_token = create_refresh_token(user)

    logger.info(f"Token refreshed for user: {user_email}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=JWT_EXPIRATION_HOURS * 3600,
        user=UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"})
    )


@app.get("/auth/profile", response_model=UserResponse)
async def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Get current user's profile."""
    return UserResponse(**{k: v for k, v in current_user.items() if k != "hashed_password"})

@app.put("/auth/profile", response_model=UserResponse)
async def update_current_user_profile(
    update_data: UserUpdate,
    current_user: dict = Depends(get_current_user)
):
    """Update current user's profile."""
    user_email = current_user["email"]
    
    # Users can only update their own name, not role or active status
    if update_data.full_name is not None:
        users_db[user_email]["full_name"] = update_data.full_name
    
    # Only admins can update role and active status
    if update_data.role is not None or update_data.is_active is not None:
        # Check if user has admin permissions
        user_role = UserRole(current_user["role"])
        if user_role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can update role and active status"
            )
        
        if update_data.role is not None:
            users_db[user_email]["role"] = update_data.role
        if update_data.is_active is not None:
            users_db[user_email]["is_active"] = update_data.is_active
    
    updated_user = users_db[user_email]
    return UserResponse(**{k: v for k, v in updated_user.items() if k != "hashed_password"})

@app.get("/auth/users", response_model=List[UserResponse])
async def list_users(
    current_user: dict = Depends(require_permission(Permission.USER_READ))
):
    """List all users (requires user read permission)."""
    return [
        UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"})
        for user in users_db.values()
    ]

@app.get("/auth/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: dict = Depends(require_permission(Permission.USER_READ))
):
    """Get a specific user by ID."""
    for user in users_db.values():
        if user["id"] == user_id:
            return UserResponse(**{k: v for k, v in user.items() if k != "hashed_password"})
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="User not found"
    )

@app.put("/auth/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    update_data: UserUpdate,
    current_user: dict = Depends(require_permission(Permission.USER_UPDATE))
):
    """Update a user (admin only)."""
    target_user = None
    target_email = None
    
    for email, user in users_db.items():
        if user["id"] == user_id:
            target_user = user
            target_email = email
            break
    
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update user data
    if update_data.full_name is not None:
        target_user["full_name"] = update_data.full_name
    if update_data.role is not None:
        target_user["role"] = update_data.role
    if update_data.is_active is not None:
        target_user["is_active"] = update_data.is_active
    
    logger.info(f"User updated: {target_email} by {current_user['email']}")
    
    return UserResponse(**{k: v for k, v in target_user.items() if k != "hashed_password"})

@app.delete("/auth/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: dict = Depends(require_permission(Permission.USER_DELETE))
):
    """Delete a user (admin only)."""
    target_email = None
    
    for email, user in users_db.items():
        if user["id"] == user_id:
            target_email = email
            break
    
    if not target_email:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent self-deletion
    if target_email == current_user["email"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    del users_db[target_email]
    
    logger.info(f"User deleted: {target_email} by {current_user['email']}")
    
    return {"message": "User deleted successfully"}

@app.post("/auth/validate")
async def validate_token(current_user: dict = Depends(get_current_user)):
    """Validate a JWT token and return user info."""
    return {
        "valid": True,
        "user": UserResponse(**{k: v for k, v in current_user.items() if k != "hashed_password"}),
        "permissions": ROLE_PERMISSIONS.get(UserRole(current_user["role"]), [])
    }

@app.get("/auth/roles")
async def list_roles():
    """List all available roles and their permissions."""
    return {
        "roles": {
            role.value: {
                "name": role.value,
                "permissions": [perm.value for perm in permissions]
            }
            for role, permissions in ROLE_PERMISSIONS.items()
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
