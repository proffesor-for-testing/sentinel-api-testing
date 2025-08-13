from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import structlog
import uuid
from enum import Enum
from prometheus_fastapi_instrumentator import Instrumentator

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

# Configuration from centralized settings
JWT_SECRET_KEY = security_settings.jwt_secret_key
JWT_ALGORITHM = security_settings.jwt_algorithm
JWT_EXPIRATION_HOURS = security_settings.jwt_expiration_hours

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
    token_type: str
    expires_in: int
    user: UserResponse

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
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

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

@app.post("/auth/login", response_model=TokenResponse)
async def login_user(login_data: UserLogin):
    """Authenticate user and return access token."""
    user = users_db.get(login_data.email)
    
    if not user or not verify_password(login_data.password, user["hashed_password"]):
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
    
    # Create access token
    access_token = create_access_token(user)
    
    logger.info(f"User logged in: {login_data.email}")
    
    return TokenResponse(
        access_token=access_token,
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
