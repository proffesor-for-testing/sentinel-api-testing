"""
Authentication middleware for Sentinel services.
This module provides reusable authentication and authorization utilities.
"""

from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
import os
from typing import Dict, List, Optional, Any
import logging
import structlog
from enum import Enum

# Import configuration
from config.settings import get_service_settings

# Get configuration
service_settings = get_service_settings()

logger = logging.getLogger(__name__)

security = HTTPBearer()

class AuthenticationError(Exception):
    """Custom exception for authentication errors."""
    pass

class AuthorizationError(Exception):
    """Custom exception for authorization errors."""
    pass

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Validate JWT token and return current user information.
    This function can be used as a FastAPI dependency.
    """
    token = credentials.credentials
    
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            # Get correlation ID from context
            headers = {"Authorization": f"Bearer {token}"}
            try:
                context_vars = structlog.contextvars.get_contextvars()
                correlation_id = context_vars.get("correlation_id")
                if correlation_id:
                    headers["X-Correlation-ID"] = correlation_id
            except:
                pass  # If no correlation ID context, continue without it
                
            response = await client.post(
                f"{service_settings.auth_service_url}/auth/validate",
                headers=headers
            )
            
            if response.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            elif response.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication service unavailable"
                )
            
            try:
                auth_data = response.json()
                return {
                    "user": auth_data["user"],
                    "token": token,
                    "permissions": auth_data["permissions"]
                }
            except (ValueError, KeyError) as e:
                logger.error(f"Malformed response from auth service: {e}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Authentication service returned invalid response"
                )
            
        except httpx.TimeoutException:
            logger.error("Authentication service timeout")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Auth service timeout"
            )
        except httpx.RequestError:
            logger.error("Failed to connect to authentication service")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Auth service unavailable"
            )

def require_permission(permission: str):
    """
    Create a dependency that requires a specific permission.
    
    Args:
        permission: The required permission (e.g., "spec:create")
    
    Returns:
        FastAPI dependency function
    """
    async def permission_checker(auth_data: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if auth_data is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required"
            )
            
        user_permissions = auth_data.get("permissions", [])
        
        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission}"
            )
        
        return auth_data
    
    return permission_checker

def require_any_permission(permissions: List[str]):
    """
    Create a dependency that requires any of the specified permissions.
    
    Args:
        permissions: List of acceptable permissions
    
    Returns:
        FastAPI dependency function
    """
    async def permission_checker(auth_data: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_permissions = auth_data.get("permissions", [])
        
        if not any(perm in user_permissions for perm in permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required one of: {', '.join(permissions)}"
            )
        
        return auth_data
    
    return permission_checker

def require_role(required_role: str):
    """
    Create a dependency that requires a specific role or higher.
    
    Args:
        required_role: The minimum required role
    
    Returns:
        FastAPI dependency function
    """
    role_hierarchy = {
        "viewer": 0,
        "tester": 1,
        "manager": 2,
        "admin": 3
    }
    
    async def role_checker(auth_data: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = auth_data["user"]["role"]
        
        if role_hierarchy.get(user_role, -1) < role_hierarchy.get(required_role, 999):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required: {required_role} or higher"
            )
        
        return auth_data
    
    return role_checker

async def optional_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))) -> Optional[Dict[str, Any]]:
    """
    Optional authentication - returns user data if token is provided and valid, None otherwise.
    Useful for endpoints that have different behavior for authenticated vs anonymous users.
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None

class AuthMiddleware:
    """
    Middleware class for handling authentication across services.
    """
    
    def __init__(self, auth_service_url: str = None):
        self.auth_service_url = auth_service_url or service_settings.auth_service_url
    
    async def validate_token(self, token: str) -> Dict[str, Any]:
        """Validate a JWT token and return user data."""
        async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
            try:
                response = await client.post(
                    f"{self.auth_service_url}/auth/validate",
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    raise AuthenticationError("Invalid token")
                    
            except httpx.RequestError:
                raise AuthenticationError("Authentication service unavailable")
    
    async def check_permission(self, token: str, permission: str) -> bool:
        """Check if a token has a specific permission."""
        try:
            auth_data = await self.validate_token(token)
            permissions = auth_data.get("permissions", [])
            return permission in permissions
        except AuthenticationError:
            return False
    
    async def get_user_from_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get user data from token, return None if invalid."""
        try:
            auth_data = await self.validate_token(token)
            return auth_data.get("user")
        except AuthenticationError:
            return None

# Global middleware instance
auth_middleware = AuthMiddleware()

# Common permission constants for easy import
class Permissions(str, Enum):
    """Common permission constants."""
    
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

# Common role constants
class Roles:
    """Common role constants."""
    ADMIN = "admin"
    MANAGER = "manager"
    TESTER = "tester"
    VIEWER = "viewer"
