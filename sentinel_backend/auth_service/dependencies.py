"""
Authentication dependencies that can be easily mocked for testing.
"""
from typing import Optional, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from datetime import datetime

# This can be overridden in tests
security = HTTPBearer()

# Global that can be replaced in tests
_get_current_user_impl: Optional[Callable] = None
_require_permission_impl: Optional[Callable] = None


def get_security():
    """Get the security scheme - can be overridden in tests."""
    return security


def set_test_auth_implementations(
    get_current_user_func: Optional[Callable] = None,
    require_permission_func: Optional[Callable] = None
):
    """Set test implementations for auth functions."""
    global _get_current_user_impl, _require_permission_impl
    _get_current_user_impl = get_current_user_func
    _require_permission_impl = require_permission_func


def reset_auth_implementations():
    """Reset auth implementations to None."""
    global _get_current_user_impl, _require_permission_impl
    _get_current_user_impl = None
    _require_permission_impl = None


async def get_current_user_wrapper(credentials: HTTPAuthorizationCredentials = Depends(get_security())):
    """Wrapper that delegates to either test or real implementation."""
    if _get_current_user_impl:
        return await _get_current_user_impl(credentials)
    
    # Import here to avoid circular imports
    from auth_service.main import get_current_user as real_get_current_user
    return real_get_current_user(credentials)


def require_permission_wrapper(permission):
    """Wrapper that delegates to either test or real implementation."""
    if _require_permission_impl:
        return _require_permission_impl(permission)
    
    # Import here to avoid circular imports
    from auth_service.main import require_permission as real_require_permission
    return real_require_permission(permission)