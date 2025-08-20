"""
Unit tests for security configuration validation.

This module tests JWT settings, authentication configuration,
CORS settings, and other security-related configurations.
"""

import os
import pytest
from unittest.mock import patch, MagicMock
import secrets
from datetime import timedelta

from sentinel_backend.config.settings import (
    SecuritySettings,
    get_security_settings
)
from sentinel_backend.config.validation import ConfigurationValidator


class TestSecuritySettings:
    """Test suite for security configuration settings."""
    
    @pytest.fixture
    def security_settings(self):
        """Create SecuritySettings instance."""
        return get_security_settings()
    
    def test_jwt_secret_key_validation(self):
        """Test JWT secret key validation."""
        validator = ConfigurationValidator()
        
        # Test with weak secret key
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_JWT_SECRET_KEY': 'weak'
        }):
            validator.errors = []
            validator._validate_security_settings()
            
            assert len(validator.errors) > 0
            assert any("jwt" in error.lower() and "secret" in error.lower() 
                      for error in validator.errors)
    
    def test_jwt_secret_key_strength(self):
        """Test JWT secret key strength requirements."""
        validator = ConfigurationValidator()
        
        # Test with strong secret key
        strong_key = secrets.token_urlsafe(32)
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_JWT_SECRET_KEY': strong_key
        }):
            validator.errors = []
            validator._validate_security_settings()
            
            # Should not have errors for strong key
            jwt_errors = [e for e in validator.errors if "jwt" in e.lower()]
            assert len(jwt_errors) == 0
    
    def test_jwt_expiration_settings(self):
        """Test JWT token expiration configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_JWT_EXPIRATION_HOURS': '24',
            'SENTINEL_SECURITY_JWT_REFRESH_EXPIRATION_DAYS': '7'
        }):
            settings = get_security_settings()
            
            assert settings.jwt_expiration_hours == 24
            assert settings.jwt_refresh_expiration_days == 7
    
    def test_invalid_jwt_expiration(self):
        """Test validation of invalid JWT expiration values."""
        validator = ConfigurationValidator()
        
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_JWT_EXPIRATION_HOURS': '-1'
        }):
            validator.errors = []
            validator._validate_security_settings()
            
            assert len(validator.errors) > 0
            assert any("expiration" in error.lower() for error in validator.errors)
    
    def test_default_admin_credentials_validation(self):
        """Test validation of default admin credentials."""
        validator = ConfigurationValidator()
        
        # Test with default/weak admin password in production
        with patch.dict(os.environ, {
            'SENTINEL_ENVIRONMENT': 'production',
            'SENTINEL_SECURITY_DEFAULT_ADMIN_PASSWORD': 'admin123'
        }):
            validator.environment = 'production'
            validator.warnings = []
            validator._validate_security_settings()
            
            assert len(validator.warnings) > 0
            assert any("admin" in warning.lower() and "password" in warning.lower() 
                      for warning in validator.warnings)
    
    def test_cors_configuration(self):
        """Test CORS configuration settings."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_CORS_ORIGINS': '["http://localhost:3000", "https://app.example.com"]',
            'SENTINEL_SECURITY_CORS_ALLOW_CREDENTIALS': 'true',
            'SENTINEL_SECURITY_CORS_MAX_AGE': '3600'
        }):
            settings = get_security_settings()
            
            assert "http://localhost:3000" in settings.cors_origins
            assert "https://app.example.com" in settings.cors_origins
            assert settings.cors_allow_credentials is True
            assert settings.cors_max_age == 3600
    
    def test_cors_wildcard_warning(self):
        """Test warning for wildcard CORS origins."""
        validator = ConfigurationValidator()
        
        with patch.dict(os.environ, {
            'SENTINEL_ENVIRONMENT': 'production',
            'SENTINEL_SECURITY_CORS_ORIGINS': '["*"]'
        }):
            validator.environment = 'production'
            validator.warnings = []
            validator._validate_security_settings()
            
            assert len(validator.warnings) > 0
            assert any("cors" in warning.lower() and "wildcard" in warning.lower() 
                      for warning in validator.warnings)
    
    def test_rate_limiting_configuration(self):
        """Test rate limiting configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_RATE_LIMIT_ENABLED': 'true',
            'SENTINEL_SECURITY_RATE_LIMIT_REQUESTS': '100',
            'SENTINEL_SECURITY_RATE_LIMIT_WINDOW': '60'
        }):
            settings = get_security_settings()
            
            assert settings.rate_limit_enabled is True
            assert settings.rate_limit_requests == 100
            assert settings.rate_limit_window == 60
    
    def test_password_policy_configuration(self):
        """Test password policy configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_PASSWORD_MIN_LENGTH': '12',
            'SENTINEL_SECURITY_PASSWORD_REQUIRE_UPPERCASE': 'true',
            'SENTINEL_SECURITY_PASSWORD_REQUIRE_LOWERCASE': 'true',
            'SENTINEL_SECURITY_PASSWORD_REQUIRE_NUMBERS': 'true',
            'SENTINEL_SECURITY_PASSWORD_REQUIRE_SPECIAL': 'true'
        }):
            settings = get_security_settings()
            
            assert settings.password_min_length == 12
            assert settings.password_require_uppercase is True
            assert settings.password_require_lowercase is True
            assert settings.password_require_numbers is True
            assert settings.password_require_special is True
    
    def test_session_configuration(self):
        """Test session management configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_SESSION_TIMEOUT': '1800',
            'SENTINEL_SECURITY_SESSION_SECURE_COOKIE': 'true',
            'SENTINEL_SECURITY_SESSION_HTTPONLY': 'true',
            'SENTINEL_SECURITY_SESSION_SAMESITE': 'strict'
        }):
            settings = get_security_settings()
            
            assert settings.session_timeout == 1800
            assert settings.session_secure_cookie is True
            assert settings.session_httponly is True
            assert settings.session_samesite == 'strict'
    
    def test_api_key_configuration(self):
        """Test API key configuration settings."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_API_KEY_ENABLED': 'true',
            'SENTINEL_SECURITY_API_KEY_HEADER': 'X-API-Key',
            'SENTINEL_SECURITY_API_KEY_LENGTH': '32'
        }):
            settings = get_security_settings()
            
            assert settings.api_key_enabled is True
            assert settings.api_key_header == 'X-API-Key'
            assert settings.api_key_length == 32
    
    def test_encryption_configuration(self):
        """Test encryption configuration settings."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_ENCRYPTION_KEY': secrets.token_urlsafe(32),
            'SENTINEL_SECURITY_ENCRYPTION_ALGORITHM': 'AES256'
        }):
            settings = get_security_settings()
            
            assert settings.encryption_key is not None
            assert settings.encryption_algorithm == 'AES256'
    
    def test_audit_logging_configuration(self):
        """Test audit logging configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_AUDIT_LOG_ENABLED': 'true',
            'SENTINEL_SECURITY_AUDIT_LOG_LEVEL': 'INFO',
            'SENTINEL_SECURITY_AUDIT_LOG_RETENTION_DAYS': '90'
        }):
            settings = get_security_settings()
            
            assert settings.audit_log_enabled is True
            assert settings.audit_log_level == 'INFO'
            assert settings.audit_log_retention_days == 90


class TestSecurityValidationRules:
    """Test specific security validation rules."""
    
    def test_production_security_requirements(self):
        """Test that production environment enforces strict security."""
        validator = ConfigurationValidator()
        
        with patch.dict(os.environ, {
            'SENTINEL_ENVIRONMENT': 'production',
            'SENTINEL_SECURITY_JWT_SECRET_KEY': 'weak',
            'SENTINEL_SECURITY_SESSION_SECURE_COOKIE': 'false',
            'SENTINEL_SECURITY_CORS_ORIGINS': '["*"]'
        }):
            validator.environment = 'production'
            validator.errors = []
            validator.warnings = []
            validator._validate_security_settings()
            
            # Should have multiple security issues
            assert len(validator.errors) > 0
            assert len(validator.warnings) > 0
    
    def test_development_security_relaxation(self):
        """Test that development environment allows relaxed security."""
        validator = ConfigurationValidator()
        
        with patch.dict(os.environ, {
            'SENTINEL_ENVIRONMENT': 'development',
            'SENTINEL_SECURITY_SESSION_SECURE_COOKIE': 'false',
            'SENTINEL_SECURITY_CORS_ORIGINS': '["*"]'
        }):
            validator.environment = 'development'
            validator.errors = []
            validator.warnings = []
            validator._validate_security_settings()
            
            # Should not have errors in development
            assert len(validator.errors) == 0
            # May have warnings
            assert len(validator.warnings) >= 0
    
    def test_rbac_configuration(self):
        """Test Role-Based Access Control configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_RBAC_ENABLED': 'true',
            'SENTINEL_SECURITY_DEFAULT_ROLE': 'viewer',
            'SENTINEL_SECURITY_ADMIN_ROLE': 'admin'
        }):
            settings = get_security_settings()
            
            assert settings.rbac_enabled is True
            assert settings.default_role == 'viewer'
            assert settings.admin_role == 'admin'
    
    def test_oauth_configuration(self):
        """Test OAuth configuration settings."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_OAUTH_ENABLED': 'true',
            'SENTINEL_SECURITY_OAUTH_PROVIDER': 'google',
            'SENTINEL_SECURITY_OAUTH_CLIENT_ID': 'client-id',
            'SENTINEL_SECURITY_OAUTH_CLIENT_SECRET': 'client-secret'
        }):
            settings = get_security_settings()
            
            assert settings.oauth_enabled is True
            assert settings.oauth_provider == 'google'
            assert settings.oauth_client_id == 'client-id'
            assert settings.oauth_client_secret == 'client-secret'
    
    def test_security_headers_configuration(self):
        """Test security headers configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_SECURITY_CSP_ENABLED': 'true',
            'SENTINEL_SECURITY_HSTS_ENABLED': 'true',
            'SENTINEL_SECURITY_HSTS_MAX_AGE': '31536000',
            'SENTINEL_SECURITY_X_FRAME_OPTIONS': 'DENY'
        }):
            settings = get_security_settings()
            
            assert settings.csp_enabled is True
            assert settings.hsts_enabled is True
            assert settings.hsts_max_age == 31536000
            assert settings.x_frame_options == 'DENY'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])