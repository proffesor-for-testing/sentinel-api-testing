"""
Unit tests for configuration validation and environment-specific settings.

This module tests the configuration loading, validation rules, and
environment-specific behavior of the Sentinel platform configuration system.
"""

import os
import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
import tempfile

from sentinel_backend.config.validation import (
    ConfigurationValidator,
    ConfigurationError,
    StartupChecker,
    ConfigurationManager,
    ConfigurationReporter
)
from sentinel_backend.config.settings import (
    Environment,
    DatabaseSettings,
    ServiceSettings,
    ApplicationSettings,
    get_database_settings,
    get_service_settings,
    get_application_settings
)


class TestConfigurationValidator:
    """Test suite for ConfigurationValidator."""
    
    @pytest.fixture
    def validator(self):
        """Create a ConfigurationValidator instance."""
        return ConfigurationValidator()
    
    def test_validate_all_success(self, validator):
        """Test successful validation of all configuration."""
        with patch.multiple(validator,
                          _validate_environment=MagicMock(),
                          _validate_database_settings=MagicMock(),
                          _validate_service_settings=MagicMock(),
                          _validate_security_settings=MagicMock(),
                          _validate_network_settings=MagicMock(),
                          _validate_application_settings=MagicMock(),
                          _validate_file_permissions=MagicMock(),
                          _validate_dependencies=MagicMock()):
            
            is_valid, errors, warnings = validator.validate_all()
            
            assert is_valid is True
            assert errors == []
            assert warnings == []
    
    def test_validate_environment_valid(self, validator):
        """Test validation of valid environment settings."""
        for env in ["development", "testing", "production", "docker"]:
            validator.environment = env
            validator.errors = []
            validator._validate_environment()
            assert len(validator.errors) == 0
    
    def test_validate_environment_invalid(self, validator):
        """Test validation of invalid environment settings."""
        validator.environment = "invalid_env"
        validator.errors = []
        validator._validate_environment()
        
        assert len(validator.errors) == 1
        assert "Invalid environment" in validator.errors[0]
    
    def test_validate_production_environment_missing_vars(self, validator):
        """Test validation of production environment with missing variables."""
        validator.environment = "production"
        validator.errors = []
        
        with patch.dict(os.environ, {}, clear=True):
            validator._validate_environment()
            
            assert len(validator.errors) > 0
            assert any("JWT_SECRET_KEY" in error for error in validator.errors)
            assert any("DB_URL" in error for error in validator.errors)
    
    @patch('sentinel_backend.config.validation.get_database_settings')
    def test_validate_database_settings_valid(self, mock_get_db, validator):
        """Test validation of valid database settings."""
        mock_settings = MagicMock()
        mock_settings.url = "postgresql+asyncpg://user:pass@localhost:5432/db"
        mock_settings.pool_size = 10
        mock_settings.max_overflow = 20
        mock_get_db.return_value = mock_settings
        
        validator.errors = []
        validator._validate_database_settings()
        
        assert len(validator.errors) == 0
    
    @patch('sentinel_backend.config.validation.get_database_settings')
    def test_validate_database_settings_invalid_url(self, mock_get_db, validator):
        """Test validation of invalid database URL."""
        mock_settings = MagicMock()
        mock_settings.url = "invalid://url"
        mock_settings.pool_size = 10
        mock_get_db.return_value = mock_settings
        
        validator.errors = []
        validator._validate_database_settings()
        
        assert len(validator.errors) > 0
        assert any("database" in error.lower() for error in validator.errors)
    
    @patch('sentinel_backend.config.validation.get_service_settings')
    def test_validate_service_settings_valid(self, mock_get_service, validator):
        """Test validation of valid service settings."""
        mock_settings = MagicMock()
        mock_settings.auth_service_url = "http://auth:8000"
        mock_settings.spec_service_url = "http://spec:8001"
        mock_settings.service_timeout = 30
        mock_get_service.return_value = mock_settings
        
        validator.errors = []
        validator._validate_service_settings()
        
        assert len(validator.errors) == 0
    
    def test_validate_file_permissions(self, validator):
        """Test validation of file permissions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.txt"
            test_file.write_text("test")
            
            validator.errors = []
            validator.warnings = []
            
            with patch('sentinel_backend.config.validation.Path') as mock_path:
                mock_path.return_value.exists.return_value = True
                mock_path.return_value.is_file.return_value = True
                mock_path.return_value.stat.return_value.st_mode = 0o644
                
                validator._validate_file_permissions()
                
                # Should not have errors for normal file permissions
                assert len(validator.errors) == 0


class TestEnvironmentSpecificConfiguration:
    """Test environment-specific configuration loading."""
    
    def test_development_environment_config(self):
        """Test configuration loading for development environment."""
        with patch.dict(os.environ, {'SENTINEL_ENVIRONMENT': 'development'}):
            db_settings = get_database_settings()
            app_settings = get_application_settings()
            
            assert app_settings.debug is True
            assert app_settings.enable_docs is True
            assert "localhost" in db_settings.url or "127.0.0.1" in db_settings.url
    
    def test_production_environment_config(self):
        """Test configuration loading for production environment."""
        with patch.dict(os.environ, {
            'SENTINEL_ENVIRONMENT': 'production',
            'SENTINEL_APP_DEBUG': 'false',
            'SENTINEL_APP_ENABLE_DOCS': 'false'
        }):
            app_settings = get_application_settings()
            
            assert app_settings.debug is False
            assert app_settings.enable_docs is False
    
    def test_testing_environment_config(self):
        """Test configuration loading for testing environment."""
        with patch.dict(os.environ, {'SENTINEL_ENVIRONMENT': 'testing'}):
            db_settings = get_database_settings()
            app_settings = get_application_settings()
            
            assert app_settings.debug is True
            assert "test" in db_settings.url or app_settings.environment == "testing"
    
    def test_docker_environment_config(self):
        """Test configuration loading for Docker environment."""
        with patch.dict(os.environ, {'SENTINEL_ENVIRONMENT': 'docker'}):
            service_settings = get_service_settings()
            
            # In Docker, services use container names
            assert "auth_service" in service_settings.auth_service_url or \
                   "localhost" not in service_settings.auth_service_url


class TestConfigurationHotReload:
    """Test configuration hot reload functionality."""
    
    def test_reload_on_env_change(self):
        """Test configuration reload when environment variables change."""
        original_value = os.environ.get('SENTINEL_APP_MAX_TEST_CASES_PER_SPEC')
        
        try:
            # Set initial value
            os.environ['SENTINEL_APP_MAX_TEST_CASES_PER_SPEC'] = '100'
            settings1 = get_application_settings()
            assert settings1.max_test_cases_per_spec == 100
            
            # Change value
            os.environ['SENTINEL_APP_MAX_TEST_CASES_PER_SPEC'] = '200'
            # Clear cache to force reload
            get_application_settings.cache_clear()
            settings2 = get_application_settings()
            assert settings2.max_test_cases_per_spec == 200
            
        finally:
            # Restore original value
            if original_value:
                os.environ['SENTINEL_APP_MAX_TEST_CASES_PER_SPEC'] = original_value
            else:
                os.environ.pop('SENTINEL_APP_MAX_TEST_CASES_PER_SPEC', None)
            get_application_settings.cache_clear()


class TestConfigurationOverrides:
    """Test configuration override mechanisms."""
    
    def test_env_file_override(self):
        """Test that .env file values can be overridden by environment variables."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.env', delete=False) as f:
            f.write("SENTINEL_APP_MAX_CONCURRENT_AGENTS=5\n")
            env_file = f.name
        
        try:
            # Override with environment variable
            with patch.dict(os.environ, {
                'SENTINEL_APP_MAX_CONCURRENT_AGENTS': '10',
                'SENTINEL_ENV_FILE': env_file
            }):
                settings = get_application_settings()
                # Environment variable should take precedence
                assert settings.max_concurrent_agents == 10
        finally:
            os.unlink(env_file)
    
    def test_default_values_fallback(self):
        """Test that default values are used when no overrides exist."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear cache to ensure fresh load
            get_application_settings.cache_clear()
            settings = get_application_settings()
            
            # Should use default values
            assert settings.max_test_cases_per_spec > 0
            assert settings.max_concurrent_agents > 0
            assert settings.default_page_size > 0


class TestConfigurationValidationRules:
    """Test specific validation rules for configuration."""
    
    def test_validate_pool_size_limits(self):
        """Test validation of database pool size limits."""
        validator = ConfigurationValidator()
        
        with patch('sentinel_backend.config.validation.get_database_settings') as mock_get_db:
            # Test invalid pool size (too small)
            mock_settings = MagicMock()
            mock_settings.pool_size = 0
            mock_settings.max_overflow = 10
            mock_settings.url = "postgresql://localhost/db"
            mock_get_db.return_value = mock_settings
            
            validator.errors = []
            validator._validate_database_settings()
            
            assert len(validator.errors) > 0
            assert any("pool" in error.lower() for error in validator.errors)
    
    def test_validate_timeout_values(self):
        """Test validation of timeout configuration values."""
        validator = ConfigurationValidator()
        
        with patch('sentinel_backend.config.validation.get_service_settings') as mock_get_service:
            # Test invalid timeout (negative value)
            mock_settings = MagicMock()
            mock_settings.service_timeout = -1
            mock_settings.health_check_timeout = 5
            mock_get_service.return_value = mock_settings
            
            validator.errors = []
            validator._validate_service_settings()
            
            assert len(validator.errors) > 0
            assert any("timeout" in error.lower() for error in validator.errors)
    
    def test_validate_url_formats(self):
        """Test validation of URL formats in configuration."""
        validator = ConfigurationValidator()
        
        # Test various URL formats
        valid_urls = [
            "http://localhost:8000",
            "https://api.example.com",
            "postgresql://user:pass@localhost/db",
            "amqp://guest:guest@localhost:5672/"
        ]
        
        invalid_urls = [
            "not-a-url",
            "ftp://invalid-protocol.com",
            "http://",
            "://missing-protocol"
        ]
        
        for url in valid_urls:
            assert validator._is_valid_url(url) is True
        
        for url in invalid_urls:
            assert validator._is_valid_url(url) is False


class TestConfigurationDependencies:
    """Test configuration dependency validation."""
    
    def test_llm_provider_dependencies(self):
        """Test validation of LLM provider configuration dependencies."""
        validator = ConfigurationValidator()
        
        with patch.dict(os.environ, {
            'SENTINEL_APP_LLM_PROVIDER': 'openai',
            'SENTINEL_APP_OPENAI_API_KEY': ''
        }):
            validator.errors = []
            validator._validate_application_settings()
            
            # Should have error about missing API key
            assert len(validator.errors) > 0
            assert any("api" in error.lower() and "key" in error.lower() 
                      for error in validator.errors)
    
    def test_service_interdependencies(self):
        """Test validation of service interdependencies."""
        validator = ConfigurationValidator()
        
        with patch('sentinel_backend.config.validation.get_service_settings') as mock_get_service:
            mock_settings = MagicMock()
            # Auth service is required by all other services
            mock_settings.auth_service_url = ""
            mock_settings.spec_service_url = "http://spec:8001"
            mock_get_service.return_value = mock_settings
            
            validator.errors = []
            validator._validate_service_settings()
            
            assert len(validator.errors) > 0
            assert any("auth" in error.lower() for error in validator.errors)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])