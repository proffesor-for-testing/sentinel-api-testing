"""
Unit tests for database configuration and connection validation.

This module tests database connection strings, pool settings,
migration configuration, and database-specific settings.
"""

import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from urllib.parse import urlparse

from sentinel_backend.config.settings import (
    DatabaseSettings,
    get_database_settings
)
from sentinel_backend.config.validation import ConfigurationValidator


class TestDatabaseConfiguration:
    """Test suite for database configuration."""
    
    @pytest.fixture
    def db_settings(self):
        """Create DatabaseSettings instance."""
        return get_database_settings()
    
    def test_database_url_parsing(self):
        """Test parsing of database connection URLs."""
        test_urls = [
            ("postgresql://user:pass@localhost/db", "postgresql", "localhost", "db"),
            ("postgresql+asyncpg://user:pass@host:5432/mydb", "postgresql+asyncpg", "host", "mydb"),
            ("mysql://root:password@127.0.0.1:3306/test", "mysql", "127.0.0.1", "test"),
        ]
        
        for url, expected_scheme, expected_host, expected_db in test_urls:
            parsed = urlparse(url)
            assert parsed.scheme == expected_scheme
            assert parsed.hostname == expected_host
            assert parsed.path.lstrip('/') == expected_db
    
    def test_database_pool_configuration(self):
        """Test database connection pool settings."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_POOL_SIZE': '20',
            'SENTINEL_DB_MAX_OVERFLOW': '30',
            'SENTINEL_DB_POOL_TIMEOUT': '60',
            'SENTINEL_DB_POOL_RECYCLE': '7200'
        }):
            settings = get_database_settings()
            
            assert settings.pool_size == 20
            assert settings.max_overflow == 30
            assert settings.pool_timeout == 60
            assert settings.pool_recycle == 7200
    
    def test_invalid_pool_size_validation(self):
        """Test validation of invalid pool size settings."""
        validator = ConfigurationValidator()
        
        with patch.dict(os.environ, {
            'SENTINEL_DB_POOL_SIZE': '0',
            'SENTINEL_DB_MAX_OVERFLOW': '-1'
        }):
            validator.errors = []
            validator._validate_database_settings()
            
            assert len(validator.errors) > 0
            assert any("pool" in error.lower() for error in validator.errors)
    
    def test_database_url_validation(self):
        """Test validation of database URL format."""
        validator = ConfigurationValidator()
        
        # Test invalid URL
        with patch.dict(os.environ, {
            'SENTINEL_DB_URL': 'not-a-valid-url'
        }):
            validator.errors = []
            validator._validate_database_settings()
            
            assert len(validator.errors) > 0
            assert any("database" in error.lower() and "url" in error.lower() 
                      for error in validator.errors)
    
    def test_supported_database_drivers(self):
        """Test validation of supported database drivers."""
        validator = ConfigurationValidator()
        
        supported_drivers = [
            "postgresql://localhost/db",
            "postgresql+asyncpg://localhost/db",
            "postgresql+psycopg2://localhost/db",
            "mysql://localhost/db",
            "mysql+aiomysql://localhost/db",
            "sqlite:///path/to/db.sqlite"
        ]
        
        for url in supported_drivers:
            with patch.dict(os.environ, {'SENTINEL_DB_URL': url}):
                validator.errors = []
                validator._validate_database_settings()
                
                driver_errors = [e for e in validator.errors if "unsupported" in e.lower()]
                assert len(driver_errors) == 0
    
    def test_database_migration_settings(self):
        """Test database migration configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_AUTO_MIGRATE': 'true',
            'SENTINEL_DB_MIGRATION_TIMEOUT': '600'
        }):
            settings = get_database_settings()
            
            assert settings.auto_migrate is True
            assert settings.migration_timeout == 600
    
    def test_database_ssl_configuration(self):
        """Test database SSL connection configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_SSL_MODE': 'require',
            'SENTINEL_DB_SSL_CERT': '/path/to/cert.pem',
            'SENTINEL_DB_SSL_KEY': '/path/to/key.pem',
            'SENTINEL_DB_SSL_CA': '/path/to/ca.pem'
        }):
            settings = get_database_settings()
            
            assert settings.ssl_mode == 'require'
            assert settings.ssl_cert == '/path/to/cert.pem'
            assert settings.ssl_key == '/path/to/key.pem'
            assert settings.ssl_ca == '/path/to/ca.pem'
    
    @pytest.mark.asyncio
    async def test_database_connection_validation(self):
        """Test actual database connection validation."""
        validator = ConfigurationValidator()
        
        with patch('sentinel_backend.config.validation.create_async_engine') as mock_engine:
            mock_conn = AsyncMock()
            mock_engine.return_value.connect.return_value.__aenter__.return_value = mock_conn
            
            result = await validator._test_database_connection()
            
            assert result is True
            mock_engine.assert_called_once()
    
    def test_database_schema_configuration(self):
        """Test database schema configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_SCHEMA': 'sentinel',
            'SENTINEL_DB_CREATE_SCHEMA': 'true'
        }):
            settings = get_database_settings()
            
            assert settings.schema == 'sentinel'
            assert settings.create_schema is True
    
    def test_database_connection_retry_settings(self):
        """Test database connection retry configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_CONNECT_RETRY_COUNT': '5',
            'SENTINEL_DB_CONNECT_RETRY_INTERVAL': '2'
        }):
            settings = get_database_settings()
            
            assert settings.connect_retry_count == 5
            assert settings.connect_retry_interval == 2
    
    def test_database_query_settings(self):
        """Test database query configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_QUERY_TIMEOUT': '30',
            'SENTINEL_DB_STATEMENT_TIMEOUT': '60000',
            'SENTINEL_DB_LOCK_TIMEOUT': '10000'
        }):
            settings = get_database_settings()
            
            assert settings.query_timeout == 30
            assert settings.statement_timeout == 60000
            assert settings.lock_timeout == 10000
    
    def test_database_backup_configuration(self):
        """Test database backup configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_BACKUP_ENABLED': 'true',
            'SENTINEL_DB_BACKUP_SCHEDULE': '0 2 * * *',
            'SENTINEL_DB_BACKUP_RETENTION_DAYS': '30'
        }):
            settings = get_database_settings()
            
            assert settings.backup_enabled is True
            assert settings.backup_schedule == '0 2 * * *'
            assert settings.backup_retention_days == 30
    
    def test_read_replica_configuration(self):
        """Test read replica database configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_READ_REPLICA_URL': 'postgresql://replica.example.com/db',
            'SENTINEL_DB_USE_READ_REPLICA': 'true'
        }):
            settings = get_database_settings()
            
            assert settings.read_replica_url == 'postgresql://replica.example.com/db'
            assert settings.use_read_replica is True
    
    def test_database_monitoring_configuration(self):
        """Test database monitoring configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_MONITORING_ENABLED': 'true',
            'SENTINEL_DB_SLOW_QUERY_THRESHOLD': '1000',
            'SENTINEL_DB_LOG_QUERIES': 'true'
        }):
            settings = get_database_settings()
            
            assert settings.monitoring_enabled is True
            assert settings.slow_query_threshold == 1000
            assert settings.log_queries is True


class TestDatabaseConnectionStrings:
    """Test various database connection string formats."""
    
    def test_postgresql_connection_strings(self):
        """Test PostgreSQL connection string variations."""
        test_cases = [
            "postgresql://user:pass@localhost/db",
            "postgresql+asyncpg://user:pass@localhost:5432/db",
            "postgresql://user:pass@host1,host2,host3/db",  # Multiple hosts
            "postgresql://user:pass@localhost/db?sslmode=require",
            "postgresql://user:pass@localhost/db?connect_timeout=10&application_name=sentinel"
        ]
        
        for conn_str in test_cases:
            with patch.dict(os.environ, {'SENTINEL_DB_URL': conn_str}):
                settings = get_database_settings()
                assert settings.url == conn_str
    
    def test_mysql_connection_strings(self):
        """Test MySQL connection string variations."""
        test_cases = [
            "mysql://root:password@localhost/db",
            "mysql+aiomysql://user:pass@localhost:3306/db",
            "mysql://user:pass@localhost/db?charset=utf8mb4",
            "mysql://user:pass@localhost/db?ssl_ca=/path/to/ca.pem"
        ]
        
        for conn_str in test_cases:
            with patch.dict(os.environ, {'SENTINEL_DB_URL': conn_str}):
                settings = get_database_settings()
                assert settings.url == conn_str
    
    def test_connection_string_with_special_characters(self):
        """Test connection strings with special characters in password."""
        special_passwords = [
            "p@ssw0rd!",
            "pass#word$123",
            "p%40ssword",  # URL encoded @
            "pass&word=test"
        ]
        
        for password in special_passwords:
            conn_str = f"postgresql://user:{password}@localhost/db"
            with patch.dict(os.environ, {'SENTINEL_DB_URL': conn_str}):
                settings = get_database_settings()
                assert password in settings.url or "%" in settings.url


class TestDatabaseFailover:
    """Test database failover and high availability configuration."""
    
    def test_failover_configuration(self):
        """Test database failover configuration."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_FAILOVER_ENABLED': 'true',
            'SENTINEL_DB_PRIMARY_URL': 'postgresql://primary.example.com/db',
            'SENTINEL_DB_STANDBY_URLS': '["postgresql://standby1.example.com/db", "postgresql://standby2.example.com/db"]'
        }):
            settings = get_database_settings()
            
            assert settings.failover_enabled is True
            assert settings.primary_url == 'postgresql://primary.example.com/db'
            assert len(settings.standby_urls) == 2
    
    def test_connection_pool_per_host(self):
        """Test connection pool configuration per host."""
        with patch.dict(os.environ, {
            'SENTINEL_DB_POOL_SIZE_PER_HOST': '5',
            'SENTINEL_DB_MAX_HOSTS': '3'
        }):
            settings = get_database_settings()
            
            assert settings.pool_size_per_host == 5
            assert settings.max_hosts == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])