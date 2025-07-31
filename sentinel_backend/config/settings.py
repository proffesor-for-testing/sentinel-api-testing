"""
Sentinel Configuration Settings

This module defines all configuration settings for the Sentinel platform using
Pydantic BaseSettings for type-safe configuration management with environment
variable support.
"""

import os
from typing import Optional, List, Dict, Any
from functools import lru_cache
from pydantic import Field, validator
from pydantic_settings import BaseSettings
from enum import Enum


class Environment(str, Enum):
    """Supported deployment environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"
    DOCKER = "docker"


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""
    
    # Connection settings
    url: str = Field(
        default="postgresql+asyncpg://sentinel:sentinel_password@localhost:5432/sentinel_db",
        description="Database connection URL"
    )
    
    # Pool settings
    pool_size: int = Field(default=10, description="Database connection pool size")
    max_overflow: int = Field(default=20, description="Maximum pool overflow")
    pool_timeout: int = Field(default=30, description="Pool timeout in seconds")
    pool_recycle: int = Field(default=3600, description="Pool recycle time in seconds")
    
    # Migration settings
    auto_migrate: bool = Field(default=True, description="Auto-run database migrations")
    migration_timeout: int = Field(default=300, description="Migration timeout in seconds")
    
    class Config:
        env_prefix = "SENTINEL_DB_"
        case_sensitive = False


class ServiceSettings(BaseSettings):
    """Inter-service communication settings."""
    
    # Service URLs
    auth_service_url: str = Field(
        default="http://auth_service:8005",
        description="Authentication service URL"
    )
    spec_service_url: str = Field(
        default="http://spec_service:8001", 
        description="Specification service URL"
    )
    orchestration_service_url: str = Field(
        default="http://orchestration_service:8002",
        description="Orchestration service URL"
    )
    data_service_url: str = Field(
        default="http://data_service:8004",
        description="Data service URL"
    )
    execution_service_url: str = Field(
        default="http://execution_service:8003",
        description="Execution service URL"
    )
    
    # Service timeouts
    service_timeout: int = Field(default=30, description="Default service timeout in seconds")
    health_check_timeout: int = Field(default=5, description="Health check timeout in seconds")
    health_check_interval: int = Field(default=30, description="Health check interval in seconds")
    
    class Config:
        env_prefix = "SENTINEL_SERVICE_"
        case_sensitive = False


class SecuritySettings(BaseSettings):
    """Security configuration settings."""
    
    # JWT settings
    jwt_secret_key: str = Field(
        default="sentinel-dev-secret-key-change-in-production",
        description="JWT secret key for token signing"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    jwt_expiration_hours: int = Field(default=24, description="JWT token expiration in hours")
    
    # Password settings
    password_min_length: int = Field(default=8, description="Minimum password length")
    password_require_uppercase: bool = Field(default=True, description="Require uppercase in passwords")
    password_require_lowercase: bool = Field(default=True, description="Require lowercase in passwords")
    password_require_numbers: bool = Field(default=True, description="Require numbers in passwords")
    password_require_special: bool = Field(default=False, description="Require special characters in passwords")
    
    # Session settings
    session_timeout_minutes: int = Field(default=60, description="Session timeout in minutes")
    max_login_attempts: int = Field(default=5, description="Maximum login attempts before lockout")
    lockout_duration_minutes: int = Field(default=15, description="Account lockout duration in minutes")
    
    # CORS settings
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8080"],
        description="Allowed CORS origins"
    )
    cors_allow_credentials: bool = Field(default=True, description="Allow CORS credentials")
    cors_allow_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="Allowed CORS methods"
    )
    cors_allow_headers: List[str] = Field(
        default=["*"],
        description="Allowed CORS headers"
    )
    
    # Rate limiting
    rate_limit_requests: int = Field(default=100, description="Rate limit requests per window")
    rate_limit_window_seconds: int = Field(default=60, description="Rate limit window in seconds")
    
    # Default admin user
    default_admin_email: str = Field(default="admin@sentinel.com", description="Default admin email")
    default_admin_password: str = Field(default="admin123", description="Default admin password")
    
    @validator('jwt_secret_key')
    def validate_jwt_secret(cls, v, values):
        """Validate JWT secret key strength."""
        if len(v) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")
        if v == "sentinel-dev-secret-key-change-in-production" and os.getenv("SENTINEL_ENV") == "production":
            raise ValueError("Default JWT secret key cannot be used in production")
        return v
    
    class Config:
        env_prefix = "SENTINEL_SECURITY_"
        case_sensitive = False


class NetworkSettings(BaseSettings):
    """Network and infrastructure settings."""
    
    # Service ports
    api_gateway_port: int = Field(default=8000, description="API Gateway port")
    auth_service_port: int = Field(default=8005, description="Auth service port")
    spec_service_port: int = Field(default=8001, description="Spec service port")
    orchestration_service_port: int = Field(default=8002, description="Orchestration service port")
    execution_service_port: int = Field(default=8003, description="Execution service port")
    data_service_port: int = Field(default=8004, description="Data service port")
    database_port: int = Field(default=5432, description="Database port")
    
    # Host settings
    host: str = Field(default="0.0.0.0", description="Service host binding")
    
    # Timeout settings
    http_timeout: int = Field(default=30, description="HTTP client timeout in seconds")
    websocket_timeout: int = Field(default=60, description="WebSocket timeout in seconds")
    
    # Health check settings
    health_check_enabled: bool = Field(default=True, description="Enable health checks")
    health_check_path: str = Field(default="/health", description="Health check endpoint path")
    
    class Config:
        env_prefix = "SENTINEL_NETWORK_"
        case_sensitive = False


class ApplicationSettings(BaseSettings):
    """Application-level configuration settings."""
    
    # General settings
    app_name: str = Field(default="Sentinel API Testing Platform", description="Application name")
    app_version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Enable debug mode")
    
    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string"
    )
    log_file: Optional[str] = Field(default=None, description="Log file path")
    
    # Pagination settings
    default_page_size: int = Field(default=20, description="Default pagination page size")
    max_page_size: int = Field(default=100, description="Maximum pagination page size")
    
    # Feature flags
    enable_analytics: bool = Field(default=True, description="Enable analytics features")
    enable_performance_testing: bool = Field(default=True, description="Enable performance testing")
    enable_security_testing: bool = Field(default=True, description="Enable security testing")
    enable_data_mocking: bool = Field(default=True, description="Enable data mocking")
    
    # Agent settings
    max_concurrent_agents: int = Field(default=10, description="Maximum concurrent agents")
    agent_timeout_seconds: int = Field(default=300, description="Agent execution timeout")
    
    # Test settings
    max_test_cases_per_spec: int = Field(default=1000, description="Maximum test cases per specification")
    test_execution_timeout: int = Field(default=600, description="Test execution timeout in seconds")
    
    # LLM settings
    llm_provider: str = Field(default="openai", description="LLM provider (openai, anthropic, etc.)")
    llm_api_key: Optional[str] = Field(default=None, description="LLM API key")
    llm_model: str = Field(default="gpt-3.5-turbo", description="LLM model name")
    llm_max_tokens: int = Field(default=2000, description="LLM maximum tokens")
    llm_temperature: float = Field(default=0.7, description="LLM temperature")
    
    # Data mocking settings
    data_mocking_default_count: int = Field(default=10, description="Default number of mock data items to generate")
    data_mocking_max_response_variations: int = Field(default=5, description="Maximum response variations per endpoint")
    data_mocking_max_parameter_variations: int = Field(default=3, description="Maximum parameter variations per endpoint")
    data_mocking_max_entity_variations: int = Field(default=5, description="Maximum entity variations per schema")
    data_mocking_faker_locale: str = Field(default="en_US", description="Faker locale for data generation")
    data_mocking_realistic_bias: float = Field(default=0.8, description="Bias towards realistic data generation (0.0-1.0)")
    
    # Security testing settings
    security_max_bola_vectors: int = Field(default=12, description="Maximum BOLA attack vectors per parameter")
    security_max_auth_scenarios: int = Field(default=4, description="Maximum authentication scenarios per test")
    security_test_timeout: int = Field(default=30, description="Security test timeout in seconds")
    security_enable_aggressive_testing: bool = Field(default=False, description="Enable aggressive security testing techniques")
    security_max_injection_payloads: int = Field(default=20, description="Maximum injection payloads per test")
    security_injection_timeout: int = Field(default=10, description="Injection test timeout in seconds")
    
    # Performance testing settings
    performance_default_users: int = Field(default=10, description="Default number of virtual users for performance tests")
    performance_max_users: int = Field(default=1000, description="Maximum number of virtual users")
    performance_test_duration: int = Field(default=60, description="Default performance test duration in seconds")
    performance_ramp_up_time: int = Field(default=30, description="Default ramp-up time in seconds")
    performance_think_time: int = Field(default=1, description="Default think time between requests in seconds")
    
    # Cache settings
    cache_enabled: bool = Field(default=True, description="Enable caching")
    cache_ttl_seconds: int = Field(default=3600, description="Cache TTL in seconds")
    
    # Monitoring settings
    metrics_enabled: bool = Field(default=True, description="Enable metrics collection")
    tracing_enabled: bool = Field(default=False, description="Enable distributed tracing")
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()
    
    class Config:
        env_prefix = "SENTINEL_APP_"
        case_sensitive = False


class Settings(BaseSettings):
    """Main settings class that combines all configuration sections."""
    
    # Environment
    environment: Environment = Field(default=Environment.DEVELOPMENT, description="Deployment environment")
    
    # Configuration sections
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    services: ServiceSettings = Field(default_factory=ServiceSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    application: ApplicationSettings = Field(default_factory=ApplicationSettings)
    
    # Global settings
    config_file: Optional[str] = Field(default=None, description="Configuration file path")
    
    def __init__(self, **kwargs):
        """Initialize settings with environment-specific defaults."""
        super().__init__(**kwargs)
        self._load_environment_config()
    
    def _load_environment_config(self):
        """Load environment-specific configuration."""
        env_file = None
        
        if self.environment == Environment.DEVELOPMENT:
            env_file = "config/development.env"
        elif self.environment == Environment.TESTING:
            env_file = "config/testing.env"
        elif self.environment == Environment.PRODUCTION:
            env_file = "config/production.env"
        elif self.environment == Environment.DOCKER:
            env_file = "config/docker.env"
        
        if env_file and os.path.exists(env_file):
            # Load environment file if it exists
            from dotenv import load_dotenv
            load_dotenv(env_file)
    
    @validator('environment', pre=True)
    def validate_environment(cls, v):
        """Validate and convert environment string."""
        if isinstance(v, str):
            try:
                return Environment(v.lower())
            except ValueError:
                raise ValueError(f"Invalid environment: {v}. Must be one of: {list(Environment)}")
        return v
    
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == Environment.DEVELOPMENT
    
    def is_testing(self) -> bool:
        """Check if running in testing environment."""
        return self.environment == Environment.TESTING
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION
    
    def is_docker(self) -> bool:
        """Check if running in Docker environment."""
        return self.environment == Environment.DOCKER
    
    class Config:
        env_prefix = "SENTINEL_"
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    
    This function uses lru_cache to ensure settings are loaded only once
    and reused across the application.
    """
    # Determine environment from environment variable
    env = os.getenv("SENTINEL_ENVIRONMENT", "development").lower()
    
    return Settings(environment=env)


# Convenience function to get specific setting sections
def get_database_settings() -> DatabaseSettings:
    """Get database settings."""
    return get_settings().database


def get_service_settings() -> ServiceSettings:
    """Get service settings."""
    return get_settings().services


def get_security_settings() -> SecuritySettings:
    """Get security settings."""
    return get_settings().security


def get_network_settings() -> NetworkSettings:
    """Get network settings."""
    return get_settings().network


def get_application_settings() -> ApplicationSettings:
    """Get application settings."""
    return get_settings().application
