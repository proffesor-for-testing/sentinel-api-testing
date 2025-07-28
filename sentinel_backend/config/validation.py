"""
Configuration validation and error handling utilities.

This module provides comprehensive validation for all configuration settings,
startup checks, error reporting, and configuration management tools.
"""

import os
import sys
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse
import re
import json

from pydantic import ValidationError
from .settings import (
    get_database_settings,
    get_service_settings,
    get_application_settings,
    get_security_settings,
    get_network_settings
)

# Configure logging for validation
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigurationError(Exception):
    """Custom exception for configuration errors."""
    pass

class ConfigurationValidator:
    """Comprehensive configuration validator."""
    
    def __init__(self):
        """Initialize the configuration validator."""
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.environment = os.getenv("SENTINEL_ENVIRONMENT", "development")
    
    def validate_all(self) -> Tuple[bool, List[str], List[str]]:
        """
        Validate all configuration settings.
        
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        logger.info(f"Starting configuration validation for environment: {self.environment}")
        
        # Reset error and warning lists
        self.errors = []
        self.warnings = []
        
        # Validate each configuration section
        self._validate_environment()
        self._validate_database_settings()
        self._validate_service_settings()
        self._validate_security_settings()
        self._validate_network_settings()
        self._validate_application_settings()
        self._validate_file_permissions()
        self._validate_dependencies()
        
        is_valid = len(self.errors) == 0
        
        if is_valid:
            logger.info("✅ Configuration validation passed")
        else:
            logger.error(f"❌ Configuration validation failed with {len(self.errors)} errors")
        
        if self.warnings:
            logger.warning(f"⚠️  Configuration validation completed with {len(self.warnings)} warnings")
        
        return is_valid, self.errors, self.warnings
    
    def _validate_environment(self):
        """Validate environment settings."""
        valid_environments = ["development", "testing", "production", "docker"]
        
        if self.environment not in valid_environments:
            self.errors.append(
                f"Invalid environment '{self.environment}'. "
                f"Valid environments: {', '.join(valid_environments)}"
            )
        
        # Check for required environment variables based on environment
        if self.environment == "production":
            required_prod_vars = [
                "SENTINEL_SECURITY_JWT_SECRET_KEY",
                "SENTINEL_DB_URL",
                "SENTINEL_SECURITY_DEFAULT_ADMIN_PASSWORD"
            ]
            
            for var in required_prod_vars:
                if not os.getenv(var):
                    self.errors.append(f"Required production environment variable missing: {var}")
    
    def _validate_database_settings(self):
        """Validate database configuration."""
        try:
            db_settings = get_database_settings()
            
            # Validate database URL format
            if not self._is_valid_database_url(db_settings.database_url):
                self.errors.append(f"Invalid database URL format: {db_settings.database_url}")
            
            # Validate pool settings
            if db_settings.pool_size <= 0:
                self.errors.append(f"Database pool_size must be positive, got: {db_settings.pool_size}")
            
            if db_settings.max_overflow < 0:
                self.errors.append(f"Database max_overflow must be non-negative, got: {db_settings.max_overflow}")
            
            if db_settings.pool_timeout <= 0:
                self.errors.append(f"Database pool_timeout must be positive, got: {db_settings.pool_timeout}")
            
            if db_settings.pool_recycle <= 0:
                self.errors.append(f"Database pool_recycle must be positive, got: {db_settings.pool_recycle}")
            
            # Production-specific validations
            if self.environment == "production":
                if "localhost" in db_settings.database_url or "127.0.0.1" in db_settings.database_url:
                    self.warnings.append("Using localhost database URL in production environment")
                
                if db_settings.pool_size < 5:
                    self.warnings.append(f"Database pool_size ({db_settings.pool_size}) may be too small for production")
        
        except ValidationError as e:
            self.errors.append(f"Database settings validation error: {e}")
        except Exception as e:
            self.errors.append(f"Unexpected error validating database settings: {e}")
    
    def _validate_service_settings(self):
        """Validate service configuration."""
        try:
            service_settings = get_service_settings()
            
            # Validate service URLs
            service_urls = {
                "auth_service_url": service_settings.auth_service_url,
                "spec_service_url": service_settings.spec_service_url,
                "orchestration_service_url": service_settings.orchestration_service_url,
                "data_service_url": service_settings.data_service_url,
                "execution_service_url": service_settings.execution_service_url,
            }
            
            for service_name, url in service_urls.items():
                if not self._is_valid_url(url):
                    self.errors.append(f"Invalid {service_name}: {url}")
            
            # Validate timeout settings
            if service_settings.service_timeout <= 0:
                self.errors.append(f"Service timeout must be positive, got: {service_settings.service_timeout}")
            
            if service_settings.health_check_timeout <= 0:
                self.errors.append(f"Health check timeout must be positive, got: {service_settings.health_check_timeout}")
            
            if service_settings.health_check_interval <= 0:
                self.errors.append(f"Health check interval must be positive, got: {service_settings.health_check_interval}")
            
            # Check for reasonable timeout values
            if service_settings.service_timeout > 300:  # 5 minutes
                self.warnings.append(f"Service timeout ({service_settings.service_timeout}s) is very high")
            
            if service_settings.health_check_timeout > service_settings.service_timeout:
                self.warnings.append("Health check timeout is greater than service timeout")
        
        except ValidationError as e:
            self.errors.append(f"Service settings validation error: {e}")
        except Exception as e:
            self.errors.append(f"Unexpected error validating service settings: {e}")
    
    def _validate_security_settings(self):
        """Validate security configuration."""
        try:
            security_settings = get_security_settings()
            
            # Validate JWT secret key
            if len(security_settings.jwt_secret_key) < 32:
                self.errors.append("JWT secret key must be at least 32 characters long")
            
            if security_settings.jwt_secret_key == "your-secret-key-here":
                self.errors.append("JWT secret key must be changed from default value")
            
            # Validate JWT algorithm
            valid_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]
            if security_settings.jwt_algorithm not in valid_algorithms:
                self.errors.append(f"Invalid JWT algorithm: {security_settings.jwt_algorithm}")
            
            # Validate JWT expiration
            if security_settings.jwt_expiration_hours <= 0:
                self.errors.append(f"JWT expiration must be positive, got: {security_settings.jwt_expiration_hours}")
            
            if security_settings.jwt_expiration_hours > 24 * 7:  # 1 week
                self.warnings.append(f"JWT expiration ({security_settings.jwt_expiration_hours}h) is very long")
            
            # Validate password policy
            if security_settings.password_min_length < 8:
                self.warnings.append(f"Password minimum length ({security_settings.password_min_length}) is less than recommended 8 characters")
            
            # Validate admin credentials
            if not self._is_valid_email(security_settings.default_admin_email):
                self.errors.append(f"Invalid admin email format: {security_settings.default_admin_email}")
            
            if len(security_settings.default_admin_password) < security_settings.password_min_length:
                self.errors.append("Default admin password does not meet minimum length requirement")
            
            # Production-specific security validations
            if self.environment == "production":
                if security_settings.default_admin_password in ["admin", "password", "123456"]:
                    self.errors.append("Default admin password is too weak for production")
                
                if not security_settings.password_require_uppercase:
                    self.warnings.append("Password policy should require uppercase letters in production")
                
                if not security_settings.password_require_numbers:
                    self.warnings.append("Password policy should require numbers in production")
                
                if not security_settings.password_require_special:
                    self.warnings.append("Password policy should require special characters in production")
        
        except ValidationError as e:
            self.errors.append(f"Security settings validation error: {e}")
        except Exception as e:
            self.errors.append(f"Unexpected error validating security settings: {e}")
    
    def _validate_network_settings(self):
        """Validate network configuration."""
        try:
            network_settings = get_network_settings()
            
            # Validate ports
            ports = {
                "api_gateway_port": network_settings.api_gateway_port,
                "auth_service_port": network_settings.auth_service_port,
                "spec_service_port": network_settings.spec_service_port,
                "orchestration_service_port": network_settings.orchestration_service_port,
                "execution_service_port": network_settings.execution_service_port,
                "data_service_port": network_settings.data_service_port,
                "database_port": network_settings.database_port,
            }
            
            for port_name, port in ports.items():
                if not self._is_valid_port(port):
                    self.errors.append(f"Invalid {port_name}: {port}")
            
            # Check for port conflicts
            port_values = list(ports.values())
            if len(port_values) != len(set(port_values)):
                self.errors.append("Port conflict detected: multiple services using the same port")
            
            # Validate host
            if not network_settings.host:
                self.errors.append("Network host cannot be empty")
            
            # Validate timeouts
            if network_settings.http_timeout <= 0:
                self.errors.append(f"HTTP timeout must be positive, got: {network_settings.http_timeout}")
            
            if network_settings.websocket_timeout <= 0:
                self.errors.append(f"WebSocket timeout must be positive, got: {network_settings.websocket_timeout}")
        
        except ValidationError as e:
            self.errors.append(f"Network settings validation error: {e}")
        except Exception as e:
            self.errors.append(f"Unexpected error validating network settings: {e}")
    
    def _validate_application_settings(self):
        """Validate application configuration."""
        try:
            app_settings = get_application_settings()
            
            # Validate pagination settings
            if app_settings.default_page_size <= 0:
                self.errors.append(f"Default page size must be positive, got: {app_settings.default_page_size}")
            
            if app_settings.max_page_size <= 0:
                self.errors.append(f"Max page size must be positive, got: {app_settings.max_page_size}")
            
            if app_settings.default_page_size > app_settings.max_page_size:
                self.errors.append("Default page size cannot be greater than max page size")
            
            # Validate agent settings
            if app_settings.max_concurrent_agents <= 0:
                self.errors.append(f"Max concurrent agents must be positive, got: {app_settings.max_concurrent_agents}")
            
            if hasattr(app_settings, 'agent_timeout_seconds') and app_settings.agent_timeout_seconds <= 0:
                self.errors.append(f"Agent timeout must be positive, got: {app_settings.agent_timeout_seconds}")
            
            # Validate test settings
            if app_settings.max_test_cases_per_spec <= 0:
                self.errors.append(f"Max test cases per spec must be positive, got: {app_settings.max_test_cases_per_spec}")
            
            if app_settings.test_execution_timeout <= 0:
                self.errors.append(f"Test execution timeout must be positive, got: {app_settings.test_execution_timeout}")
            
            # Validate LLM settings
            if hasattr(app_settings, 'llm_provider') and app_settings.llm_provider:
                valid_providers = ["openai", "anthropic", "mock"]
                if app_settings.llm_provider not in valid_providers:
                    self.warnings.append(f"Unknown LLM provider: {app_settings.llm_provider}")
            
            # Production-specific validations
            if self.environment == "production":
                if app_settings.debug:
                    self.warnings.append("Debug mode is enabled in production")
                
                if app_settings.log_level == "DEBUG":
                    self.warnings.append("Debug logging is enabled in production")
        
        except ValidationError as e:
            self.errors.append(f"Application settings validation error: {e}")
        except Exception as e:
            self.errors.append(f"Unexpected error validating application settings: {e}")
    
    def _validate_file_permissions(self):
        """Validate file permissions and accessibility."""
        config_dir = Path(__file__).parent
        
        # Check if config files exist and are readable
        config_files = [
            "development.env",
            "testing.env",
            "production.env",
            "docker.env"
        ]
        
        for config_file in config_files:
            file_path = config_dir / config_file
            if not file_path.exists():
                self.warnings.append(f"Configuration file not found: {config_file}")
            elif not file_path.is_file():
                self.errors.append(f"Configuration path is not a file: {config_file}")
            elif not os.access(file_path, os.R_OK):
                self.errors.append(f"Configuration file is not readable: {config_file}")
    
    def _validate_dependencies(self):
        """Validate that required dependencies are available."""
        required_modules = [
            "fastapi",
            "uvicorn",
            "pydantic",
            "sqlalchemy",
            "asyncpg",
            "httpx",
            "python-jose",
            "passlib",
            "python-multipart"
        ]
        
        missing_modules = []
        for module in required_modules:
            try:
                __import__(module.replace("-", "_"))
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            self.errors.append(f"Missing required dependencies: {', '.join(missing_modules)}")
    
    def _is_valid_database_url(self, url: str) -> bool:
        """Validate database URL format."""
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme in ["postgresql", "postgresql+asyncpg"] and
                parsed.hostname and
                parsed.path and
                parsed.path != "/"
            )
        except Exception:
            return False
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            parsed = urlparse(url)
            return parsed.scheme in ["http", "https"] and parsed.hostname
        except Exception:
            return False
    
    def _is_valid_port(self, port: int) -> bool:
        """Validate port number."""
        return isinstance(port, int) and 1 <= port <= 65535
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

class ConfigurationReporter:
    """Generate configuration reports and summaries."""
    
    @staticmethod
    def generate_report() -> Dict[str, Any]:
        """Generate a comprehensive configuration report."""
        try:
            report = {
                "environment": os.getenv("SENTINEL_ENVIRONMENT", "development"),
                "timestamp": str(os.times()),
                "validation_status": "unknown",
                "sections": {}
            }
            
            # Validate configuration
            validator = ConfigurationValidator()
            is_valid, errors, warnings = validator.validate_all()
            
            report["validation_status"] = "valid" if is_valid else "invalid"
            report["errors"] = errors
            report["warnings"] = warnings
            
            # Add configuration sections
            try:
                report["sections"]["database"] = get_database_settings().dict()
            except Exception as e:
                report["sections"]["database"] = {"error": str(e)}
            
            try:
                report["sections"]["services"] = get_service_settings().dict()
            except Exception as e:
                report["sections"]["services"] = {"error": str(e)}
            
            try:
                report["sections"]["security"] = {
                    k: v if k != "jwt_secret_key" else "***REDACTED***"
                    for k, v in get_security_settings().dict().items()
                }
            except Exception as e:
                report["sections"]["security"] = {"error": str(e)}
            
            try:
                report["sections"]["network"] = get_network_settings().dict()
            except Exception as e:
                report["sections"]["network"] = {"error": str(e)}
            
            try:
                report["sections"]["application"] = get_application_settings().dict()
            except Exception as e:
                report["sections"]["application"] = {"error": str(e)}
            
            return report
        
        except Exception as e:
            return {
                "environment": os.getenv("SENTINEL_ENVIRONMENT", "development"),
                "validation_status": "error",
                "error": str(e)
            }
    
    @staticmethod
    def print_report(report: Dict[str, Any]):
        """Print a formatted configuration report."""
        print("=" * 60)
        print("SENTINEL CONFIGURATION REPORT")
        print("=" * 60)
        print(f"Environment: {report.get('environment', 'unknown')}")
        print(f"Status: {report.get('validation_status', 'unknown').upper()}")
        print()
        
        if report.get("errors"):
            print("ERRORS:")
            for error in report["errors"]:
                print(f"  ❌ {error}")
            print()
        
        if report.get("warnings"):
            print("WARNINGS:")
            for warning in report["warnings"]:
                print(f"  ⚠️  {warning}")
            print()
        
        if report.get("sections"):
            print("CONFIGURATION SECTIONS:")
            for section_name, section_data in report["sections"].items():
                print(f"  📁 {section_name.upper()}")
                if isinstance(section_data, dict) and "error" in section_data:
                    print(f"    ❌ Error: {section_data['error']}")
                else:
                    print(f"    ✅ Loaded successfully")
            print()
        
        print("=" * 60)

def validate_startup_configuration() -> bool:
    """
    Validate configuration at application startup.
    
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    validator = ConfigurationValidator()
    is_valid, errors, warnings = validator.validate_all()
    
    if not is_valid:
        logger.error("Configuration validation failed!")
        for error in errors:
            logger.error(f"  ❌ {error}")
        
        if warnings:
            logger.warning("Configuration warnings:")
            for warning in warnings:
                logger.warning(f"  ⚠️  {warning}")
        
        return False
    
    if warnings:
        logger.warning("Configuration loaded with warnings:")
        for warning in warnings:
            logger.warning(f"  ⚠️  {warning}")
    
    logger.info("✅ Configuration validation passed")
    return True

def main():
    """Main function for running configuration validation from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate Sentinel configuration")
    parser.add_argument("--report", action="store_true", help="Generate detailed report")
    parser.add_argument("--json", action="store_true", help="Output report as JSON")
    parser.add_argument("--environment", help="Override environment")
    
    args = parser.parse_args()
    
    if args.environment:
        os.environ["SENTINEL_ENVIRONMENT"] = args.environment
    
    if args.report:
        report = ConfigurationReporter.generate_report()
        
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            ConfigurationReporter.print_report(report)
    else:
        is_valid = validate_startup_configuration()
        sys.exit(0 if is_valid else 1)

if __name__ == "__main__":
    main()
