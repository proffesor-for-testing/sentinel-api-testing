"""
Test configuration utilities and helpers.

This module provides test-specific configuration management,
test data generation, and testing utilities.
"""

import os
import tempfile
from typing import Dict, Any, Optional
from pathlib import Path

from config.settings import (
    get_database_settings,
    get_service_settings,
    get_application_settings,
    get_security_settings,
    get_network_settings
)

class TestConfig:
    """Test configuration manager."""
    
    def __init__(self):
        """Initialize test configuration."""
        # Ensure we're in testing environment
        os.environ["SENTINEL_ENVIRONMENT"] = "testing"
        
        # Get all configuration settings
        self.database = get_database_settings()
        self.services = get_service_settings()
        self.application = get_application_settings()
        self.security = get_security_settings()
        self.network = get_network_settings()
        
        # Test-specific settings
        self.test_data_dir = Path(__file__).parent / "data"
        self.temp_dir = Path(tempfile.gettempdir()) / "sentinel_tests"
        self.temp_dir.mkdir(exist_ok=True)
    
    @property
    def test_database_url(self) -> str:
        """Get test database URL."""
        return self.database.database_url
    
    @property
    def service_urls(self) -> Dict[str, str]:
        """Get all service URLs for testing."""
        return {
            "auth": self.services.auth_service_url,
            "spec": self.services.spec_service_url,
            "orchestration": self.services.orchestration_service_url,
            "data": self.services.data_service_url,
            "execution": self.services.execution_service_url,
        }
    
    @property
    def test_timeouts(self) -> Dict[str, int]:
        """Get test timeout configurations."""
        return {
            "service": self.services.service_timeout,
            "health_check": self.services.health_check_timeout,
            "test_execution": self.application.test_execution_timeout,
            "agent": getattr(self.application, 'agent_timeout_seconds', 30),
        }
    
    @property
    def test_limits(self) -> Dict[str, int]:
        """Get test limit configurations."""
        return {
            "max_test_cases": self.application.max_test_cases_per_spec,
            "max_concurrent_agents": self.application.max_concurrent_agents,
            "page_size": self.application.default_page_size,
            "max_page_size": self.application.max_page_size,
        }
    
    def get_test_jwt_secret(self) -> str:
        """Get JWT secret for testing."""
        return self.security.jwt_secret_key
    
    def get_test_admin_credentials(self) -> Dict[str, str]:
        """Get test admin credentials."""
        return {
            "email": self.security.default_admin_email,
            "password": self.security.default_admin_password,
        }
    
    def create_temp_file(self, content: str, suffix: str = ".json") -> Path:
        """Create a temporary file with content."""
        temp_file = self.temp_dir / f"test_{os.getpid()}_{suffix}"
        temp_file.write_text(content)
        return temp_file
    
    def cleanup_temp_files(self):
        """Clean up temporary test files."""
        if self.temp_dir.exists():
            for file in self.temp_dir.glob("*"):
                if file.is_file():
                    file.unlink()

# Global test configuration instance
test_config = TestConfig()

class TestDataGenerator:
    """Generate test data for various scenarios."""
    
    @staticmethod
    def generate_openapi_spec(
        title: str = "Test API",
        version: str = "1.0.0",
        paths: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate a sample OpenAPI specification."""
        if paths is None:
            paths = {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "array",
                                            "items": {"$ref": "#/components/schemas/User"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CreateUser"}
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "description": "Created",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/User"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        
        return {
            "openapi": "3.0.0",
            "info": {
                "title": title,
                "version": version
            },
            "paths": paths,
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "name": {"type": "string"},
                            "email": {"type": "string", "format": "email"},
                            "created_at": {"type": "string", "format": "date-time"}
                        },
                        "required": ["id", "name", "email"]
                    },
                    "CreateUser": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 100},
                            "email": {"type": "string", "format": "email"}
                        },
                        "required": ["name", "email"]
                    }
                }
            }
        }
    
    @staticmethod
    def generate_test_case(
        name: str = "Test Case",
        method: str = "GET",
        path: str = "/test",
        agent_type: str = "functional-positive",
        **kwargs
    ) -> Dict[str, Any]:
        """Generate a sample test case."""
        base_case = {
            "name": name,
            "method": method,
            "path": path,
            "headers": {"Content-Type": "application/json"},
            "query_params": {},
            "body": None,
            "expected_status": 200,
            "expected_response_schema": {"type": "object"},
            "tags": ["test"],
            "agent_type": agent_type,
            "description": f"Generated test case for {method} {path}",
            "assertions": []
        }
        base_case.update(kwargs)
        return base_case
    
    @staticmethod
    def generate_test_suite(
        name: str = "Test Suite",
        spec_id: int = 1,
        test_cases: Optional[list] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Generate a sample test suite."""
        if test_cases is None:
            test_cases = []
        
        base_suite = {
            "name": name,
            "description": f"Generated test suite: {name}",
            "spec_id": spec_id,
            "tags": ["test"],
            "test_cases": test_cases,
            "created_by": "test-user",
            "is_active": True
        }
        base_suite.update(kwargs)
        return base_suite
    
    @staticmethod
    def generate_test_run(
        suite_id: int = 1,
        environment: str = "testing",
        base_url: str = "http://test-api.example.com",
        **kwargs
    ) -> Dict[str, Any]:
        """Generate a sample test run."""
        base_run = {
            "suite_id": suite_id,
            "environment": environment,
            "base_url": base_url,
            "status": "pending",
            "total_tests": 0,
            "passed_tests": 0,
            "failed_tests": 0,
            "execution_time": 0.0,
            "results": [],
            "started_by": "test-user",
            "configuration": {}
        }
        base_run.update(kwargs)
        return base_run
    
    @staticmethod
    def generate_security_payloads() -> Dict[str, list]:
        """Generate security test payloads."""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "1' UNION SELECT * FROM users --",
                "admin'--",
                "' OR 1=1#"
            ],
            "xss": [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
                "<svg onload=alert('xss')>",
                "';alert('xss');//"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            "ldap_injection": [
                "*)(uid=*",
                "*)(|(uid=*))",
                "admin)(&(password=*))",
                "*))%00"
            ]
        }
    
    @staticmethod
    def generate_performance_config(
        virtual_users: int = 10,
        duration: str = "30s",
        ramp_up_time: str = "10s"
    ) -> Dict[str, Any]:
        """Generate performance test configuration."""
        return {
            "virtual_users": virtual_users,
            "duration": duration,
            "ramp_up_time": ramp_up_time,
            "thresholds": {
                "http_req_duration": ["p(95)<500"],
                "http_req_failed": ["rate<0.1"],
                "http_reqs": ["rate>10"]
            },
            "scenarios": {
                "default": {
                    "executor": "ramping-vus",
                    "startVUs": 1,
                    "stages": [
                        {"duration": ramp_up_time, "target": virtual_users},
                        {"duration": duration, "target": virtual_users},
                        {"duration": "10s", "target": 0}
                    ]
                }
            }
        }

class TestAssertions:
    """Common test assertions and validators."""
    
    @staticmethod
    def assert_valid_response_structure(response_data: Dict[str, Any], expected_keys: list):
        """Assert that response has expected structure."""
        for key in expected_keys:
            assert key in response_data, f"Missing key '{key}' in response"
    
    @staticmethod
    def assert_valid_test_case(test_case: Dict[str, Any]):
        """Assert that test case has valid structure."""
        required_keys = ["name", "method", "path", "expected_status", "agent_type"]
        for key in required_keys:
            assert key in test_case, f"Missing required key '{key}' in test case"
        
        assert test_case["method"] in ["GET", "POST", "PUT", "DELETE", "PATCH"], \
            f"Invalid HTTP method: {test_case['method']}"
        
        assert isinstance(test_case["expected_status"], int), \
            "Expected status must be an integer"
        
        assert 100 <= test_case["expected_status"] <= 599, \
            f"Invalid HTTP status code: {test_case['expected_status']}"
    
    @staticmethod
    def assert_valid_test_suite(test_suite: Dict[str, Any]):
        """Assert that test suite has valid structure."""
        required_keys = ["name", "spec_id"]
        for key in required_keys:
            assert key in test_suite, f"Missing required key '{key}' in test suite"
        
        assert isinstance(test_suite["spec_id"], int), \
            "Spec ID must be an integer"
        
        if "test_cases" in test_suite:
            assert isinstance(test_suite["test_cases"], list), \
                "Test cases must be a list"
    
    @staticmethod
    def assert_valid_test_run(test_run: Dict[str, Any]):
        """Assert that test run has valid structure."""
        required_keys = ["suite_id", "environment", "base_url", "status"]
        for key in required_keys:
            assert key in test_run, f"Missing required key '{key}' in test run"
        
        valid_statuses = ["pending", "running", "completed", "failed", "cancelled"]
        assert test_run["status"] in valid_statuses, \
            f"Invalid status: {test_run['status']}"
        
        assert isinstance(test_run["suite_id"], int), \
            "Suite ID must be an integer"

# Export commonly used items
__all__ = [
    "TestConfig",
    "test_config",
    "TestDataGenerator",
    "TestAssertions"
]
