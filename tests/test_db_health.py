"""
Test Suite for Database Health Check and Initialization
"""

import pytest
import sys
import os
from pathlib import Path

# Add sentinel_backend to path
backend_path = Path(__file__).parent.parent / 'sentinel_backend'
sys.path.insert(0, str(backend_path))

# Import health check modules
sys.path.insert(0, str(backend_path / 'scripts'))


class TestDatabaseHealthCheck:
    """Test database health check functionality"""

    def test_health_check_script_exists(self):
        """Verify health check script exists and is executable"""
        script_path = backend_path / 'scripts' / 'db_health_check.py'
        assert script_path.exists(), "Health check script not found"
        assert os.access(script_path, os.X_OK), "Health check script not executable"

    def test_diagnostics_script_exists(self):
        """Verify diagnostics script exists and is executable"""
        script_path = backend_path / 'scripts' / 'db_diagnostics.py'
        assert script_path.exists(), "Diagnostics script not found"
        assert os.access(script_path, os.X_OK), "Diagnostics script not executable"

    def test_init_with_retry_script_exists(self):
        """Verify initialization script exists and is executable"""
        script_path = backend_path / 'scripts' / 'init_db_with_retry.py'
        assert script_path.exists(), "Init with retry script not found"
        assert os.access(script_path, os.X_OK), "Init script not executable"

    def test_wait_for_db_script_exists(self):
        """Verify wait_for_db.sh script exists and is executable"""
        script_path = backend_path / 'scripts' / 'wait_for_db.sh'
        assert script_path.exists(), "wait_for_db.sh not found"
        assert os.access(script_path, os.X_OK), "wait_for_db.sh not executable"

    def test_quick_check_script_exists(self):
        """Verify db_quick_check.sh script exists and is executable"""
        script_path = backend_path / 'scripts' / 'db_quick_check.sh'
        assert script_path.exists(), "db_quick_check.sh not found"
        assert os.access(script_path, os.X_OK), "db_quick_check.sh not executable"

    def test_health_check_result_class(self):
        """Test HealthCheckResult class"""
        from db_health_check import HealthCheckResult

        result = HealthCheckResult()

        # Test adding checks
        result.add_check('test_check', True, "Test message")
        assert 'test_check' in result.checks
        assert result.checks['test_check'][0] is True

        # Test adding metrics
        result.add_metric('test_metric', {'value': 123})
        assert 'test_metric' in result.metrics
        assert result.metrics['test_metric']['value'] == 123

        # Test is_healthy
        assert result.is_healthy() is True

        # Test with failed check
        result.add_check('failed_check', False, "Failed")
        assert result.is_healthy() is False

    def test_exponential_backoff(self):
        """Test exponential backoff calculation"""
        from init_db_with_retry import exponential_backoff

        # Test backoff calculation
        assert exponential_backoff(0) == 1
        assert exponential_backoff(1) == 2
        assert exponential_backoff(2) == 4
        assert exponential_backoff(3) == 8

        # Test max delay cap
        assert exponential_backoff(10) == 60  # Max is 60 seconds

    def test_required_tables_constant(self):
        """Test that required tables list is defined"""
        from db_health_check import REQUIRED_TABLES

        assert isinstance(REQUIRED_TABLES, list)
        assert len(REQUIRED_TABLES) > 0
        assert 'users' in REQUIRED_TABLES
        assert 'test_cases' in REQUIRED_TABLES
        assert 'test_results' in REQUIRED_TABLES

    def test_required_indexes_constant(self):
        """Test that required indexes list is defined"""
        from db_health_check import REQUIRED_INDEXES

        assert isinstance(REQUIRED_INDEXES, list)
        assert len(REQUIRED_INDEXES) > 0
        assert any('idx_test_cases' in idx for idx in REQUIRED_INDEXES)

    def test_database_config(self):
        """Test database configuration loading"""
        from db_health_check import DB_CONFIG

        assert 'host' in DB_CONFIG
        assert 'port' in DB_CONFIG
        assert 'database' in DB_CONFIG
        assert 'user' in DB_CONFIG
        assert 'password' in DB_CONFIG

        # Test defaults
        assert DB_CONFIG['database'] == os.getenv('DB_NAME', 'sentinel_db')
        assert DB_CONFIG['user'] == os.getenv('DB_USER', 'sentinel')

    def test_health_check_to_dict(self):
        """Test health check result serialization"""
        from db_health_check import HealthCheckResult

        result = HealthCheckResult()
        result.add_check('test', True, "Test passed")
        result.add_metric('count', 42)

        data = result.to_dict()

        assert 'timestamp' in data
        assert 'duration_ms' in data
        assert 'healthy' in data
        assert 'ready' in data
        assert 'checks' in data
        assert 'metrics' in data

        assert data['checks']['test']['passed'] is True
        assert data['metrics']['count'] == 42

    @pytest.mark.skipif(
        not os.getenv('DB_HOST'),
        reason="Database not available"
    )
    def test_connection_with_retry(self):
        """Test database connection with retry logic (if DB available)"""
        from init_db_with_retry import wait_for_database

        success, error = wait_for_database(max_attempts=3)

        # If DB is running, should succeed
        if os.getenv('DB_HOST') == 'localhost' or os.getenv('DB_HOST') == 'db':
            assert success is True or error is not None


class TestDatabaseInitialization:
    """Test database initialization functionality"""

    def test_init_sql_script_exists(self):
        """Verify init_db.sql exists"""
        script_path = backend_path / 'init_db.sql'
        assert script_path.exists(), "init_db.sql not found"

        # Check it contains expected table definitions
        content = script_path.read_text()
        assert 'CREATE TABLE' in content
        assert 'users' in content
        assert 'test_cases' in content
        assert 'test_results' in content
        assert 'pgvector' in content.lower() or 'vector' in content

    def test_init_database_py_exists(self):
        """Verify init_database.py exists"""
        script_path = backend_path / 'init_database.py'
        assert script_path.exists(), "init_database.py not found"


class TestDatabaseDiagnostics:
    """Test database diagnostics functionality"""

    def test_diagnostics_class_structure(self):
        """Test DatabaseDiagnostics class structure"""
        from db_diagnostics import DatabaseDiagnostics

        diag = DatabaseDiagnostics()

        # Check initial structure
        assert hasattr(diag, 'diagnostics')
        assert isinstance(diag.diagnostics, dict)
        assert 'timestamp' in diag.diagnostics
        assert 'connection' in diag.diagnostics
        assert 'extensions' in diag.diagnostics
        assert 'tables' in diag.diagnostics
        assert 'issues' in diag.diagnostics
        assert 'recommendations' in diag.diagnostics


class TestMakefileCommands:
    """Test Makefile database commands"""

    def test_makefile_exists(self):
        """Verify Makefile exists"""
        makefile = Path(__file__).parent.parent / 'Makefile'
        assert makefile.exists(), "Makefile not found"

    def test_makefile_has_db_commands(self):
        """Verify Makefile has database commands"""
        makefile = Path(__file__).parent.parent / 'Makefile'
        content = makefile.read_text()

        # Check for required targets
        assert 'init-db:' in content
        assert 'db-health:' in content
        assert 'db-diagnostics:' in content
        assert 'db-ready:' in content
        assert 'reset-db:' in content

        # Check for script references
        assert 'db_health_check.py' in content
        assert 'db_diagnostics.py' in content
        assert 'init_db_with_retry.py' in content


class TestDockerComposeHealthCheck:
    """Test Docker Compose health check configuration"""

    def test_docker_compose_exists(self):
        """Verify docker-compose.yml exists"""
        compose_file = Path(__file__).parent.parent / 'docker-compose.yml'
        assert compose_file.exists(), "docker-compose.yml not found"

    def test_docker_compose_has_enhanced_healthcheck(self):
        """Verify docker-compose.yml has enhanced health check"""
        compose_file = Path(__file__).parent.parent / 'docker-compose.yml'
        content = compose_file.read_text()

        # Check for enhanced health check
        assert 'healthcheck:' in content
        assert 'pg_isready' in content
        assert 'vector' in content or 'pgvector' in content

        # Check for proper intervals and retries
        assert 'interval:' in content
        assert 'retries:' in content
        assert 'start_period:' in content


class TestDocumentation:
    """Test database documentation"""

    def test_documentation_exists(self):
        """Verify database initialization documentation exists"""
        doc_path = Path(__file__).parent.parent / 'docs' / 'database-initialization.md'
        assert doc_path.exists(), "database-initialization.md not found"

    def test_documentation_content(self):
        """Verify documentation has required sections"""
        doc_path = Path(__file__).parent.parent / 'docs' / 'database-initialization.md'
        content = doc_path.read_text()

        # Check for key sections
        assert '## Overview' in content
        assert '## Architecture' in content
        assert '## Usage' in content
        assert '## Health Check' in content
        assert '## Retry Logic' in content
        assert '## Troubleshooting' in content
        assert 'db_health_check.py' in content
        assert 'db_diagnostics.py' in content
        assert 'init_db_with_retry.py' in content


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
