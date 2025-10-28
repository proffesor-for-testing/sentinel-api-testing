#!/usr/bin/env python3
"""
Database Health Check Script for Sentinel
Comprehensive health validation for PostgreSQL with pgvector extension

This script provides:
- Liveness check (database is responding)
- Readiness check (database is fully initialized)
- pgvector extension verification
- Connection pool status
- Schema validation
- Performance metrics
"""

import os
import sys
import time
import json
import logging
from typing import Dict, List, Tuple
from datetime import datetime
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'sentinel_db'),
    'user': os.getenv('DB_USER', 'sentinel'),
    'password': os.getenv('DB_PASSWORD', 'sentinel_password'),
    'connect_timeout': 5
}

# Required tables for full initialization
REQUIRED_TABLES = [
    'users', 'projects', 'api_specifications', 'test_cases',
    'test_suites', 'test_suite_entries', 'test_runs', 'test_results'
]

# Required indexes for performance
REQUIRED_INDEXES = [
    'idx_test_cases_spec_id',
    'idx_test_results_run_id',
    'idx_test_results_case_id',
    'idx_test_runs_suite_id',
    'idx_test_runs_status'
]


class HealthCheckResult:
    """Container for health check results"""
    def __init__(self):
        self.checks: Dict[str, Tuple[bool, str]] = {}
        self.metrics: Dict[str, any] = {}
        self.start_time = time.time()

    def add_check(self, name: str, passed: bool, message: str = ""):
        """Add a health check result"""
        self.checks[name] = (passed, message)
        status = "✓" if passed else "✗"
        level = logging.INFO if passed else logging.ERROR
        logger.log(level, f"{status} {name}: {message}")

    def add_metric(self, name: str, value: any):
        """Add a performance metric"""
        self.metrics[name] = value

    def is_healthy(self) -> bool:
        """Check if all health checks passed"""
        return all(passed for passed, _ in self.checks.values())

    def is_ready(self) -> bool:
        """Check if database is ready for use (subset of health checks)"""
        critical_checks = [
            'database_connection',
            'pgvector_extension',
            'tables_exist',
            'schema_valid'
        ]
        return all(
            self.checks.get(check, (False, ""))[0]
            for check in critical_checks
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output"""
        duration = time.time() - self.start_time
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'duration_ms': round(duration * 1000, 2),
            'healthy': self.is_healthy(),
            'ready': self.is_ready(),
            'checks': {
                name: {'passed': passed, 'message': msg}
                for name, (passed, msg) in self.checks.items()
            },
            'metrics': self.metrics
        }


def check_database_connection() -> Tuple[bool, str, psycopg2.extensions.connection]:
    """
    Liveness check: Can we connect to the database?
    Returns: (success, message, connection)
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        cursor.close()
        return True, f"Connected to {version.split(',')[0]}", conn
    except psycopg2.OperationalError as e:
        return False, f"Connection failed: {str(e)}", None
    except Exception as e:
        return False, f"Unexpected error: {str(e)}", None


def check_pgvector_extension(conn) -> Tuple[bool, str]:
    """
    Check if pgvector extension is installed and functional
    """
    try:
        cursor = conn.cursor()

        # Check if extension exists
        cursor.execute("""
            SELECT extname, extversion
            FROM pg_extension
            WHERE extname = 'vector';
        """)
        result = cursor.fetchone()

        if not result:
            # Try to create extension
            try:
                cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                cursor.execute("""
                    SELECT extname, extversion
                    FROM pg_extension
                    WHERE extname = 'vector';
                """)
                result = cursor.fetchone()
            except Exception as e:
                cursor.close()
                return False, f"pgvector not available: {str(e)}"

        if result:
            ext_name, ext_version = result

            # Test vector operations
            cursor.execute("SELECT '[1,2,3]'::vector;")
            test_vector = cursor.fetchone()[0]

            cursor.close()
            return True, f"pgvector v{ext_version} functional"
        else:
            cursor.close()
            return False, "pgvector extension not found"

    except Exception as e:
        return False, f"pgvector check failed: {str(e)}"


def check_tables_exist(conn) -> Tuple[bool, str]:
    """
    Check if all required tables exist
    """
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = ANY(%s);
        """, (REQUIRED_TABLES,))

        existing_tables = [row[0] for row in cursor.fetchall()]
        missing_tables = set(REQUIRED_TABLES) - set(existing_tables)

        cursor.close()

        if missing_tables:
            return False, f"Missing tables: {', '.join(missing_tables)}"
        return True, f"All {len(REQUIRED_TABLES)} required tables exist"

    except Exception as e:
        return False, f"Table check failed: {str(e)}"


def check_schema_validity(conn) -> Tuple[bool, str]:
    """
    Validate schema structure for critical tables
    """
    try:
        cursor = conn.cursor()
        issues = []

        # Check test_results columns (common source of issues)
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'test_results'
            AND table_schema = 'public';
        """)
        columns = [row[0] for row in cursor.fetchall()]

        required_columns = [
            'id', 'run_id', 'test_case_id', 'case_id', 'status',
            'response_code', 'response_headers', 'response_body',
            'latency_ms', 'assertion_failures'
        ]

        missing_columns = set(required_columns) - set(columns)
        if missing_columns:
            issues.append(f"test_results missing: {', '.join(missing_columns)}")

        # Check for indexes
        cursor.execute("""
            SELECT indexname
            FROM pg_indexes
            WHERE schemaname = 'public'
            AND indexname = ANY(%s);
        """, (REQUIRED_INDEXES,))

        existing_indexes = [row[0] for row in cursor.fetchall()]
        missing_indexes = set(REQUIRED_INDEXES) - set(existing_indexes)
        if missing_indexes:
            issues.append(f"missing indexes: {', '.join(missing_indexes)}")

        cursor.close()

        if issues:
            return False, "; ".join(issues)
        return True, "Schema structure valid"

    except Exception as e:
        return False, f"Schema validation failed: {str(e)}"


def check_connection_pool(conn) -> Tuple[bool, str, dict]:
    """
    Check database connection pool status
    """
    try:
        cursor = conn.cursor()

        # Get connection stats
        cursor.execute("""
            SELECT
                count(*) as total_connections,
                count(*) FILTER (WHERE state = 'active') as active,
                count(*) FILTER (WHERE state = 'idle') as idle,
                count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction
            FROM pg_stat_activity
            WHERE datname = %s;
        """, (DB_CONFIG['database'],))

        row = cursor.fetchone()
        stats = {
            'total': row[0],
            'active': row[1],
            'idle': row[2],
            'idle_in_transaction': row[3]
        }

        # Get max connections
        cursor.execute("SHOW max_connections;")
        max_conn = int(cursor.fetchone()[0])
        stats['max_connections'] = max_conn
        stats['usage_percent'] = round((stats['total'] / max_conn) * 100, 2)

        cursor.close()

        # Warning if usage is high
        if stats['usage_percent'] > 80:
            return False, f"High connection usage: {stats['usage_percent']}%", stats

        return True, f"Connections: {stats['total']}/{max_conn} ({stats['usage_percent']}%)", stats

    except Exception as e:
        return False, f"Connection pool check failed: {str(e)}", {}


def check_database_size(conn) -> Tuple[bool, str, dict]:
    """
    Check database size and table sizes
    """
    try:
        cursor = conn.cursor()

        # Database size
        cursor.execute("""
            SELECT pg_size_pretty(pg_database_size(%s)) as size;
        """, (DB_CONFIG['database'],))
        db_size = cursor.fetchone()[0]

        # Table sizes
        cursor.execute("""
            SELECT
                tablename,
                pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                pg_total_relation_size(schemaname||'.'||tablename) as bytes
            FROM pg_tables
            WHERE schemaname = 'public'
            ORDER BY bytes DESC
            LIMIT 10;
        """)

        table_sizes = [
            {'table': row[0], 'size': row[1], 'bytes': row[2]}
            for row in cursor.fetchall()
        ]

        cursor.close()

        metrics = {
            'database_size': db_size,
            'top_tables': table_sizes
        }

        return True, f"Database size: {db_size}", metrics

    except Exception as e:
        return False, f"Size check failed: {str(e)}", {}


def check_query_performance(conn) -> Tuple[bool, str, dict]:
    """
    Test query performance with simple operations
    """
    try:
        cursor = conn.cursor()

        # Simple query timing
        start = time.time()
        cursor.execute("SELECT 1;")
        cursor.fetchone()
        simple_query_ms = round((time.time() - start) * 1000, 2)

        # Check if test_results has data
        cursor.execute("SELECT COUNT(*) FROM test_results;")
        result_count = cursor.fetchone()[0]

        if result_count > 0:
            # Query timing on real data
            start = time.time()
            cursor.execute("""
                SELECT id, status, latency_ms
                FROM test_results
                LIMIT 100;
            """)
            cursor.fetchall()
            query_with_data_ms = round((time.time() - start) * 1000, 2)
        else:
            query_with_data_ms = 0

        cursor.close()

        metrics = {
            'simple_query_ms': simple_query_ms,
            'data_query_ms': query_with_data_ms,
            'test_results_count': result_count
        }

        # Warn if queries are slow
        if simple_query_ms > 100:
            return False, f"Slow queries detected: {simple_query_ms}ms", metrics

        return True, f"Query performance OK (simple: {simple_query_ms}ms)", metrics

    except Exception as e:
        return False, f"Performance check failed: {str(e)}", {}


def perform_health_check(detailed: bool = False) -> HealthCheckResult:
    """
    Perform comprehensive health check

    Args:
        detailed: Include detailed metrics and performance checks

    Returns:
        HealthCheckResult object
    """
    result = HealthCheckResult()
    conn = None

    logger.info("=" * 60)
    logger.info("Sentinel Database Health Check")
    logger.info("=" * 60)

    # 1. Database Connection (Liveness)
    passed, msg, conn = check_database_connection()
    result.add_check('database_connection', passed, msg)

    if not conn:
        logger.error("Cannot proceed without database connection")
        return result

    try:
        # 2. pgvector Extension
        passed, msg = check_pgvector_extension(conn)
        result.add_check('pgvector_extension', passed, msg)

        # 3. Tables Exist
        passed, msg = check_tables_exist(conn)
        result.add_check('tables_exist', passed, msg)

        # 4. Schema Validity
        passed, msg = check_schema_validity(conn)
        result.add_check('schema_valid', passed, msg)

        # 5. Connection Pool
        passed, msg, metrics = check_connection_pool(conn)
        result.add_check('connection_pool', passed, msg)
        result.add_metric('connection_pool', metrics)

        if detailed:
            # 6. Database Size
            passed, msg, metrics = check_database_size(conn)
            result.add_check('database_size', passed, msg)
            result.add_metric('database_size', metrics)

            # 7. Query Performance
            passed, msg, metrics = check_query_performance(conn)
            result.add_check('query_performance', passed, msg)
            result.add_metric('query_performance', metrics)

    finally:
        if conn:
            conn.close()

    logger.info("=" * 60)
    if result.is_ready():
        logger.info("✅ Database is READY")
    elif result.checks.get('database_connection', (False, ""))[0]:
        logger.warning("⚠️  Database is LIVE but NOT READY")
    else:
        logger.error("❌ Database is NOT HEALTHY")
    logger.info("=" * 60)

    return result


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Sentinel Database Health Check'
    )
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Include detailed metrics and performance checks'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    parser.add_argument(
        '--liveness',
        action='store_true',
        help='Quick liveness check (connection only)'
    )
    parser.add_argument(
        '--readiness',
        action='store_true',
        help='Readiness check (database fully initialized)'
    )

    args = parser.parse_args()

    # Quick checks for container health probes
    if args.liveness:
        passed, msg, conn = check_database_connection()
        if conn:
            conn.close()
        sys.exit(0 if passed else 1)

    # Full health check
    result = perform_health_check(detailed=args.detailed)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))

    # Readiness check mode
    if args.readiness:
        sys.exit(0 if result.is_ready() else 1)

    # Standard mode
    sys.exit(0 if result.is_healthy() else 1)


if __name__ == "__main__":
    main()
