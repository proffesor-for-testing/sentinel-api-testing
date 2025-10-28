#!/usr/bin/env python3
"""
Enhanced Database Initialization Script with Retry Logic
Robust initialization with exponential backoff and comprehensive error handling

Features:
- Exponential backoff retry logic
- Pre-initialization validation
- Atomic operations with rollback
- Comprehensive error reporting
- Progress tracking
"""

import os
import sys
import time
import logging
from typing import Optional, Tuple
from datetime import datetime
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'database': os.getenv('DB_NAME', 'sentinel_db'),
    'user': os.getenv('DB_USER', 'sentinel'),
    'password': os.getenv('DB_PASSWORD', 'sentinel_password'),
    'connect_timeout': 5
}

# Retry configuration
MAX_RETRIES = 10
INITIAL_RETRY_DELAY = 1  # seconds
MAX_RETRY_DELAY = 60  # seconds
BACKOFF_MULTIPLIER = 2


def exponential_backoff(attempt: int) -> float:
    """Calculate exponential backoff delay"""
    delay = min(INITIAL_RETRY_DELAY * (BACKOFF_MULTIPLIER ** attempt), MAX_RETRY_DELAY)
    return delay


def wait_for_database(max_attempts: int = MAX_RETRIES) -> Tuple[bool, Optional[str]]:
    """
    Wait for database to be available with exponential backoff

    Returns:
        (success, error_message)
    """
    logger.info("=" * 60)
    logger.info("WAITING FOR DATABASE")
    logger.info("=" * 60)

    for attempt in range(max_attempts):
        try:
            # Try to connect
            conn = psycopg2.connect(**DB_CONFIG)
            cursor = conn.cursor()

            # Verify it's actually working
            cursor.execute("SELECT 1;")
            result = cursor.fetchone()

            cursor.close()
            conn.close()

            if result and result[0] == 1:
                logger.info(f"✅ Database ready after {attempt + 1} attempt(s)")
                return True, None

        except psycopg2.OperationalError as e:
            delay = exponential_backoff(attempt)
            logger.warning(
                f"Attempt {attempt + 1}/{max_attempts} failed: {e}"
            )

            if attempt < max_attempts - 1:
                logger.info(f"Retrying in {delay:.1f} seconds...")
                time.sleep(delay)
            else:
                error_msg = f"Database unavailable after {max_attempts} attempts"
                logger.error(f"❌ {error_msg}")
                return False, error_msg

        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            logger.error(f"❌ {error_msg}")
            return False, error_msg

    return False, "Maximum retries exceeded"


def check_pgvector_extension(conn) -> Tuple[bool, Optional[str]]:
    """
    Ensure pgvector extension is installed

    Returns:
        (success, error_message)
    """
    logger.info("\n" + "=" * 60)
    logger.info("CHECKING PGVECTOR EXTENSION")
    logger.info("=" * 60)

    try:
        cursor = conn.cursor()

        # Check if extension exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM pg_extension
            WHERE extname = 'vector';
        """)

        if cursor.fetchone()[0] == 0:
            logger.info("Installing pgvector extension...")
            try:
                cursor.execute("CREATE EXTENSION IF NOT EXISTS vector;")
                logger.info("✅ pgvector extension installed")
            except Exception as e:
                error_msg = f"Failed to install pgvector: {e}"
                logger.error(f"❌ {error_msg}")
                cursor.close()
                return False, error_msg
        else:
            logger.info("✅ pgvector extension already installed")

        # Test vector operations
        cursor.execute("SELECT '[1,2,3]'::vector;")
        result = cursor.fetchone()

        if result:
            logger.info("✅ pgvector extension functional")
            cursor.close()
            return True, None
        else:
            error_msg = "pgvector test failed"
            logger.error(f"❌ {error_msg}")
            cursor.close()
            return False, error_msg

    except Exception as e:
        error_msg = f"pgvector check failed: {e}"
        logger.error(f"❌ {error_msg}")
        return False, error_msg


def check_existing_schema(conn) -> dict:
    """
    Check what tables and schema elements already exist

    Returns:
        dict with existing schema information
    """
    logger.info("\n" + "=" * 60)
    logger.info("CHECKING EXISTING SCHEMA")
    logger.info("=" * 60)

    try:
        cursor = conn.cursor()

        # Check tables
        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        existing_tables = [row[0] for row in cursor.fetchall()]

        logger.info(f"Existing tables: {len(existing_tables)}")
        for table in existing_tables:
            logger.info(f"  - {table}")

        # Check for required tables
        required_tables = [
            'users', 'projects', 'api_specifications', 'test_cases',
            'test_suites', 'test_suite_entries', 'test_runs', 'test_results'
        ]

        missing_tables = set(required_tables) - set(existing_tables)

        cursor.close()

        schema_info = {
            'existing_tables': existing_tables,
            'required_tables': required_tables,
            'missing_tables': list(missing_tables),
            'is_complete': len(missing_tables) == 0
        }

        if missing_tables:
            logger.warning(f"⚠️  Missing tables: {', '.join(missing_tables)}")
        else:
            logger.info("✅ All required tables exist")

        return schema_info

    except Exception as e:
        logger.error(f"Schema check failed: {e}")
        return {
            'error': str(e),
            'existing_tables': [],
            'missing_tables': [],
            'is_complete': False
        }


def execute_sql_script(conn, script_path: str) -> Tuple[bool, Optional[str]]:
    """
    Execute SQL script with error handling

    Returns:
        (success, error_message)
    """
    logger.info(f"\nExecuting script: {script_path}")

    try:
        with open(script_path, 'r') as f:
            sql_script = f.read()

        cursor = conn.cursor()

        # Execute in a transaction for safety
        try:
            cursor.execute(sql_script)
            conn.commit()
            logger.info("✅ Script executed successfully")
            cursor.close()
            return True, None

        except Exception as e:
            conn.rollback()
            error_msg = f"Script execution failed: {e}"
            logger.error(f"❌ {error_msg}")
            cursor.close()
            return False, error_msg

    except FileNotFoundError:
        error_msg = f"Script file not found: {script_path}"
        logger.error(f"❌ {error_msg}")
        return False, error_msg
    except Exception as e:
        error_msg = f"Failed to read script: {e}"
        logger.error(f"❌ {error_msg}")
        return False, error_msg


def verify_initialization(conn) -> Tuple[bool, list]:
    """
    Verify that initialization was successful

    Returns:
        (success, list_of_issues)
    """
    logger.info("\n" + "=" * 60)
    logger.info("VERIFYING INITIALIZATION")
    logger.info("=" * 60)

    issues = []

    try:
        cursor = conn.cursor()

        # Check all required tables exist
        required_tables = [
            'users', 'projects', 'api_specifications', 'test_cases',
            'test_suites', 'test_suite_entries', 'test_runs', 'test_results'
        ]

        for table in required_tables:
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = %s;
            """, (table,))

            if cursor.fetchone()[0] == 0:
                issues.append(f"Table {table} not found")
                logger.error(f"❌ Table {table} not found")
            else:
                logger.info(f"✅ Table {table} exists")

        # Check critical columns in test_results
        cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'test_results' AND table_schema = 'public';
        """)
        columns = [row[0] for row in cursor.fetchall()]

        required_columns = [
            'id', 'run_id', 'test_case_id', 'case_id', 'status',
            'response_code', 'latency_ms', 'assertion_failures'
        ]

        missing_columns = set(required_columns) - set(columns)
        if missing_columns:
            for col in missing_columns:
                issues.append(f"Column test_results.{col} not found")
                logger.error(f"❌ Column test_results.{col} not found")
        else:
            logger.info("✅ All required columns exist")

        # Check indexes
        cursor.execute("""
            SELECT indexname
            FROM pg_indexes
            WHERE schemaname = 'public';
        """)
        indexes = [row[0] for row in cursor.fetchall()]
        logger.info(f"✅ {len(indexes)} indexes created")

        # Check default admin user
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'admin@sentinel.com';")
        if cursor.fetchone()[0] == 0:
            issues.append("Default admin user not found")
            logger.warning("⚠️  Default admin user not found")
        else:
            logger.info("✅ Default admin user exists")

        cursor.close()

        if not issues:
            logger.info("\n✅ INITIALIZATION VERIFIED SUCCESSFULLY")
            return True, []
        else:
            logger.error(f"\n❌ VERIFICATION FAILED: {len(issues)} issue(s)")
            return False, issues

    except Exception as e:
        issues.append(f"Verification error: {e}")
        logger.error(f"❌ Verification failed: {e}")
        return False, issues


def initialize_database_with_retry() -> bool:
    """
    Main initialization function with comprehensive error handling

    Returns:
        success: bool
    """
    start_time = time.time()

    logger.info("=" * 60)
    logger.info("SENTINEL DATABASE INITIALIZATION")
    logger.info(f"Started at: {datetime.utcnow().isoformat()}")
    logger.info("=" * 60)

    # Step 1: Wait for database
    success, error = wait_for_database()
    if not success:
        logger.error(f"❌ Initialization failed: {error}")
        return False

    conn = None
    try:
        # Step 2: Connect
        conn = psycopg2.connect(**DB_CONFIG)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        logger.info("✅ Connected to database")

        # Step 3: Check pgvector
        success, error = check_pgvector_extension(conn)
        if not success:
            logger.error(f"❌ Initialization failed: {error}")
            return False

        # Step 4: Check existing schema
        schema_info = check_existing_schema(conn)

        # Step 5: Execute initialization script if needed
        if not schema_info['is_complete']:
            logger.info("\n" + "=" * 60)
            logger.info("INITIALIZING SCHEMA")
            logger.info("=" * 60)

            script_path = os.path.join(
                os.path.dirname(__file__),
                '..',
                'init_db.sql'
            )

            success, error = execute_sql_script(conn, script_path)
            if not success:
                logger.error(f"❌ Initialization failed: {error}")
                return False
        else:
            logger.info("\n✅ Schema already complete, skipping initialization")

        # Step 6: Verify initialization
        success, issues = verify_initialization(conn)
        if not success:
            logger.error("❌ Initialization verification failed:")
            for issue in issues:
                logger.error(f"  - {issue}")
            return False

        # Success!
        duration = time.time() - start_time
        logger.info("\n" + "=" * 60)
        logger.info("✅ DATABASE INITIALIZATION COMPLETE")
        logger.info(f"Duration: {duration:.2f} seconds")
        logger.info("=" * 60)

        return True

    except Exception as e:
        logger.error(f"❌ Initialization failed: {e}")
        return False

    finally:
        if conn:
            conn.close()


def main():
    """Main entry point"""
    success = initialize_database_with_retry()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
