#!/usr/bin/env python3
"""
Database Initialization Script for Sentinel
Automatically creates all required tables with proper schema
"""

import os
import sys
import time
import psycopg2
from psycopg2 import sql
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'db'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'sentinel_db'),
    'user': os.getenv('DB_USER', 'sentinel'),
    'password': os.getenv('DB_PASSWORD', 'sentinel_password')
}

def wait_for_db(max_retries=30):
    """Wait for database to be available"""
    for i in range(max_retries):
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            logger.info("Database is ready!")
            return True
        except psycopg2.OperationalError:
            logger.info(f"Waiting for database... ({i+1}/{max_retries})")
            time.sleep(2)
    logger.error("Database connection failed after maximum retries")
    return False

def check_tables_exist(conn):
    """Check if tables already exist"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name IN ('users', 'test_cases', 'test_results', 'test_runs', 'test_suites')
    """)
    count = cursor.fetchone()[0]
    cursor.close()
    return count >= 5  # All main tables exist

def initialize_database():
    """Initialize database with all required tables"""

    # Wait for database to be ready
    if not wait_for_db():
        sys.exit(1)

    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True

        # Check if already initialized
        if check_tables_exist(conn):
            logger.info("Database already initialized, checking for missing columns...")
            # We could add column checking here if needed
            return

        logger.info("Initializing database schema...")

        # Read and execute the init script
        init_script_path = os.path.join(os.path.dirname(__file__), 'init_db.sql')

        if os.path.exists(init_script_path):
            with open(init_script_path, 'r') as f:
                sql_script = f.read()

            cursor = conn.cursor()
            cursor.execute(sql_script)
            cursor.close()
            logger.info("Database schema initialized successfully!")
        else:
            logger.error(f"Init script not found at {init_script_path}")
            sys.exit(1)

    except psycopg2.Error as e:
        logger.error(f"Database error: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

def verify_initialization():
    """Verify that all tables and columns exist"""
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Check critical tables
        tables_to_check = [
            'users', 'projects', 'api_specifications', 'test_cases',
            'test_suites', 'test_suite_entries', 'test_runs', 'test_results'
        ]

        for table in tables_to_check:
            cursor.execute(f"""
                SELECT COUNT(*) FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = %s
            """, (table,))
            if cursor.fetchone()[0] == 0:
                logger.error(f"Table {table} is missing!")
                return False
            else:
                logger.info(f"✓ Table {table} exists")

        # Check for critical columns in test_results
        cursor.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'test_results' AND table_schema = 'public'
        """)
        columns = [row[0] for row in cursor.fetchall()]
        required_columns = [
            'id', 'run_id', 'test_case_id', 'case_id', 'status',
            'response_code', 'response_headers', 'response_body',
            'latency_ms', 'assertion_failures'
        ]

        missing_columns = set(required_columns) - set(columns)
        if missing_columns:
            logger.warning(f"Missing columns in test_results: {missing_columns}")
            return False

        logger.info("✓ All required columns exist in test_results")

        cursor.close()
        return True

    except psycopg2.Error as e:
        logger.error(f"Verification error: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    logger.info("Starting database initialization...")
    initialize_database()

    if verify_initialization():
        logger.info("✅ Database initialization completed successfully!")
    else:
        logger.error("❌ Database initialization verification failed")
        sys.exit(1)