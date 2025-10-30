#!/bin/bash
set -e

# Docker entrypoint script for Sentinel backend services
# Ensures database is ready and initialized before starting service

SERVICE_NAME="${SERVICE_NAME:-unknown-service}"
DB_HOST="${DB_HOST:-db}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-sentinel}"
DB_NAME="${DB_NAME:-sentinel_db}"
MAX_RETRIES=30
RETRY_INTERVAL=2

echo "=========================================="
echo "Sentinel Service Startup: $SERVICE_NAME"
echo "=========================================="
echo "Database Host: $DB_HOST:$DB_PORT"
echo "Database Name: $DB_NAME"
echo "Database User: $DB_USER"
echo ""

# Function to wait for database to be ready
wait_for_db() {
    echo "Waiting for database to be ready..."
    local retry_count=0

    while [ $retry_count -lt $MAX_RETRIES ]; do
        if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > /dev/null 2>&1; then
            echo "✅ Database is ready!"
            return 0
        fi

        retry_count=$((retry_count + 1))
        echo "⏳ Attempt $retry_count/$MAX_RETRIES - Database not ready, waiting ${RETRY_INTERVAL}s..."
        sleep $RETRY_INTERVAL
    done

    echo "❌ ERROR: Database failed to become ready after $MAX_RETRIES attempts"
    exit 1
}

# Function to check if database schema is initialized
check_schema() {
    echo "Checking database schema..."

    # Check if test_runs table exists (required table)
    if PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        -c "SELECT 1 FROM test_runs LIMIT 1;" > /dev/null 2>&1; then
        echo "✅ Database schema is initialized"
        return 0
    else
        echo "⚠️  Database schema not initialized"
        return 1
    fi
}

# Function to initialize database schema
initialize_schema() {
    echo "Initializing database schema..."

    # Run initialization script with retry logic
    if python3 /app/sentinel_backend/scripts/init_db_with_retry.py; then
        echo "✅ Database schema initialized successfully"
        return 0
    else
        echo "❌ ERROR: Failed to initialize database schema"
        exit 1
    fi
}

# Main startup logic
main() {
    # Step 1: Wait for database to be ready
    wait_for_db

    # Step 2: Check if schema is initialized
    if ! check_schema; then
        # Step 3: Initialize schema if not present
        initialize_schema
    fi

    # Step 4: Start the service
    echo ""
    echo "=========================================="
    echo "Starting $SERVICE_NAME"
    echo "=========================================="
    echo "Command: $@"
    echo ""

    # Execute the service command
    exec "$@"
}

# Run main function with all arguments
main "$@"
