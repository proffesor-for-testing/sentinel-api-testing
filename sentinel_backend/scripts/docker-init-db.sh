#!/bin/bash
set -e

# Docker database initialization script
# This runs ONLY on first database creation (via docker-entrypoint-initdb.d)
# It's idempotent - safe to run multiple times, preserves existing data

echo "=========================================="
echo "Sentinel Database Initialization"
echo "=========================================="
echo "Database: $POSTGRES_DB"
echo "User: $POSTGRES_USER"
echo ""

# Function to check if tables exist
check_tables_exist() {
    echo "Checking if database schema already exists..."

    # Check if test_runs table exists (indicator of initialized schema)
    if psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT 1 FROM test_runs LIMIT 1;" > /dev/null 2>&1; then
        echo "✅ Database schema already exists - skipping initialization"
        echo "   (Preserving existing data)"
        return 0
    else
        echo "⚠️  Database schema not found - will initialize"
        return 1
    fi
}

# Function to install required Python packages
install_python_packages() {
    echo "Installing required Python packages..."
    pip3 install -q psycopg2-binary sqlalchemy asyncpg structlog pydantic pydantic-settings > /dev/null 2>&1
    echo "✅ Python packages installed"
}

# Function to run initialization script
initialize_database() {
    echo ""
    echo "=========================================="
    echo "Initializing Database Schema"
    echo "=========================================="

    # Set Python path
    export PYTHONPATH=/scripts:$PYTHONPATH

    # Set database URL for the initialization script
    export SENTINEL_DB_URL="postgresql+asyncpg://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/$POSTGRES_DB"

    # Run the initialization script
    cd /scripts
    if python3 init_db_with_retry.py; then
        echo ""
        echo "✅ Database schema initialized successfully!"
        echo ""
        echo "Created tables:"
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt" | head -20
        echo ""
        return 0
    else
        echo "❌ ERROR: Failed to initialize database schema"
        return 1
    fi
}

# Main execution
main() {
    # Check if schema already exists
    if check_tables_exist; then
        echo ""
        echo "=========================================="
        echo "✅ Database Ready (Existing Data Preserved)"
        echo "=========================================="
        exit 0
    fi

    # Install required packages
    install_python_packages

    # Initialize the database
    if initialize_database; then
        echo "=========================================="
        echo "✅ Database Initialization Complete"
        echo "=========================================="
        exit 0
    else
        echo "=========================================="
        echo "❌ Database Initialization Failed"
        echo "=========================================="
        exit 1
    fi
}

# Run main function
main
