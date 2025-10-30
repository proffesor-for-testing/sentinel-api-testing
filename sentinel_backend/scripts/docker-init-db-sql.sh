#!/bin/bash
set -e

# Docker database initialization script (SQL-only version)
# This runs ONLY on first database creation (via docker-entrypoint-initdb.d)
# It's idempotent - safe to run multiple times, preserves existing data

echo "=========================================="
echo "Sentinel Database Initialization (SQL)"
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

# Function to create schema using SQL
initialize_database_sql() {
    echo ""
    echo "=========================================="
    echo "Initializing Database Schema (SQL)"
    echo "=========================================="

    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'EOF'
-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create projects table
CREATE TABLE IF NOT EXISTS projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name, owner_id)
);

-- Create api_specifications table
CREATE TABLE IF NOT EXISTS api_specifications (
    id SERIAL PRIMARY KEY,
    project_id INTEGER,
    title TEXT,
    description TEXT,
    raw_spec TEXT NOT NULL,
    parsed_spec JSONB NOT NULL,
    internal_graph JSONB,
    source_url TEXT,
    source_filename TEXT,
    llm_readiness_score FLOAT,
    version VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create test_cases table
CREATE TABLE IF NOT EXISTS test_cases (
    id SERIAL PRIMARY KEY,
    spec_id INTEGER NOT NULL,
    agent_type VARCHAR(255) NOT NULL,
    description TEXT,
    test_definition JSONB NOT NULL,
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create test_suites table
CREATE TABLE IF NOT EXISTS test_suites (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create test_suite_entries table
CREATE TABLE IF NOT EXISTS test_suite_entries (
    suite_id INTEGER REFERENCES test_suites(id) ON DELETE CASCADE,
    case_id INTEGER REFERENCES test_cases(id) ON DELETE CASCADE,
    execution_order INTEGER DEFAULT 0,
    PRIMARY KEY (suite_id, case_id)
);

-- Create test_runs table
CREATE TABLE IF NOT EXISTS test_runs (
    id SERIAL PRIMARY KEY,
    suite_id INTEGER REFERENCES test_suites(id) ON DELETE CASCADE NOT NULL,
    status VARCHAR(50) NOT NULL,
    target_environment TEXT,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Create test_results table
CREATE TABLE IF NOT EXISTS test_results (
    id BIGSERIAL PRIMARY KEY,
    run_id INTEGER REFERENCES test_runs(id) ON DELETE CASCADE NOT NULL,
    case_id INTEGER REFERENCES test_cases(id) ON DELETE CASCADE NOT NULL,
    status VARCHAR(50) NOT NULL,
    response_code INTEGER,
    response_headers JSONB,
    response_body TEXT,
    latency_ms INTEGER,
    assertion_failures JSONB,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_test_cases_spec_id ON test_cases(spec_id);
CREATE INDEX IF NOT EXISTS idx_test_results_run_id ON test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_suite_id ON test_runs(suite_id);
CREATE INDEX IF NOT EXISTS idx_test_cases_id ON test_cases(id);
CREATE INDEX IF NOT EXISTS idx_test_results_id ON test_results(id);

-- Create default admin user (password: admin123)
INSERT INTO users (email, username, hashed_password, is_active, is_admin)
VALUES (
    'admin@sentinel.com',
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzS.lhAway',
    TRUE,
    TRUE
) ON CONFLICT (email) DO NOTHING;

EOF

    echo ""
    echo "✅ Database schema initialized successfully!"
    echo ""
    echo "Created tables:"
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\dt" | head -20
    echo ""
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

    # Initialize the database with SQL
    if initialize_database_sql; then
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
