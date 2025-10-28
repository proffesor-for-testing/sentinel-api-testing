#!/bin/bash
# Wait for database to be ready before starting services
# This script is used in Docker containers to ensure database is available

set -e

host="${DB_HOST:-db}"
port="${DB_PORT:-5432}"
user="${DB_USER:-sentinel}"
database="${DB_NAME:-sentinel_db}"

max_attempts=30
attempt=0

echo "=================================================="
echo "Waiting for PostgreSQL database to be ready..."
echo "=================================================="
echo "Host: $host:$port"
echo "Database: $database"
echo "User: $user"
echo ""

while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt + 1))

    # Try to connect
    if PGPASSWORD="$DB_PASSWORD" psql -h "$host" -p "$port" -U "$user" -d "$database" -c "SELECT 1;" > /dev/null 2>&1; then
        echo "✅ Database is ready!"

        # Check pgvector extension
        if PGPASSWORD="$DB_PASSWORD" psql -h "$host" -p "$port" -U "$user" -d "$database" -c "SELECT 1 FROM pg_extension WHERE extname = 'vector';" > /dev/null 2>&1; then
            echo "✅ pgvector extension is available"
        else
            echo "⚠️  pgvector extension not found, attempting to create..."
            PGPASSWORD="$DB_PASSWORD" psql -h "$host" -p "$port" -U "$user" -d "$database" -c "CREATE EXTENSION IF NOT EXISTS vector;" > /dev/null 2>&1 || true
        fi

        exit 0
    fi

    echo "Attempt $attempt/$max_attempts: Database not ready yet..."
    sleep 2
done

echo "❌ Database failed to become ready after $max_attempts attempts"
exit 1
