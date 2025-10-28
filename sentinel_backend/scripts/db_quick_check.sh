#!/bin/bash
# Quick database check for Docker healthcheck
# Optimized for minimal overhead in container health checks

set -e

host="${DB_HOST:-localhost}"
port="${DB_PORT:-5432}"
user="${DB_USER:-sentinel}"
database="${DB_NAME:-sentinel_db}"

# Quick connection check
if ! PGPASSWORD="$DB_PASSWORD" psql -h "$host" -p "$port" -U "$user" -d "$database" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "Database connection failed"
    exit 1
fi

# Quick pgvector check
if ! PGPASSWORD="$DB_PASSWORD" psql -h "$host" -p "$port" -U "$user" -d "$database" -c "SELECT 1 FROM pg_extension WHERE extname = 'vector' LIMIT 1;" > /dev/null 2>&1; then
    echo "pgvector extension not available"
    exit 1
fi

echo "healthy"
exit 0
