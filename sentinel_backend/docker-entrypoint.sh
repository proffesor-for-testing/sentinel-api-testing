#!/bin/bash
# Docker entrypoint script for Sentinel services
# Ensures database is initialized before starting services

set -e

# Function to initialize database
init_database() {
    echo "Checking database initialization..."
    python /app/sentinel_backend/init_database.py
    if [ $? -eq 0 ]; then
        echo "Database initialization successful"
    else
        echo "Database initialization failed, but continuing..."
        # You might want to exit here in production
    fi
}

# Service-specific initialization
case "$1" in
    "data_service")
        echo "Starting Data Service..."
        init_database
        exec uvicorn sentinel_backend.data_service.main:app --host 0.0.0.0 --port 8004 --reload
        ;;
    "spec_service")
        echo "Starting Spec Service..."
        init_database
        exec uvicorn sentinel_backend.spec_service.main:app --host 0.0.0.0 --port 8001 --reload
        ;;
    "orchestration_service")
        echo "Starting Orchestration Service..."
        init_database
        exec uvicorn sentinel_backend.orchestration_service.main:app --host 0.0.0.0 --port 8002 --reload
        ;;
    "execution_service")
        echo "Starting Execution Service..."
        init_database
        exec uvicorn sentinel_backend.execution_service.main:app --host 0.0.0.0 --port 8003 --reload
        ;;
    "api_gateway")
        echo "Starting API Gateway..."
        init_database
        exec uvicorn sentinel_backend.api_gateway.main:app --host 0.0.0.0 --port 8000 --reload
        ;;
    "auth_service")
        echo "Starting Auth Service..."
        init_database
        exec uvicorn sentinel_backend.auth_service.main:app --host 0.0.0.0 --port 8005 --reload
        ;;
    *)
        echo "Unknown service: $1"
        echo "Usage: $0 {data_service|spec_service|orchestration_service|execution_service|api_gateway|auth_service}"
        exit 1
        ;;
esac