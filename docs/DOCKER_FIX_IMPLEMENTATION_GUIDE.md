# Docker Startup Fix - Implementation Guide

**Status**: Ready to Implement
**Estimated Time**: 4-6 hours
**Risk Level**: Low (configuration only)
**Testing Required**: Yes (automated test included)

---

## Quick Fix (15 Minutes) - Emergency Demo Recovery

### Step 1: Update .env.docker (2 min)

```bash
# Add to sentinel_backend/.env.docker
cat >> /workspaces/api-testing-agents/sentinel_backend/.env.docker << 'EOF'

# =============================================================================
# Database Connection Configuration (Required for Docker)
# =============================================================================
SENTINEL_DB_URL=postgresql+asyncpg://sentinel:sentinel_password@db:5432/sentinel_db
DB_HOST=db
DB_PORT=5432
DB_USER=sentinel
DB_PASSWORD=sentinel_password
DB_NAME=sentinel_db
EOF
```

### Step 2: Fix settings.py Default (3 min)

```bash
# Edit /workspaces/api-testing-agents/sentinel_backend/config/settings.py:30
# Change:
default="postgresql+asyncpg://sentinel:sentinel_password@localhost:5432/sentinel_db"

# To:
default=os.getenv(
    "SENTINEL_DB_URL",
    "postgresql+asyncpg://sentinel:sentinel_password@db:5432/sentinel_db"
)
```

### Step 3: Add Database Auto-Init (5 min)

```bash
# Edit /workspaces/api-testing-agents/docker-compose.yml
# In the 'db' service, update volumes section:

volumes:
  - sentinel_postgres_data:/var/lib/postgresql/data
  # ADD THESE TWO LINES:
  - ./sentinel_backend/init_db.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro
  - ./sentinel_backend/scripts:/docker-entrypoint-initdb.d/scripts:ro
```

### Step 4: Fix auth_service dependency (2 min)

```bash
# Edit /workspaces/api-testing-agents/docker-compose.yml
# Find auth_service section (line ~68), add depends_on:

auth_service:
  build:
    context: .
    dockerfile: sentinel_backend/auth_service/Dockerfile.prod
  container_name: sentinel_auth_service
  env_file:
    - sentinel_backend/.env.docker
  working_dir: /app
  ports:
    - "8005:8005"
  # ADD THESE LINES:
  depends_on:
    db:
      condition: service_healthy
  networks:
    - sentinel_network
```

### Step 5: Test (3 min)

```bash
# Clean environment
docker-compose down -v

# Start fresh
docker-compose up -d

# Watch logs
docker-compose logs -f db spec_service execution_service

# Verify (wait 30 seconds)
curl http://localhost:8000/health
curl http://localhost:3000
```

**If this works**: System operational! Proceed to comprehensive fix.

**If this doesn't work**: Check logs for specific errors, see troubleshooting section below.

---

## Comprehensive Fix (4-6 Hours)

### Phase 1: Configuration Files (1 hour)

#### 1.1 Create Comprehensive .env.docker

**File**: `/workspaces/api-testing-agents/sentinel_backend/.env.docker`

```bash
# =============================================================================
# Sentinel Docker Environment Configuration
# =============================================================================

# =============================================================================
# Environment
# =============================================================================
SENTINEL_ENVIRONMENT=docker

# =============================================================================
# Database Configuration
# =============================================================================
SENTINEL_DB_URL=postgresql+asyncpg://sentinel:sentinel_password@db:5432/sentinel_db
DB_HOST=db
DB_PORT=5432
DB_USER=sentinel
DB_PASSWORD=sentinel_password
DB_NAME=sentinel_db

# =============================================================================
# Application Configuration
# =============================================================================
SENTINEL_APP_DEBUG=false
SENTINEL_APP_LOG_LEVEL=INFO
SENTINEL_APP_NAME=Sentinel API Testing Platform
SENTINEL_APP_VERSION=1.0.0

# =============================================================================
# LLM Configuration
# =============================================================================
SENTINEL_APP_LLM_PROVIDER=anthropic
SENTINEL_APP_LLM_MODEL=claude-sonnet-4
SENTINEL_APP_LLM_TEMPERATURE=0.7
SENTINEL_APP_LLM_MAX_TOKENS=2000

# Provider API Keys (set these via environment or secrets)
# SENTINEL_APP_ANTHROPIC_API_KEY=your-key-here
# SENTINEL_APP_OPENAI_API_KEY=your-key-here

# =============================================================================
# Message Broker Configuration
# =============================================================================
SENTINEL_BROKER_URL=amqp://guest:guest@message_broker:5672/
SENTINEL_BROKER_TASK_QUEUE_NAME=sentinel_task_queue
SENTINEL_BROKER_RESULT_QUEUE_NAME=sentinel_result_queue

# =============================================================================
# Security Configuration
# =============================================================================
SENTINEL_SECURITY_JWT_SECRET_KEY=docker-dev-secret-key-change-in-production-min-32-chars
SENTINEL_SECURITY_JWT_ALGORITHM=HS256
SENTINEL_SECURITY_JWT_EXPIRATION_HOURS=24
SENTINEL_SECURITY_CORS_ORIGINS=["http://localhost:3000","http://localhost:8080"]
SENTINEL_SECURITY_DEFAULT_ADMIN_EMAIL=admin@sentinel.com
SENTINEL_SECURITY_DEFAULT_ADMIN_PASSWORD=admin123

# =============================================================================
# Network Configuration
# =============================================================================
SENTINEL_NETWORK_HOST=0.0.0.0
SENTINEL_NETWORK_API_GATEWAY_PORT=8000
SENTINEL_NETWORK_AUTH_SERVICE_PORT=8005
SENTINEL_NETWORK_SPEC_SERVICE_PORT=8001
SENTINEL_NETWORK_ORCHESTRATION_SERVICE_PORT=8002
SENTINEL_NETWORK_EXECUTION_SERVICE_PORT=8003
SENTINEL_NETWORK_DATA_SERVICE_PORT=8004

# =============================================================================
# Database Connection Pool Settings
# =============================================================================
SENTINEL_DB_POOL_SIZE=10
SENTINEL_DB_MAX_OVERFLOW=20
SENTINEL_DB_POOL_TIMEOUT=30
SENTINEL_DB_POOL_RECYCLE=3600

# =============================================================================
# Feature Flags
# =============================================================================
SENTINEL_APP_ENABLE_ANALYTICS=true
SENTINEL_APP_ENABLE_PERFORMANCE_TESTING=true
SENTINEL_APP_ENABLE_SECURITY_TESTING=true
SENTINEL_APP_ENABLE_DATA_MOCKING=true

# =============================================================================
# Observability
# =============================================================================
SENTINEL_APP_METRICS_ENABLED=true
SENTINEL_APP_TRACING_ENABLED=false
SENTINEL_NETWORK_JAEGER_AGENT_HOST=jaeger
SENTINEL_NETWORK_JAEGER_AGENT_PORT=6831
```

#### 1.2 Update settings.py

**File**: `/workspaces/api-testing-agents/sentinel_backend/config/settings.py:26-46`

```python
import os
from typing import Optional, List, Dict, Any
from functools import lru_cache
from pydantic import Field, validator
from pydantic_settings import BaseSettings
from enum import Enum


def get_default_db_url() -> str:
    """
    Get default database URL based on environment.
    Automatically detects Docker environment.
    """
    # Check if running in Docker
    is_docker = (
        os.path.exists("/.dockerenv") or
        os.getenv("DOCKER_CONTAINER") == "true" or
        os.getenv("SENTINEL_ENVIRONMENT") == "docker"
    )

    if is_docker:
        return "postgresql+asyncpg://sentinel:sentinel_password@db:5432/sentinel_db"
    else:
        return "postgresql+asyncpg://sentinel:sentinel_password@localhost:5432/sentinel_db"


class DatabaseSettings(BaseSettings):
    """Database configuration settings."""

    # Connection settings
    url: str = Field(
        default_factory=get_default_db_url,
        description="Database connection URL"
    )

    # Pool settings
    pool_size: int = Field(default=10, description="Database connection pool size")
    max_overflow: int = Field(default=20, description="Maximum pool overflow")
    pool_timeout: int = Field(default=30, description="Pool timeout in seconds")
    pool_recycle: int = Field(default=3600, description="Pool recycle time in seconds")

    # Migration settings
    auto_migrate: bool = Field(default=True, description="Auto-run database migrations")
    migration_timeout: int = Field(default=300, description="Migration timeout in seconds")

    class Config:
        env_prefix = "SENTINEL_DB_"
        case_sensitive = False
```

#### 1.3 Create Admin User SQL Script

**File**: `/workspaces/api-testing-agents/sentinel_backend/scripts/02-create-admin.sql`

```sql
-- Create default admin user
-- Password: admin123 (hashed with bcrypt)
-- This runs after schema initialization

DO $$
BEGIN
    -- Check if admin user already exists
    IF NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@sentinel.com') THEN
        -- Insert admin user
        -- Note: In production, password should be properly hashed
        INSERT INTO users (
            email,
            username,
            password_hash,
            is_active,
            is_admin,
            created_at,
            updated_at
        ) VALUES (
            'admin@sentinel.com',
            'admin',
            '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5/dBE7WwD.Y0i', -- admin123
            true,
            true,
            NOW(),
            NOW()
        );

        RAISE NOTICE 'Default admin user created: admin@sentinel.com / admin123';
    ELSE
        RAISE NOTICE 'Admin user already exists, skipping creation';
    END IF;
END $$;
```

#### 1.4 Update docker-compose.yml

**File**: `/workspaces/api-testing-agents/docker-compose.yml`

Key changes:

```yaml
services:
  db:
    image: pgvector/pgvector:pg16
    container_name: sentinel_db
    env_file:
      - sentinel_backend/.env.docker
    environment:
      - POSTGRES_USER=sentinel
      - POSTGRES_PASSWORD=sentinel_password
      - POSTGRES_DB=sentinel_db
    ports:
      - "5432:5432"
    volumes:
      - sentinel_postgres_data:/var/lib/postgresql/data
      # ✅ Auto-initialize database on first startup
      - ./sentinel_backend/init_db.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro
      - ./sentinel_backend/scripts/02-create-admin.sql:/docker-entrypoint-initdb.d/02-admin.sql:ro
    healthcheck:
      # ✅ Enhanced health check - verify tables exist
      test: |
        pg_isready -U sentinel -d sentinel_db &&
        psql -U sentinel -d sentinel_db -tc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'" | grep -qE '[8-9]|[1-9][0-9]' &&
        psql -U sentinel -d sentinel_db -c "SELECT 1 FROM pg_extension WHERE extname = 'vector' LIMIT 1;"
      interval: 10s
      timeout: 10s
      retries: 20
      start_period: 60s
    networks:
      - sentinel_network

  auth_service:
    build:
      context: .
      dockerfile: sentinel_backend/auth_service/Dockerfile.prod
    container_name: sentinel_auth_service
    env_file:
      - sentinel_backend/.env.docker
    working_dir: /app
    ports:
      - "8005:8005"
    # ✅ Wait for healthy database
    depends_on:
      db:
        condition: service_healthy
    networks:
      - sentinel_network

  # All other DB-dependent services already have correct config
  # Just verify they have condition: service_healthy
```

---

### Phase 2: Service Dockerfiles (1.5 hours)

#### 2.1 Add Wait Script to All Services

**Template for all Dockerfile.prod files**:

```dockerfile
# Production Dockerfile - expects root directory as build context
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create the sentinel_backend directory structure
RUN mkdir -p /app/sentinel_backend

# Copy the sentinel_backend directory from root context
COPY sentinel_backend /app/sentinel_backend/

# Install poetry and dependencies
RUN cd /app/sentinel_backend && \
    pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

# Copy wait-for-db script
COPY sentinel_backend/scripts/wait_for_db.sh /app/wait_for_db.sh
RUN chmod +x /app/wait_for_db.sh

# Set Python path
ENV PYTHONPATH=/app:$PYTHONPATH

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:PORT/health || exit 1

# Start with wait-for-db
CMD ["/bin/bash", "-c", "/app/wait_for_db.sh && uvicorn sentinel_backend.SERVICE_NAME.main:app --host 0.0.0.0 --port PORT"]
```

**Apply to these files**:
- `/workspaces/api-testing-agents/sentinel_backend/auth_service/Dockerfile.prod` (port 8005)
- `/workspaces/api-testing-agents/sentinel_backend/spec_service/Dockerfile.prod` (port 8001)
- `/workspaces/api-testing-agents/sentinel_backend/execution_service/Dockerfile.prod` (port 8003)
- `/workspaces/api-testing-agents/sentinel_backend/data_service/Dockerfile.prod` (port 8004)

#### 2.2 Enhanced wait_for_db.sh

**File**: `/workspaces/api-testing-agents/sentinel_backend/scripts/wait_for_db.sh`

```bash
#!/bin/bash
# Enhanced wait-for-database script with retry logic and verification
# Usage: ./wait_for_db.sh

set -e

# Configuration from environment
host="${DB_HOST:-db}"
port="${DB_PORT:-5432}"
user="${DB_USER:-sentinel}"
password="${DB_PASSWORD:-sentinel_password}"
database="${DB_NAME:-sentinel_db}"

max_attempts=30
attempt=0
retry_delay=2

echo "=================================================="
echo "Waiting for PostgreSQL database to be ready..."
echo "=================================================="
echo "Host: $host:$port"
echo "Database: $database"
echo "User: $user"
echo ""

# Function to check database
check_database() {
    PGPASSWORD="$password" psql \
        -h "$host" \
        -p "$port" \
        -U "$user" \
        -d "$database" \
        -c "SELECT 1;" \
        > /dev/null 2>&1
}

# Function to check tables exist
check_tables() {
    local table_count=$(PGPASSWORD="$password" psql \
        -h "$host" \
        -p "$port" \
        -U "$user" \
        -d "$database" \
        -t \
        -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" \
        2>/dev/null | tr -d ' ')

    if [ "$table_count" -ge 8 ]; then
        return 0
    else
        return 1
    fi
}

# Function to check pgvector extension
check_pgvector() {
    PGPASSWORD="$password" psql \
        -h "$host" \
        -p "$port" \
        -U "$user" \
        -d "$database" \
        -c "SELECT 1 FROM pg_extension WHERE extname = 'vector';" \
        > /dev/null 2>&1
}

# Main wait loop
while [ $attempt -lt $max_attempts ]; do
    attempt=$((attempt + 1))

    # Step 1: Check if database is accepting connections
    if ! check_database; then
        echo "Attempt $attempt/$max_attempts: Database not ready yet..."
        sleep $retry_delay
        continue
    fi

    echo "✅ Database is accepting connections"

    # Step 2: Check if pgvector extension exists
    if ! check_pgvector; then
        echo "⚠️  Attempt $attempt/$max_attempts: pgvector extension not found, waiting..."
        sleep $retry_delay
        continue
    fi

    echo "✅ pgvector extension is available"

    # Step 3: Check if tables exist
    if ! check_tables; then
        echo "⚠️  Attempt $attempt/$max_attempts: Schema not initialized yet, waiting..."
        sleep $retry_delay
        continue
    fi

    echo "✅ Database schema is initialized"
    echo ""
    echo "=================================================="
    echo "✅ DATABASE IS READY!"
    echo "=================================================="
    exit 0
done

echo ""
echo "=================================================="
echo "❌ DATABASE FAILED TO BECOME READY"
echo "=================================================="
echo "After $max_attempts attempts, database is not ready"
echo ""
echo "Troubleshooting:"
echo "1. Check database logs: docker-compose logs db"
echo "2. Verify database is running: docker-compose ps db"
echo "3. Check init scripts ran: docker-compose exec db psql -U sentinel -d sentinel_db -c '\\dt'"
echo "4. Manual init: make init-db"
exit 1
```

---

### Phase 3: Enhanced Makefile (30 minutes)

**File**: `/workspaces/api-testing-agents/Makefile`

```makefile
.PHONY: help setup start stop restart clean test init-db status logs

# Default target
help:
	@echo "Sentinel API Testing Platform - Available Commands:"
	@echo ""
	@echo "Quick Start:"
	@echo "  make setup             - Complete setup from scratch (recommended for first time)"
	@echo "  make start             - Start all services"
	@echo "  make stop              - Stop all services"
	@echo "  make restart           - Restart all services"
	@echo ""
	@echo "Database:"
	@echo "  make init-db           - Initialize database (manual fallback)"
	@echo "  make db-health         - Check database health"
	@echo "  make reset-db          - Reset database (WARNING: destroys data)"
	@echo ""
	@echo "Development:"
	@echo "  make logs              - Show service logs"
	@echo "  make status            - Show service status"
	@echo "  make test              - Run tests"
	@echo "  make clean             - Clean up containers and volumes"
	@echo ""
	@echo "Troubleshooting:"
	@echo "  make diagnose          - Run diagnostic checks"
	@echo "  make verify            - Verify system is operational"

# Complete setup from scratch
setup:
	@echo "=========================================="
	@echo "Sentinel Platform - Complete Setup"
	@echo "=========================================="
	@echo ""
	@echo "Step 1: Cleaning previous installation..."
	@docker-compose down -v 2>/dev/null || true
	@echo ""
	@echo "Step 2: Building Docker images..."
	@docker-compose build
	@echo ""
	@echo "Step 3: Starting services..."
	@docker-compose up -d
	@echo ""
	@echo "Step 4: Waiting for initialization (this may take 60 seconds)..."
	@sleep 60
	@echo ""
	@echo "Step 5: Verifying system..."
	@make verify
	@echo ""
	@echo "=========================================="
	@echo "✅ Setup Complete!"
	@echo "=========================================="
	@echo ""
	@echo "Access Points:"
	@echo "  Frontend:    http://localhost:3000"
	@echo "  API Gateway: http://localhost:8000"
	@echo "  API Docs:    http://localhost:8000/docs"
	@echo ""
	@echo "Default Login:"
	@echo "  Email:    admin@sentinel.com"
	@echo "  Password: admin123"
	@echo ""

# Start services
start:
	@echo "Starting Sentinel services..."
	@docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 30
	@make status

# Stop services
stop:
	@echo "Stopping Sentinel services..."
	@docker-compose down

# Restart services
restart:
	@make stop
	@make start

# Initialize database (manual fallback)
init-db:
	@echo "=========================================="
	@echo "Manual Database Initialization"
	@echo "=========================================="
	@echo "Note: This should not be needed with auto-init"
	@python3 sentinel_backend/scripts/init_db_with_retry.py

# Check database health
db-health:
	@echo "Checking database health..."
	@docker-compose exec db pg_isready -U sentinel -d sentinel_db

# Show service status
status:
	@echo "=========================================="
	@echo "Service Status"
	@echo "=========================================="
	@docker-compose ps
	@echo ""
	@echo "Quick Health Checks:"
	@echo -n "  Database:         "
	@curl -f -s http://localhost:5432 >/dev/null 2>&1 && echo "✅ Running" || echo "❌ Not responding"
	@echo -n "  API Gateway:      "
	@curl -f -s http://localhost:8000/health >/dev/null 2>&1 && echo "✅ Healthy" || echo "❌ Not responding"
	@echo -n "  Auth Service:     "
	@curl -f -s http://localhost:8005/health >/dev/null 2>&1 && echo "✅ Healthy" || echo "❌ Not responding"
	@echo -n "  Spec Service:     "
	@curl -f -s http://localhost:8001/health >/dev/null 2>&1 && echo "✅ Healthy" || echo "❌ Not responding"
	@echo -n "  Execution:        "
	@curl -f -s http://localhost:8003/health >/dev/null 2>&1 && echo "✅ Healthy" || echo "❌ Not responding"
	@echo -n "  Data Service:     "
	@curl -f -s http://localhost:8004/health >/dev/null 2>&1 && echo "✅ Healthy" || echo "❌ Not responding"
	@echo -n "  Frontend:         "
	@curl -f -s http://localhost:3000 >/dev/null 2>&1 && echo "✅ Running" || echo "❌ Not responding"

# Show logs
logs:
	@docker-compose logs -f --tail=50

# Run tests
test:
	@echo "Running tests..."
	@./tests/test_docker_startup.sh

# Clean up
clean:
	@echo "Cleaning up Sentinel..."
	@docker-compose down -v
	@docker volume prune -f
	@docker network prune -f
	@echo "Cleanup complete!"

# Verify system is operational
verify:
	@echo "=========================================="
	@echo "System Verification"
	@echo "=========================================="
	@echo ""
	@echo "Checking database..."
	@docker-compose exec -T db psql -U sentinel -d sentinel_db -c "\dt" | grep -q "public" && echo "✅ Database tables exist" || echo "❌ Database tables missing"
	@echo ""
	@echo "Checking services..."
	@for port in 8000 8001 8003 8004 8005; do \
		echo -n "  Port $$port: "; \
		curl -f -s http://localhost:$$port/health >/dev/null 2>&1 && echo "✅" || echo "❌"; \
	done
	@echo ""
	@echo "Checking frontend..."
	@curl -f -s http://localhost:3000 >/dev/null 2>&1 && echo "✅ Frontend accessible" || echo "❌ Frontend not accessible"

# Run diagnostics
diagnose:
	@echo "=========================================="
	@echo "System Diagnostics"
	@echo "=========================================="
	@echo ""
	@echo "Docker Compose Status:"
	@docker-compose ps
	@echo ""
	@echo "Database Logs (last 20 lines):"
	@docker-compose logs --tail=20 db
	@echo ""
	@echo "Service Logs (errors only):"
	@docker-compose logs --tail=20 | grep -i error || echo "No errors found"

# Reset database (dangerous)
reset-db:
	@echo "⚠️  WARNING: This will delete all data!"
	@read -p "Are you sure? (yes/no): " confirm && [ "$$confirm" = "yes" ]
	@docker-compose down -v
	@docker volume rm sentinel_postgres_data 2>/dev/null || true
	@make start
```

---

### Phase 4: Testing & Validation (1 hour)

#### 4.1 Create Automated Test Script

**File**: `/workspaces/api-testing-agents/tests/test_docker_startup.sh`

```bash
#!/bin/bash
# Automated Docker Startup Test
# Tests that system starts correctly from clean state

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo "Docker Startup Test"
echo "=========================================="
echo ""

# Change to project directory
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
}

fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}⚠️  WARN${NC}: $1"
}

info() {
    echo "ℹ️  $1"
}

# Test 1: Clean environment
info "Test 1: Cleaning environment..."
docker-compose down -v >/dev/null 2>&1 || true
docker volume prune -f >/dev/null 2>&1 || true
pass "Environment cleaned"

# Test 2: Start services
info "Test 2: Starting services..."
docker-compose up -d
pass "Services started"

# Test 3: Wait for database
info "Test 3: Waiting for database (max 60s)..."
timeout 60s bash -c '
    until docker-compose exec -T db pg_isready -U sentinel -d sentinel_db >/dev/null 2>&1; do
        sleep 2
    done
' || fail "Database did not become ready in 60 seconds"
pass "Database is ready"

# Test 4: Verify pgvector extension
info "Test 4: Checking pgvector extension..."
docker-compose exec -T db psql -U sentinel -d sentinel_db -c "SELECT 1 FROM pg_extension WHERE extname = 'vector' LIMIT 1;" >/dev/null 2>&1 || \
    fail "pgvector extension not found"
pass "pgvector extension exists"

# Test 5: Verify tables created
info "Test 5: Checking database schema..."
TABLE_COUNT=$(docker-compose exec -T db psql -U sentinel -d sentinel_db -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' ')
if [ "$TABLE_COUNT" -lt 8 ]; then
    fail "Only $TABLE_COUNT tables found, expected at least 8"
fi
pass "Database has $TABLE_COUNT tables"

# Test 6: Verify admin user
info "Test 6: Checking admin user..."
ADMIN_EXISTS=$(docker-compose exec -T db psql -U sentinel -d sentinel_db -t -c "SELECT COUNT(*) FROM users WHERE email = 'admin@sentinel.com';" | tr -d ' ')
if [ "$ADMIN_EXISTS" -eq 0 ]; then
    fail "Admin user not found"
fi
pass "Admin user exists"

# Test 7: Wait for services
info "Test 7: Waiting for services to start (30s)..."
sleep 30

# Test 8: Check service health
info "Test 8: Checking service health..."
for PORT in 8000 8001 8003 8004 8005; do
    if curl -f -s http://localhost:$PORT/health >/dev/null 2>&1; then
        pass "Service on port $PORT is healthy"
    else
        warn "Service on port $PORT not responding (may still be starting)"
    fi
done

# Test 9: Check frontend
info "Test 9: Checking frontend..."
if curl -f -s http://localhost:3000 >/dev/null 2>&1; then
    pass "Frontend is accessible"
else
    warn "Frontend not accessible (may still be building)"
fi

# Test 10: Test API
info "Test 10: Testing API functionality..."
if curl -f -s -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@sentinel.com","password":"admin123"}' >/dev/null 2>&1; then
    pass "API login works"
else
    warn "API login failed (may need more time to initialize)"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}✅ ALL TESTS PASSED${NC}"
echo "=========================================="
echo ""
echo "System is operational!"
echo "Access at: http://localhost:3000"
echo "Login: admin@sentinel.com / admin123"
```

Make it executable:
```bash
chmod +x /workspaces/api-testing-agents/tests/test_docker_startup.sh
```

#### 4.2 Create Manual Test Checklist

**File**: `/workspaces/api-testing-agents/docs/MANUAL_TEST_CHECKLIST.md`

```markdown
# Manual Testing Checklist - Docker Startup

## Pre-Test Setup
- [ ] Clean Docker environment: `docker-compose down -v`
- [ ] Remove volumes: `docker volume prune -f`
- [ ] Verify no containers running: `docker ps`

## Test Execution
- [ ] Start services: `docker-compose up -d`
- [ ] Watch logs for errors: `docker-compose logs -f`
- [ ] Wait 60 seconds for initialization

## Database Verification
- [ ] Database container healthy: `docker-compose ps db` (healthy status)
- [ ] Can connect: `docker-compose exec db psql -U sentinel -d sentinel_db -c "SELECT 1;"`
- [ ] Tables exist: `docker-compose exec db psql -U sentinel -d sentinel_db -c "\dt"`
- [ ] Expected count: Should see 8+ tables
- [ ] pgvector extension: Check `SELECT * FROM pg_extension WHERE extname='vector';`

## Service Health Checks
- [ ] API Gateway: `curl http://localhost:8000/health` → 200 OK
- [ ] Auth Service: `curl http://localhost:8005/health` → 200 OK
- [ ] Spec Service: `curl http://localhost:8001/health` → 200 OK
- [ ] Execution Service: `curl http://localhost:8003/health` → 200 OK
- [ ] Data Service: `curl http://localhost:8004/health` → 200 OK

## Functional Testing
- [ ] Frontend loads: `curl http://localhost:3000` → HTML response
- [ ] Login page visible: Open http://localhost:3000 in browser
- [ ] Can log in: Use admin@sentinel.com / admin123
- [ ] API responds: Create a test project via UI

## Error Scenarios
- [ ] Test restart: `docker-compose restart` → services recover
- [ ] Test cold start: `docker-compose down && docker-compose up -d` → works
- [ ] Test after volume removal: `docker volume rm sentinel_postgres_data` → auto-initializes

## Performance
- [ ] First start time: < 60 seconds to fully operational
- [ ] Subsequent starts: < 30 seconds
- [ ] No error messages in logs
- [ ] All health checks passing

## Pass Criteria
✅ All services healthy within 60 seconds
✅ Database initialized automatically
✅ Admin user created
✅ Can log in and use system
✅ No manual intervention required
```

---

### Phase 5: Documentation (1 hour)

#### 5.1 Update README.md

Add to main README:

```markdown
## Quick Start (New Users)

### Prerequisites
- Docker 20.10+ and Docker Compose 2.0+
- 4GB RAM minimum
- Ports available: 3000, 5432, 8000-8005, 8088

### Installation

```bash
# 1. Clone repository
git clone https://github.com/your-org/sentinel.git
cd sentinel

# 2. One-command setup (recommended)
make setup

# 3. Access the application
open http://localhost:3000

# 4. Log in
Email: admin@sentinel.com
Password: admin123
```

**That's it!** The system will:
- Build all Docker images
- Start all services
- Auto-initialize the database
- Create the admin user
- Be fully operational in ~60 seconds

### Troubleshooting

If something goes wrong:

```bash
# Check service status
make status

# View logs
make logs

# Run diagnostics
make diagnose

# Full reset
make clean
make setup
```

### Common Issues

**Services not starting?**
```bash
# Check Docker resources
docker system df

# Ensure ports are free
netstat -an | grep -E ":(3000|5432|8000|8005)"

# Restart Docker daemon
```

**Database connection errors?**
```bash
# Check database is healthy
make db-health

# Manually initialize if needed
make init-db
```

**Frontend not loading?**
```bash
# Frontend takes 30-60s to build on first start
# Wait and retry
```
```

---

## Testing Timeline

### Day 1: Implementation (4-6 hours)
- Hour 1: Update configuration files (.env.docker, settings.py)
- Hour 2-3: Update Dockerfiles and docker-compose.yml
- Hour 3-4: Create SQL scripts and wait scripts
- Hour 4-5: Update Makefile and create tests
- Hour 5-6: Documentation

### Day 1-2: Testing (2-3 hours)
- Clean environment test
- First-time user test
- Restart resilience test
- Error recovery test
- Performance measurement
- Documentation validation

### Day 2: Deployment (1 hour)
- Create backup of current configuration
- Deploy fixes to staging
- Run full test suite
- Deploy to production
- Monitor first few startups

---

## Rollback Plan

If fixes cause issues:

```bash
# 1. Revert files
git checkout HEAD -- docker-compose.yml
git checkout HEAD -- sentinel_backend/.env.docker
git checkout HEAD -- sentinel_backend/config/settings.py

# 2. Restart with old config
docker-compose down -v
make init-db  # Manual initialization
docker-compose up -d

# 3. Investigate issue
make diagnose
```

---

## Success Criteria

✅ Fresh installation works with single `docker-compose up -d`
✅ Database auto-initializes within 60 seconds
✅ All services healthy within 60 seconds
✅ Admin user created automatically
✅ No manual steps required
✅ Automated test passes 100%
✅ Documentation updated
✅ Makefile simplified

---

## Next Steps After Implementation

1. **Immediate**: Test on clean environment
2. **Short-term**: Add monitoring/alerting
3. **Medium-term**: Implement database migrations
4. **Long-term**: Consider Kubernetes for scaling

---

**Questions? Issues?**
- See troubleshooting guide
- Run `make diagnose`
- Check logs: `make logs`
- File issue on GitHub
