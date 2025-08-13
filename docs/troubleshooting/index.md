# Troubleshooting Guide - Sentinel API Testing Platform

This guide helps you diagnose and resolve common issues with the Sentinel platform. Use this as your first resource when encountering problems.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Installation Issues](#installation-issues)
3. [Service Connectivity Problems](#service-connectivity-problems)
4. [Authentication & Authorization](#authentication--authorization)
5. [Test Execution Failures](#test-execution-failures)
6. [Performance Issues](#performance-issues)
7. [Database Problems](#database-problems)
8. [Docker & Container Issues](#docker--container-issues)
9. [LLM Provider Issues](#llm-provider-issues)
10. [API Errors](#api-errors)
11. [Debugging Techniques](#debugging-techniques)
12. [FAQ](#frequently-asked-questions)

## Quick Diagnostics

### Health Check Script

Run this script to quickly diagnose common issues:

```bash
#!/bin/bash
# sentinel-health-check.sh

echo "=== Sentinel Platform Health Check ==="
echo

# Check Docker
echo "1. Checking Docker..."
if docker --version > /dev/null 2>&1; then
    echo "✓ Docker is installed: $(docker --version)"
else
    echo "✗ Docker is not installed or not in PATH"
fi

# Check Docker Compose
echo "2. Checking Docker Compose..."
if docker-compose --version > /dev/null 2>&1; then
    echo "✓ Docker Compose is installed: $(docker-compose --version)"
else
    echo "✗ Docker Compose is not installed"
fi

# Check services
echo "3. Checking running services..."
docker-compose ps

# Check connectivity
echo "4. Testing API Gateway..."
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    echo "✓ API Gateway is responding"
else
    echo "✗ API Gateway is not responding"
fi

# Check database
echo "5. Testing database connection..."
docker-compose exec postgres pg_isready > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Database is ready"
else
    echo "✗ Database is not ready"
fi

# Check RabbitMQ
echo "6. Testing RabbitMQ..."
if curl -f http://localhost:15672 > /dev/null 2>&1; then
    echo "✓ RabbitMQ Management UI is accessible"
else
    echo "✗ RabbitMQ is not responding"
fi

echo
echo "=== Health Check Complete ==="
```

## Installation Issues

### Problem: Docker Compose fails to start services

**Symptoms:**
- `docker-compose up` fails with errors
- Services exit immediately after starting
- Port binding errors

**Solutions:**

1. **Check port availability:**
```bash
# Check if ports are in use
lsof -i :8000  # API Gateway
lsof -i :5432  # PostgreSQL
lsof -i :5672  # RabbitMQ

# Kill processes using the ports
kill -9 $(lsof -t -i:8000)
```

2. **Clean Docker environment:**
```bash
# Stop all containers
docker-compose down

# Remove all containers and volumes
docker-compose down -v

# Rebuild from scratch
docker-compose up --build --force-recreate
```

3. **Check Docker resources:**
```bash
# Increase Docker memory (Docker Desktop)
# Go to Settings > Resources > Memory: 8GB minimum

# Check available space
docker system df

# Clean up unused resources
docker system prune -a --volumes
```

### Problem: "Module not found" errors

**Symptoms:**
- Python import errors
- Missing dependencies

**Solutions:**

```bash
# Rebuild containers with no cache
docker-compose build --no-cache

# For local development
cd sentinel_backend
poetry install

# Or with pip
pip install -r requirements.txt
```

## Service Connectivity Problems

### Problem: Services cannot communicate with each other

**Symptoms:**
- "Connection refused" errors
- "Host not found" errors
- Timeout errors between services

**Solutions:**

1. **Check Docker network:**
```bash
# List networks
docker network ls

# Inspect network
docker network inspect sentinel-network

# Recreate network
docker-compose down
docker network prune
docker-compose up
```

2. **Verify service names:**
```bash
# Check service resolution
docker-compose exec api-gateway nslookup postgres
docker-compose exec api-gateway ping -c 1 rabbitmq
```

3. **Check environment variables:**
```bash
# Verify service URLs
docker-compose exec api-gateway env | grep SERVICE

# Update .env file
nano .env
# Ensure correct service names:
# SPEC_SERVICE_URL=http://spec-service:8001
# AUTH_SERVICE_URL=http://auth-service:8005
```

### Problem: Cannot access services from host

**Symptoms:**
- Cannot access http://localhost:8000
- Connection refused from browser

**Solutions:**

1. **Check port mapping:**
```bash
# Verify port mapping
docker-compose ps

# Check if service is listening
docker-compose exec api-gateway netstat -tlnp
```

2. **Firewall issues:**
```bash
# macOS
sudo pfctl -d  # Disable firewall temporarily

# Linux
sudo ufw status
sudo ufw allow 8000

# Windows
# Check Windows Defender Firewall settings
```

## Authentication & Authorization

### Problem: Cannot login with default credentials

**Symptoms:**
- "Invalid credentials" error
- 401 Unauthorized responses

**Solutions:**

1. **Reset admin password:**
```python
# reset_admin_password.py
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import bcrypt

DATABASE_URL = "postgresql://sentinel:password@localhost:5432/sentinel"

async def reset_password():
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    # Hash new password
    new_password = "admin123"
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    
    # Update admin user
    session.execute(
        "UPDATE users SET password_hash = :hash WHERE email = 'admin@sentinel.com'",
        {"hash": hashed.decode()}
    )
    session.commit()
    print("Password reset successfully")

asyncio.run(reset_password())
```

2. **Create new admin user:**
```bash
# Via API
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newadmin@sentinel.com",
    "password": "newpassword",
    "role": "admin"
  }'
```

### Problem: JWT token expired or invalid

**Symptoms:**
- "Token expired" errors
- "Invalid token" errors

**Solutions:**

```bash
# Get new token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@sentinel.com", "password": "admin123"}'

# Refresh token
curl -X POST http://localhost:8000/auth/refresh \
  -H "Authorization: Bearer YOUR_REFRESH_TOKEN"
```

## Test Execution Failures

### Problem: Tests fail to execute

**Symptoms:**
- Test runs stuck in "pending" state
- No test results generated
- Timeout errors

**Solutions:**

1. **Check Rust Core service:**
```bash
# Check if Rust Core is running
docker-compose ps sentinel-rust-core

# Check logs
docker-compose logs -f sentinel-rust-core

# Restart service
docker-compose restart sentinel-rust-core
```

2. **Check RabbitMQ queues:**
```bash
# Access RabbitMQ management UI
open http://localhost:15672
# Default credentials: guest/guest

# Or via CLI
docker-compose exec rabbitmq rabbitmqctl list_queues
```

3. **Clear stuck tasks:**
```bash
# Purge queues
docker-compose exec rabbitmq rabbitmqctl purge_queue sentinel_task_queue
```

### Problem: API specification validation fails

**Symptoms:**
- "Invalid specification" errors
- Schema validation errors

**Solutions:**

1. **Validate OpenAPI spec:**
```bash
# Use online validator
# https://editor.swagger.io/

# Or use CLI tool
npm install -g @apidevtools/swagger-cli
swagger-cli validate your-spec.yaml
```

2. **Common spec issues:**
```yaml
# Ensure required fields
openapi: "3.0.0"  # or swagger: "2.0"
info:
  title: "API Title"
  version: "1.0.0"
paths: {}  # At least empty object

# Fix $ref paths
# Wrong: $ref: 'User'
# Right: $ref: '#/components/schemas/User'
```

## Performance Issues

### Problem: Slow test execution

**Symptoms:**
- Tests take too long to complete
- High CPU/memory usage
- Timeouts

**Solutions:**

1. **Optimize Docker resources:**
```yaml
# docker-compose.yml
services:
  api-gateway:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '1'
          memory: 512M
```

2. **Database optimization:**
```sql
-- Add indexes
CREATE INDEX idx_test_runs_status ON test_runs(status);
CREATE INDEX idx_test_results_run_id ON test_results(test_run_id);

-- Analyze tables
ANALYZE test_runs;
ANALYZE test_results;

-- Check slow queries
SELECT * FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 10;
```

3. **Adjust concurrency:**
```python
# config/settings.py
MAX_CONCURRENT_TESTS = 10  # Reduce if system is overloaded
WORKER_POOL_SIZE = 4
```

### Problem: Memory leaks

**Symptoms:**
- Increasing memory usage over time
- Services crashing with OOM errors

**Solutions:**

```bash
# Monitor memory usage
docker stats

# Set memory limits
docker-compose up -d --scale api-gateway=1 --memory=1g

# Enable garbage collection logging
PYTHONMALLOC=debug
PYTHONASYNCIODEBUG=1
```

## Database Problems

### Problem: Database connection errors

**Symptoms:**
- "Could not connect to database" errors
- "Too many connections" errors

**Solutions:**

1. **Check connection pool:**
```python
# config/settings.py
DATABASE_POOL_SIZE = 20
DATABASE_MAX_OVERFLOW = 40
DATABASE_POOL_TIMEOUT = 30
```

2. **Reset connections:**
```sql
-- Kill all connections
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE datname = 'sentinel' AND pid <> pg_backend_pid();

-- Check connection count
SELECT count(*) FROM pg_stat_activity;
```

### Problem: Database migrations fail

**Symptoms:**
- Alembic migration errors
- Schema mismatch errors

**Solutions:**

```bash
# Check migration status
docker-compose exec api-gateway alembic current

# Rollback migration
docker-compose exec api-gateway alembic downgrade -1

# Force migration
docker-compose exec api-gateway alembic stamp head
docker-compose exec api-gateway alembic upgrade head

# Reset database (CAUTION: Data loss!)
docker-compose down -v
docker-compose up -d postgres
docker-compose exec api-gateway alembic upgrade head
```

## Docker & Container Issues

### Problem: Container keeps restarting

**Symptoms:**
- Container in restart loop
- Exit code 1 or 125

**Solutions:**

1. **Check logs:**
```bash
# View logs
docker-compose logs -f service-name

# Check last 100 lines
docker-compose logs --tail=100 service-name
```

2. **Debug container:**
```bash
# Run with shell
docker-compose run --rm api-gateway /bin/sh

# Check file permissions
ls -la /app

# Test startup command
python main.py
```

### Problem: "No space left on device"

**Solutions:**

```bash
# Check disk usage
df -h

# Clean Docker
docker system prune -a --volumes

# Remove old images
docker image prune -a

# Remove build cache
docker builder prune
```

## LLM Provider Issues

### Problem: LLM features not working

**Symptoms:**
- Tests not using AI enhancements
- "LLM provider not configured" errors
- API key validation failures

**Solutions:**

1. **Check configuration:**
```bash
cd sentinel_backend
python scripts/validate_llm_config.py
```

2. **Verify API keys:**
```bash
# Check if keys are set
grep "SENTINEL_APP_.*_API_KEY" .env

# Test API key directly
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $SENTINEL_APP_ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01"
```

3. **Switch providers:**
```bash
# Try a different provider
./scripts/switch_llm.sh openai

# Or disable LLM temporarily
./scripts/switch_llm.sh none
```

### Problem: High LLM costs

**Symptoms:**
- Unexpected API charges
- Budget alerts triggered

**Solutions:**

1. **Enable caching:**
```bash
export SENTINEL_APP_LLM_CACHE_ENABLED=true
export SENTINEL_APP_LLM_CACHE_TTL=7200
```

2. **Use cheaper models:**
```bash
# Switch to GPT-3.5 Turbo
./scripts/switch_llm.sh
# Select OpenAI -> GPT-3.5 Turbo
```

3. **Use local models:**
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull mistral:7b

# Configure Sentinel
./scripts/switch_llm.sh local
```

### Problem: Ollama connection issues

**Symptoms:**
- "Connection refused" to localhost:11434
- Docker can't reach Ollama

**Solutions:**

1. **For Docker access:**
```bash
# Start Ollama on all interfaces
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# Or use host network in Docker
docker run --network host ...
```

2. **Check Ollama status:**
```bash
ollama list  # List installed models
ollama ps    # Show running models
```

## API Errors

### Common HTTP Status Codes

| Status | Meaning | Common Causes | Solutions |
|--------|---------|---------------|-----------|
| 400 | Bad Request | Invalid JSON, missing fields | Check request format |
| 401 | Unauthorized | Missing/invalid token | Login and get new token |
| 403 | Forbidden | Insufficient permissions | Check user role |
| 404 | Not Found | Wrong endpoint, resource deleted | Verify URL and resource |
| 409 | Conflict | Duplicate resource | Check for existing resources |
| 422 | Unprocessable Entity | Validation errors | Check field requirements |
| 429 | Too Many Requests | Rate limit exceeded | Wait and retry |
| 500 | Internal Server Error | Server bug | Check server logs |
| 502 | Bad Gateway | Service down | Check service health |
| 503 | Service Unavailable | Overloaded/maintenance | Wait and retry |

### Problem: CORS errors

**Symptoms:**
- "Access-Control-Allow-Origin" errors in browser
- Preflight request failures

**Solutions:**

```python
# config/settings.py
CORS_ORIGINS = [
    "http://localhost:3000",
    "https://app.sentinel.example.com"
]

# Or allow all (development only)
CORS_ORIGINS = ["*"]
```

## Debugging Techniques

### Enable Debug Logging

```python
# .env
SENTINEL_DEBUG=true
SENTINEL_LOG_LEVEL=DEBUG

# Python service
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Use Interactive Debugging

```python
# Add breakpoint in code
import pdb; pdb.set_trace()

# Or use IPython
import IPython; IPython.embed()
```

### Network Debugging

```bash
# Capture traffic
docker-compose exec api-gateway tcpdump -i any -w capture.pcap

# Test with curl verbose
curl -v http://localhost:8000/health

# Use httpie for better output
pip install httpie
http GET localhost:8000/health
```

### Database Query Debugging

```python
# Enable SQL logging
import logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# Or in config
SQLALCHEMY_ECHO = True
```

## Frequently Asked Questions

### Q: How do I reset everything and start fresh?

```bash
# Complete reset
docker-compose down -v
docker system prune -a --volumes
rm -rf postgres_data/
docker-compose up --build
```

### Q: How do I backup my data before troubleshooting?

```bash
# Backup database
docker-compose exec postgres pg_dump -U sentinel sentinel > backup.sql

# Backup Docker volumes
docker run --rm -v sentinel_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz /data
```

### Q: How do I run Sentinel without Docker?

```bash
# Install dependencies
cd sentinel_backend
poetry install

# Start PostgreSQL and RabbitMQ locally
brew services start postgresql
brew services start rabbitmq

# Run migrations
alembic upgrade head

# Start services
python api_gateway/main.py
```

### Q: How do I enable verbose logging?

```bash
# Set environment variables
export SENTINEL_LOG_LEVEL=DEBUG
export SENTINEL_LOG_FORMAT=verbose

# Or in docker-compose.yml
environment:
  - SENTINEL_LOG_LEVEL=DEBUG
  - PYTHONUNBUFFERED=1
```

### Q: How do I test a specific service in isolation?

```bash
# Run single service
docker-compose up api-gateway

# With dependencies
docker-compose up api-gateway postgres rabbitmq
```

## Getting Additional Help

If you cannot resolve your issue:

1. **Search existing issues:**
   - GitHub Issues: https://github.com/proffesor-for-testing/sentinel-api-testing/issues

2. **Create detailed bug report:**
   ```markdown
   **Environment:**
   - OS: [e.g., Ubuntu 22.04]
   - Docker version: [e.g., 20.10.21]
   - Sentinel version: [e.g., 1.0.0]
   
   **Steps to reproduce:**
   1. Step one
   2. Step two
   
   **Expected behavior:**
   What should happen
   
   **Actual behavior:**
   What actually happens
   
   **Logs:**
   ```
   Paste relevant logs here
   ```
   ```

3. **Community support:**
   - Discord: https://discord.gg/sentinel
   - Stack Overflow: Tag with `sentinel-api-testing`

4. **Commercial support:**
   - Email: support@sentinel.example.com
   - Enterprise: https://sentinel.example.com/enterprise

## Diagnostic Commands Reference

```bash
# Service health
docker-compose ps
docker-compose logs service-name
docker stats

# Network
docker network ls
docker network inspect sentinel-network
docker-compose exec service-name ping other-service

# Database
docker-compose exec postgres psql -U sentinel -c "SELECT version();"
docker-compose exec postgres pg_isready

# RabbitMQ
docker-compose exec rabbitmq rabbitmqctl status
docker-compose exec rabbitmq rabbitmqctl list_queues

# Disk usage
docker system df
du -sh *

# Process investigation
docker-compose exec service-name ps aux
docker-compose exec service-name top
```

---

← [Back to Documentation](../index.md) | [API Reference](../api-reference/index.md) →