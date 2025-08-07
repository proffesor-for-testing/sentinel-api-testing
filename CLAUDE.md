# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Backend Development (Python/FastAPI)
```bash
# Navigate to backend
cd sentinel_backend

# Install dependencies
poetry install

# Run individual services
cd api_gateway && poetry run uvicorn main:app --reload --port 8000
cd spec_service && poetry run uvicorn main:app --reload --port 8001
cd orchestration_service && poetry run uvicorn main:app --reload --port 8002
cd execution_service && poetry run uvicorn main:app --reload --port 8003
cd data_service && poetry run uvicorn main:app --reload --port 8004
cd auth_service && poetry run uvicorn main:app --reload --port 8005

# Full platform startup (Docker)
docker-compose up --build

# Run tests
./run_tests.sh                    # All tests with comprehensive options
./run_tests.sh -t unit           # Unit tests only
./run_tests.sh -t integration -d # Integration tests in Docker
pytest                           # Direct pytest execution
```

### Frontend Development (React)
```bash
# Navigate to frontend
cd sentinel_frontend

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build

# Run tests
npm test
```

### Code Quality & Linting
```bash
# Backend (Python)
cd sentinel_backend
poetry run black .              # Code formatting
poetry run isort .              # Import sorting
poetry run flake8 .             # Linting
poetry run mypy .               # Type checking

# Frontend (JavaScript/React)
cd sentinel_frontend
npm run test                    # Run tests
```

### Rust Core Development
```bash
# Navigate to Rust core
cd sentinel_backend/sentinel_rust_core

# Build and run
cargo build --release
cargo run

# Run tests
cargo test
```

## Architecture Overview

### Microservices Architecture
The platform follows a microservices pattern with specialized services:

- **API Gateway** (8000): Single entry point, RBAC integration, request routing
- **Auth Service** (8005): JWT authentication, user management, RBAC
- **Spec Service** (8001): OpenAPI specification parsing and management
- **Orchestration Service** (8002): AI agent coordination and task delegation
- **Execution Service** (8003): Test execution engine and scheduling
- **Data Service** (8004): Analytics, persistence, historical data
- **Sentinel Rust Core** (8088): High-performance agent execution via ruv-swarm

### AI Agent System
The platform uses specialized ephemeral AI agents for different testing domains:

#### Functional Testing Agents
- **Functional-Positive-Agent**: Valid test case generation with schema-based data
- **Functional-Negative-Agent**: Boundary value analysis and creative negative testing
- **Functional-Stateful-Agent**: Multi-step workflows using Semantic Operation Dependency Graphs

#### Security Testing Agents
- **Security-Auth-Agent**: BOLA, function-level authorization, auth bypass testing
- **Security-Injection-Agent**: SQL/NoSQL/Command/Prompt injection vulnerability testing

#### Other Agents
- **Performance-Planner-Agent**: k6/JMeter script generation for load testing
- **Data-Mocking-Agent**: Schema-aware realistic test data generation

### Message Broker Architecture
- **RabbitMQ** integration for asynchronous task processing
- **Publisher**: Orchestration Service publishes agent tasks
- **Consumer**: Sentinel Rust Core consumes and processes tasks
- **Durability**: Messages persist across service restarts

## Configuration Management

### Centralized Configuration System
All configuration is managed through `sentinel_backend/config/settings.py` using Pydantic BaseSettings:

```python
from config.settings import get_settings, get_service_settings, get_application_settings

settings = get_settings()
service_settings = get_service_settings()
app_settings = get_application_settings()
```

### Environment Configuration
Set environment with `SENTINEL_ENVIRONMENT`:
- `development` (default): Local development
- `testing`: Test environment
- `production`: Production deployment
- `docker`: Docker container deployment

### Key Environment Variables
```bash
# Database
SENTINEL_DB_URL=postgresql+asyncpg://user:pass@host/db
SENTINEL_DB_POOL_SIZE=20

# Service URLs
SENTINEL_SERVICE_AUTH_SERVICE_URL=http://auth:8005
SENTINEL_SERVICE_SERVICE_TIMEOUT=60

# Security
SENTINEL_SECURITY_JWT_SECRET_KEY=your-secret-key
SENTINEL_SECURITY_JWT_EXPIRATION_HOURS=24

# Observability
SENTINEL_NETWORK_JAEGER_AGENT_HOST=localhost
SENTINEL_NETWORK_JAEGER_AGENT_PORT=6831
SENTINEL_BROKER_URL=amqp://guest:guest@message_broker:5672/
```

## Observability Stack

### Monitoring & Tracing
- **Prometheus** (9090): Metrics collection with automatic FastAPI instrumentation
- **Jaeger** (16686): Distributed tracing with OpenTelemetry integration
- **Structured Logging**: JSON-formatted logs with correlation IDs

### Testing Observability
```bash
# Test observability stack
python test_observability_e2e.py

# Test message broker integration
python test_rabbitmq_integration.py
```

## Development Patterns

### Configuration Access Pattern
```python
# Service-level configuration
from config.settings import get_service_settings
service_settings = get_service_settings()
timeout = service_settings.service_timeout
url = service_settings.auth_service_url

# Application-level configuration
from config.settings import get_application_settings
app_settings = get_application_settings()
log_level = app_settings.log_level
debug = app_settings.debug
```

### Agent Development Pattern
1. Define agent specification in `memory-bank/agent-specifications.md`
2. Implement agent logic in `orchestration_service/agents/`
3. Add agent type to orchestration service delegation
4. Update database models if needed
5. Add configuration parameters to settings

### Service Communication Pattern
- All inter-service communication uses centralized URLs from configuration
- HTTP clients use `service_settings.service_timeout` for consistent timeouts
- Correlation IDs propagated across all service calls for tracing

### Testing Patterns
- Use pytest markers: `@pytest.mark.unit`, `@pytest.mark.integration`, etc.
- Environment-specific test configuration in `config/testing.env`
- Comprehensive fixtures in `tests/conftest.py`
- Docker test environment with `docker-compose.test.yml`

## Database Architecture

### Technology Stack
- **PostgreSQL** with **pgvector** extension for vector operations
- **SQLAlchemy** async ORM with **asyncpg** driver
- **Alembic** for database migrations

### Key Models
- Specifications, TestCases, TestRuns, Results
- User management with RBAC (Users, Roles, Permissions)
- Agent execution tracking and analytics

## RBAC System

### Default Admin Credentials
- Email: `admin@sentinel.com`
- Password: `admin123`

### Role Hierarchy
- **Admin**: Full access including user management
- **Manager**: Most permissions except user management  
- **Tester**: Testing operations (create/edit test cases, run tests)
- **Viewer**: Read-only access

### Demo RBAC
```bash
python demo_rbac.py  # Demonstrates authentication and authorization
```

## Key Implementation Notes

### Hybrid AI Approach
The platform combines deterministic algorithms (for rigor) with LLM capabilities (for creativity). This pattern is used across all agents.

### Specification-Driven Development
All agent behavior and test generation is driven by OpenAPI specifications. The platform deeply understands API specs to generate intelligent tests.

### Error Handling Patterns
- Configuration validation with fail-fast startup
- Comprehensive error reporting with clear, actionable messages
- Structured logging with correlation ID tracking

### Security Best Practices
- JWT-based authentication with secure token handling
- Role-based access control with granular permissions
- No sensitive data in version control (use environment variables)
- Password hashing with bcrypt

## CI/CD Integration

### Available Templates
- **GitHub Actions**: `ci_templates/github-actions.yml`
- **GitLab CI**: `ci_templates/gitlab-ci.yml`
- **Jenkins**: `ci_templates/Jenkinsfile`

### CLI Tool
```bash
# Use the CLI for CI/CD integration
cd sentinel_backend/cli
python main.py --help
```

This platform represents a comprehensive AI-powered API testing solution with enterprise-grade architecture, observability, and security features.