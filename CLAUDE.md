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

### LLM Configuration & Management
```bash
# Interactive LLM configuration
cd sentinel_backend/scripts
./switch_llm.sh                 # Interactive wizard
./switch_llm.sh claude          # Quick preset for Claude
./switch_llm.sh openai          # Quick preset for OpenAI
./switch_llm.sh local           # Quick preset for local Ollama

# Docker-specific configuration
./switch_llm_docker.sh gpt4     # Switch Docker to GPT-4
./switch_llm_docker.sh gemini   # Switch Docker to Gemini 2.5

# Validate LLM configuration
python scripts/validate_llm_config.py
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

### Test Execution Guidelines
**IMPORTANT**: Always run tests in Docker to ensure consistent environment:
```bash
cd sentinel_backend
./run_tests.sh -d              # Run all tests in Docker
./run_tests.sh -d -t unit      # Run only unit tests in Docker
./run_tests.sh -d -t integration # Run only integration tests in Docker

# Rebuild test Docker image after dependency changes
docker-compose -f docker-compose.test.yml build test_runner
```

**Current Test Status** (as of latest fixes):
- **96.3% pass rate** (208/216 tests passing)
- 8 remaining failures are known issues with integration/rust tests
- All critical unit tests passing

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

## LLM Integration

### Multi-Provider Support
The platform includes a comprehensive LLM abstraction layer supporting multiple providers with automatic fallback capabilities. All AI agents can leverage LLM capabilities while maintaining backward compatibility.

### Default Configuration
The platform uses **Anthropic's Claude Sonnet 4** as the default LLM provider for all AI agents. This provides:
- Excellent balance of performance and cost
- 200k token context window
- Strong reasoning capabilities
- Vision support for multimodal testing

To use the default configuration, simply set:
```bash
export SENTINEL_APP_ANTHROPIC_API_KEY=your-anthropic-api-key
```

### Supported Providers

#### Commercial Providers
- **OpenAI**: GPT-4 Turbo, GPT-4, GPT-3.5 Turbo
- **Anthropic**: Claude Opus 4.1/4, Claude Sonnet 4, Claude Haiku 3.5
- **Google**: Gemini 2.5 Pro, Gemini 2.5 Flash, Gemini 2.0 Flash
- **Mistral**: Mistral Large, Mistral Small 3, Codestral

#### Open Source Models (via Ollama)
- **DeepSeek**: DeepSeek-R1 (671B/70B/32B variants)
- **Meta Llama**: Llama 3.3 70B, Llama 3.1 (405B/70B/8B)
- **Alibaba Qwen**: Qwen 2.5 (72B/32B/7B), Qwen 2.5 Coder
- **Others**: Mistral 7B, Phi-3 14B, Gemma 2 27B, Command R 35B

### Switching Providers

#### Using Configuration Scripts (Recommended)
The platform includes interactive scripts for easy LLM configuration:

```bash
# Interactive configuration
cd sentinel_backend/scripts
./switch_llm.sh

# Quick presets
./switch_llm.sh claude    # Anthropic Claude Sonnet 4 (default)
./switch_llm.sh openai    # OpenAI GPT-4 Turbo
./switch_llm.sh gemini    # Google Gemini 2.5 Flash
./switch_llm.sh local     # Ollama with local models
./switch_llm.sh none      # Disable LLM

# Docker quick switch
./switch_llm_docker.sh gpt4      # GPT-4 Turbo
./switch_llm_docker.sh gemini    # Gemini 2.5 Flash
./switch_llm_docker.sh local     # Local Ollama
```

#### Manual Configuration
You can also manually set environment variables:
```bash
# OpenAI
export SENTINEL_APP_LLM_PROVIDER=openai
export SENTINEL_APP_OPENAI_API_KEY=your-key
export SENTINEL_APP_LLM_MODEL=gpt-4-turbo

# Google Gemini
export SENTINEL_APP_LLM_PROVIDER=google
export SENTINEL_APP_GOOGLE_API_KEY=your-key
export SENTINEL_APP_LLM_MODEL=gemini-2.5-pro

# Mistral
export SENTINEL_APP_LLM_PROVIDER=mistral
export SENTINEL_APP_MISTRAL_API_KEY=your-key
export SENTINEL_APP_LLM_MODEL=mistral-large

# Local (Ollama)
export SENTINEL_APP_LLM_PROVIDER=ollama
export SENTINEL_APP_LLM_MODEL=llama3.3:70b
export SENTINEL_APP_OLLAMA_BASE_URL=http://localhost:11434

# Disable LLM (deterministic only)
export SENTINEL_APP_LLM_PROVIDER=none
```

### Advanced Features

#### Fallback Chain
Configure automatic fallback to secondary providers:
```bash
export SENTINEL_APP_LLM_FALLBACK_ENABLED=true
export SENTINEL_APP_LLM_FALLBACK_PROVIDERS=anthropic,openai,ollama
```

#### Cost Management
Track and limit LLM usage costs:
```bash
export SENTINEL_APP_LLM_COST_TRACKING_ENABLED=true
export SENTINEL_APP_LLM_BUDGET_LIMIT=100.0  # USD
export SENTINEL_APP_LLM_BUDGET_ALERT_THRESHOLD=0.8
```

#### Response Caching
Enable caching to reduce API calls:
```bash
export SENTINEL_APP_LLM_CACHE_ENABLED=true
export SENTINEL_APP_LLM_CACHE_TTL=3600  # 1 hour
export SENTINEL_APP_LLM_CACHE_MAX_SIZE=1000
```

### Validating LLM Configuration
Use the validation script to test your LLM setup:
```bash
cd sentinel_backend
poetry run python scripts/validate_llm_config.py
```

This will:
- Check environment configuration
- Validate API keys
- Test primary and fallback providers
- Verify agent LLM integration
- Provide recommendations for any issues

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

# LLM Configuration (Multi-Vendor Support)
SENTINEL_APP_LLM_PROVIDER=anthropic  # Options: anthropic, openai, google, mistral, ollama, vllm, none
SENTINEL_APP_LLM_MODEL=claude-sonnet-4  # Default model for the provider
SENTINEL_APP_ANTHROPIC_API_KEY=sk-ant-...  # Anthropic API key
SENTINEL_APP_OPENAI_API_KEY=sk-...  # OpenAI API key
SENTINEL_APP_GOOGLE_API_KEY=...  # Google API key
SENTINEL_APP_MISTRAL_API_KEY=...  # Mistral API key
SENTINEL_APP_LLM_TEMPERATURE=0.5
SENTINEL_APP_LLM_MAX_TOKENS=2000
SENTINEL_APP_LLM_FALLBACK_ENABLED=true  # Enable automatic provider fallback
SENTINEL_APP_LLM_FALLBACK_PROVIDERS=anthropic,openai,ollama  # Fallback chain

# For local models (Ollama/vLLM)
SENTINEL_APP_OLLAMA_BASE_URL=http://localhost:11434
SENTINEL_APP_VLLM_BASE_URL=http://localhost:8000

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