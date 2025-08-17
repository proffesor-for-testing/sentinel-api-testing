# Sentinel - AI Agentic API Testing Platform

Sentinel is an advanced, AI-powered platform designed to automate the entire API testing lifecycle. It leverages a modular, microservices-inspired architecture and an ecosystem of specialized, ephemeral AI agents to provide comprehensive, intelligent, and efficient testing across functional, security, and performance domains.

## 🏗️ Architecture Overview

The platform is built upon the **ruv-FANN** and **ruv-swarm** frameworks, enabling a paradigm of "ephemeral swarm intelligence" where lightweight, WASM-based agents are dynamically spawned to perform specific testing tasks and dissolved upon completion.

### Core Services

- **API Gateway** (Port 8000): Single entry point for all user interactions with RBAC integration
- **Authentication Service** (Port 8005): JWT-based authentication and user management
- **Specification Service** (Port 8001): Manages API specification ingestion and parsing
- **Orchestration Service** (Port 8002): Central brain managing agentic workflows
- **Execution Service** (Port 8003): Handles test execution and scheduling
- **Data & Analytics Service** (Port 8004): Manages data persistence and analytics
- **PostgreSQL Database** (Port 5432): Data storage with pgvector extension
- **Sentinel Rust Core** (Port 8088): High-performance agentic core powered by `ruv-swarm`
- **RabbitMQ Message Broker** (Port 5672/15672): Asynchronous task queue for decoupled service communication
- **Prometheus** (Port 9090): Metrics collection and monitoring
- **Jaeger** (Port 16686): Distributed tracing and request flow visualization

## 🤖 Specialized Agents

The platform employs a workforce of specialized AI agents:

### Functional Testing Agents
- **Functional-Positive-Agent**: Generates valid, "happy path" test cases with schema-based data generation
- **Functional-Negative-Agent**: Creates boundary value analysis and creative negative testing scenarios
- **Functional-Stateful-Agent**: Builds complex multi-step workflows using Semantic Operation Dependency Graphs (SODG)

### Security Testing Agents
- **Security-Auth-Agent**: Tests for BOLA, function-level authorization, and authentication bypass vulnerabilities
- **Security-Injection-Agent**: Probes for SQL/NoSQL/Command injection and LLM prompt injection attacks

### Performance Testing Agents
- **Performance-Planner-Agent**: Generates comprehensive load, stress, and spike testing scenarios with k6/JMeter scripts

### Planned Agents
- **Spec-Linter-Agent**: Analyzes API specs for "LLM-readiness"
- **Performance-Analyzer-Agent**: Analyzes performance test results with AI-powered insights

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+ (for local development)
- Poetry (for dependency management)
- Node.js 14+ and npm (for frontend development)
- Anthropic API Key (for LLM-powered features)

### Running the Platform

1. **Clone and navigate to the project:**
   ```bash
   cd "Agents for API testing/sentinel_backend"
   ```

2. **Set up LLM configuration (required for AI features):**
   ```bash
   export SENTINEL_APP_ANTHROPIC_API_KEY=your-anthropic-api-key
   ```

3. **Start all services:**
   ```bash
   docker-compose up --build
   ```

4. **Access the platform:**
   - **Frontend Application**: http://localhost:3000
     - Default credentials: `admin@sentinel.com` / `admin123`
   - API Gateway: http://localhost:8000
   - Specification Service: http://localhost:8001
   - Orchestration Service: http://localhost:8002
   - Execution Service: http://localhost:8003
   - Data & Analytics Service: http://localhost:8004

### API Documentation

Once running, you can access the interactive API documentation:
- API Gateway: http://localhost:8000/docs
- Each service also exposes its own `/docs` endpoint

### Observability & Monitoring

The platform includes comprehensive observability features:

- **Prometheus Metrics**: http://localhost:9090
  - View service metrics and health status
  - Query time-series data for performance analysis
  - Monitor request rates, latencies, and error rates

- **Jaeger Tracing**: http://localhost:16686
  - Visualize distributed request flows across services
  - Analyze service dependencies and bottlenecks
  - Debug complex multi-service interactions

- **Structured Logging**: All services output JSON-formatted logs with:
  - Correlation IDs for request tracking
  - Service context and metadata
  - Error details and stack traces

### Testing Observability

Run the comprehensive observability test suite:
```bash
python test_observability_e2e.py
```

This validates:
- ✅ All services are healthy and responding
- ✅ Correlation ID propagation across services
- ✅ Prometheus metrics exposure
- ✅ Jaeger trace collection
- ✅ End-to-end request flow tracking

## 🎨 Frontend Features

The platform includes a comprehensive React-based frontend with the following features:

### Core Functionality
- **Authentication System**: JWT-based login with secure token management
- **Dashboard**: Real-time database-driven metrics and system status
- **Specifications Management**: 
  - Upload and parse OpenAPI specifications (including OpenAPI 3.1.0 with webhooks)
  - View detailed specification information including endpoints and schemas
  - Full CRUD operations (Create, Read, Update, Delete)
  - Quick Test functionality for rapid test generation
  - Generate Tests with AI agent selection
- **Test Cases Browser**: 
  - View all generated test cases with filtering by agent type
  - Display full test definition details (method, endpoint, expected status)
  - Create test suites from selected test cases
  - Tag management for organization
  - Detailed test case inspection with specification relationships
- **Test Suites Management**:
  - Create, view, edit, and delete test suites
  - Add/remove test cases from suites
  - View test case count and specification relationships
  - One-click test suite execution
- **Test Runs**: 
  - Execute test suites against target environments
  - Modal-based test run creation workflow
  - Real-time status tracking
  - Detailed results viewing
- **Analytics**: Comprehensive dashboards with trend analysis and insights

### AI-Powered Test Generation
- **Agent Selection Modal**: Choose from multiple specialized AI agents
- **Quick Test**: One-click test generation using default agents
- **LLM Enhancement**: All agents powered by Claude Sonnet 4 for intelligent test creation
- **Real-time Progress**: Track test generation status and results

## 📁 Project Structure

```
Agents for API testing/
├── memory-bank/                    # Project documentation and memory bank
│   ├── projectbrief.md            # Project overview and objectives
│   ├── productContext.md          # Problem statement and vision
│   ├── systemPatterns.md          # Architecture patterns
│   ├── techContext.md             # Technology stack
│   ├── activeContext.md           # Current focus and next steps
│   ├── progress.md                # Implementation roadmap
│   ├── agent-specifications.md    # Detailed agent capabilities
│   ├── database-schema.md         # Database design
│   └── api-design.md              # REST API specifications
├── sentinel_backend/               # Backend services
│   ├── docker-compose.yml         # Multi-container orchestration
│   ├── pyproject.toml             # Python dependencies
│   ├── api_gateway/               # API Gateway service
│   ├── spec_service/              # Specification service
│   ├── orchestration_service/     # Agent orchestration
│   │   └── agents/                # AI agent implementations
│   │       ├── functional_positive_agent.py
│   │       ├── functional_negative_agent.py
│   │       ├── functional_stateful_agent.py
│   │       ├── security_auth_agent.py
│   │       ├── security_injection_agent.py
│   │       └── performance_planner_agent.py
│   ├── execution_service/         # Test execution
│   └── data_service/              # Data & analytics
├── sentinel_frontend/              # React-based frontend UI
│   ├── src/                       # React application source
│   │   ├── components/            # Reusable UI components
│   │   ├── pages/                 # Application pages
│   │   └── services/              # API communication
│   ├── package.json               # Node.js dependencies
│   └── tailwind.config.js         # Tailwind CSS configuration
├── demo_phase2.py                 # Basic functionality demonstration
├── demo_phase3.py                 # Agent capabilities demonstration
├── demo_phase3_frontend.py        # Frontend features demonstration
├── demo_phase4.py                 # Security & performance demonstration
├── demo_rbac.py                   # RBAC authentication & authorization demonstration
├── demo_standalone.py             # Standalone demo (no Docker)
└── .clinerules                    # Development patterns and preferences
```


## 🤖 Multi-LLM Provider Support

### Overview
The platform features a comprehensive LLM abstraction layer that enables all AI agents to leverage multiple LLM providers with automatic fallback capabilities. This hybrid approach combines deterministic algorithms with LLM creativity for superior test generation.

### Supported Providers
- **Anthropic** (Default): Claude Opus 4.1/4, Claude Sonnet 4, Claude Haiku 3.5
- **OpenAI**: GPT-4 Turbo, GPT-4, GPT-3.5 Turbo
- **Google**: Gemini 2.5 Pro, Gemini 2.5 Flash, Gemini 2.0 Flash
- **Mistral**: Mistral Large, Small 3, Codestral
- **Ollama** (Local): DeepSeek-R1, Llama 3.3, Qwen 2.5, and more

### Key Features
- **Automatic Fallback**: Seamlessly switches to backup providers on failure
- **Cost Tracking**: Real-time usage monitoring with budget limits
- **Response Caching**: Reduces API calls and costs
- **Token Management**: Intelligent context window handling
- **Provider-Specific Templates**: Optimized prompts for each model

### Quick Configuration

#### Using Configuration Scripts (Recommended)
```bash
# Interactive configuration wizard
cd sentinel_backend/scripts
./switch_llm.sh

# Quick presets
./switch_llm.sh claude    # Use Claude Sonnet 4 (default)
./switch_llm.sh openai    # Use OpenAI GPT-4 Turbo
./switch_llm.sh gemini    # Use Google Gemini 2.5
./switch_llm.sh local     # Use local Ollama
./switch_llm.sh none      # Disable LLM
```

#### Manual Configuration
```bash
# Use default (Claude Sonnet 4)
export SENTINEL_APP_ANTHROPIC_API_KEY=your-key

# Switch to OpenAI
export SENTINEL_APP_LLM_PROVIDER=openai
export SENTINEL_APP_OPENAI_API_KEY=your-key
export SENTINEL_APP_LLM_MODEL=gpt-4-turbo

# Use local models with Ollama
export SENTINEL_APP_LLM_PROVIDER=ollama
export SENTINEL_APP_LLM_MODEL=llama3.3:70b
```

For detailed configuration options and scripts, see:
- [CLAUDE.md](CLAUDE.md#llm-integration) - Complete LLM configuration guide
- [Scripts README](sentinel_backend/scripts/README.md) - Script documentation

## 🛠️ Development

### Local Development Setup

#### Backend Services

1. **Install dependencies:**
   ```bash
   cd sentinel_backend
   poetry install
   ```

2. **Run individual services:**
   ```bash
   # Example: Run the API Gateway
   cd api_gateway
   poetry run uvicorn main:app --reload --port 8000
   ```

#### Frontend Application

1. **Navigate to frontend directory:**
   ```bash
   cd sentinel_frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```

4. **Access the frontend:**
   - Frontend Application: http://localhost:3000
   - Default credentials: `admin@sentinel.com` / `admin123`

**Note**: The frontend requires the backend services to be running. You can either:
- Use Docker Compose to start all backend services: `docker-compose up` (from `sentinel_backend/`)
- Run individual backend services manually as shown above

### Configuration Management

The platform uses a comprehensive centralized configuration system built with Pydantic BaseSettings for type-safe configuration management.

#### Configuration Structure

All configuration is managed through `sentinel_backend/config/settings.py` with the following sections:

- **Database Settings**: Connection strings, pool configurations, migration settings
- **Service Discovery**: Inter-service URLs, ports, timeouts, health check intervals
- **Security Configuration**: JWT secrets, password policies, CORS settings, rate limiting
- **Network Settings**: Host bindings, port mappings, timeout configurations
- **Application Settings**: Feature flags, pagination limits, logging levels, agent parameters

#### Environment-Specific Configuration

The platform supports multiple deployment environments:

```bash
# Development (default)
SENTINEL_ENVIRONMENT=development

# Testing
SENTINEL_ENVIRONMENT=testing

# Production
SENTINEL_ENVIRONMENT=production

# Docker
SENTINEL_ENVIRONMENT=docker
```

#### Configuration Files

Environment-specific configuration files are located in `sentinel_backend/config/`:

- `development.env` - Local development settings
- `testing.env` - Test environment settings
- `production.env` - Production deployment settings
- `docker.env` - Docker container settings

#### Configuration Usage

Services import configuration using centralized functions:

```python
from config.settings import get_settings, get_service_settings, get_application_settings

# Get all settings
settings = get_settings()

# Get specific setting sections
service_settings = get_service_settings()
app_settings = get_application_settings()

# Use configuration
timeout = service_settings.service_timeout
log_level = app_settings.log_level
```

#### Environment Variables

All configuration can be overridden using environment variables with the `SENTINEL_` prefix:

```bash
# Database configuration
SENTINEL_DB_URL=postgresql+asyncpg://user:pass@host/db
SENTINEL_DB_POOL_SIZE=20

# Service URLs
SENTINEL_SERVICE_AUTH_SERVICE_URL=http://auth:8005
SENTINEL_SERVICE_SERVICE_TIMEOUT=60

# Security settings
SENTINEL_SECURITY_JWT_SECRET_KEY=your-secret-key
SENTINEL_SECURITY_JWT_EXPIRATION_HOURS=24

# Application settings
SENTINEL_APP_LOG_LEVEL=DEBUG
SENTINEL_APP_DEBUG=true
```

#### Docker Configuration

For Docker deployments, use the `.env.docker` file:

```bash
# Copy and customize the Docker environment file
cp sentinel_backend/.env.docker sentinel_backend/.env.local
# Edit .env.local with your settings
docker-compose --env-file .env.local up
```

#### Production Security

For production deployments:

1. **Change default secrets**: Update JWT secret keys and database passwords
2. **Use environment variables**: Never commit secrets to version control
3. **Validate configuration**: The system validates configuration on startup
4. **Monitor configuration**: Enable configuration audit logging

### Observability Configuration

The platform includes comprehensive observability settings:

```python
# Jaeger tracing configuration
SENTINEL_NETWORK_JAEGER_AGENT_HOST=localhost
SENTINEL_NETWORK_JAEGER_AGENT_PORT=6831

# Prometheus metrics
# Metrics are automatically exposed on /metrics endpoint for all services

# Structured logging
SENTINEL_APP_LOG_LEVEL=INFO
SENTINEL_APP_LOG_FORMAT=json  # json or text

# Message Broker configuration
SENTINEL_BROKER_URL=amqp://guest:guest@message_broker:5672/
SENTINEL_BROKER_TASK_QUEUE_NAME=sentinel_task_queue
SENTINEL_BROKER_RESULT_QUEUE_NAME=sentinel_result_queue
```

### Message Broker Architecture

The platform uses RabbitMQ for asynchronous task processing:

- **Task Queue**: The Orchestration Service publishes agent tasks to RabbitMQ
- **Consumer**: The Sentinel Rust Core consumes tasks from the queue
- **Durability**: Messages persist across service restarts
- **Scalability**: Multiple Rust Core instances can consume from the same queue

To test the message broker integration:
```bash
python3 test_rabbitmq_integration.py
```

This validates:
- ✅ RabbitMQ connection and queue management
- ✅ Task publishing from Python services
- ✅ Task consumption by Rust Core
- ✅ Message persistence and durability

For production deployments:
1. Configure external Jaeger collector for trace aggregation
2. Set up Prometheus scraping and alerting rules
3. Use log aggregation tools (ELK, Splunk) for centralized logging
4. Enable correlation ID propagation for distributed debugging

### Testing Infrastructure

The platform includes a comprehensive testing infrastructure with **408+ tests** covering all critical components:

#### Test Coverage
- **AI Agents**: 184 tests covering all 8 specialized agents with comprehensive unit testing
- **Auth Service**: 24 tests covering authentication, authorization, and user management
- **API Gateway**: 23 tests covering routing, middleware, and service communication
- **Spec Service**: 21 tests covering OpenAPI parsing and specification management
- **Orchestration Service**: 24 tests covering agent management and task delegation
- **Data Service**: 25 tests covering CRUD operations and analytics
- **Execution Service**: 22 tests covering test execution and result collection
- **LLM Providers**: 50+ tests covering all provider integrations and fallback mechanisms
- **Agent LLM Integration**: 20+ tests covering agent-LLM interaction patterns
- **Rust Integration**: 3 tests (conditionally run based on service availability)

#### Running Tests
```bash
# IMPORTANT: Always run tests in Docker for consistent environment
cd sentinel_backend
./run_tests.sh -d                # Run all tests in Docker (RECOMMENDED)
./run_tests.sh -d -t unit        # Unit tests only in Docker
./run_tests.sh -d -t integration # Integration tests in Docker
./run_tests.sh -d -t agents      # AI agent tests in Docker

# Run AI Agent Tests
./run_agent_tests.sh              # Run all agent tests with colored output
./run_agent_tests.sh -c           # Run with coverage report
./run_agent_tests.sh base auth    # Run specific agent tests
./run_agent_tests.sh -v -p        # Verbose with parallel execution

# Smart test filtering based on environment
./run_tests_filtered.sh          # Auto-detects Rust service availability
./run_tests_filtered.sh --with-rust  # Force Rust tests with mocks
pytest -m "not rust"              # Exclude Rust tests explicitly

# Rebuild test Docker image after dependency changes
docker-compose -f docker-compose.test.yml build test_runner

# Run tests for specific service
pytest tests/unit/test_auth_service.py -v
pytest tests/unit/test_llm_providers.py -v
pytest tests/unit/agents/         # Run all agent tests

# Run tests with coverage
pytest tests/unit/ --cov=. --cov-report=term-missing
```

#### Factory Pattern Architecture
All services implement the factory pattern for enhanced testability:
- Dependency injection at app creation time
- Mock mode for isolated testing without external dependencies
- Configurable timeouts and connections
- Consistent testing approach across all services

#### Test Helpers & Fixtures
- `tests/helpers/auth_helpers.py`: Authentication test utilities
- `tests/fixtures/`: Shared test data and mock responses
- Docker test environment for consistent testing

### Database Setup

The platform uses PostgreSQL with the pgvector extension. The database schema is defined in `memory-bank/database-schema.md`.

### Authentication & RBAC

The platform includes comprehensive Role-Based Access Control (RBAC) with a modern React-based authentication system:

**Frontend Authentication:**
- **Login Page**: http://localhost:3000/login (automatically redirected when not authenticated)
- **Demo Credentials Button**: Quick-fill form with default admin credentials
- **Route Protection**: All dashboard pages require authentication
- **User Menu**: Access profile and logout functionality from the top-right corner

**Default Admin Credentials:**
- Email: `admin@sentinel.com`
- Password: `admin123`

**User Roles:**
- **Admin**: Full access including user management
- **Manager**: Most permissions except user management
- **Tester**: Testing-focused permissions (create/edit test cases, run tests)
- **Viewer**: Read-only access to all resources

**Authentication Features:**
- JWT-based authentication with secure token storage
- Redux state management for authentication across the application
- Automatic token handling in API requests
- Session persistence across browser refreshes
- Secure logout with token cleanup

**Demo RBAC Features:**
```bash
python demo_rbac.py
```

This script demonstrates authentication, authorization, and role-based permissions across different user types.

## 📊 Key Features

- **Intelligent Test Generation**: AI agents automatically generate comprehensive test suites
- **Multi-Domain Testing**: Covers functional, security, and performance testing
- **Specification-Driven**: Deep understanding of OpenAPI specifications
- **Hybrid AI Approach**: Combines deterministic algorithms with LLM creativity
- **Real-time Analytics**: Historical trend analysis and anomaly detection
- **CI/CD Integration**: Seamless integration with modern DevOps workflows

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions from the community! Whether you're a developer, a tester, or just an enthusiast, there are many ways to get involved.

Before you start, please read our [**Code of Conduct**](CODE_OF_CONDUCT.md) to understand our community standards.

### How to Contribute

For a detailed guide on how to contribute, set up your development environment, and follow our style guidelines, please see our [**Contributing Guide**](CONTRIBUTING.md).

Here's a quick overview of the process:

1.  **Find an issue** to work on or propose a new feature. Check out issues labeled `good first issue` for a great place to start.
2.  **Fork the repository** and create a new branch for your work.
3.  **Make your changes**, following the project's coding and style guidelines.
4.  **Write tests** to cover your changes and ensure existing tests pass.
5.  **Submit a Pull Request** with a clear description of your changes.

We use GitHub issues to track bugs and feature requests. Please use our issue templates when creating a new issue:

-   [**Report a Bug**](https://github.com/proffesor-for-testing/sentinel-api-testing/issues/new?template=bug_report.md)
-   [**Request a Feature**](https://github.com/proffesor-for-testing/sentinel-api-testing/issues/new?template=feature_request.md)

### Key Principles

This project follows the patterns and preferences outlined in `.clinerules`. Key principles include:

-   **Modularity**: Develop within the microservices architecture.
-   **Agent Specialization**: Create specialized agents for new testing types.
-   **Specification-Driven**: All development is driven by API specifications.
-   **Hybrid AI**: Combine deterministic algorithms with LLM capabilities.

## 📚 Documentation

### 📖 Comprehensive Documentation Portal

The Sentinel platform now includes extensive documentation covering all aspects of usage, deployment, and development:

#### [**📘 Complete Documentation Index**](docs/index.md)
Your starting point for all Sentinel documentation.

#### Core Documentation Sections:

- **[User Guide](docs/user-guide/index.md)** - Complete guide for using Sentinel
  - [Quick Start Guide](docs/user-guide/quick-start.md) - Get up and running in minutes
  - [Managing API Specifications](docs/user-guide/specifications.md) - Upload and manage OpenAPI specs
  - [Understanding Test Types](docs/user-guide/test-types.md) - Learn about different testing approaches
  - [CI/CD Integration](docs/user-guide/cicd-integration.md) - Integrate with your DevOps pipeline

- **[Technical Guide](docs/technical-guide/index.md)** - In-depth technical documentation
  - [Architecture Overview](docs/technical-guide/architecture.md) - System design and components
  - Service components and interactions
  - Agent implementation details
  - Database schema and models

- **[API Reference](docs/api-reference/index.md)** - Complete API documentation
  - REST API endpoints with examples
  - Authentication and authorization
  - Code examples in multiple languages
  - SDK libraries and usage

- **[Deployment Guide](docs/deployment/index.md)** - Production deployment instructions
  - Docker and Kubernetes deployment
  - Cloud platform deployments (AWS, GCP, Azure)
  - Scaling strategies
  - Security hardening

- **[Troubleshooting Guide](docs/troubleshooting/index.md)** - Diagnose and resolve issues
  - Common problems and solutions
  - Debugging techniques
  - Performance optimization
  - FAQ

#### Memory Bank Documentation:

Additional technical documentation is maintained in the `memory-bank/` directory:

- **[Project Brief](memory-bank/projectbrief.md)**: Overall project scope and objectives
- **[System Patterns](memory-bank/systemPatterns.md)**: Architectural decisions and patterns
- **[Agent Specifications](memory-bank/agent-specifications.md)**: Detailed agent capabilities and workflows
- **[Database Schema](memory-bank/database-schema.md)**: Complete data model design
- **[API Design](memory-bank/api-design.md)**: Internal REST API specifications
- **[Progress Tracking](memory-bank/progress.md)**: Implementation roadmap and status
- **[Active Context](memory-bank/activeContext.md)**: Current development focus

## 🔮 Future Vision

Sentinel aims to transform API testing from a manual, reactive process to an intelligent, proactive, and automated part of the development lifecycle. The platform will continuously evolve to incorporate the latest advances in AI and testing methodologies.

---

The Sentinel platform is production-ready and provides comprehensive API testing across all major domains:

🔧 **Functional Testing**: Positive, negative, and stateful workflow testing with advanced boundary value analysis and creative test generation.

🔐 **Security Testing**: BOLA, function-level authorization, authentication bypass, and comprehensive injection vulnerability testing (SQL/NoSQL/Command/Prompt injection for LLM-backed APIs).

⚡ **Performance Testing**: Load, stress, and spike testing with intelligent API analysis and automated k6/JMeter script generation.

📊 **Enhanced Reporting**: React-based UI with detailed failure analysis, agent-specific insights, and interactive test case exploration.

The platform is enterprise-ready for comprehensive API testing across functional, security, and performance domains!
