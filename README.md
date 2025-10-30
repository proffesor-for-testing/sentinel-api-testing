# 🛡️ Sentinel - AI-Powered API Testing Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org/)
[![Tests](https://img.shields.io/badge/Tests-540%2B-green.svg)](./sentinel_backend/tests/)

> **Transform API testing with specialized AI agents that generate, execute, and analyze comprehensive test suites automatically.**

Sentinel is an enterprise-grade, AI-powered platform that automates the entire API testing lifecycle using specialized agents for functional, security, and performance testing. Built with a modern microservices architecture and hybrid Python/Rust implementation for optimal performance.

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📖 Documentation](#-documentation)
- [🏗️ Architecture](#️-architecture)
- [🤖 AI Agents](#-ai-agents)
- [💻 Usage](#-usage)
- [🧪 Testing](#-testing)
- [🛠️ Development](#️-development)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🆘 Support](#-support)

---

## ✨ Features

### 🎯 **Intelligent Test Generation**
- **AI-Powered Agents**: 7 specialized agents for functional, security, and performance testing
- **Multi-LLM Support**: Anthropic Claude, OpenAI GPT-4, Google Gemini, Mistral, and local Ollama models
- **Specification-Driven**: Automatic test generation from OpenAPI/Swagger specifications
- **Hybrid Architecture**: Python + Rust with intelligent routing based on real-time performance metrics

### 🔒 **Comprehensive Testing**
- **Functional Testing**: Positive, negative, and stateful workflow testing
- **Security Testing**: BOLA, injection attacks (SQL/NoSQL/Command/LLM), authorization testing
- **Performance Testing**: Load, stress, and spike testing with k6/JMeter/Locust
- **540+ Tests**: 97.8% pass rate with comprehensive coverage

### 🎨 **Modern User Interface**
- **React Dashboard**: Real-time metrics and interactive test management
- **Specification Management**: Upload, parse, and manage OpenAPI specs
- **Test Execution**: One-click test runs with detailed results
- **Analytics**: Trend analysis and comprehensive reporting

### ⚡ **Enterprise-Ready**
- **Microservices Architecture**: 10 independent, scalable services
- **Docker Deployment**: Complete containerization with Docker Compose
- **Observability**: Prometheus metrics, Jaeger tracing, structured logging
- **RBAC**: Role-based access control with JWT authentication

---

## 🚀 Quick Start

Get Sentinel running in **under 5 minutes**:

### Prerequisites

- **Docker** and **Docker Compose** (required)
- **Git** (required)
- **Make** (optional, for convenience commands)
- **Python 3.10+** (only for local development)
- **Node.js 14+** (only for frontend development)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/proffesor-for-testing/sentinel-api-testing.git
   cd sentinel-api-testing
   ```

2. **Configure LLM provider** (optional but recommended for AI features)
   ```bash
   # Set your API key for AI-powered test generation
   export SENTINEL_APP_ANTHROPIC_API_KEY="your-anthropic-api-key"

   # Or use the configuration script for other providers
   cd sentinel_backend/scripts
   ./switch_llm.sh claude    # Claude (default)
   ./switch_llm.sh openai    # OpenAI GPT-4
   ./switch_llm.sh gemini    # Google Gemini
   ./switch_llm.sh local     # Local Ollama
   ```

3. **Start the platform**
   ```bash
   # Complete setup with one command
   make setup

   # Or manually with Docker Compose
   docker-compose up --build -d
   make init-db
   ```

4. **Access the platform**
   - 🌐 **Frontend**: http://localhost:3000
   - 🔐 **Login**: `admin@sentinel.com` / `admin123`
   - 📚 **API Docs**: http://localhost:8000/docs
   - 🧪 **Test API**: http://localhost:8080 (Petstore demo)

### Verify Installation

```bash
# Check all services are running
make status

# View service logs
make logs

# Run health checks
curl http://localhost:3000/health
curl http://localhost:8000/health
```

**That's it!** You now have a fully functional AI-powered API testing platform running locally.

---

## 📖 Documentation

### 📘 **Getting Started**
- [**Quick Start Guide**](docs/user-guide/quick-start.md) - Detailed setup instructions
- [**User Guide**](docs/user-guide/index.md) - Complete platform usage guide
- [**FAQ**](docs/troubleshooting/index.md) - Common questions and solutions

### 🏗️ **Technical Documentation**
- [**Architecture Overview**](docs/technical-guide/architecture.md) - System design and components
- [**API Reference**](docs/api-reference/index.md) - REST API documentation
- [**Database Schema**](memory-bank/database-schema.md) - Data model design
- [**Hybrid Python/Rust Architecture**](docs/HYBRID_AGENT_ARCHITECTURE.md) - Performance details

### 🚀 **Deployment & Operations**
- [**Deployment Guide**](docs/deployment/index.md) - Production deployment
- [**Docker Guide**](QUICK_DEPLOYMENT_GUIDE.md) - Container orchestration
- [**Troubleshooting**](docs/troubleshooting/index.md) - Common issues and solutions
- [**Observability**](README.md#observability--monitoring) - Metrics and tracing

### 🤖 **AI Agents**
- [**Agent Specifications**](memory-bank/agent-specifications.md) - Detailed agent capabilities
- [**Rust Agents**](docs/RUST_AGENTS_OVERVIEW.md) - High-performance implementations
- [**LLM Configuration**](CLAUDE.md#llm-integration) - Multi-provider setup

---

## 🏗️ Architecture

Sentinel uses a modern microservices architecture with 10 independent services:

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React + nginx)                 │
│                     http://localhost:3000                   │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                   API Gateway (FastAPI)                     │
│                     http://localhost:8000                   │
└─────┬────────┬────────┬────────┬────────┬──────────────────┘
      │        │        │        │        │
┌─────▼────┐ ┌▼──────┐ ┌▼──────┐ ┌▼─────┐ ┌▼────────────────┐
│   Auth   │ │ Spec  │ │ Orch. │ │ Exec.│ │  Data Service   │
│ Service  │ │Service│ │Service│ │Service│ │   (Analytics)   │
│  :8005   │ │ :8001 │ │ :8002 │ │ :8003│ │      :8004      │
└──────────┘ └───────┘ └───┬───┘ └──────┘ └─────────────────┘
                            │
                   ┌────────▼────────┐
                   │  Rust Core      │
                   │  (ruv-swarm)    │
                   │     :8088       │
                   └────────┬────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
    ┌────▼─────┐     ┌─────▼──────┐    ┌─────▼──────┐
    │PostgreSQL│     │  RabbitMQ  │    │ Prometheus │
    │  +vector │     │   :5672    │    │   :9090    │
    │  :5432   │     └────────────┘    └────────────┘
    └──────────┘
```

### Core Services

| Service | Port | Description |
|---------|------|-------------|
| **Frontend** | 3000 | React UI with Redux state management |
| **API Gateway** | 8000 | Single entry point with RBAC |
| **Auth Service** | 8005 | JWT authentication and user management |
| **Spec Service** | 8001 | OpenAPI specification management |
| **Orchestration** | 8002 | AI agent coordination and workflows |
| **Execution Service** | 8003 | Test execution engine |
| **Data Service** | 8004 | Data persistence and analytics |
| **Rust Core** | 8088 | High-performance agent execution |
| **PostgreSQL** | 5432 | Database with pgvector for AI |
| **RabbitMQ** | 5672 | Asynchronous message broker |

---

## 🤖 AI Agents

Sentinel employs **7 specialized AI agents** with both Python and Rust implementations:

### Functional Testing Agents
- **🟢 Functional-Positive-Agent**: Valid "happy path" test generation with schema-based data
- **🔴 Functional-Negative-Agent**: Boundary value analysis and creative negative testing
- **🔄 Functional-Stateful-Agent**: Complex multi-step workflows with dependency graphs

### Security Testing Agents
- **🔒 Security-Auth-Agent**: BOLA, authorization bypass, authentication vulnerabilities
- **💉 Security-Injection-Agent**: SQL/NoSQL/Command/LLM injection attack testing

### Performance Testing Agents
- **⚡ Performance-Planner-Agent**: Load, stress, spike testing with k6/JMeter/Locust scripts

### Data Generation Agents
- **📊 Data-Mocking-Agent**: Intelligent, schema-aware test data generation

### Performance

| Implementation | Language | Performance | Use Case |
|----------------|----------|-------------|----------|
| **Python Agents** | Python | **Optimized** | General testing, LLM integration |
| **Rust Agents** | Rust | **Alternative** | Experimental high-volume scenarios |

**Intelligent Routing**: System selects optimal implementation based on real-time performance metrics. Benchmark testing shows Python and Rust implementations have comparable performance with different strengths - Python excels at LLM-integrated workflows while Rust provides consistent performance for high-volume generation.

**Performance Note**: Early claims of "18-21x" Rust performance advantage have been revised after comprehensive benchmarking. Actual performance varies by workload - see `docs/BENCHMARK_RESULTS.md` for detailed metrics.

---

## 💻 Usage

### 1️⃣ Upload API Specification

```bash
# Via UI: Navigate to Specifications → Upload
# Or via API:
curl -X POST http://localhost:8000/api/v1/specifications \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@petstore.yaml"
```

### 2️⃣ Generate Tests with AI

```bash
# Via UI: Click "Generate Tests" → Select agents
# Or via API:
curl -X POST http://localhost:8000/api/v1/test-generation \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "specification_id": "spec-123",
    "agents": ["functional-positive", "security-auth"],
    "options": {
      "max_tests_per_agent": 50,
      "use_rust": true
    }
  }'
```

### 3️⃣ Execute Test Suites

```bash
# Via UI: Test Suites → Click "Run"
# Or via API:
curl -X POST http://localhost:8000/api/v1/test-runs \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "test_suite_id": "suite-456",
    "target_environment": "http://api.example.com"
  }'
```

### 4️⃣ View Results & Analytics

- **Dashboard**: Real-time metrics at http://localhost:3000/dashboard
- **Test Runs**: Detailed results at http://localhost:3000/test-runs
- **Analytics**: Trend analysis at http://localhost:3000/analytics

### Example Workflow

```bash
# 1. Start the platform
make setup

# 2. Login to the UI
# Visit http://localhost:3000
# Login: admin@sentinel.com / admin123

# 3. Upload Petstore specification
# Navigate to Specifications → Upload → Choose petstore.yaml

# 4. Generate tests with multiple agents
# Click "Generate Tests" → Select all agents → Generate

# 5. Create test suite
# Navigate to Test Cases → Select tests → "Create Suite"

# 6. Run tests
# Navigate to Test Suites → Select suite → "Run Tests"
# Target: http://localhost:8080 (Petstore API)

# 7. View results
# Navigate to Test Runs → Click latest run → View detailed results
```

---

## 🧪 Testing

Sentinel includes **540+ comprehensive tests** with 97.8% pass rate:

### Run All Tests

```bash
# Recommended: Run tests in Docker for consistency
cd sentinel_backend
./run_tests.sh -d

# Run specific test categories
./run_tests.sh -d -t unit          # Unit tests (456 tests)
./run_tests.sh -d -t integration   # Integration tests (20 tests)
./run_tests.sh -d -t e2e           # End-to-end tests (30 tests)
./run_tests.sh -d -t agents        # AI agent tests (184 tests)
```

### Test Coverage

| Category | Tests | Coverage | Status |
|----------|-------|----------|--------|
| **AI Agents** | 184 | 100% | ✅ Complete |
| **LLM Providers** | 272 | 100% | ✅ Complete |
| **Unit Tests** | 456 | 84% | ✅ Complete |
| **Integration** | 20 | 4% | ✅ Complete |
| **Backend E2E** | 30 | 6% | ✅ Complete |
| **Frontend E2E** | 45+ | 8% | ✅ Complete |
| **Total** | **540+** | **97.8%** | ✅ **Production Ready** |

### Frontend E2E Tests (Playwright)

```bash
cd sentinel_frontend
npm test                           # Run all Playwright tests
npm test -- auth.spec.ts          # Run authentication tests
npm test -- --headed              # Run with browser UI
```

### Performance Tests

```bash
cd sentinel_backend
pytest tests/performance/ -v       # Run all performance tests
pytest tests/performance/test_load_performance.py -v  # Load testing
```

---

## 🛠️ Development

### Local Development Setup

#### Backend Services

1. **Install dependencies**
   ```bash
   cd sentinel_backend
   poetry install
   ```

2. **Run individual services**
   ```bash
   # Example: API Gateway
   cd api_gateway
   poetry run uvicorn main:app --reload --port 8000
   ```

#### Frontend Application

1. **Install dependencies**
   ```bash
   cd sentinel_frontend
   npm install
   ```

2. **Start development server**
   ```bash
   npm start  # Runs on port 3000 with hot reload
   ```

### Configuration

All configuration is centralized in `sentinel_backend/config/settings.py`:

```python
from config.settings import get_settings, get_service_settings

# Get configuration
settings = get_settings()
service_settings = get_service_settings()

# Use configuration
database_url = settings.database.url
timeout = service_settings.service_timeout
```

**Environment Variables**: All settings can be overridden with `SENTINEL_*` prefix:

```bash
export SENTINEL_DB_URL="postgresql+asyncpg://user:pass@host/db"
export SENTINEL_APP_LOG_LEVEL="DEBUG"
export SENTINEL_SECURITY_JWT_SECRET_KEY="your-secret-key"
```

### Database Management

```bash
make init-db       # Initialize or repair database
make reset-db      # Complete reset (WARNING: data loss)
make backup-db     # Backup to timestamped file
make restore-db    # Restore from backup
```

### Useful Commands

```bash
make help          # Show all available commands
make start         # Start all services
make stop          # Stop all services
make restart       # Restart services
make status        # Check service health
make logs          # View service logs
make clean         # Clean up containers and volumes
```

---

## 🤝 Contributing

We welcome contributions! Whether you're fixing bugs, adding features, or improving documentation, your help is appreciated.

### Quick Start

1. **Fork the repository** and clone your fork
   ```bash
   git clone https://github.com/YOUR_USERNAME/sentinel-api-testing.git
   cd sentinel-api-testing
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the project's coding standards
   - Write tests for new features
   - Update documentation as needed

4. **Run tests**
   ```bash
   cd sentinel_backend
   ./run_tests.sh -d
   ```

5. **Commit and push**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**
   - Go to the repository on GitHub
   - Click "New Pull Request"
   - Select your branch
   - Fill in the PR template

### Development Guidelines

- **Code Style**: Follow PEP 8 for Python, ESLint for JavaScript/React
- **Testing**: Maintain 90%+ test coverage for new code
- **Documentation**: Update relevant docs for new features
- **Commits**: Use conventional commits (feat:, fix:, docs:, etc.)

### Resources

- [**Contributing Guide**](CONTRIBUTING.md) - Detailed contribution instructions
- [**Code of Conduct**](CODE_OF_CONDUCT.md) - Community standards
- [**Development Setup**](docs/technical-guide/index.md) - Technical documentation

### Report Issues

- [**Report a Bug**](https://github.com/proffesor-for-testing/sentinel-api-testing/issues/new?template=bug_report.md)
- [**Request a Feature**](https://github.com/proffesor-for-testing/sentinel-api-testing/issues/new?template=feature_request.md)

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

### 📚 Documentation

- [**Complete Documentation**](docs/index.md) - Full documentation portal
- [**FAQ**](docs/troubleshooting/index.md) - Frequently asked questions
- [**Troubleshooting Guide**](docs/troubleshooting/index.md) - Common issues and solutions

### 💬 Community

- **GitHub Issues**: [Report bugs or request features](https://github.com/proffesor-for-testing/sentinel-api-testing/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/proffesor-for-testing/sentinel-api-testing/discussions)

### 🔧 Common Issues

<details>
<summary><strong>Database connection errors</strong></summary>

```bash
# Fix database issues
make init-db

# Or complete reset
make reset-db
```
</details>

<details>
<summary><strong>Services not starting</strong></summary>

```bash
# Check service status
make status

# View logs for errors
make logs

# Restart all services
make restart
```
</details>

<details>
<summary><strong>Frontend blank page</strong></summary>

```bash
# Ensure backend is running
make status

# Check frontend logs
docker-compose logs frontend

# Restart frontend
docker-compose restart frontend
```
</details>

<details>
<summary><strong>Test execution fails</strong></summary>

- Ensure target API URL is valid (starts with `http://` or `https://`)
- Check target API is accessible: `curl http://your-api-url`
- Verify test suite has test cases assigned
</details>

### 📧 Contact

For additional support or questions:
- Open an issue on [GitHub](https://github.com/proffesor-for-testing/sentinel-api-testing/issues)
- Check our [documentation](docs/index.md)

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

Made with ❤️ by the Sentinel Team

[Documentation](docs/index.md) • [Contributing](CONTRIBUTING.md) • [License](LICENSE) • [Issues](https://github.com/proffesor-for-testing/sentinel-api-testing/issues)

</div>
