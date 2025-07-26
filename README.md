# Sentinel - AI Agentic API Testing Platform

Sentinel is an advanced, AI-powered platform designed to automate the entire API testing lifecycle. It leverages a modular, microservices-inspired architecture and an ecosystem of specialized, ephemeral AI agents to provide comprehensive, intelligent, and efficient testing across functional, security, and performance domains.

## 🏗️ Architecture Overview

The platform is built upon the **ruv-FANN** and **ruv-swarm** frameworks, enabling a paradigm of "ephemeral swarm intelligence" where lightweight, WASM-based agents are dynamically spawned to perform specific testing tasks and dissolved upon completion.

### Core Services

- **API Gateway** (Port 8000): Single entry point for all user interactions
- **Specification Service** (Port 8001): Manages API specification ingestion and parsing
- **Orchestration Service** (Port 8002): Central brain managing agentic workflows
- **Execution Service** (Port 8003): Handles test execution and scheduling
- **Data & Analytics Service** (Port 8004): Manages data persistence and analytics
- **PostgreSQL Database** (Port 5432): Data storage with pgvector extension

## 🤖 Specialized Agents

The platform employs a workforce of specialized AI agents:

- **Spec-Linter-Agent**: Analyzes API specs for "LLM-readiness"
- **Functional-Positive-Agent**: Generates valid, "happy path" test cases
- **Functional-Negative-Agent**: Creates boundary and error condition tests
- **Functional-Stateful-Agent**: Builds complex multi-step workflows
- **Security-Auth-Agent**: Tests authentication/authorization vulnerabilities
- **Security-Injection-Agent**: Probes for injection attacks (including prompt injection)
- **Performance-Planner-Agent**: Generates performance test plans
- **Performance-Analyzer-Agent**: Analyzes performance test results

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+ (for local development)
- Poetry (for dependency management)

### Running the Platform

1. **Clone and navigate to the project:**
   ```bash
   cd "Agents for API testing/sentinel_backend"
   ```

2. **Start all services:**
   ```bash
   docker-compose up --build
   ```

3. **Access the services:**
   - API Gateway: http://localhost:8000
   - Specification Service: http://localhost:8001
   - Orchestration Service: http://localhost:8002
   - Execution Service: http://localhost:8003
   - Data & Analytics Service: http://localhost:8004

### API Documentation

Once running, you can access the interactive API documentation:
- API Gateway: http://localhost:8000/docs
- Each service also exposes its own `/docs` endpoint

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
│   │       └── functional_stateful_agent.py
│   ├── execution_service/         # Test execution
│   └── data_service/              # Data & analytics
├── sentinel_frontend/              # React-based frontend UI
│   ├── src/                       # React application source
│   │   ├── components/            # Reusable UI components
│   │   ├── pages/                 # Application pages
│   │   └── services/              # API communication
│   ├── package.json               # Node.js dependencies
│   └── tailwind.config.js         # Tailwind CSS configuration
├── demo_phase2.py                 # Phase 2 demonstration script
├── demo_phase3.py                 # Phase 3 agent demonstration
├── demo_phase3_frontend.py        # Phase 3 frontend demonstration
├── demo_standalone.py             # Standalone demo (no Docker)
└── .clinerules                    # Development patterns and preferences
```

## 🔄 Development Phases

The project follows a phased implementation approach:

### Phase 1: MVP Foundation ✅ COMPLETED
- ✅ Core architectural components
- ✅ Basic service structure
- ✅ Specification parser implementation
- ✅ Database connection and models

### Phase 2: Minimum Viable Product ✅ COMPLETED
- ✅ Basic Functional-Positive-Agent
- ✅ Test execution engine
- ✅ Simple reporting UI
- ✅ End-to-end workflow implementation

### Phase 3: Core Features ✅ COMPLETED
- ✅ Functional-Negative-Agent (BVA + creative testing)
- ✅ Functional-Stateful-Agent (SODG-based workflows)
- ✅ Enhanced Reporting UI with detailed failure analysis
- ✅ Agent-specific insights and test type classification

### Phase 4: Advanced Capabilities (Next)
- ⬜ Security and performance agents
- ⬜ Historical trend analysis
- ⬜ Advanced analytics and anomaly detection

### Phase 5: Enterprise Readiness
- ⬜ CI/CD integration
- ⬜ Collaboration features
- ⬜ Production deployment

## 🛠️ Development

### Local Development Setup

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

### Database Setup

The platform uses PostgreSQL with the pgvector extension. The database schema is defined in `memory-bank/database-schema.md`.

## 📊 Key Features

- **Intelligent Test Generation**: AI agents automatically generate comprehensive test suites
- **Multi-Domain Testing**: Covers functional, security, and performance testing
- **Specification-Driven**: Deep understanding of OpenAPI specifications
- **Hybrid AI Approach**: Combines deterministic algorithms with LLM creativity
- **Real-time Analytics**: Historical trend analysis and anomaly detection
- **CI/CD Integration**: Seamless integration with modern DevOps workflows

## 🤝 Contributing

This project follows the patterns and preferences outlined in `.clinerules`. Key principles:

- **Modularity**: Develop within the microservices architecture
- **Agent Specialization**: Create specialized agents for new testing types
- **Specification-Driven**: All development driven by API specifications
- **Hybrid AI**: Combine deterministic algorithms with LLM capabilities

## 📚 Documentation

Comprehensive documentation is maintained in the `memory-bank/` directory:

- **Project Brief**: Overall project scope and objectives
- **System Patterns**: Architectural decisions and patterns
- **Agent Specifications**: Detailed agent capabilities and workflows
- **Database Schema**: Complete data model design
- **API Design**: Internal REST API specifications

## 🔮 Future Vision

Sentinel aims to transform API testing from a manual, reactive process to an intelligent, proactive, and automated part of the development lifecycle. The platform will continuously evolve to incorporate the latest advances in AI and testing methodologies.

---

**Note**: Phase 3 has been completed! The platform now includes comprehensive functional testing agents (Positive, Negative, and Stateful) with an enhanced React-based reporting UI. The system provides advanced boundary value analysis, creative negative testing, and multi-step workflow validation with detailed failure analysis and agent-specific insights.
