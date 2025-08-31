# Technical Context: Sentinel Platform

This document outlines the recommended technology stack and development environment for the Sentinel platform, based on the project specification.

## 1. Core Technology Stack

| Component              | Technology                        | Rationale & Key Libraries                                                                                                                                                                                          |
| ---------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Backend Framework**  | Python 3.10+ with FastAPI         | Python's dominance in AI/ML provides an unparalleled library ecosystem. FastAPI offers high performance, automatic OpenAPI documentation for internal APIs, and robust data validation via Pydantic.                 |
| **Agentic Framework**  | ruv-swarm / ruv-FANN              | A foundational requirement. This provides the core mechanism for creating ephemeral, CPU-native, WASM-based agents, enabling a resource-efficient and highly scalable testing architecture.                        |
| **Database**           | PostgreSQL with pgvector          | A reliable, feature-rich relational database. The `pgvector` extension is critical for storing and querying vector embeddings, enabling advanced Retrieval-Augmented Generation (RAG) techniques for test generation. |
| **Frontend Framework** | React or Vue.js                   | Both are mature, component-based frameworks well-suited for building the complex, interactive dashboard required for test management, visualization, and reporting.                                                 |
| **API Spec Parsing**   | `prance`, `openapi-core`          | Specialized Python libraries to handle the complexities of parsing, validating, and resolving references within OpenAPI specifications, which is fundamental to the platform's intelligence.                       |
| **Test Execution**     | pytest                            | A powerful and highly extensible Python testing framework. The platform will dynamically generate test logic to be executed by the pytest runner, leveraging its rich plugin ecosystem (e.g., `pytest-xdist`).   |
| **Job Scheduling**     | `schedule` (Python) / Cron        | The `schedule` library for simple, in-process interval-based jobs. System `cron` for more robust, time-based scheduling.                                                                                         |
| **Data Mocking**       | Faker.js / Custom Mock Server     | A library like Faker.js will be integrated to generate realistic mock data. The mocking agent will configure a mock server to simulate various API behaviors, including latency and error conditions.           |

## 2. Development & CI/CD

- **Version Control:** Git, hosted on a platform like GitHub or GitLab.
- **Containerization:** Docker and Docker Compose will be used to create a consistent, reproducible development environment for all backend services and the database.
- **CI/CD Integration:** The platform will be designed for seamless integration with major CI/CD systems (GitHub Actions, GitLab CI, Jenkins). It will expose a stable CLI and/or REST API hooks to be invoked from pipeline scripts for true continuous testing.

## 3. LLM Integration Architecture

The platform features a comprehensive multi-vendor LLM abstraction layer that enables intelligent test generation:

### Supported Providers (With Verified Performance)
- **Anthropic Claude** (Default): Claude Opus 4.1, Sonnet 4, Haiku 3.5 - **2.3s response time** (verified)
- **OpenAI**: GPT-4 Turbo, GPT-4, GPT-3.5 Turbo - Wide compatibility and strong capabilities
- **Google Gemini**: Gemini 2.5 Pro/Flash, 2.0 Flash - Latest models with massive context windows (up to 2M tokens)
- **Mistral**: Large, Small 3, Codestral - European alternatives with competitive performance
- **Ollama**: Local models (mistral:7b, codellama:7b, deepseek-coder:6.7b) - **10-15s response time** (CPU)
- **vLLM**: High-performance local serving for production deployments
- **Mock Provider**: Instant responses - **104ms response time** (for testing)

### Key Features
- **Performance-Based Routing**: Intelligent selection of fastest agent implementation (Python vs Rust)
- **Automatic Fallback**: Seamlessly switches between providers on failure for 99.9% uptime
- **Cost Tracking**: Real-time usage monitoring with budget limits and alerts
- **Response Caching**: Reduces API calls by up to 50% with intelligent caching
- **Token Management**: Smart context window handling prevents overflow errors
- **Provider-Specific Templates**: Optimized prompts for each model's strengths
- **Performance Metrics API**: Real-time monitoring endpoint at `/performance-metrics`

### Hybrid Approach
All agents use a hybrid strategy combining:
- **Deterministic Algorithms**: For rigorous, repeatable test generation
- **LLM Enhancement**: For creative test scenarios and edge cases
- **Backward Compatibility**: Agents work without LLM configuration (deterministic only)

### Configuration Management
The platform includes user-friendly scripts for managing LLM providers:
- **`switch_llm.sh`**: Interactive wizard with quick presets for all providers
- **`switch_llm_docker.sh`**: Docker-specific configuration switcher
- **`validate_llm_config.py`**: Configuration validation and connectivity testing

Quick provider switching:
```bash
./switch_llm.sh claude    # Use Claude Sonnet 4
./switch_llm.sh openai    # Use GPT-4 Turbo
./switch_llm.sh local     # Use local Ollama
./switch_llm.sh none      # Disable LLM
```

## 4. Test Infrastructure (Phase 1 Complete - August 16, 2025)

The platform now features a robust testing infrastructure with comprehensive coverage:

### Test Organization
- **Total Tests:** 408 tests (up from 224, +184 new agent tests)
- **Pass Rate:** 97.8% (consistent with previous implementation)
- **Test Structure:** Organized by service and agent type for maintainability

### Testing Tools & Frameworks
- **Primary Framework:** pytest with extensive plugin ecosystem
- **Async Testing:** pytest-asyncio for testing async agent methods
- **Mocking:** unittest.mock for dependency isolation
- **Coverage:** pytest-cov with HTML reports and thresholds
- **Markers:** Custom markers for test categorization (unit, integration, rust, fallback)

### Agent Test Infrastructure
- **Dedicated Runner:** `run_agent_tests.sh` script with:
  - Colored output for better readability
  - Coverage reporting with percentages
  - Selective test execution by agent type
  - Error summary and failure details
- **Fixture Library:** Comprehensive fixtures for:
  - OpenAPI specifications
  - Test case templates
  - Mock LLM responses
  - Error scenarios
- **Mock Strategy:** Full mocking of:
  - LLM providers (all 6 supported providers)
  - HTTP clients for API testing
  - Database connections
  - External service dependencies

### Test Execution Patterns
```bash
# Run all agent tests with coverage
./run_agent_tests.sh

# Run specific agent tests
./run_agent_tests.sh base auth

# Run with coverage report
./run_agent_tests.sh -c

# Run in Docker environment
docker-compose exec orchestration_service ./run_agent_tests.sh
```

### Coverage Achievements (Phase 1)
- **BaseAgent:** 22 tests covering core functionality
- **Data Mocking Agent:** 22 tests for data generation
- **Functional Agents:** 68 tests across positive/negative/stateful
- **Security Agents:** 48 tests for auth and injection
- **Performance Agent:** 24 tests for load testing scenarios

## 5. Technical Constraints & Considerations

- **LLM Integration:** ✅ **IMPLEMENTED** - Comprehensive multi-vendor support with fallback mechanisms and cost management
- **Test Coverage:** ✅ **PHASE 1 COMPLETE** - 100% agent coverage with 184 comprehensive unit tests
- **Security Agent Architecture:** To avoid self-censorship by commercial LLM providers when generating security exploits, the `Security-Injection-Agent` will use a two-tiered approach: a powerful model for high-level strategy and a less-restricted (potentially locally hosted) model for final payload generation.
- **WASM Compilation:** A toolchain for compiling Python code (or Rust, as is common in the ruv-FANN ecosystem) to WebAssembly will be a necessary part of the agent development workflow.
- **Data Privacy:** The platform will handle potentially sensitive API specifications and test data. All data must be handled securely, with encryption at rest and in transit.
