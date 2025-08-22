# Changelog

All notable changes to the Sentinel API Testing Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-08-22

### Added
- **Asynchronous Test Generation**
  - New `/generate-tests-async` endpoint for non-blocking test generation
  - Task status polling with `/task-status/{task_id}` endpoint
  - Real-time progress tracking showing which agent is currently running
  - Prevents 503 timeout errors for long-running test generation

- **Analytics API Integration**
  - Added 6 analytics endpoints to API Gateway
  - `/api/v1/analytics/trends/failure-rate` - Historical failure rate trends
  - `/api/v1/analytics/trends/latency` - Latency trends with percentiles
  - `/api/v1/analytics/anomalies` - Anomaly detection in test results
  - `/api/v1/analytics/predictions` - Predictive insights
  - `/api/v1/analytics/insights` - Quality insights and recommendations
  - `/api/v1/analytics/health-summary` - Overall health dashboard

### Fixed
- **Test Generation Issues**
  - Fixed duplicate test case generation by implementing MD5-based deduplication
  - Fixed `FunctionalStatefulAgent` OperationNode subscript error
  - Resolved async test generation timeout issues with background tasks

- **Analytics Page Issues**
  - Fixed Analytics.js using incorrect fetch URLs (was hitting React dev server instead of API)
  - Fixed SQL query errors in data service (incorrect field references)
  - Fixed `TestResult.agent_type` error by properly joining TestCase table
  - Fixed `response_time_ms` to `latency_ms` field name mismatch
  - Fixed variable name shadowing issue (`status` variable conflicting with imported module)

### Changed
- Updated frontend to use apiService for all API calls instead of raw fetch
- Enhanced .gitignore to exclude .claude-flow directories
- Improved error handling in async test generation

## [1.0.0] - 2025-08-18

### Added
- **Comprehensive Test Implementation (Phase 3 & 4)**
  - 6 integration test files with 2,342 lines of test code
  - 97 test methods covering critical backend components
  - API workflow tests (formerly E2E) for end-to-end API testing
  - Playwright E2E testing framework for frontend
  - Page Object Model architecture for maintainable tests
  - Cross-browser testing support (Chrome, Firefox, Safari, Mobile)

### Changed
- Renamed `tests/e2e` to `tests/api_workflows` for better clarity
- Updated Dockerfile.test to fix SQLAlchemy version compatibility
- Enhanced test organization and structure

### Test Coverage Updates
- **Phase 1**: ✅ AI Agent Tests (100% - 184 tests)
- **Phase 2**: ✅ LLM Provider Tests (100% - 272+ tests)
- **Phase 3**: ✅ Integration Tests (100% - 6 files)
- **Phase 4**: 🔄 API Workflow Tests (33% - 2 of 6 files)
- **NEW**: Playwright E2E Tests for Frontend

### Infrastructure
- Added Playwright configuration for E2E testing
- Created test fixtures and page objects
- Implemented test data management
- Added comprehensive test documentation

## [1.0.0] - 2025-08-16

### Added
- **Phase 1: AI Agent Unit Tests**
  - Complete test coverage for all 8 AI agents
  - 184 comprehensive unit tests
  - Full mocking and async support
  - Dedicated test runner (`run_agent_tests.sh`)

- **Phase 2: LLM Provider Tests**
  - 100% coverage for all LLM providers
  - Provider factory and fallback mechanism tests
  - Token counting and cost calculation tests
  - Response caching tests
  - Model registry tests

### Infrastructure
- Docker test environment setup
- CI/CD pipeline integration
- Test coverage reporting
- Pytest configuration with markers

## [0.9.0] - 2025-08-14

### Added
- Initial platform release
- Microservices architecture
- AI agent system for test generation
- Multi-LLM provider support
- RBAC authentication system
- API specification management
- Test execution engine
- Analytics and reporting

### Core Services
- API Gateway (Port 8000)
- Auth Service (Port 8005)
- Spec Service (Port 8001)
- Orchestration Service (Port 8002)
- Execution Service (Port 8003)
- Data Service (Port 8004)
- Sentinel Rust Core (Port 8088)

### AI Agents
- Functional-Positive-Agent
- Functional-Negative-Agent
- Functional-Stateful-Agent
- Security-Auth-Agent
- Security-Injection-Agent
- Performance-Planner-Agent
- Data-Mocking-Agent

### Infrastructure
- PostgreSQL with pgvector
- RabbitMQ message broker
- Prometheus monitoring
- Jaeger distributed tracing
- Docker Compose orchestration