# Sentinel Phase 2 MVP - Complete End-to-End API Testing

## 🎯 Overview

Phase 2 of the Sentinel platform delivers a **complete end-to-end workflow** for AI-powered API testing. This MVP demonstrates the core capability: **ingest spec → generate tests → run tests → see results**.

### What's Working in Phase 2

✅ **API Specification Parsing** - Upload and parse OpenAPI 3.0 specifications  
✅ **Functional-Positive-Agent** - Generate realistic "happy path" test cases  
✅ **Test Execution Engine** - HTTP client-based test runner with validation  
✅ **Complete End-to-End Flow** - Single API call for the entire workflow  
✅ **Service Integration** - All microservices communicate via REST APIs  
✅ **Result Analysis** - Detailed test results with pass/fail status and latency  

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.10+ (for the demo script)
- `httpx` library: `pip install httpx`

### 1. Start All Services

```bash
cd sentinel_backend
docker-compose up -d
```

This starts all 5 microservices:
- **API Gateway** (port 8080) - Main entry point
- **Spec Service** (port 8001) - API specification parsing
- **Orchestration Service** (port 8002) - Agent coordination
- **Execution Service** (port 8003) - Test execution
- **Data Service** (port 8004) - Database operations

### 2. Run the Demo

```bash
python demo_phase2.py
```

This demonstrates the complete workflow using the JSONPlaceholder API as a test target.

### 3. Manual Testing

You can also test individual endpoints:

```bash
# Check if all services are healthy
curl http://localhost:8080/health

# Upload an API specification
curl -X POST http://localhost:8080/api/v1/specifications \
  -H "Content-Type: application/json" \
  -d '{"raw_spec": "{...openapi spec...}", "source_filename": "my-api.yaml"}'

# Generate test cases
curl -X POST http://localhost:8080/api/v1/generate-tests \
  -H "Content-Type: application/json" \
  -d '{"spec_id": 1, "agent_types": ["Functional-Positive-Agent"]}'

# Run the complete end-to-end flow
curl -X POST http://localhost:8080/api/v1/test-complete-flow \
  -H "Content-Type: application/json" \
  -d '{
    "raw_spec": "{...openapi spec...}",
    "target_environment": "https://api.example.com",
    "source_filename": "my-api.yaml"
  }'
```

## 🏗️ Architecture

### Microservices Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   API Gateway   │────│  Spec Service    │────│ Orchestration       │
│   (Port 8080)   │    │  (Port 8001)     │    │ Service (Port 8002) │
└─────────────────┘    └──────────────────┘    └─────────────────────┘
         │                                               │
         │              ┌──────────────────┐            │
         └──────────────│  Data Service    │────────────┘
                        │  (Port 8004)     │
                        └──────────────────┘
                                 │
                        ┌──────────────────┐
                        │ Execution Service│
                        │  (Port 8003)     │
                        └──────────────────┘
```

### Key Components

1. **Functional-Positive-Agent** (`sentinel_backend/orchestration_service/agents/`)
   - Generates realistic test cases from OpenAPI specifications
   - Uses schema-based data generation with intelligent defaults
   - Creates tests for GET, POST, PUT, PATCH, DELETE operations

2. **Test Execution Engine** (`sentinel_backend/execution_service/`)
   - HTTP client-based test runner
   - Validates response status codes and basic assertions
   - Measures latency and captures response data

3. **Complete End-to-End Flow** (`/api/v1/test-complete-flow`)
   - Single API endpoint that orchestrates the entire workflow
   - Handles spec upload, test generation, suite creation, and execution
   - Returns comprehensive results with summary statistics

## 📊 What Gets Generated

The Functional-Positive-Agent creates test cases that:

- **Use realistic data** based on schema types and property names
- **Include proper headers** (Content-Type, Accept, etc.)
- **Handle path parameters** with generated IDs and values
- **Generate request bodies** for POST/PUT/PATCH operations
- **Set appropriate expectations** for success status codes
- **Include basic assertions** for response validation

### Example Generated Test Case

```json
{
  "endpoint": "/posts/123",
  "method": "GET",
  "description": "Positive test: Get a specific post",
  "headers": {
    "Content-Type": "application/json",
    "Accept": "application/json"
  },
  "query_params": {},
  "expected_status": 200,
  "assertions": [
    {
      "type": "status_code",
      "expected": 200
    },
    {
      "type": "response_schema",
      "schema": {...}
    }
  ]
}
```

## 🔍 API Endpoints

### Core Workflow Endpoints

- `POST /api/v1/test-complete-flow` - **Complete end-to-end testing workflow**
- `GET /health` - Service health check
- `GET /` - Gateway status and available endpoints

### Individual Component Endpoints

- `POST /api/v1/specifications` - Upload API specification
- `GET /api/v1/specifications` - List all specifications
- `POST /api/v1/generate-tests` - Generate test cases using agents
- `GET /api/v1/test-cases` - List generated test cases
- `POST /api/v1/test-suites` - Create test suites
- `POST /api/v1/test-runs` - Execute test runs
- `GET /api/v1/test-runs/{run_id}` - Get test run results

## 📈 Results and Analytics

Test execution provides:

- **Summary Statistics**: Total tests, passed, failed, errors
- **Individual Test Results**: Status, HTTP response code, latency
- **Assertion Failures**: Detailed failure reasons
- **Response Data**: Headers and body content (truncated)
- **Performance Metrics**: Request latency in milliseconds

## 🛠️ Development

### Project Structure

```
sentinel_backend/
├── api_gateway/           # Main entry point and request routing
├── spec_service/          # OpenAPI specification parsing
├── orchestration_service/ # Agent coordination and management
│   └── agents/           # AI testing agents
├── execution_service/     # Test execution and validation
├── data_service/         # Database operations and persistence
├── docker-compose.yml    # Service orchestration
└── pyproject.toml       # Python dependencies
```

### Key Technologies

- **FastAPI** - Web framework for all services
- **Pydantic** - Data validation and serialization
- **httpx** - HTTP client for service communication and test execution
- **PostgreSQL** - Database (configured in docker-compose)
- **Docker** - Containerization and service orchestration

### Adding New Agents

1. Create a new agent class in `orchestration_service/agents/`
2. Inherit from `BaseAgent` and implement the `execute` method
3. Register the agent in `orchestration_service/main.py`
4. Update the API Gateway to support the new agent type

## 🎯 What's Next (Phase 3)

The next phase will add:

- **Functional-Negative-Agent** - Boundary value analysis and error testing
- **Functional-Stateful-Agent** - Multi-step workflow testing
- **Enhanced Reporting UI** - Web interface for test results
- **Better Assertion Engine** - More sophisticated response validation

## 🐛 Troubleshooting

### Services Won't Start

```bash
# Check service logs
docker-compose logs api_gateway
docker-compose logs spec_service
# etc.

# Restart all services
docker-compose down
docker-compose up -d
```

### Demo Script Fails

1. Ensure all services are running: `docker-compose ps`
2. Check service health: `curl http://localhost:8080/health`
3. Verify the target API is accessible: `curl https://jsonplaceholder.typicode.com/posts`

### Port Conflicts

If you have port conflicts, modify the ports in `docker-compose.yml`:

```yaml
services:
  api_gateway:
    ports:
      - "8080:8000"  # Change 8080 to another port
```

## 📝 Example Usage

See `demo_phase2.py` for a complete working example that:

1. Checks service health
2. Uploads a sample OpenAPI specification
3. Generates test cases using the Functional-Positive-Agent
4. Creates a test suite
5. Executes tests against a real API
6. Displays detailed results

The demo uses the JSONPlaceholder API (https://jsonplaceholder.typicode.com) as a test target, making it easy to run without setting up your own API.

---

**🎉 Congratulations!** You now have a working AI-powered API testing platform that can automatically generate and execute realistic test cases from OpenAPI specifications.
