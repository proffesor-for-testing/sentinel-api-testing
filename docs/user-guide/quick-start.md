# Quick Start Guide

Get up and running with Sentinel in just a few minutes! This guide will walk you through the essential steps to start testing your APIs.

## Prerequisites

Before you begin, ensure you have:
- Docker and Docker Compose installed
- An OpenAPI/Swagger specification file (JSON or YAML)
- Basic familiarity with REST APIs

## Step 1: Start Sentinel

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/proffesor-for-testing/sentinel-api-testing.git
cd sentinel-api-testing/sentinel_backend
```

2. (Optional) Configure LLM Provider:
```bash
# Use the interactive configuration script
cd scripts
./switch_llm.sh claude    # Use Anthropic Claude (default)
# Or choose: openai, gemini, local, none
cd ..
```

3. Start all services:
```bash
docker-compose up --build
```

4. Wait for all services to be ready (typically 30-60 seconds). You'll see log messages indicating each service is running.

### Verify Installation

Open your browser and navigate to:
- **API Gateway**: http://localhost:8000/docs
- **Web Interface**: http://localhost:3000 (if frontend is running)

You should see the interactive API documentation.

## Step 2: Authenticate

### Default Admin Account

Use the default admin credentials to get started:
- **Email**: `admin@sentinel.com`
- **Password**: `admin123`

### Get an Access Token

Using curl:
```bash
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@sentinel.com",
    "password": "admin123"
  }'
```

Save the returned `access_token` for subsequent requests.

### Using the Web Interface

If using the web interface, simply log in with the credentials above. The interface will handle authentication automatically.

## Step 3: Upload Your API Specification

### Via API

```bash
curl -X POST "http://localhost:8000/specifications" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API",
    "version": "1.0.0",
    "spec_data": {
      "openapi": "3.0.0",
      "info": {
        "title": "My API",
        "version": "1.0.0"
      },
      "paths": {
        "/users": {
          "get": {
            "summary": "Get all users",
            "responses": {
              "200": {
                "description": "Success"
              }
            }
          }
        }
      }
    }
  }'
```

### Via Web Interface

1. Navigate to the "Specifications" page
2. Click "Upload New Specification"
3. Select your OpenAPI file or paste the JSON/YAML content
4. Click "Upload"

## Step 4: Run Your First Test

### Quick Test - All Test Types

Run a comprehensive test suite covering functional, security, and performance:

```bash
curl -X POST "http://localhost:8000/test-runs" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "spec_id": 1,
    "test_types": ["functional", "security", "performance"],
    "config": {
      "base_url": "https://api.example.com"
    }
  }'
```

### Functional Test Only

For a quicker initial test, run just functional tests:

```bash
curl -X POST "http://localhost:8000/test-runs" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "spec_id": 1,
    "test_types": ["functional"],
    "config": {
      "base_url": "https://api.example.com"
    }
  }'
```

## Step 5: View Results

### Get Test Run Status

```bash
curl -X GET "http://localhost:8000/test-runs/1" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### View Detailed Results

```bash
curl -X GET "http://localhost:8000/test-runs/1/results" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using the Web Interface

1. Navigate to "Test Runs"
2. Click on your test run to see details
3. Explore:
   - Overall statistics
   - Individual test results
   - Failure analysis
   - Performance metrics

## Step 6: Explore Analytics

### View Historical Trends

Navigate to the Analytics dashboard to see:
- Test success rates over time
- Performance trends
- Security vulnerability patterns
- Anomaly detection alerts

## Quick Examples

### Example 1: Test a Public API

Test the JSONPlaceholder API:

```bash
# Upload specification
curl -X POST "http://localhost:8000/specifications" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "JSONPlaceholder",
    "version": "1.0.0",
    "spec_data": {
      "openapi": "3.0.0",
      "info": {"title": "JSONPlaceholder", "version": "1.0.0"},
      "servers": [{"url": "https://jsonplaceholder.typicode.com"}],
      "paths": {
        "/posts": {
          "get": {"summary": "Get posts", "responses": {"200": {"description": "Success"}}},
          "post": {
            "summary": "Create post",
            "requestBody": {
              "content": {
                "application/json": {
                  "schema": {
                    "type": "object",
                    "properties": {
                      "title": {"type": "string"},
                      "body": {"type": "string"},
                      "userId": {"type": "integer"}
                    }
                  }
                }
              }
            },
            "responses": {"201": {"description": "Created"}}
          }
        }
      }
    }
  }'

# Run tests
curl -X POST "http://localhost:8000/test-runs" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "spec_id": 1,
    "test_types": ["functional"],
    "config": {
      "base_url": "https://jsonplaceholder.typicode.com"
    }
  }'
```

### Example 2: Using the CLI

```bash
# Install the CLI
pip install sentinel-cli

# Configure authentication
sentinel auth login --email admin@sentinel.com --password admin123

# Upload specification
sentinel spec upload ./my-api-spec.yaml

# Run tests
sentinel test run --spec-id 1 --types functional,security

# View results
sentinel test results --run-id 1
```

## Next Steps

Now that you've run your first test:

1. **Learn about test types**: Understand [different testing approaches](./test-types.md)
2. **Interpret results**: Learn to [analyze test reports](./test-results.md)
3. **Set up CI/CD**: Integrate with your [DevOps pipeline](./cicd-integration.md)
4. **Configure advanced tests**: Explore [advanced features](./advanced-features.md)
5. **Configure LLM providers**: Enhance tests with [AI capabilities](../../sentinel_backend/docs/llm-configuration-guide.md)

## Troubleshooting

### Services Not Starting

If services fail to start:
1. Check Docker is running: `docker --version`
2. Ensure ports are available: 8000-8005, 5432, 5672, 15672
3. Check logs: `docker-compose logs [service-name]`

### Authentication Issues

If you can't authenticate:
1. Ensure the auth service is running: `docker-compose ps auth_service`
2. Check you're using the correct credentials
3. Verify the token format in requests

### Test Execution Failures

If tests fail to execute:
1. Verify your API specification is valid
2. Ensure the target API is accessible
3. Check LLM configuration if using AI features: `cd scripts && python validate_llm_config.py`

### LLM Provider Issues

If LLM features aren't working:
1. Verify API keys are set in `.env` or `docker.env`
2. Run validation: `python scripts/validate_llm_config.py`
3. Try switching providers: `./scripts/switch_llm.sh`
4. Use deterministic mode as fallback: `./scripts/switch_llm.sh none`
3. Check the base URL configuration

## Getting Help

- Check the [Troubleshooting Guide](../troubleshooting/index.md)
- Review [Common Issues](../troubleshooting/common-issues.md)
- Search [GitHub Issues](https://github.com/proffesor-for-testing/sentinel-api-testing/issues)

---

🎉 **Congratulations!** You've successfully run your first API test with Sentinel. Continue to the [next guide](./specifications.md) to learn more about managing API specifications.