# API Reference - Sentinel API Testing Platform

Complete API documentation for the Sentinel platform with examples in multiple programming languages.

## Base URL

```
Production: https://api.sentinel.example.com
Staging: https://staging-api.sentinel.example.com
Local: http://localhost:8000
```

## Authentication

All API requests require authentication using JWT tokens.

### Obtaining a Token

```bash
POST /auth/login
```

**Request:**
```json
{
  "email": "user@example.com",
  "password": "your-password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 86400,
  "user": {
    "id": 1,
    "email": "user@example.com",
    "role": "admin"
  }
}
```

### Using the Token

Include the token in the Authorization header:

```bash
Authorization: Bearer YOUR_ACCESS_TOKEN
```

## API Endpoints

### Authentication Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | User login |
| POST | `/auth/logout` | User logout |
| POST | `/auth/refresh` | Refresh token |
| POST | `/auth/register` | Register new user |
| GET | `/auth/me` | Get current user |
| PUT | `/auth/password` | Change password |

### Specification Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/specifications` | List all specifications |
| POST | `/specifications` | Create new specification |
| GET | `/specifications/{id}` | Get specification details |
| PUT | `/specifications/{id}` | Update specification |
| DELETE | `/specifications/{id}` | Delete specification |
| POST | `/specifications/{id}/validate` | Validate specification |
| GET | `/specifications/{id}/endpoints` | List specification endpoints |

### Test Execution Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/test-runs` | Create new test run |
| GET | `/test-runs` | List test runs |
| GET | `/test-runs/{id}` | Get test run details |
| PUT | `/test-runs/{id}/cancel` | Cancel test run |
| GET | `/test-runs/{id}/results` | Get test results |
| GET | `/test-runs/{id}/logs` | Get test logs |
| POST | `/test-runs/{id}/rerun` | Rerun failed tests |

### Data & Analytics Service

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/analytics/trends` | Get historical trends |
| GET | `/analytics/metrics` | Get test metrics |
| GET | `/analytics/anomalies` | Get detected anomalies |
| GET | `/analytics/insights` | Get AI-generated insights |
| POST | `/analytics/compare` | Compare test runs |
| GET | `/analytics/export` | Export analytics data |

## Detailed Endpoint Documentation

### 1. Create Specification

**Endpoint:** `POST /specifications`

**Description:** Upload a new API specification for testing.

**Request Body:**
```json
{
  "name": "User Management API",
  "version": "1.0.0",
  "description": "API for managing users",
  "tags": ["users", "authentication"],
  "spec_data": {
    "openapi": "3.0.0",
    "info": {
      "title": "User Management API",
      "version": "1.0.0"
    },
    "servers": [
      {
        "url": "https://api.example.com"
      }
    ],
    "paths": {
      "/users": {
        "get": {
          "summary": "List users",
          "responses": {
            "200": {
              "description": "Success",
              "content": {
                "application/json": {
                  "schema": {
                    "type": "array",
                    "items": {
                      "$ref": "#/components/schemas/User"
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "components": {
      "schemas": {
        "User": {
          "type": "object",
          "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
            "email": {"type": "string", "format": "email"}
          }
        }
      }
    }
  }
}
```

**Response:**
```json
{
  "id": 1,
  "name": "User Management API",
  "version": "1.0.0",
  "description": "API for managing users",
  "tags": ["users", "authentication"],
  "status": "active",
  "created_at": "2025-01-08T10:00:00Z",
  "updated_at": "2025-01-08T10:00:00Z",
  "validation": {
    "status": "valid",
    "warnings": [],
    "info": {
      "endpoints": 1,
      "schemas": 1
    }
  }
}
```

**Code Examples:**

<details>
<summary>Python</summary>

```python
import requests
import json

url = "http://localhost:8000/specifications"
headers = {
    "Authorization": "Bearer YOUR_TOKEN",
    "Content-Type": "application/json"
}

spec_data = {
    "name": "User Management API",
    "version": "1.0.0",
    "spec_data": {
        # OpenAPI specification
    }
}

response = requests.post(url, headers=headers, json=spec_data)
print(response.json())
```
</details>

<details>
<summary>JavaScript</summary>

```javascript
const axios = require('axios');

const specData = {
  name: "User Management API",
  version: "1.0.0",
  spec_data: {
    // OpenAPI specification
  }
};

axios.post('http://localhost:8000/specifications', specData, {
  headers: {
    'Authorization': 'Bearer YOUR_TOKEN',
    'Content-Type': 'application/json'
  }
})
.then(response => {
  console.log(response.data);
})
.catch(error => {
  console.error(error);
});
```
</details>

<details>
<summary>cURL</summary>

```bash
curl -X POST "http://localhost:8000/specifications" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "User Management API",
    "version": "1.0.0",
    "spec_data": {
      "openapi": "3.0.0",
      "info": {"title": "User Management API", "version": "1.0.0"},
      "paths": {}
    }
  }'
```
</details>

### 2. Create Test Run

**Endpoint:** `POST /test-runs`

**Description:** Start a new test execution for a specification.

**Request Body:**
```json
{
  "spec_id": 1,
  "test_types": ["functional", "security", "performance"],
  "config": {
    "base_url": "https://api.example.com",
    "environment": "staging",
    "parallel": true,
    "timeout": 300,
    "functional": {
      "positive": true,
      "negative": true,
      "stateful": true
    },
    "security": {
      "auth": true,
      "injection": {
        "enabled": true,
        "aggressiveness": "medium"
      }
    },
    "performance": {
      "users": 100,
      "duration": "10m",
      "ramp_up": "1m"
    }
  },
  "tags": ["regression", "nightly"]
}
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "spec_id": 1,
  "status": "running",
  "test_types": ["functional", "security", "performance"],
  "config": {
    // Configuration details
  },
  "created_at": "2025-01-08T10:00:00Z",
  "started_at": "2025-01-08T10:00:01Z",
  "estimated_completion": "2025-01-08T10:15:00Z",
  "progress": {
    "total": 150,
    "completed": 0,
    "passed": 0,
    "failed": 0
  }
}
```

**Code Examples:**

<details>
<summary>Python</summary>

```python
import requests

def create_test_run(spec_id, test_types, config):
    url = "http://localhost:8000/test-runs"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "spec_id": spec_id,
        "test_types": test_types,
        "config": config
    }
    
    response = requests.post(url, headers=headers, json=payload)
    return response.json()

# Example usage
test_run = create_test_run(
    spec_id=1,
    test_types=["functional", "security"],
    config={
        "base_url": "https://api.example.com",
        "environment": "staging"
    }
)
print(f"Test run started: {test_run['id']}")
```
</details>

### 3. Get Test Results

**Endpoint:** `GET /test-runs/{id}/results`

**Description:** Retrieve detailed results for a test run.

**Query Parameters:**
- `page` (integer): Page number for pagination
- `limit` (integer): Number of results per page
- `status` (string): Filter by status (passed, failed, skipped)
- `test_type` (string): Filter by test type

**Response:**
```json
{
  "test_run_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "summary": {
    "total": 150,
    "passed": 140,
    "failed": 8,
    "skipped": 2,
    "duration": 845.23,
    "success_rate": 93.33
  },
  "results": [
    {
      "id": 1,
      "test_case": {
        "name": "GET /users - Valid request",
        "type": "functional-positive",
        "endpoint": "/users",
        "method": "GET"
      },
      "status": "passed",
      "duration": 0.234,
      "assertions": [
        {
          "type": "status_code",
          "expected": 200,
          "actual": 200,
          "passed": true
        },
        {
          "type": "response_time",
          "expected": "<1000ms",
          "actual": "234ms",
          "passed": true
        }
      ]
    },
    {
      "id": 2,
      "test_case": {
        "name": "POST /users - SQL Injection attempt",
        "type": "security-injection",
        "endpoint": "/users",
        "method": "POST"
      },
      "status": "failed",
      "duration": 0.456,
      "error": {
        "type": "vulnerability_detected",
        "message": "Potential SQL injection vulnerability detected",
        "severity": "high",
        "details": {
          "payload": "'; DROP TABLE users; --",
          "response": "Database error occurred",
          "recommendation": "Implement parameterized queries"
        }
      }
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total_pages": 8,
    "total_items": 150
  }
}
```

### 4. Get Analytics Trends

**Endpoint:** `GET /analytics/trends`

**Description:** Retrieve historical trend data for test executions.

**Query Parameters:**
- `spec_id` (integer): Filter by specification
- `start_date` (string): Start date (ISO 8601)
- `end_date` (string): End date (ISO 8601)
- `interval` (string): Aggregation interval (hour, day, week, month)
- `metrics` (array): Metrics to include

**Response:**
```json
{
  "spec_id": 1,
  "period": {
    "start": "2025-01-01T00:00:00Z",
    "end": "2025-01-08T00:00:00Z",
    "interval": "day"
  },
  "trends": [
    {
      "date": "2025-01-01",
      "metrics": {
        "total_runs": 5,
        "success_rate": 95.2,
        "avg_duration": 523.4,
        "failed_tests": 12,
        "p95_response_time": 890
      }
    },
    {
      "date": "2025-01-02",
      "metrics": {
        "total_runs": 6,
        "success_rate": 93.8,
        "avg_duration": 545.2,
        "failed_tests": 15,
        "p95_response_time": 920
      }
    }
  ],
  "insights": {
    "trend_direction": "declining",
    "anomalies_detected": 2,
    "predicted_next_value": 92.5,
    "recommendations": [
      "Success rate showing downward trend",
      "Response times increased by 8% this week",
      "Consider investigating failing authentication tests"
    ]
  }
}
```

## Error Responses

All endpoints follow a consistent error response format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": {
      "field": "spec_id",
      "reason": "Specification not found"
    },
    "timestamp": "2025-01-08T10:00:00Z",
    "correlation_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `AUTHENTICATION_REQUIRED` | 401 | Missing or invalid authentication |
| `PERMISSION_DENIED` | 403 | Insufficient permissions |
| `RESOURCE_NOT_FOUND` | 404 | Requested resource not found |
| `VALIDATION_ERROR` | 400 | Invalid request parameters |
| `CONFLICT` | 409 | Resource conflict |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Internal server error |

## Rate Limiting

API requests are rate limited based on your subscription tier:

| Tier | Requests/Hour | Concurrent Tests | Data Retention |
|------|---------------|------------------|----------------|
| Free | 100 | 1 | 7 days |
| Starter | 1,000 | 5 | 30 days |
| Professional | 10,000 | 20 | 90 days |
| Enterprise | Unlimited | Unlimited | Unlimited |

Rate limit information is included in response headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1609459200
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Webhook Configuration

```json
POST /webhooks
{
  "url": "https://your-app.com/webhook",
  "events": ["test.completed", "test.failed"],
  "secret": "your-webhook-secret"
}
```

### Webhook Payload

```json
{
  "event": "test.completed",
  "timestamp": "2025-01-08T10:00:00Z",
  "data": {
    "test_run_id": "550e8400-e29b-41d4-a716-446655440000",
    "spec_id": 1,
    "status": "completed",
    "summary": {
      "total": 150,
      "passed": 140,
      "failed": 10
    }
  },
  "signature": "sha256=..."
}
```

## SDK Libraries

Official SDK libraries are available for popular languages:

- **Python**: `pip install sentinel-sdk`
- **JavaScript/Node.js**: `npm install @sentinel/sdk`
- **Go**: `go get github.com/sentinel/sdk-go`
- **Java**: Maven/Gradle dependency available
- **Ruby**: `gem install sentinel-sdk`

### Python SDK Example

```python
from sentinel_sdk import SentinelClient

client = SentinelClient(
    api_key="YOUR_API_KEY",
    base_url="https://api.sentinel.example.com"
)

# Upload specification
spec = client.specifications.create(
    name="My API",
    spec_file="openapi.yaml"
)

# Run tests
test_run = client.test_runs.create(
    spec_id=spec.id,
    test_types=["functional", "security"]
)

# Wait for completion
test_run.wait_for_completion()

# Get results
results = test_run.get_results()
print(f"Success rate: {results.success_rate}%")
```

## API Versioning

The API uses URL versioning. The current version is `v1`.

```
https://api.sentinel.example.com/v1/specifications
```

### Version Deprecation Policy

- New versions are released with 6 months notice
- Deprecated versions are supported for 12 months
- Breaking changes are only introduced in major versions

## Support

For API support:
- Documentation: https://docs.sentinel.example.com
- Status Page: https://status.sentinel.example.com
- Support Email: api-support@sentinel.example.com
- Developer Forum: https://forum.sentinel.example.com

---

← [Back to Documentation](../index.md) | [Next: Deployment Guide](../deployment/index.md) →