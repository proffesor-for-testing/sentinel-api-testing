# Sentinel Frontend - Backend API Integration

## Overview

The Sentinel frontend integrates with multiple backend services. The feedback system connects to the **Orchestration Service** (port 8002) for user feedback and learning features.

## Service Architecture

```
Frontend (Port 3000)
    │
    ├─→ API Gateway (8000)           - General API operations
    ├─→ Orchestration Service (8002) - Feedback & Learning ⭐
    ├─→ Auth Service (8005)          - Authentication
    └─→ Spec Service (8001)          - API specifications
```

## Configuration Files

### Development (.env.development)
```env
REACT_APP_API_BASE_URL=http://localhost:8002
REACT_APP_FEEDBACK_ENDPOINT=/api/v1/feedback
```

### Docker (.env.docker)
```env
REACT_APP_API_BASE_URL=http://orchestration_service:8002
REACT_APP_FEEDBACK_ENDPOINT=/api/v1/feedback
```

## Backend CORS Configuration Required

⚠️ **IMPORTANT**: The Orchestration Service must enable CORS for frontend origins.

### Required Setup in orchestration_service/main.py:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Sentinel Orchestration Service")

# CORS Configuration - Add this before any routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # Development
        "http://frontend:3000",       # Docker
        "http://127.0.0.1:3000",     # Alternative localhost
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Correlation-ID",
        "Accept"
    ],
    expose_headers=["X-Correlation-ID"]
)
```

## Feedback API Endpoints

All feedback endpoints are prefixed with `/api/v1/feedback`:

### POST /api/v1/feedback/test-case
Submit feedback for a single test case.

**Request:**
```typescript
{
  test_case_id: string;
  rating: number;          // 1-5
  feedback_type: "quality" | "accuracy" | "coverage" | "performance" | "false_positive" | "false_negative";
  is_helpful: boolean;
  found_issue: boolean;
  comment?: string;
  execution_time_ms?: number;
}
```

**Response:**
```typescript
{
  success: boolean;
  feedback_id: string;
  test_case_id: string;
  learning_status: string;
  message: string;
  queued_for_learning: boolean;
}
```

### POST /api/v1/feedback/test-suite
Submit feedback for an entire test suite.

**Request:**
```typescript
{
  suite_id: string;
  spec_id: string;
  overall_rating: number;   // 1-5
  quality_score: number;    // 1-5
  coverage_score: number;   // 1-5
  accuracy_score: number;   // 1-5
  speed_score: number;      // 1-5
  coverage_gaps: Array<{
    category: string;
    description: string;
    priority: string;
  }>;
  excellent_tests: string[];
  false_positives: string[];
  comment?: string;
}
```

**Response:**
```typescript
{
  success: boolean;
  feedback_id: string;
  suite_id: string;
  learning_status: string;
  message: string;
  queued_for_learning: boolean;
  gaps_queued_for_generation: number;
}
```

### GET /api/v1/feedback/statistics
Get feedback and learning statistics.

**Response:**
```typescript
{
  total_feedback_count: number;
  average_rating: number;
  helpful_percentage: number;
  issue_found_percentage: number;
  coverage_gaps_identified: number;
  coverage_gaps_resolved: number;
  pattern_count: number;
  average_confidence: number;
  feedback_by_type: Record<string, number>;
  feedback_trend: Array<{
    date: string;
    count: number;
    avg_rating: number;
  }>;
}
```

### GET /api/v1/feedback/test-case/{test_id}
Get all feedback for a specific test case.

**Response:**
```typescript
{
  success: boolean;
  test_case_id: string;
  feedback_count: number;
  feedback: Array<{
    feedback_id: string;
    test_case_id: string;
    rating: number;
    feedback_type: string;
    is_helpful: boolean;
    found_issue: boolean;
    comment: string;
    created_at: string;
    learning_applied: boolean;
    pattern_updates: string[];
  }>;
}
```

### GET /api/v1/feedback/patterns/{pattern_id}
Get feedback summary for a learned pattern.

**Response:**
```typescript
{
  success: boolean;
  pattern_feedback: {
    pattern_id: string;
    usage_count: number;
    success_count: number;
    failure_count: number;
    average_rating: number;
    confidence: number;
    last_updated: string;
    feedback_count: number;
    recent_feedback: Array<{
      rating: number;
      comment: string;
      created_at: string;
    }>;
  };
}
```

## Authentication

All feedback endpoints require authentication via JWT token:

```typescript
headers: {
  'Authorization': 'Bearer <jwt_token>',
  'Content-Type': 'application/json'
}
```

Token should be stored in localStorage with key `authToken`.

## Error Handling

The frontend includes comprehensive error handling:

### Network Errors
```typescript
{
  message: "Unable to connect to backend service. Please check if the orchestration service is running.",
  code: "NETWORK_ERROR",
  details: {
    url: string,
    baseURL: string,
    suggestion: "Verify orchestration service is running on port 8002"
  }
}
```

### CORS Errors
```typescript
{
  message: "CORS error: Backend needs CORS configuration for frontend origin",
  code: "CORS_ERROR",
  details: {
    suggestion: "Add CORSMiddleware to orchestration service"
  }
}
```

### Rate Limiting
- **Limit**: 10 requests per minute per user
- **Status Code**: 429 Too Many Requests
- **Response**: "Rate limit exceeded. Maximum 10 requests per minute."

## Request Tracing

All requests include a correlation ID for tracing:

```typescript
headers: {
  'X-Correlation-ID': 'frontend-{timestamp}-{random}'
}
```

The backend echoes this ID back in the response headers for log correlation.

## Retry Logic

The feedback service includes automatic retry for transient failures:

- **Max Retries**: 3
- **Retry Delay**: Exponential backoff (1s, 2s, 4s)
- **Retryable Errors**: Network errors (no response) and 5xx server errors

## Testing Connection

### Development
1. Start orchestration service: `cd sentinel_backend && python -m uvicorn orchestration_service.main:app --port 8002`
2. Verify service: `curl http://localhost:8002/`
3. Start frontend: `cd sentinel_frontend && npm start`
4. Check browser console for connection status

### Docker
1. Start all services: `make start`
2. Check service health: `make status`
3. View logs: `docker-compose logs orchestration_service`

## Troubleshooting

### Connection Refused
- Verify orchestration service is running on port 8002
- Check if port is already in use: `lsof -i :8002`
- Review service logs for startup errors

### CORS Errors
- Verify CORSMiddleware is configured in orchestration service
- Check frontend origin is in `allow_origins` list
- Confirm browser is making requests from correct origin

### 401 Unauthorized
- Verify auth token is present in localStorage
- Check token hasn't expired
- Ensure token is valid for orchestration service

### 404 Not Found
- Verify endpoint path matches `/api/v1/feedback/*`
- Check router is registered in main.py: `app.include_router(feedback_router)`
- Confirm backend service is fully initialized

## Performance Considerations

- **Timeout**: 30 seconds for all requests
- **Concurrent Requests**: Debounced to prevent duplicate submissions
- **Caching**: Statistics cached for 60 seconds
- **Batch Operations**: Suite feedback includes multiple test cases

## Security Notes

- All endpoints require authentication
- Rate limiting prevents abuse
- CORS restricts origins
- Input validation on all payloads
- SQL injection protection via parameterized queries
- XSS protection via input sanitization
