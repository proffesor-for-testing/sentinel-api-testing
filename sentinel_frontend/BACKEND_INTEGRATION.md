# Backend Integration Guide

## Overview

The Sentinel frontend has been configured to connect to the Orchestration Service (port 8002) for feedback and learning features.

## Files Modified/Created

### Configuration Files

1. **sentinel_frontend/src/services/feedbackService.ts** ✅
   - Updated API base URL to use orchestration service
   - Added environment variable configuration
   - Enhanced error handling for network and CORS issues
   - Added correlation ID generation for request tracing
   - Increased timeout to 30 seconds for backend processing
   - Updated all endpoint paths to use configurable base URL

2. **sentinel_frontend/.env.development** ✅ (Created)
   - Development environment configuration
   - Points to `http://localhost:8002` (orchestration service)
   - Full service port reference guide

3. **sentinel_frontend/.env.docker** ✅ (Updated)
   - Docker environment configuration
   - Points to `http://orchestration_service:8002` (Docker service name)
   - Production-ready settings

### Documentation

4. **sentinel_frontend/docs/API_INTEGRATION.md** ✅ (Created)
   - Comprehensive API integration guide
   - All feedback endpoint specifications
   - Request/response examples with TypeScript types
   - Authentication requirements
   - Error handling documentation
   - Troubleshooting guide

5. **sentinel_backend/orchestration_service/CORS_SETUP.md** ✅ (Created)
   - Step-by-step CORS configuration guide
   - Code examples for orchestration service
   - Testing instructions
   - Security considerations
   - Common issues and solutions

### Utilities

6. **sentinel_frontend/src/utils/connectionHealth.ts** ✅ (Created)
   - Connection health monitoring utility
   - Service status checking functions
   - Automatic health monitoring with listeners
   - Troubleshooting suggestions generator
   - TypeScript interfaces for health status

### Testing Scripts

7. **sentinel_frontend/scripts/test-api-connection.sh** ✅ (Created)
   - Automated connection testing script
   - Tests orchestration service health
   - Verifies CORS configuration
   - Checks response times
   - Tests all backend services

## Environment Variables

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

## Backend Service Ports

| Service | Port | URL (Dev) | URL (Docker) |
|---------|------|-----------|--------------|
| Frontend | 3000 | http://localhost:3000 | http://frontend:3000 |
| API Gateway | 8000 | http://localhost:8000 | http://api_gateway:8000 |
| Spec Service | 8001 | http://localhost:8001 | http://spec_service:8001 |
| **Orchestration** | **8002** | **http://localhost:8002** | **http://orchestration_service:8002** |
| Execution | 8003 | http://localhost:8003 | http://execution_service:8003 |
| Data Service | 8004 | http://localhost:8004 | http://data_service:8004 |
| Auth Service | 8005 | http://localhost:8005 | http://auth_service:8005 |
| Rust Core | 8088 | http://localhost:8088 | http://rust_core:8088 |

## ⚠️ Required Backend Setup

**CRITICAL**: The orchestration service needs CORS configuration to accept requests from the frontend.

### Add to `sentinel_backend/orchestration_service/main.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Sentinel Orchestration Service")

# Add CORS middleware (after app creation, before routes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # Development
        "http://frontend:3000",       # Docker
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

See detailed instructions: `sentinel_backend/orchestration_service/CORS_SETUP.md`

## Testing the Integration

### 1. Automated Test Script

```bash
cd sentinel_frontend
./scripts/test-api-connection.sh
```

This tests:
- Orchestration service health
- Feedback endpoint availability
- CORS configuration
- Response times
- All backend services

### 2. Manual Testing - Development

```bash
# Terminal 1: Start orchestration service
cd sentinel_backend
python -m uvicorn orchestration_service.main:app --port 8002

# Terminal 2: Start frontend
cd sentinel_frontend
npm start

# Open browser: http://localhost:3000
# Check browser console for connection status
```

### 3. Manual Testing - Docker

```bash
# Start all services
make start

# Check service status
make status

# View orchestration service logs
docker-compose logs -f orchestration_service

# Test endpoint
curl http://localhost:8002/api/v1/feedback/statistics
```

## API Endpoints

All feedback endpoints are on the orchestration service (`/api/v1/feedback`):

- `POST /api/v1/feedback/test-case` - Submit test case feedback
- `POST /api/v1/feedback/test-suite` - Submit test suite feedback
- `GET /api/v1/feedback/statistics` - Get feedback statistics
- `GET /api/v1/feedback/test-case/{test_id}` - Get test case feedback
- `GET /api/v1/feedback/patterns/{pattern_id}` - Get pattern feedback

See full documentation: `docs/API_INTEGRATION.md`

## Error Handling

The frontend includes comprehensive error handling:

### Network Errors
```
Unable to connect to backend service.
→ Check if orchestration service is running on port 8002
```

### CORS Errors
```
CORS error: Backend needs CORS configuration
→ Add CORSMiddleware to orchestration service
```

### Rate Limiting
```
Rate limit exceeded. Maximum 10 requests per minute.
→ Wait 60 seconds before retrying
```

## Connection Health Monitoring

Use the connection health utility to monitor backend status:

```typescript
import { checkServiceHealth, connectionHealthMonitor } from './utils/connectionHealth';

// One-time check
const health = await checkServiceHealth();
console.log('Service health:', health);

// Continuous monitoring
connectionHealthMonitor.start(30000); // Check every 30 seconds
connectionHealthMonitor.addListener((health) => {
  console.log('Health update:', health);
});
```

## Troubleshooting

### Issue: Cannot connect to orchestration service

**Symptoms:**
- Network error in browser console
- "ECONNREFUSED" or "NETWORK_ERROR"

**Solutions:**
1. Verify orchestration service is running:
   ```bash
   curl http://localhost:8002/
   ```
2. Check if port 8002 is in use:
   ```bash
   lsof -i :8002
   ```
3. Review service logs for errors:
   ```bash
   tail -f sentinel_backend/logs/orchestration.log
   ```

### Issue: CORS error in browser

**Symptoms:**
- "Access to fetch blocked by CORS policy"
- "No 'Access-Control-Allow-Origin' header"

**Solutions:**
1. Add CORS middleware to orchestration service (see CORS_SETUP.md)
2. Verify frontend origin is in `allow_origins` list
3. Test CORS headers:
   ```bash
   curl -i -H "Origin: http://localhost:3000" http://localhost:8002/
   ```

### Issue: 401 Unauthorized

**Symptoms:**
- All requests return 401 status
- "Authentication required" error

**Solutions:**
1. Check auth token is present in localStorage:
   ```javascript
   localStorage.getItem('authToken')
   ```
2. Verify token hasn't expired
3. Login again to get new token

### Issue: 404 Not Found on feedback endpoints

**Symptoms:**
- `/api/v1/feedback/*` returns 404
- Other endpoints work fine

**Solutions:**
1. Verify feedback router is registered in main.py:
   ```python
   app.include_router(feedback_router)
   ```
2. Check feedback_router import is correct
3. Restart orchestration service

## Performance Considerations

- **Timeout**: 30 seconds for all requests (configurable in feedbackService.ts)
- **Retry Logic**: 3 automatic retries with exponential backoff
- **Rate Limiting**: 10 requests per minute per user
- **Correlation IDs**: All requests include unique ID for tracing

## Security Features

- ✅ JWT authentication required for all endpoints
- ✅ Rate limiting to prevent abuse
- ✅ CORS restrictions to allowed origins
- ✅ Input validation on all payloads
- ✅ SQL injection protection
- ✅ XSS protection

## Next Steps

1. ✅ Update feedbackService.ts with orchestration service URL
2. ✅ Create environment configuration files
3. ⚠️ **Add CORS middleware to orchestration service** (REQUIRED)
4. ✅ Document API integration
5. ✅ Create connection testing utilities
6. 🔲 Test frontend-backend integration
7. 🔲 Verify all feedback features work end-to-end

## Acceptance Criteria

- [x] Frontend connects to orchestration service (port 8002)
- [x] Environment variables configured for dev and Docker
- [x] Error messages show clear connection issues
- [x] Correlation IDs added to all requests
- [x] Retry logic implemented for transient failures
- [x] CORS configuration documented
- [x] Connection health monitoring available
- [x] Automated testing script created
- [ ] CORS middleware added to backend (REQUIRED BEFORE USE)
- [ ] End-to-end testing completed

## References

- Backend Feedback Endpoints: `sentinel_backend/orchestration_service/api/feedback_endpoints.py`
- CORS Setup Guide: `sentinel_backend/orchestration_service/CORS_SETUP.md`
- API Integration Docs: `sentinel_frontend/docs/API_INTEGRATION.md`
- Connection Health Utility: `sentinel_frontend/src/utils/connectionHealth.ts`
