# CORS Configuration for Orchestration Service

## Required Setup

The Orchestration Service needs CORS (Cross-Origin Resource Sharing) middleware to allow the React frontend to make API requests.

## Implementation

Add this code to `/workspaces/api-testing-agents/sentinel_backend/orchestration_service/main.py`:

### 1. Import CORS Middleware

Add at the top of the file with other imports:

```python
from fastapi.middleware.cors import CORSMiddleware
```

### 2. Add CORS Middleware Configuration

Add this **immediately after** creating the FastAPI app instance (after `app = FastAPI(...)`):

```python
# CORS Configuration for Frontend Access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # Development frontend
        "http://127.0.0.1:3000",     # Alternative localhost
        "http://frontend:3000",       # Docker frontend service
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Correlation-ID",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
    expose_headers=["X-Correlation-ID"],
    max_age=3600,  # Cache preflight requests for 1 hour
)
```

## Complete Example

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
# ... other imports ...

app = FastAPI(title="Sentinel Orchestration Service")

# CORS Configuration - Must be added BEFORE routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # Development
        "http://127.0.0.1:3000",     # Alternative localhost
        "http://frontend:3000",       # Docker
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Correlation-ID",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
    expose_headers=["X-Correlation-ID"],
    max_age=3600,
)

# Instrument for Prometheus
Instrumentator().instrument(app).expose(app)

# Set up Jaeger tracing
setup_tracing(app, "orchestration-service")

# ... rest of the code ...
```

## Why This Is Required

1. **Browser Security**: Browsers block cross-origin requests by default for security
2. **Frontend-Backend Communication**: Frontend (port 3000) needs to call backend (port 8002)
3. **Authentication**: `allow_credentials=True` allows sending auth tokens
4. **Correlation IDs**: Custom headers need explicit permission

## Testing CORS Configuration

After adding CORS middleware, test with:

```bash
# Test CORS preflight request
curl -i -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,Authorization" \
  http://localhost:8002/api/v1/feedback/test-case

# Expected response includes:
# Access-Control-Allow-Origin: http://localhost:3000
# Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH
# Access-Control-Allow-Headers: Content-Type, Authorization, X-Correlation-ID, ...
```

Or use the automated test script:

```bash
cd sentinel_frontend
./scripts/test-api-connection.sh
```

## Common Issues

### Issue: CORS headers not present
**Solution**: Ensure middleware is added BEFORE any routes or other middleware

### Issue: Credentials not allowed
**Solution**: Check `allow_credentials=True` is set

### Issue: Header not allowed
**Solution**: Add the header name to `allow_headers` list

### Issue: Docker CORS not working
**Solution**: Add Docker service name to `allow_origins`: `"http://frontend:3000"`

## Production Configuration

For production, use environment variable for allowed origins:

```python
import os

ALLOWED_ORIGINS = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:3000,http://frontend:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # ... rest of config ...
)
```

## Security Considerations

1. **Never use `allow_origins=["*"]`** in production - always specify exact origins
2. **Validate origins** against a whitelist
3. **Use HTTPS** in production: `https://yourdomain.com`
4. **Limit methods** to only what's needed
5. **Monitor CORS logs** for suspicious activity

## Verification Checklist

- [ ] CORS middleware imported
- [ ] Middleware added after app creation, before routes
- [ ] Development origin included: `http://localhost:3000`
- [ ] Docker origin included: `http://frontend:3000`
- [ ] `allow_credentials=True` set
- [ ] All required headers in `allow_headers`
- [ ] `X-Correlation-ID` in `expose_headers`
- [ ] Tested with frontend connection
- [ ] No CORS errors in browser console

## References

- [FastAPI CORS Documentation](https://fastapi.tiangolo.com/tutorial/cors/)
- [MDN CORS Guide](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [Frontend API Integration](../../sentinel_frontend/docs/API_INTEGRATION.md)
