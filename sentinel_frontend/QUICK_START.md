# Quick Start - Frontend Backend Integration

## 🚀 One-Line Summary

Frontend now connects to **Orchestration Service (port 8002)** for feedback endpoints instead of API Gateway (port 8000).

## ⚠️ Required Action

**Add CORS to orchestration service** before frontend can connect:

```python
# In sentinel_backend/orchestration_service/main.py
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Correlation-ID"],
)
```

📖 **Full guide**: `sentinel_backend/orchestration_service/CORS_SETUP.md`

## ✅ What Changed

| Item | Before | After |
|------|--------|-------|
| API Base URL (Dev) | `http://localhost:8000` | `http://localhost:8002` |
| API Base URL (Docker) | `http://api_gateway:8000` | `http://orchestration_service:8002` |
| Feedback Endpoints | Not connected | `/api/v1/feedback/*` |
| Error Handling | Basic | Network + CORS + Retry |
| Request Tracing | None | Correlation IDs |
| Timeout | 10 seconds | 30 seconds |

## 🧪 Quick Test

```bash
# Test connection
cd sentinel_frontend
./scripts/test-api-connection.sh

# Start services
cd sentinel_backend
python -m uvicorn orchestration_service.main:app --port 8002

# Start frontend (new terminal)
cd sentinel_frontend
npm start
```

## 📁 Key Files

- **Config**: `.env.development`, `.env.docker`
- **Service**: `src/services/feedbackService.ts`
- **Docs**: `docs/API_INTEGRATION.md`
- **CORS**: `../sentinel_backend/orchestration_service/CORS_SETUP.md`
- **Health**: `src/utils/connectionHealth.ts`
- **Test**: `scripts/test-api-connection.sh`

## 🎯 Acceptance Criteria

- [x] Frontend configured for port 8002
- [x] Environment variables set
- [x] Error handling enhanced
- [x] Documentation complete
- [ ] **CORS added to backend** ⚠️
- [ ] Connection tested successfully

## 📞 Support

If issues occur:
1. Check `BACKEND_INTEGRATION.md` for troubleshooting
2. Run `./scripts/test-api-connection.sh` for diagnostics
3. Review `docs/API_INTEGRATION.md` for API details
