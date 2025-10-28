# Quick Deployment Guide - Learning Integration

**Time Required:** 25 minutes
**Current Status:** 85% complete, 3 tasks remaining

---

## Prerequisites

- Docker and Docker Compose installed
- PostgreSQL container running
- All code changes from fix agents applied

---

## Deployment Steps

### Step 1: Install Dependencies (15 minutes)

```bash
cd /workspaces/api-testing-agents/sentinel_backend

# Install required packages
pip install sqlalchemy==2.0.23
pip install asyncpg==0.29.0
pip install structlog==23.2.0
pip install aiofiles==23.2.1

# Verify installation
python -c "import sqlalchemy; print(f'SQLAlchemy {sqlalchemy.__version__}')"
python -c "import asyncpg; print('asyncpg installed')"
python -c "import structlog; print('structlog installed')"
```

**Expected Output:**
```
SQLAlchemy 2.0.23
asyncpg installed
structlog installed
```

---

### Step 2: Run Database Migrations (5 minutes)

```bash
cd /workspaces/api-testing-agents/sentinel_backend

# Run migrations
alembic upgrade head

# Verify tables created
docker exec sentinel_postgres psql -U sentinel -d sentinel_db -c "\dt" | grep feedback
```

**Expected Output:**
```
test_case_feedback
test_suite_feedback
feedback_learning_queue
test_case_patterns
```

---

### Step 3: Add CORS Middleware (5 minutes)

Edit `sentinel_backend/orchestration_service/main.py`:

Add this import at the top:
```python
from fastapi.middleware.cors import CORSMiddleware
```

Add this middleware after `app = FastAPI()`:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://frontend:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Correlation-ID"],
)
```

---

## Verification

### Test API Endpoints

```bash
# 1. Start orchestration service
cd sentinel_backend
python -m uvicorn orchestration_service.main:app --port 8002 --reload

# 2. In another terminal, test endpoints
curl http://localhost:8002/docs  # Should show Swagger UI
curl http://localhost:8002/api/v1/feedback/statistics  # Should return JSON

# 3. Test feedback submission
curl -X POST http://localhost:8002/api/v1/feedback/test-case \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d '{
    "test_case_id": "test-123",
    "rating": 5,
    "feedback_type": "quality",
    "helpful": true,
    "issue_found": false,
    "comment": "Excellent test!"
  }'
```

**Expected Response:**
```json
{
  "feedback_id": "uuid-here",
  "test_case_id": "test-123",
  "rating": 5,
  "learning_queued": true,
  "message": "Feedback received and queued for learning"
}
```

### Verify Database

```bash
# Check feedback saved
docker exec sentinel_postgres psql -U sentinel -d sentinel_db \
  -c "SELECT id, rating, helpful FROM test_case_feedback LIMIT 5;"

# Check queue entry
docker exec sentinel_postgres psql -U sentinel -d sentinel_db \
  -c "SELECT id, processing_status FROM feedback_learning_queue LIMIT 5;"
```

---

## Docker Deployment

```bash
# 1. Rebuild containers with new dependencies
docker-compose build orchestration_service frontend

# 2. Start all services
docker-compose up -d

# 3. Check service health
docker-compose ps
curl http://localhost:8002/health

# 4. Run migrations in Docker
docker-compose exec orchestration_service alembic upgrade head

# 5. Test endpoints
curl http://localhost:8002/api/v1/feedback/statistics
```

---

## Troubleshooting

### Issue: "Module 'sqlalchemy' not found"
**Solution:** Run `pip install sqlalchemy asyncpg` in the backend container

### Issue: "Table 'test_case_feedback' doesn't exist"
**Solution:** Run `alembic upgrade head` to create tables

### Issue: "CORS error in browser"
**Solution:** Verify CORS middleware is added to main.py

### Issue: "404 on /api/v1/feedback/*"
**Solution:** Verify routers are registered in main.py

---

## Next Steps (Optional)

### Complete Agent Integration (30 minutes)

```bash
# Apply same modifications to final 2 agents
# Files: sentinel_backend/agents/security_injection_agent.py
#        sentinel_backend/agents/performance_planner_agent.py

# Follow pattern from: agents/functional_negative_agent.py
```

### End-to-End Test (15 minutes)

```bash
# Run integration test suite
cd sentinel_backend
pytest tests/integration/test_real_learning_integration.py -v
```

---

## Success Checklist

- [ ] Dependencies installed
- [ ] Migrations run successfully
- [ ] CORS middleware added
- [ ] API endpoints accessible
- [ ] Feedback saves to database
- [ ] Queue entries created
- [ ] Docker containers healthy
- [ ] Frontend connects to backend

**When all checked:** ✅ **READY FOR PRODUCTION**

---

**Total Time:** 25 minutes
**Difficulty:** Easy
**Risk:** Low

For detailed documentation, see:
- `docs/POST_FIX_VERIFICATION_REPORT.md`
- `docs/FIXES_COMPLETE_SUMMARY.md`
