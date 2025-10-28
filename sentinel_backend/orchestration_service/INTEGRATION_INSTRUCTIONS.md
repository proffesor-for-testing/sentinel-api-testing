# AQE Fleet Integration Instructions

## Quick Start

Add these lines to your FastAPI orchestration service:

```python
# In sentinel_backend/orchestration_service/main.py

from sentinel_backend.orchestration_service.aqe_integration import initialize_aqe

# After app creation
app = FastAPI(title="Sentinel Orchestration Service")

# Initialize AQE Fleet
aqe = initialize_aqe(app)
```

That's it! The AQE Fleet is now integrated.

## Verify Integration

```bash
# Start the service
python -m uvicorn sentinel_backend.orchestration_service.main:app --reload

# Test endpoints
curl http://localhost:8002/aqe/agents
curl http://localhost:8002/aqe/stats
```

## Available Endpoints

- `GET /aqe/agents` - List all 19 agents
- `POST /aqe/agents/invoke` - Invoke an agent
- `GET /aqe/tasks/{task_id}` - Check task status
- `WS /aqe/ws/tasks/{task_id}` - Real-time progress

See `/docs/aqe-integration-guide.md` for complete documentation.
