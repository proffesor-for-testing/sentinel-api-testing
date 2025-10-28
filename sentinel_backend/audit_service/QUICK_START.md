# Quick Start Guide - Audit Trail System

## Prerequisites

```bash
# Install dependencies
cd /workspaces/api-testing-agents/sentinel_backend
pip install fastapi uvicorn sqlalchemy psycopg2-binary pydantic python-dateutil
```

## 1. Database Setup

```bash
# Create audit database
createdb sentinel_audit

# Or use existing Sentinel database
export AUDIT_DATABASE_URL="postgresql://sentinel:sentinel@localhost:5432/sentinel_db"
```

## 2. Initialize Schema

```python
# Run this Python script to initialize the database
from audit_service.storage.database_schema import Base, init_timescale
from sqlalchemy import create_engine
import os

database_url = os.getenv('AUDIT_DATABASE_URL', 'postgresql://sentinel:sentinel@localhost:5432/sentinel_db')
engine = create_engine(database_url)

# Create tables
Base.metadata.create_all(engine)

# Initialize TimescaleDB (optional but recommended for production)
try:
    init_timescale(engine)
    print("✅ TimescaleDB features initialized")
except Exception as e:
    print(f"⚠️ TimescaleDB not available: {e}")
    print("   (Tables created successfully without TimescaleDB features)")
```

## 3. Start the Service

### Standalone Mode
```bash
cd /workspaces/api-testing-agents/sentinel_backend
python -m audit_service.main
```

### Integrated Mode
```python
from fastapi import FastAPI
from audit_service.middleware import AuditMiddleware

app = FastAPI()

# Add audit middleware
app.add_middleware(AuditMiddleware)

# Your routes here...
```

## 4. Test the API

```bash
# Health check
curl http://localhost:8088/audit/health

# Query events
curl "http://localhost:8088/audit/events?limit=10"

# Get statistics
curl "http://localhost:8088/audit/events/stats"
```

## 5. Emit Events

```python
from audit_service.emitter import get_emitter
from audit_service.models.events import EventType, UserEvent

emitter = get_emitter()

# Emit a user login event
event = UserEvent(
    event_type=EventType.USER_LOGIN,
    user_id="user-123",
    username="john.doe",
    email="john@example.com",
    action="login",
    ip_address="192.168.1.1"
)

emitter.emit(event)

# Check emitter metrics
print(emitter.get_metrics())
```

## 6. Run Tests

```bash
cd /workspaces/api-testing-agents/sentinel_backend

# Run all audit tests
pytest audit_service/tests/ -v

# Run with coverage
pytest audit_service/tests/ --cov=audit_service --cov-report=html
```

## 7. Frontend Integration

```tsx
import AuditEventList from './components/AuditTrail/AuditEventList';

function AuditPage() {
  return (
    <div>
      <h1>Audit Trail</h1>
      <AuditEventList
        startTime={new Date('2024-01-01')}
        endTime={new Date()}
        eventTypes={['user.login', 'test.executed']}
        searchQuery="success"
      />
    </div>
  );
}
```

## Key Files

### Backend
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/models/events.py` - 43 event types
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/emitter.py` - Event emitter (10K+ events/sec)
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/api.py` - REST API endpoints
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/storage/database_schema.py` - Database schema
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/storage/repository.py` - Data access layer

### Frontend
- `/workspaces/api-testing-agents/sentinel_frontend/src/components/AuditTrail/AuditEventList.tsx` - React component
- `/workspaces/api-testing-agents/sentinel_frontend/src/components/AuditTrail/AuditEventList.css` - Styles

## Environment Variables

```bash
# Event Emitter
export AUDIT_BATCH_SIZE=100
export AUDIT_DEDUP_WINDOW=60
export AUDIT_SECRET_KEY="your-secret-key-here"

# Database
export AUDIT_DATABASE_URL="postgresql://user:pass@host:port/dbname"

# Service
export AUDIT_SERVICE_PORT=8088
```

## Common Operations

### Export Events
```bash
# Export to CSV
curl "http://localhost:8088/audit/events/export?format=csv&start_time=2024-01-01T00:00:00Z" -o events.csv

# Export to JSON
curl "http://localhost:8088/audit/events/export?format=json&start_time=2024-01-01T00:00:00Z" -o events.json
```

### Generate Compliance Report
```bash
curl -X POST "http://localhost:8088/audit/compliance/report" \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "soc2",
    "start_time": "2024-01-01T00:00:00Z",
    "end_time": "2024-12-31T23:59:59Z"
  }'
```

### GDPR Anonymization
```bash
curl -X POST "http://localhost:8088/audit/anonymize?actor=user-123"
```

## Troubleshooting

### Database Connection Issues
```bash
# Check PostgreSQL is running
pg_isready

# Test connection
psql -h localhost -U sentinel -d sentinel_db -c "SELECT 1"
```

### Event Emitter Not Working
```python
from audit_service.emitter import get_emitter

emitter = get_emitter()
print(emitter.get_metrics())  # Check queue size and batches
emitter.flush()  # Force flush pending events
```

### TimescaleDB Not Available
If TimescaleDB is not installed, the system will still work with standard PostgreSQL but without:
- Automatic partitioning
- Compression
- Continuous aggregates

This is acceptable for development/testing but recommended for production.

## Next Steps

1. ✅ Run tests to verify installation
2. ✅ Initialize database schema
3. ✅ Start the service
4. ✅ Integrate with your services
5. ✅ Add frontend component to your UI
6. ✅ Configure retention policies
7. ✅ Set up monitoring

## Support

See:
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/README.md` - Complete documentation
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/IMPLEMENTATION_SUMMARY.md` - Implementation details
- `/workspaces/api-testing-agents/sentinel_backend/audit_service/integration_example.py` - Integration examples
