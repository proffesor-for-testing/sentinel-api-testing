# Audit Trail System Documentation

## Overview

The Sentinel Audit Trail System provides comprehensive event-driven auditing for complete traceability and regulatory compliance (SOC2, GDPR, HIPAA).

## Architecture

### Components

1. **Event Models** - Type-safe event schemas
2. **Event Emitter** - Thread-safe event collection with buffering
3. **Event Storage** - TimescaleDB-optimized time-series database
4. **Event Repository** - High-performance data access layer
5. **REST API** - Query and reporting endpoints
6. **Compliance Engine** - SOC2/GDPR/HIPAA report generation
7. **Audit Middleware** - Automatic API request auditing

### Event Types

The system tracks multiple event categories:

- **User Events**: login, logout, role changes, account management
- **Agent Events**: spawning, execution, completion, failures
- **Test Events**: creation, execution, results
- **API Events**: all HTTP requests and responses
- **System Events**: startup, shutdown, configuration changes
- **Data Events**: CRUD operations, exports
- **Security Events**: authentication failures, access denied, policy violations
- **Compliance Events**: GDPR requests, data retention

## Features

### 1. Event Collection

**Automatic Batching**
```python
from sentinel_backend.audit_service.emitter import get_global_emitter

emitter = get_global_emitter()

# Emit events - automatically batched for performance
await emitter.emit(
    event_type=EventType.USER_LOGIN,
    actor=EventActor(id="user-123", type="user"),
    action="login",
    outcome=EventOutcome.SUCCESS
)
```

**Deduplication**
- Prevents duplicate events within configurable time window
- Reduces storage overhead
- Configurable per-emitter

**Context Manager**
```python
# Automatic duration tracking
async with emitter.event_context(
    EventType.TEST_EXECUTED,
    actor,
    "run_tests"
):
    # Do work
    await run_test_suite()
```

### 2. Storage Optimization

**TimescaleDB Integration**
- Automatic time-series partitioning
- Continuous aggregates for fast queries
- Compression for old data
- Configurable retention policies

**Indexing Strategy**
- Primary: `(timestamp, event_type)`
- Actor queries: `(actor_id, timestamp)`
- Resource queries: `(resource_id, timestamp)`
- Full-text search on descriptions
- GIN indexes for JSONB and array columns

### 3. Querying

**REST API Endpoints**

```bash
# Query events
GET /api/v1/audit/events?start_time=2024-01-01&event_types=user.login&limit=100

# Get statistics
GET /api/v1/audit/statistics?start_time=2024-01-01

# Export events
GET /api/v1/audit/export?format=csv&start_time=2024-01-01

# Get specific event
GET /api/v1/audit/events/{event_id}
```

**Filtering Options**
- Time range
- Event types, severities, outcomes
- Actor IDs and types
- Resource IDs and types
- Full-text search
- Tag-based filtering

### 4. Compliance Features

**Event Immutability**
- Append-only storage
- Cryptographic signatures for critical events
- Signature verification

**GDPR Compliance**
```bash
# Anonymize user events (right to be forgotten)
POST /api/v1/audit/compliance/anonymize?user_id=user-123
```

**SOC2/HIPAA Reports**
```bash
# Generate compliance report
POST /api/v1/audit/reports/generate
{
  "report_type": "soc2",
  "start_time": "2024-01-01T00:00:00Z",
  "end_time": "2024-12-31T23:59:59Z"
}
```

### 5. Integration

**Automatic API Auditing**
```python
from fastapi import FastAPI
from sentinel_backend.audit_service.middleware import install_audit_middleware

app = FastAPI()

# Install middleware
install_audit_middleware(
    app,
    exclude_paths=["/health", "/metrics"],
    exclude_methods=["OPTIONS"]
)
```

**Manual Event Emission**
```python
from sentinel_backend.audit_service.emitter import get_global_emitter
from sentinel_backend.audit_service.models.events import (
    EventType, EventActor, EventOutcome
)

emitter = get_global_emitter()

# User login event
await emitter.emit_user_login(
    user_id="user-123",
    user_email="user@example.com",
    ip_address="192.168.1.1",
    success=True
)

# Agent execution event
await emitter.emit_agent_execution(
    agent_id="agent-456",
    agent_type="functional",
    action="generate_tests",
    outcome=EventOutcome.SUCCESS,
    duration_ms=1500
)

# API request event
await emitter.emit_api_request(
    user_id="user-123",
    method="POST",
    path="/api/v1/tests",
    status_code=201,
    duration_ms=250,
    ip_address="192.168.1.1"
)
```

## Database Schema

### Main Event Table

```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    outcome VARCHAR(20) NOT NULL,

    -- Actor information
    actor_id VARCHAR(255) NOT NULL,
    actor_type VARCHAR(50) NOT NULL,
    actor_name VARCHAR(255),
    actor_ip VARCHAR(45),
    actor_session_id VARCHAR(255),

    -- Action and resource
    action VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255),
    resource_type VARCHAR(50),

    -- Details
    description TEXT,
    duration_ms INTEGER,
    metadata JSONB DEFAULT '{}',
    tags TEXT[],

    -- Compliance
    signature VARCHAR(512),
    is_deleted BOOLEAN DEFAULT FALSE,
    anonymized BOOLEAN DEFAULT FALSE
);

-- Convert to hypertable (TimescaleDB)
SELECT create_hypertable('audit_events', 'timestamp',
    chunk_time_interval => INTERVAL '1 day');
```

### Retention Policies

```sql
-- Compression after 7 days
SELECT add_compression_policy('audit_events', INTERVAL '7 days');

-- Retention after 1 year (configurable per event type)
SELECT add_retention_policy('audit_events', INTERVAL '365 days');
```

## Performance

### Metrics

- **Write throughput**: 10,000+ events/second
- **Query latency**: <100ms for time-range queries
- **Storage efficiency**: 70% compression for old data
- **Batch processing**: 100 events/batch (configurable)

### Optimization Tips

1. **Use batching**: Events are automatically batched
2. **Enable TimescaleDB**: For production deployments
3. **Configure retention**: Set appropriate retention per event type
4. **Use continuous aggregates**: For common queries
5. **Index strategically**: Based on query patterns

## Security

### Event Signing

```python
# Sign critical events
await emitter.emit(
    event_type=EventType.USER_ROLE_CHANGED,
    actor=actor,
    action="change_role",
    outcome=EventOutcome.SUCCESS,
    sign_event=True,
    signing_key="your-secret-key"
)
```

### Access Control

- API endpoints protected by authentication
- Role-based access to audit data
- Separate permissions for GDPR operations

## Monitoring

### Emitter Statistics

```bash
GET /api/v1/audit/metrics

{
  "metrics": {
    "events_emitted": 15000,
    "events_deduplicated": 45,
    "batches_created": 150,
    "buffer_size": 12,
    "handlers_registered": 1
  }
}
```

### Health Check

```bash
GET /api/v1/audit/health

{
  "status": "healthy",
  "service": "audit",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

## Configuration

### Environment Variables

```bash
# Database
SENTINEL_DB_URL=postgresql://user:pass@localhost:5432/sentinel

# Emitter
AUDIT_BATCH_SIZE=100
AUDIT_FLUSH_INTERVAL=5
AUDIT_MAX_BUFFER_SIZE=10000
AUDIT_ENABLE_DEDUPLICATION=true

# Storage
AUDIT_RETENTION_DAYS=365
AUDIT_ENABLE_COMPRESSION=true
AUDIT_COMPRESSION_AFTER_DAYS=7

# Security
AUDIT_SIGNING_KEY=your-secret-key
AUDIT_SIGN_CRITICAL_EVENTS=true
```

## Best Practices

1. **Event Granularity**: Balance detail with storage costs
2. **Retention Policies**: Configure per event type importance
3. **Performance**: Use batching and async processing
4. **Security**: Sign critical events, protect API access
5. **Compliance**: Regular report generation and review
6. **Monitoring**: Track emitter metrics and storage growth

## Troubleshooting

### High Memory Usage

- Reduce `AUDIT_MAX_BUFFER_SIZE`
- Increase `AUDIT_FLUSH_INTERVAL`
- Check for handler processing delays

### Slow Queries

- Ensure TimescaleDB is enabled
- Check index usage with `EXPLAIN ANALYZE`
- Use continuous aggregates for common queries

### Missing Events

- Check emitter is started: `await emitter.start()`
- Verify middleware is installed
- Check exclusion lists in middleware

## Future Enhancements

1. **Real-time Streaming**: WebSocket support for live event feed
2. **Advanced Analytics**: ML-based anomaly detection
3. **Multi-tenancy**: Tenant-isolated audit trails
4. **Custom Event Types**: User-defined event schemas
5. **Export Formats**: PDF reports, Excel exports
6. **Alert Rules**: Configurable alerting on event patterns
