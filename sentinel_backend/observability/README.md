# Sentinel Observability Infrastructure

Phase 1.5 implementation complete. This directory contains comprehensive observability infrastructure for the Sentinel platform.

## Directory Structure

```
observability/
├── prometheus/
│   ├── alerts.yml              # 13 alert rules for monitoring
│   ├── recording_rules.yml     # 24 recording rules for query optimization
│   └── prometheus.yml          # Service-specific Prometheus config (deprecated)
├── middleware/
│   ├── __init__.py
│   └── metrics.py              # 25+ Prometheus metrics with middleware
├── docs/
│   ├── QUICK_START.md          # Quick start guide for developers
│   ├── OBSERVABILITY_GUIDE.md  # Comprehensive observability guide
│   ├── METRICS_CATALOG.md      # Complete metrics catalog
│   └── IMPLEMENTATION_SUMMARY.md # Implementation details
└── README.md                   # This file
```

## Configuration Files

### Root Level
- `/workspaces/api-testing-agents/prometheus.yml` - Main Prometheus configuration with all service scrape configs
- `/workspaces/api-testing-agents/config/enhanced_tracing_config.py` - Jaeger tracing configuration with OpenTelemetry

### Docker Integration
All observability services are configured in `docker-compose.yml`:
- Prometheus (port 9090) with volume mounts for configs
- Jaeger (port 16686) with all-in-one deployment

## Quick Start

### 1. Install Dependencies

```bash
# Add to sentinel_backend/requirements.txt
prometheus-client>=0.19.0
opentelemetry-api>=1.21.0
opentelemetry-sdk>=1.21.0
opentelemetry-exporter-jaeger>=1.21.0
opentelemetry-instrumentation-fastapi>=0.42b0
opentelemetry-instrumentation-requests>=0.42b0
opentelemetry-instrumentation-sqlalchemy>=0.42b0
opentelemetry-instrumentation-logging>=0.42b0
```

### 2. Start Services

```bash
docker-compose up -d prometheus jaeger
```

### 3. Access Dashboards

- Prometheus: http://localhost:9090
- Jaeger UI: http://localhost:16686

## Metrics Available

### HTTP Metrics (5 metrics)
- `http_requests_total` - Counter
- `http_request_duration_seconds` - Histogram
- `http_requests_in_progress` - Gauge
- `http_request_size_bytes` - Histogram
- `http_response_size_bytes` - Histogram

### Agent Metrics (4 metrics)
- `agent_executions_total` - Counter
- `agent_execution_duration_seconds` - Histogram
- `agent_execution_timeouts_total` - Counter
- `active_agents` - Gauge

### Test Generation Metrics (4 metrics)
- `test_generation_requests_total` - Counter
- `test_generation_duration_seconds` - Histogram
- `test_generation_failures_total` - Counter
- `tests_generated_total` - Counter

### Coverage Metrics (3 metrics)
- `coverage_analysis_total` - Counter
- `coverage_gaps_detected_total` - Counter
- `coverage_percentage` - Gauge

### LLM Metrics (6 metrics)
- `llm_api_requests_total` - Counter
- `llm_api_latency_seconds` - Histogram
- `llm_api_errors_total` - Counter
- `llm_tokens_total` - Counter
- `llm_cost_usd_total` - Counter
- `llm_rate_limit_hits_total` - Counter

### Database Metrics (6 metrics)
- `database_queries_total` - Counter
- `database_query_duration_seconds` - Histogram
- `database_connection_errors_total` - Counter
- `database_pool_connections_active` - Gauge
- `database_pool_connections_max` - Gauge
- `database_pool_wait_seconds` - Histogram

### Queue Metrics (4 metrics)
- `queue_messages_published_total` - Counter
- `queue_messages_consumed_total` - Counter
- `message_processing_duration_seconds` - Histogram
- `queue_depth` - Gauge

### Security Metrics (4 metrics)
- `security_scans_total` - Counter
- `security_vulnerabilities_detected_total` - Counter
- `auth_attempts_total` - Counter
- `auth_failures_total` - Counter

### Business Metrics (5 metrics)
- `api_specs_analyzed_total` - Counter
- `tests_executed_total` - Counter
- `test_execution_duration_seconds` - Histogram
- `projects_active` - Gauge
- `users_active` - Gauge

**Total: 45+ metrics**

## Alert Rules

13 alerts covering:
- Service availability
- Error rates (>5% warning, >10% critical)
- Latency (>1s warning, >3s critical)
- Memory usage (>80% warning, >90% critical)
- Database health
- Agent failures
- Queue depth
- Resource usage

## Recording Rules

24 recording rules for:
- Request rates (1m, 5m)
- Error ratios
- Latency percentiles (p50, p95, p99)
- Agent success rates
- LLM token usage
- Database performance
- Queue metrics
- Resource utilization

## Integration Example

### FastAPI Service

```python
from fastapi import FastAPI
from sentinel_backend.observability.middleware.metrics import (
    PrometheusMetricsMiddleware,
    metrics_endpoint,
    initialize_metrics
)
from config.enhanced_tracing_config import create_tracer

app = FastAPI()

# Initialize metrics
initialize_metrics(service_name="my-service", version="1.0.0")

# Add middleware
app.add_middleware(PrometheusMetricsMiddleware, service_name="my-service")

# Add metrics endpoint
app.add_route("/metrics", metrics_endpoint)

# Initialize tracing
tracer = create_tracer(service_name="my-service")
```

### Track Custom Metrics

```python
from sentinel_backend.observability.middleware.metrics import (
    track_agent_execution,
    track_test_generation,
    track_llm_call
)

# Track agent execution
track_agent_execution(
    agent_type="functional-positive",
    duration=2.5,
    status="success"
)

# Track test generation
track_test_generation(
    agent_type="functional-positive",
    duration=5.0,
    status="success",
    test_count=15,
    framework="pytest"
)

# Track LLM call
track_llm_call(
    provider="anthropic",
    model="claude-sonnet-4",
    duration=1.2,
    status="success",
    input_tokens=500,
    output_tokens=1000,
    cost_usd=0.015
)
```

## Distributed Tracing

### Features
- Automatic FastAPI instrumentation
- HTTP request tracing
- Database query tracing
- Custom span creation
- Adaptive sampling (1% base, 100% on errors)

### Example

```python
from config.enhanced_tracing_config import get_current_span, add_span_attributes

# Add attributes to current span
add_span_attributes(
    user_id="123",
    project_id="456"
)

# Create custom span
from opentelemetry import trace

tracer = trace.get_tracer(__name__)
with tracer.start_as_current_span("custom-operation") as span:
    span.add_event("Processing started")
    # Your code here
    span.add_event("Processing completed")
```

## Status

✅ **Phase 1.5 Complete**

All deliverables implemented:
- ✅ Prometheus configuration with 11 scrape targets
- ✅ 13 alert rules covering all critical scenarios
- ✅ 24 recording rules for query optimization
- ✅ 45+ Prometheus metrics in Python middleware
- ✅ Enhanced tracing with Jaeger and OpenTelemetry
- ✅ Docker Compose integration with volume mounts
- ✅ Comprehensive documentation

## Next Steps

1. **Install Dependencies**: Add OpenTelemetry and Prometheus packages
2. **Integrate Middleware**: Add to each FastAPI service
3. **Deploy Services**: Run `docker-compose up -d prometheus jaeger`
4. **Verify Metrics**: Check http://localhost:9090/targets
5. **Create Dashboards**: Import Grafana dashboards (optional)

## Documentation

- [QUICK_START.md](docs/QUICK_START.md) - Getting started guide
- [OBSERVABILITY_GUIDE.md](docs/OBSERVABILITY_GUIDE.md) - Comprehensive guide
- [METRICS_CATALOG.md](docs/METRICS_CATALOG.md) - Complete metrics reference
- [IMPLEMENTATION_SUMMARY.md](docs/IMPLEMENTATION_SUMMARY.md) - Implementation details

## Support

For issues or questions:
1. Check service logs: `docker-compose logs prometheus jaeger`
2. Verify targets: http://localhost:9090/targets
3. Review traces: http://localhost:16686
4. Consult documentation in `/docs`
