# Sentinel Platform Observability Guide

## Overview

This guide covers the observability infrastructure for the Sentinel AI-powered API testing platform, including metrics collection with Prometheus, distributed tracing with Jaeger, and custom business metrics.

## Table of Contents

1. [Architecture](#architecture)
2. [Metrics Collection](#metrics-collection)
3. [Distributed Tracing](#distributed-tracing)
4. [Custom Metrics](#custom-metrics)
5. [Dashboards](#dashboards)
6. [Alerting](#alerting)
7. [Troubleshooting](#troubleshooting)

---

## Architecture

### Components

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Services   │────>│  Prometheus  │────>│  Grafana    │
│  (Metrics)  │     │  (Collector) │     │ (Dashboards)│
└─────────────┘     └──────────────┘     └─────────────┘
       │
       │ (Traces)
       v
┌─────────────┐     ┌──────────────┐
│   Jaeger    │────>│  Jaeger UI   │
│   Agent     │     │   (Query)    │
└─────────────┘     └──────────────┘
```

### Services Monitored

- **API Gateway** (port 8000)
- **Auth Service** (port 8005)
- **Spec Service** (port 8001)
- **Orchestration Service** (port 8002)
- **Execution Service** (port 8003)
- **Data Service** (port 8004)
- **Rust Core** (port 8088)
- **RabbitMQ** (port 15692)
- **PostgreSQL** (via postgres_exporter)

---

## Metrics Collection

### Accessing Prometheus

**URL**: http://localhost:9090

### Standard HTTP Metrics

All services expose standard HTTP metrics via prometheus-fastapi-instrumentator:

- `http_requests_total` - Total HTTP requests by method, status, path
- `http_request_duration_seconds` - Request duration histogram
- `http_requests_in_progress` - Currently processing requests

### Query Examples

**Total requests per service:**
```promql
sum(rate(http_requests_total[5m])) by (service)
```

**Error rate by service:**
```promql
sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)
/
sum(rate(http_requests_total[5m])) by (service)
```

**95th percentile latency:**
```promql
histogram_quantile(0.95,
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service)
)
```

---

## Distributed Tracing

### Accessing Jaeger UI

**URL**: http://localhost:16686

### Trace Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────>│ API Gateway │────>│Auth Service │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           v
                    ┌─────────────┐
                    │Orchestration│
                    │   Service   │
                    └─────────────┘
                           │
                    ┌──────┴──────┐
                    v             v
            ┌─────────────┐  ┌─────────────┐
            │  Execution  │  │    Rust     │
            │   Service   │  │    Core     │
            └─────────────┘  └─────────────┘
```

### Sampling Strategy

**Development**: 100% sampling
**Staging**: 50% sampling for critical operations, 10% for others
**Production**: Custom sampler with:
- 100% for errors
- 50% for critical operations (test generation, auth)
- 10% for regular operations
- 1% for health checks

### Finding Traces

**By Operation:**
```
Service: orchestration_service
Operation: generate_tests
```

**By Tag:**
```
agent.type=functional-positive
test.type=security
```

**By Duration:**
```
Min Duration: 2s
Max Duration: 60s
```

---

## Custom Metrics

### Test Generation Metrics

```python
from sentinel_backend.observability.middleware import track_test_generation

# Usage
with track_test_generation(test_type="functional", agent_type="positive"):
    # Generate tests
    tests = agent.generate_tests(spec)
```

**Available Metrics:**
- `sentinel_test_generation_total` - Counter of tests generated
- `sentinel_test_generation_duration_seconds` - Histogram of generation time
- `sentinel_test_generation_queue_size` - Gauge of pending requests

### Agent Execution Metrics

```python
from sentinel_backend.observability.middleware import track_agent_execution

# Usage
with track_agent_execution(agent_type="positive", service="orchestration"):
    # Execute agent
    result = agent.execute()
```

**Available Metrics:**
- `sentinel_agent_executions_total` - Counter by agent type and status
- `sentinel_agent_duration_seconds` - Histogram of execution time
- `sentinel_agent_active_executions` - Gauge of active executions
- `sentinel_agent_queue_size` - Gauge of pending executions

### LLM Provider Metrics

```python
from sentinel_backend.observability.middleware import track_llm_request

# Usage
with track_llm_request(provider="anthropic", model="claude-3"):
    # Make LLM request
    response = llm.generate(prompt)
```

**Available Metrics:**
- `sentinel_llm_requests_total` - Counter by provider, model, status
- `sentinel_llm_request_duration_seconds` - Histogram of request time
- `sentinel_llm_tokens_total` - Counter of tokens used
- `sentinel_llm_cost_total` - Counter of API costs in USD
- `sentinel_llm_rate_limit_remaining` - Gauge of remaining rate limit

### Database Query Metrics

```python
from sentinel_backend.observability.middleware import track_db_query

# Usage
with track_db_query(operation="select", table="test_cases"):
    # Execute query
    result = db.query(TestCase).all()
```

**Available Metrics:**
- `db_query_duration_seconds` - Histogram by operation and table
- `db_connections_active` - Gauge of active connections
- `db_connections_max` - Gauge of max connections
- `db_query_errors_total` - Counter by operation and error type

### Rust Core Metrics

**Available Metrics:**
- `sentinel_rust_agent_executions_total` - Counter by agent type and status
- `sentinel_rust_agent_duration_seconds` - Histogram of execution time
- `sentinel_rust_agent_errors_total` - Counter by agent type and error type

---

## Dashboards

### Prometheus Dashboards

Access built-in dashboards at http://localhost:9090/graph

**Recommended Queries:**

1. **Request Rate**
   ```promql
   sum(rate(http_requests_total[5m])) by (service)
   ```

2. **Error Rate**
   ```promql
   sentinel:http_requests:error_rate
   ```

3. **Latency (P95)**
   ```promql
   sentinel:http_request_duration:p95
   ```

4. **Agent Success Rate**
   ```promql
   sentinel:agent_executions:success_rate
   ```

### Grafana Dashboards (Optional)

To set up Grafana dashboards:

1. Install Grafana:
   ```yaml
   grafana:
     image: grafana/grafana:latest
     ports:
       - "3001:3000"
     environment:
       - GF_SECURITY_ADMIN_PASSWORD=admin
     volumes:
       - grafana_data:/var/lib/grafana
   ```

2. Add Prometheus as data source:
   - URL: http://prometheus:9090
   - Access: Server (default)

3. Import dashboard templates from `/observability/grafana/`

---

## Alerting

### Alert Rules

Alert rules are defined in `prometheus/alerts.yml`.

**Critical Alerts:**
- Service Down (1 minute threshold)
- High Error Rate (>5% for 2 minutes)
- Disk Space Low (<10% remaining)

**Warning Alerts:**
- High Response Time (P95 >2s for 5 minutes)
- Database Connection Pool Exhaustion (>80% for 3 minutes)
- High Agent Failure Rate (>10% for 5 minutes)
- High Memory Usage (>2GB for 5 minutes)

### Viewing Active Alerts

**URL**: http://localhost:9090/alerts

### Configuring Alertmanager

To enable alert notifications:

1. Add Alertmanager to docker-compose:
   ```yaml
   alertmanager:
     image: prom/alertmanager:latest
     ports:
       - "9093:9093"
     volumes:
       - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
   ```

2. Configure notification channels in `alertmanager.yml`:
   - Email
   - Slack
   - PagerDuty
   - Webhook

---

## Troubleshooting

### Common Issues

#### 1. Metrics Not Appearing in Prometheus

**Check service is exposing metrics:**
```bash
curl http://localhost:8000/metrics
```

**Verify Prometheus scrape configuration:**
```bash
curl http://localhost:9090/api/v1/targets
```

**Check Prometheus logs:**
```bash
docker logs sentinel_prometheus
```

#### 2. Traces Not Appearing in Jaeger

**Verify Jaeger agent is running:**
```bash
curl http://localhost:14269/metrics
```

**Check service tracing is enabled:**
```python
# Should see tracing setup in logs
logger.info("tracing_configured", service_name="...")
```

**Check Jaeger collector:**
```bash
docker logs sentinel_jaeger
```

#### 3. High Cardinality Issues

If Prometheus is slow or using too much memory:

**Identify high-cardinality metrics:**
```promql
topk(10, count by (__name__)({__name__=~".+"}))
```

**Solutions:**
- Reduce label cardinality
- Increase scrape interval
- Use recording rules for expensive queries
- Drop unused metrics

#### 4. Missing Spans in Traces

**Cause**: Parent context not propagated

**Solution**: Ensure context propagation in HTTP calls:
```python
from sentinel_backend.config.enhanced_tracing_config import inject_context

headers = {}
inject_context(headers)
response = httpx.post(url, headers=headers)
```

### Debugging Observability Stack

**1. Check all services are healthy:**
```bash
docker ps | grep sentinel
```

**2. Verify metrics endpoints:**
```bash
for port in 8000 8001 8002 8003 8004 8005 8088; do
  echo "Checking port $port..."
  curl -s http://localhost:$port/metrics | head -5
done
```

**3. Test Jaeger tracing:**
```bash
# Send test trace
curl -X POST http://localhost:14268/api/traces \
  -H 'Content-Type: application/json' \
  -d '{"data": [{"traceId": "test123", "spanId": "span123", "operationName": "test"}]}'
```

**4. Validate Prometheus targets:**
```bash
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
```

### Performance Optimization

**1. Use recording rules** for expensive queries (see `recording_rules.yml`)

**2. Adjust scrape intervals** based on service needs:
```yaml
scrape_configs:
  - job_name: 'high_volume_service'
    scrape_interval: 30s  # Reduce frequency
```

**3. Configure retention** to manage storage:
```yaml
command:
  - '--storage.tsdb.retention.time=30d'
  - '--storage.tsdb.retention.size=50GB'
```

**4. Use Jaeger sampling** to reduce trace volume in production

---

## Integration Examples

### Adding Metrics to New Service

```python
from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator
from sentinel_backend.config.enhanced_tracing_config import setup_enhanced_tracing
from sentinel_backend.observability.middleware import set_build_info

app = FastAPI(title="My Service")

# Setup Prometheus metrics
Instrumentator().instrument(app).expose(app)

# Setup Jaeger tracing
setup_enhanced_tracing(
    app,
    service_name="my_service",
    service_version="1.0.0",
    environment="production"
)

# Set build info
set_build_info(
    version="1.0.0",
    git_commit="abc123",
    build_date="2024-01-01"
)
```

### Using Custom Metrics

```python
from sentinel_backend.observability.middleware import (
    track_agent_execution,
    agent_executions_total
)

# Context manager (recommended)
with track_agent_execution("my_agent", "my_service"):
    result = perform_work()

# Manual instrumentation
agent_executions_total.labels(
    agent_type="my_agent",
    service="my_service",
    status="success"
).inc()
```

### Adding Custom Traces

```python
from sentinel_backend.config.enhanced_tracing_config import (
    create_span,
    add_span_attributes,
    add_span_event
)

# Create custom span
with create_span("custom_operation"):
    add_span_attributes({
        "user.id": user_id,
        "operation.type": "data_processing"
    })

    # Add event
    add_span_event("processing_started", {
        "record_count": len(records)
    })

    result = process_data(records)

    add_span_event("processing_completed")
```

---

## Best Practices

### Metrics

1. **Use appropriate metric types:**
   - Counter: Monotonically increasing values (requests, errors)
   - Gauge: Values that go up and down (queue size, connections)
   - Histogram: Distributions (latency, size)

2. **Keep cardinality low:**
   - Avoid user IDs or timestamps in labels
   - Use finite sets for label values

3. **Name metrics consistently:**
   - Format: `<namespace>_<name>_<unit>`
   - Example: `sentinel_agent_duration_seconds`

### Tracing

1. **Propagate context** across service boundaries
2. **Use meaningful span names** (operation, not URL)
3. **Add relevant attributes** for filtering
4. **Record exceptions** in spans
5. **Use sampling** to control costs

### General

1. **Monitor monitoring** - Track Prometheus/Jaeger health
2. **Set up alerts** for critical metrics
3. **Review dashboards regularly** and optimize queries
4. **Document custom metrics** for team visibility
5. **Test observability** in development

---

## Additional Resources

- [Prometheus Query Language](https://prometheus.io/docs/prometheus/latest/querying/basics/)
- [Jaeger Architecture](https://www.jaegertracing.io/docs/latest/architecture/)
- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)

---

## Support

For observability issues or questions:
1. Check this guide
2. Review Prometheus/Jaeger logs
3. Consult the development team
4. File an issue in the repository
