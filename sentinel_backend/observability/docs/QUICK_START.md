# Observability Quick Start Guide

Get up and running with Sentinel's observability stack in 5 minutes.

## Prerequisites

- Docker and Docker Compose
- Sentinel backend services running

## Step 1: Start Observability Services

```bash
# Start all services including observability
make start

# Or start just observability services
docker-compose up -d prometheus jaeger
```

## Step 2: Verify Services

```bash
# Check services are running
docker ps | grep -E "prometheus|jaeger"

# Should see:
# sentinel_prometheus
# sentinel_jaeger
```

## Step 3: Access Dashboards

### Prometheus
**URL**: http://localhost:9090

**Quick Checks:**
1. Go to Status → Targets
2. Verify all services are "UP"
3. Go to Graph tab
4. Try query: `up{job="api_gateway"}`

### Jaeger
**URL**: http://localhost:16686

**Quick Checks:**
1. Select "api_gateway" from service dropdown
2. Click "Find Traces"
3. Should see recent traces

## Step 4: Generate Sample Traffic

```bash
# Make some requests to generate metrics and traces
curl http://localhost:8000/health
curl http://localhost:8000/docs
curl -X POST http://localhost:8000/api/v1/specs \
  -H "Content-Type: application/json" \
  -d '{"name": "test", "content": "..."}'
```

## Step 5: View Metrics

### In Prometheus (http://localhost:9090/graph):

**Total Requests:**
```promql
sum(rate(http_requests_total[5m])) by (service)
```

**Error Rate:**
```promql
sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)
/
sum(rate(http_requests_total[5m])) by (service)
```

**Response Time (P95):**
```promql
histogram_quantile(0.95,
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service)
)
```

**Agent Executions:**
```promql
sum(rate(sentinel_agent_executions_total[5m])) by (agent_type)
```

## Step 6: View Traces

### In Jaeger (http://localhost:16686):

1. **Service**: Select "orchestration_service"
2. **Operation**: Select "generate_tests"
3. **Lookback**: Last hour
4. **Click**: Find Traces
5. **Click on a trace** to see the full request flow

### Understanding Trace Visualization:

```
┌─────────────┐
│API Gateway  │ ───┐
└─────────────┘    │
                   ├─> ┌─────────────┐
                   │   │Auth Service │
                   │   └─────────────┘
                   │
                   └─> ┌──────────────┐
                       │Orchestration │
                       └──────────────┘
                            │
                            ├─> ┌──────────┐
                            │   │Execution │
                            │   └──────────┘
                            │
                            └─> ┌──────────┐
                                │Rust Core │
                                └──────────┘
```

## Common Queries

### 1. Service Health
```promql
# Are all services up?
up{job=~".*_service|api_gateway|sentinel_rust_core"}
```

### 2. Request Volume
```promql
# Requests per second by service
sum(rate(http_requests_total[1m])) by (service)
```

### 3. Error Tracking
```promql
# 5xx errors in last 5 minutes
sum(increase(http_requests_total{status=~"5.."}[5m])) by (service, status)
```

### 4. Performance
```promql
# Slowest endpoints (P99)
topk(10,
  histogram_quantile(0.99,
    sum(rate(http_request_duration_seconds_bucket[5m])) by (le, path)
  )
)
```

### 5. Agent Performance
```promql
# Agent execution duration (P95)
histogram_quantile(0.95,
  sum(rate(sentinel_agent_duration_seconds_bucket[5m])) by (le, agent_type)
)
```

### 6. LLM Costs
```promql
# Cost per hour by provider
sum(rate(sentinel_llm_cost_total[1h]) * 3600) by (provider)
```

### 7. Database Performance
```promql
# Slow queries (>100ms)
histogram_quantile(0.95,
  sum(rate(db_query_duration_seconds_bucket[5m])) by (le, operation)
) > 0.1
```

## Troubleshooting

### Prometheus shows "No data"

**Check:**
```bash
# Verify service exposes metrics
curl http://localhost:8000/metrics

# Check Prometheus scrape status
curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'
```

### Jaeger shows "No traces"

**Check:**
```bash
# Verify Jaeger is receiving spans
curl http://localhost:14269/metrics | grep jaeger_collector

# Check service logs for tracing errors
docker logs sentinel_api_gateway 2>&1 | grep -i trace
```

### Services not appearing

**Restart observability stack:**
```bash
docker-compose restart prometheus jaeger
```

## Next Steps

1. **Set up alerts**: Review `/observability/prometheus/alerts.yml`
2. **Create dashboards**: Import Grafana dashboards (optional)
3. **Customize metrics**: Add custom business metrics
4. **Read full guide**: See `OBSERVABILITY_GUIDE.md`

## Quick Reference

| Service | URL | Purpose |
|---------|-----|---------|
| Prometheus | http://localhost:9090 | Metrics & queries |
| Jaeger UI | http://localhost:16686 | Distributed tracing |
| API Gateway | http://localhost:8000/metrics | Gateway metrics |
| Auth Service | http://localhost:8005/metrics | Auth metrics |
| Spec Service | http://localhost:8001/metrics | Spec metrics |
| Orchestration | http://localhost:8002/metrics | Orchestration metrics |
| Execution | http://localhost:8003/metrics | Execution metrics |
| Data Service | http://localhost:8004/metrics | Data metrics |
| Rust Core | http://localhost:8088/metrics | Rust metrics |

## Support

- **Documentation**: `/sentinel_backend/observability/docs/`
- **Issues**: Check logs with `docker logs <container_name>`
- **Community**: File issues in the repository
