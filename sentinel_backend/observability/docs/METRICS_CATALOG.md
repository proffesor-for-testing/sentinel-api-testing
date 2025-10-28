# Sentinel Platform Metrics Catalog

Complete reference of all custom metrics exposed by the Sentinel platform.

## Table of Contents

1. [Test Metrics](#test-metrics)
2. [Agent Metrics](#agent-metrics)
3. [LLM Provider Metrics](#llm-provider-metrics)
4. [Database Metrics](#database-metrics)
5. [Message Broker Metrics](#message-broker-metrics)
6. [API Specification Metrics](#api-specification-metrics)
7. [Orchestration Metrics](#orchestration-metrics)
8. [Rust Core Metrics](#rust-core-metrics)

---

## Test Metrics

### sentinel_test_generation_total

**Type**: Counter

**Description**: Total number of tests generated

**Labels**:
- `test_type`: Type of test (functional, security, performance)
- `agent_type`: Agent that generated the test (positive, negative, stateful, etc.)
- `status`: Generation status (success, failed)

**Example Query**:
```promql
# Test generation rate by type
sum(rate(sentinel_test_generation_total[5m])) by (test_type)

# Failed test generations
sum(rate(sentinel_test_generation_total{status="failed"}[5m])) by (agent_type)
```

---

### sentinel_test_generation_duration_seconds

**Type**: Histogram

**Description**: Time taken to generate tests

**Labels**:
- `test_type`: Type of test
- `agent_type`: Agent that generated the test

**Buckets**: [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0]

**Example Query**:
```promql
# 95th percentile generation time
histogram_quantile(0.95,
  sum(rate(sentinel_test_generation_duration_seconds_bucket[5m])) by (le, test_type)
)
```

---

### sentinel_test_generation_queue_size

**Type**: Gauge

**Description**: Number of pending test generation requests

**Labels**: None

**Example Query**:
```promql
# Current queue size
sentinel_test_generation_queue_size

# Average queue size over time
avg_over_time(sentinel_test_generation_queue_size[1h])
```

---

### sentinel_test_execution_total

**Type**: Counter

**Description**: Total number of tests executed

**Labels**:
- `test_type`: Type of test
- `status`: Execution result (passed, failed, error, skipped)

**Example Query**:
```promql
# Test execution rate
sum(rate(sentinel_test_execution_total[5m])) by (test_type, status)

# Pass rate
sum(rate(sentinel_test_execution_total{status="passed"}[5m])) by (test_type)
/
sum(rate(sentinel_test_execution_total[5m])) by (test_type)
```

---

### sentinel_test_execution_duration_seconds

**Type**: Histogram

**Description**: Time taken to execute tests

**Labels**:
- `test_type`: Type of test

**Buckets**: [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]

**Example Query**:
```promql
# Average test execution time
rate(sentinel_test_execution_duration_seconds_sum[5m])
/
rate(sentinel_test_execution_duration_seconds_count[5m])
```

---

## Agent Metrics

### sentinel_agent_executions_total

**Type**: Counter

**Description**: Total number of agent executions

**Labels**:
- `agent_type`: Type of agent (positive, negative, stateful, auth, injection, etc.)
- `service`: Service running the agent (orchestration, execution)
- `status`: Execution status (success, failed)

**Example Query**:
```promql
# Agent execution rate
sum(rate(sentinel_agent_executions_total[5m])) by (agent_type)

# Agent failure rate
sum(rate(sentinel_agent_executions_total{status="failed"}[5m])) by (agent_type)
/
sum(rate(sentinel_agent_executions_total[5m])) by (agent_type)
```

---

### sentinel_agent_duration_seconds

**Type**: Histogram

**Description**: Time taken for agent execution

**Labels**:
- `agent_type`: Type of agent
- `service`: Service running the agent

**Buckets**: [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]

**Example Query**:
```promql
# P99 agent execution time
histogram_quantile(0.99,
  sum(rate(sentinel_agent_duration_seconds_bucket[5m])) by (le, agent_type)
)
```

---

### sentinel_agent_active_executions

**Type**: Gauge

**Description**: Number of currently active agent executions

**Labels**:
- `agent_type`: Type of agent

**Example Query**:
```promql
# Current active executions
sum(sentinel_agent_active_executions) by (agent_type)

# Max concurrent executions
max_over_time(sentinel_agent_active_executions[1h])
```

---

### sentinel_agent_queue_size

**Type**: Gauge

**Description**: Number of pending agent execution requests

**Labels**:
- `agent_type`: Type of agent

**Example Query**:
```promql
# Queue size by agent
sentinel_agent_queue_size

# Total queue backlog
sum(sentinel_agent_queue_size)
```

---

## LLM Provider Metrics

### sentinel_llm_requests_total

**Type**: Counter

**Description**: Total number of LLM API requests

**Labels**:
- `provider`: LLM provider (anthropic, openai, google, mistral, ollama)
- `model`: Model name (claude-3-opus, gpt-4, etc.)
- `status`: Request status (success, failed, timeout)

**Example Query**:
```promql
# Request rate by provider
sum(rate(sentinel_llm_requests_total[5m])) by (provider)

# Error rate by model
sum(rate(sentinel_llm_requests_total{status!="success"}[5m])) by (provider, model)
```

---

### sentinel_llm_request_duration_seconds

**Type**: Histogram

**Description**: Time taken for LLM API requests

**Labels**:
- `provider`: LLM provider
- `model`: Model name

**Buckets**: [0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0]

**Example Query**:
```promql
# Average latency by provider
rate(sentinel_llm_request_duration_seconds_sum[5m])
/
rate(sentinel_llm_request_duration_seconds_count[5m])
```

---

### sentinel_llm_tokens_total

**Type**: Counter

**Description**: Total number of tokens used

**Labels**:
- `provider`: LLM provider
- `model`: Model name
- `token_type`: Token type (prompt, completion, total)

**Example Query**:
```promql
# Token usage rate
sum(rate(sentinel_llm_tokens_total[5m])) by (provider, token_type)

# Daily token consumption
increase(sentinel_llm_tokens_total[24h])
```

---

### sentinel_llm_cost_total

**Type**: Counter

**Description**: Total cost of LLM API requests in USD

**Labels**:
- `provider`: LLM provider
- `model`: Model name

**Example Query**:
```promql
# Hourly cost
sum(rate(sentinel_llm_cost_total[1h]) * 3600) by (provider)

# Daily spend
increase(sentinel_llm_cost_total[24h])
```

---

### sentinel_llm_rate_limit_remaining

**Type**: Gauge

**Description**: Remaining LLM API rate limit

**Labels**:
- `provider`: LLM provider

**Example Query**:
```promql
# Current rate limit
sentinel_llm_rate_limit_remaining

# Rate limit utilization
(sentinel_llm_rate_limit_max - sentinel_llm_rate_limit_remaining)
/
sentinel_llm_rate_limit_max
```

---

## Database Metrics

### db_query_duration_seconds

**Type**: Histogram

**Description**: Database query duration

**Labels**:
- `operation`: SQL operation (select, insert, update, delete)
- `table`: Database table name

**Buckets**: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]

**Example Query**:
```promql
# Slowest queries
topk(10,
  histogram_quantile(0.99,
    sum(rate(db_query_duration_seconds_bucket[5m])) by (le, table, operation)
  )
)
```

---

### db_connections_active

**Type**: Gauge

**Description**: Number of active database connections

**Labels**: None

**Example Query**:
```promql
# Current active connections
db_connections_active

# Connection pool utilization
db_connections_active / db_connections_max
```

---

### db_connections_max

**Type**: Gauge

**Description**: Maximum number of database connections

**Labels**: None

---

### db_query_errors_total

**Type**: Counter

**Description**: Total number of database query errors

**Labels**:
- `operation`: SQL operation
- `error_type`: Error type (timeout, deadlock, constraint_violation, etc.)

**Example Query**:
```promql
# Error rate by type
sum(rate(db_query_errors_total[5m])) by (error_type)
```

---

## Message Broker Metrics

### sentinel_message_queue_size

**Type**: Gauge

**Description**: Number of messages in queue

**Labels**:
- `queue_name`: Queue name

**Example Query**:
```promql
# Queue depth
sentinel_message_queue_size

# Total messages across all queues
sum(sentinel_message_queue_size)
```

---

### sentinel_message_processing_duration_seconds

**Type**: Histogram

**Description**: Time taken to process messages

**Labels**:
- `queue_name`: Queue name

**Buckets**: [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]

---

### sentinel_message_processing_errors_total

**Type**: Counter

**Description**: Total number of message processing errors

**Labels**:
- `queue_name`: Queue name
- `error_type`: Error type

---

## API Specification Metrics

### sentinel_spec_analysis_duration_seconds

**Type**: Histogram

**Description**: Time taken to analyze API specifications

**Labels**:
- `spec_format`: Specification format (openapi, swagger, graphql)

**Buckets**: [0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]

---

### sentinel_spec_endpoints_detected

**Type**: Gauge

**Description**: Number of endpoints detected in API spec

**Labels**:
- `spec_id`: Specification ID

---

## Orchestration Metrics

### sentinel_workflow_executions_total

**Type**: Counter

**Description**: Total number of workflow executions

**Labels**:
- `workflow_type`: Workflow type (test_generation, execution, analysis)
- `status`: Execution status (success, failed)

---

### sentinel_workflow_duration_seconds

**Type**: Histogram

**Description**: Time taken for workflow execution

**Labels**:
- `workflow_type`: Workflow type

**Buckets**: [1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]

---

## Rust Core Metrics

### sentinel_rust_agent_executions_total

**Type**: Counter

**Description**: Total number of Rust agent executions

**Labels**:
- `agent_type`: Type of agent
- `status`: Execution status

**Example Query**:
```promql
# Rust agent execution rate
sum(rate(sentinel_rust_agent_executions_total[5m])) by (agent_type)
```

---

### sentinel_rust_agent_duration_seconds

**Type**: Histogram

**Description**: Time taken for Rust agent execution

**Labels**:
- `agent_type`: Type of agent

**Buckets**: [0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0]

**Example Query**:
```promql
# Rust vs Python agent performance comparison
histogram_quantile(0.95,
  sum(rate(sentinel_rust_agent_duration_seconds_bucket[5m])) by (le, agent_type)
)
```

---

### sentinel_rust_agent_errors_total

**Type**: Counter

**Description**: Total number of Rust agent errors

**Labels**:
- `agent_type`: Type of agent
- `error_type`: Error type

---

## Recording Rules Reference

The following aggregated metrics are pre-computed for faster queries:

- `sentinel:http_requests:rate5m`
- `sentinel:http_requests:success_rate`
- `sentinel:http_requests:error_rate`
- `sentinel:http_request_duration:p50/p90/p95/p99`
- `sentinel:agent_executions:rate5m`
- `sentinel:agent_executions:success_rate`
- `sentinel:agent_duration:p50/p95/p99`
- `sentinel:llm_requests:rate5m`
- `sentinel:llm_cost:rate1h`
- `sentinel:db_query_duration:p50/p95`

Use these in dashboards for better performance.

---

## Usage Tips

1. **Use rate() for counters** to get per-second rate
2. **Use histogram_quantile() for latency** percentiles
3. **Use recording rules** for expensive queries in dashboards
4. **Keep label cardinality low** to avoid performance issues
5. **Use irate() for spiky metrics** instead of rate()
