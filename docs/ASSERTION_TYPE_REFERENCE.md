# Assertion Type Reference

## Overview

This document provides a comprehensive reference for all supported assertion types in the Sentinel API Testing Platform. These assertion types are used by both Python and Rust agent implementations to validate API responses, performance metrics, and system behavior.

**Registry Location**: `/workspaces/api-testing-agents/sentinel_backend/common/assertion_registry.py`

## Table of Contents

1. [Status Code Assertions](#status-code-assertions)
2. [Response Time Assertions](#response-time-assertions)
3. [Throughput Assertions](#throughput-assertions)
4. [Error Rate Assertions](#error-rate-assertions)
5. [Performance Degradation Assertions](#performance-degradation-assertions)
6. [User Experience Assertions](#user-experience-assertions)
7. [Stress Test Assertions](#stress-test-assertions)
8. [Spike Test Assertions](#spike-test-assertions)
9. [Workflow Assertions](#workflow-assertions)
10. [Usage Examples](#usage-examples)
11. [Validation](#validation)

---

## Status Code Assertions

Validate HTTP response status codes.

### `status_code_in`
- **Operator**: `in`
- **Type**: `array`
- **Description**: Status code in list of accepted codes
- **Example**: `[200, 201, 204]`
- **Use Case**: When multiple status codes are acceptable (e.g., create or update operations)

```python
# Python
{
    "assertion_type": "status_code_in",
    "expected": [200, 201, 204]
}
```

```rust
// Rust
Assertion {
    assertion_type: "status_code_in".to_string(),
    expected: json!([200, 201, 204]),
    path: None,
}
```

### `status_code_eq`
- **Operator**: `==`
- **Type**: `integer`
- **Description**: Status code equals specific value
- **Example**: `200`
- **Use Case**: Exact status code validation

```python
{
    "assertion_type": "status_code_eq",
    "expected": 200
}
```

### `status_code_ne`
- **Operator**: `!=`
- **Type**: `integer`
- **Description**: Status code not equal to value
- **Example**: `500`
- **Use Case**: Ensure specific error codes are NOT returned

### `status_code_gt`
- **Operator**: `>`
- **Type**: `integer`
- **Description**: Status code greater than value
- **Example**: `199`
- **Use Case**: Validate successful responses (>= 200)

### `status_code_lt`
- **Operator**: `<`
- **Type**: `integer`
- **Description**: Status code less than value
- **Example**: `400`
- **Use Case**: Ensure no client/server errors (< 400)

---

## Response Time Assertions

Validate API response time performance.

### Basic Response Time

#### `response_time_lt`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: Response time less than threshold (ms)
- **Example**: `500ms`
- **Use Case**: General response time validation

```python
{
    "assertion_type": "response_time_lt",
    "expected": "500ms"
}
```

```rust
// Used in performance_planner.rs (line 1258)
Assertion {
    assertion_type: "response_time_p99_lt".to_string(),
    expected: json!("1000ms"),
    path: None,
}
```

#### `response_time_gt`
- **Operator**: `>`
- **Type**: `duration`
- **Description**: Response time greater than threshold (ms)
- **Example**: `100ms`

#### `response_time_eq`
- **Operator**: `==`
- **Type**: `duration`
- **Description**: Response time equals threshold (ms)
- **Example**: `250ms`

### Percentile Response Time

Critical for performance testing and SLA validation.

#### `response_time_p50_lt`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: P50 (median) response time less than threshold
- **Example**: `200ms`
- **Use Case**: Median user experience validation

```python
# Validate that 50% of requests complete within 200ms
{
    "assertion_type": "response_time_p50_lt",
    "expected": "200ms"
}
```

#### `response_time_p75_lt`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: P75 response time less than threshold
- **Example**: `300ms`
- **Use Case**: Upper-middle range performance

#### `response_time_p90_lt`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: P90 response time less than threshold
- **Example**: `500ms`
- **Use Case**: 90th percentile SLA validation

#### `response_time_p95_lt`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: P95 response time less than threshold
- **Example**: `750ms`
- **Use Case**: Standard SLA target (95% of requests)

```rust
// From performance_planner.rs (line 438)
Assertion {
    assertion_type: "response_time_p95".to_string(),
    expected: json!(success_criteria.response_time_p95),
    path: None,
}
```

#### `response_time_p99_lt`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: P99 response time less than threshold
- **Example**: `1000ms`
- **Use Case**: High-availability SLA validation

```rust
// From performance_planner.rs (line 1258)
Assertion {
    assertion_type: "response_time_p99_lt".to_string(),
    expected: json!("1000ms"),
    path: None,
}
```

#### `response_time_p99_9_lt`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: P99.9 response time less than threshold
- **Example**: `2000ms`
- **Use Case**: Extreme tail latency validation

---

## Throughput Assertions

Validate system throughput and request handling capacity.

### `throughput_gt`
- **Operator**: `>`
- **Type**: `number`
- **Description**: Throughput greater than threshold (req/sec)
- **Example**: `1000`
- **Use Case**: Minimum performance requirement

```python
{
    "assertion_type": "throughput_gt",
    "expected": 1000
}
```

```rust
// From performance_planner.rs (line 1261)
Assertion {
    assertion_type: "throughput_gt".to_string(),
    expected: json!(1000),
    path: None,
}
```

### `throughput_lt`
- **Operator**: `<`
- **Type**: `number`
- **Description**: Throughput less than threshold (req/sec)
- **Example**: `10000`
- **Use Case**: Upper limit validation

### `throughput_min`
- **Operator**: `>=`
- **Type**: `number`
- **Description**: Minimum throughput threshold (req/sec)
- **Example**: `500`
- **Use Case**: Baseline performance validation

```rust
// From performance_planner.rs (line 448)
Assertion {
    assertion_type: "throughput_min".to_string(),
    expected: json!(success_criteria.throughput_min),
    path: None,
}
```

### `throughput_rps_gt`
- **Operator**: `>`
- **Type**: `number`
- **Description**: Requests per second greater than threshold
- **Example**: `2000`
- **Use Case**: Alternative RPS metric

```rust
// From performance_planner.rs (line 1554)
Assertion {
    assertion_type: "throughput_rps_gt".to_string(),
    expected: json!(100),
    path: None,
}
```

---

## Error Rate Assertions

Validate system reliability and error handling.

### `error_rate_lt`
- **Operator**: `<`
- **Type**: `percentage`
- **Description**: Error rate less than threshold (percentage, 0.01 = 1%)
- **Example**: `0.01`
- **Use Case**: Standard error rate validation

```python
# Validate error rate is less than 1%
{
    "assertion_type": "error_rate_lt",
    "expected": 0.01
}
```

```rust
// From performance_planner.rs (line 443, 1561)
Assertion {
    assertion_type: "error_rate".to_string(),
    expected: json!(success_criteria.error_rate),
    path: None,
}
```

### `error_rate`
- **Operator**: `<=`
- **Type**: `percentage`
- **Description**: Error rate within threshold (percentage)
- **Example**: `0.05`
- **Use Case**: Maximum acceptable error rate

### `error_rate_during_spike`
- **Operator**: `<`
- **Type**: `percentage`
- **Description**: Error rate during spike test (percentage)
- **Example**: `0.10`
- **Use Case**: Spike test tolerance

```rust
// From performance_planner.rs (line 563)
Assertion {
    assertion_type: "error_rate_during_spike".to_string(),
    expected: json!(spike_criteria.error_rate_during_spike),
    path: None,
}
```

---

## Performance Degradation Assertions

Detect system degradation and resource leaks.

### `memory_leak_detection_eq`
- **Operator**: `==`
- **Type**: `boolean`
- **Description**: Memory leak detected (true/false)
- **Example**: `false`
- **Use Case**: Ensure no memory leaks during long-running tests

```python
# Assert no memory leak detected
{
    "assertion_type": "memory_leak_detection_eq",
    "expected": false
}
```

```rust
// From performance_planner.rs (line 1300)
Assertion {
    assertion_type: "memory_leak_detection_eq".to_string(),
    expected: json!(false),
    path: None,
}
```

### `performance_degradation_lt`
- **Operator**: `<`
- **Type**: `percentage`
- **Description**: Performance degradation less than threshold
- **Example**: `0.10` (10%)
- **Use Case**: Validate performance remains stable over time

```rust
// From performance_planner.rs (line 1303)
Assertion {
    assertion_type: "performance_degradation_lt".to_string(),
    expected: json!("10%"),
    path: None,
}
```

---

## User Experience Assertions

Validate end-user experience metrics.

### `user_experience_score_gt`
- **Operator**: `>`
- **Type**: `number`
- **Description**: User experience score greater than threshold (0-100)
- **Example**: `75`
- **Use Case**: Overall UX validation

```rust
// From performance_planner.rs (line 1336)
Assertion {
    assertion_type: "user_experience_score_gt".to_string(),
    expected: json!(75),
    path: None,
}
```

### `user_satisfaction_gt`
- **Operator**: `>`
- **Type**: `number`
- **Description**: User satisfaction score greater than threshold
- **Example**: `80`
- **Use Case**: Customer satisfaction metrics

```rust
// From performance_planner.rs (line 1568)
Assertion {
    assertion_type: "user_satisfaction_gt".to_string(),
    expected: json!(7.0),
    path: None,
}
```

---

## Stress Test Assertions

Validate system behavior under extreme load.

### `breaking_point_identified`
- **Operator**: `==`
- **Type**: `boolean`
- **Description**: Breaking point successfully identified
- **Example**: `true`
- **Use Case**: Stress test completion validation

```rust
// From performance_planner.rs (line 505)
Assertion {
    assertion_type: "breaking_point_identified".to_string(),
    expected: json!(stress_criteria.breaking_point_identified),
    path: None,
}
```

### `recovery_time`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: System recovery time after stress
- **Example**: `60s`
- **Use Case**: Resilience validation

```rust
// From performance_planner.rs (line 510)
Assertion {
    assertion_type: "recovery_time".to_string(),
    expected: json!(stress_criteria.recovery_time),
    path: None,
}
```

---

## Spike Test Assertions

Validate system behavior during traffic spikes.

### `spike_handling`
- **Operator**: `==`
- **Type**: `string`
- **Description**: Spike handling result
- **Example**: `graceful`
- **Use Case**: Validate graceful spike handling

```rust
// From performance_planner.rs (line 558)
Assertion {
    assertion_type: "spike_handling".to_string(),
    expected: json!(spike_criteria.spike_handling),
    path: None,
}
```

---

## Workflow Assertions

Validate multi-step workflow completion.

### `workflow_completion_rate`
- **Operator**: `>`
- **Type**: `percentage`
- **Description**: Workflow completion rate threshold
- **Example**: `0.95` (95%)
- **Use Case**: End-to-end workflow success rate

```rust
// From performance_planner.rs (line 611)
Assertion {
    assertion_type: "workflow_completion_rate".to_string(),
    expected: json!(workflow_criteria.workflow_completion_rate),
    path: None,
}
```

### `average_workflow_time`
- **Operator**: `<`
- **Type**: `duration`
- **Description**: Average workflow completion time
- **Example**: `5000ms`
- **Use Case**: Workflow performance validation

```rust
// From performance_planner.rs (line 616)
Assertion {
    assertion_type: "average_workflow_time".to_string(),
    expected: json!(workflow_criteria.average_workflow_time),
    path: None,
}
```

### `journey_completion_rate_gt`
- **Operator**: `>`
- **Type**: `percentage`
- **Description**: User journey completion rate
- **Example**: `0.90` (90%)
- **Use Case**: User journey success validation

```rust
// From performance_planner.rs (line 1341)
Assertion {
    assertion_type: "journey_completion_rate_gt".to_string(),
    expected: json!(0.90),
    path: None,
}
```

---

## Usage Examples

### Python Example (Test Case Generation)

```python
from sentinel_backend.common.assertion_registry import (
    AssertionRegistry,
    validate_assertion_type,
    get_assertion_info
)

# Validate assertion type
assertion_type = "response_time_p95_lt"
if validate_assertion_type(assertion_type):
    print(f"✓ {assertion_type} is valid")

# Get assertion info
info = get_assertion_info(assertion_type)
print(f"Operator: {info['operator']}")
print(f"Type: {info['type']}")
print(f"Description: {info['description']}")
print(f"Example: {info['example']}")

# Create test case with assertions
test_case = {
    "test_name": "API Performance Validation",
    "assertions": [
        {
            "assertion_type": "status_code_in",
            "expected": [200, 201]
        },
        {
            "assertion_type": "response_time_p95_lt",
            "expected": "500ms"
        },
        {
            "assertion_type": "error_rate_lt",
            "expected": 0.01
        }
    ]
}
```

### Rust Example (Performance Planner)

```rust
use crate::types::Assertion;
use serde_json::json;

// Create performance assertions (from performance_planner.rs)
let assertions = vec![
    // Response time assertion
    Assertion {
        assertion_type: "response_time_p99_lt".to_string(),
        expected: json!("1000ms"),
        path: None,
    },
    // Throughput assertion
    Assertion {
        assertion_type: "throughput_gt".to_string(),
        expected: json!(1000),
        path: None,
    },
    // Memory leak detection
    Assertion {
        assertion_type: "memory_leak_detection_eq".to_string(),
        expected: json!(false),
        path: None,
    },
    // Performance degradation
    Assertion {
        assertion_type: "performance_degradation_lt".to_string(),
        expected: json!("10%"),
        path: None,
    },
];
```

### Dynamic Percentile Assertions

```rust
// Generate dynamic percentile assertions
for percentile in &percentiles {
    let assertion = Assertion {
        assertion_type: format!("response_time_p{}_lt", percentile.percentile),
        expected: json!(format!("{}ms", percentile.threshold)),
        path: None,
    };
    assertions.push(assertion);
}
```

---

## Validation

### Using AssertionRegistry

```python
from sentinel_backend.common.assertion_registry import AssertionRegistry

# List all supported types
all_types = AssertionRegistry.list_all()
print(f"Total assertion types: {len(all_types)}")

# List by category
by_category = AssertionRegistry.list_by_category()
print(f"Status code assertions: {by_category['status_code']}")
print(f"Response time assertions: {by_category['response_time']}")

# Validate custom assertion type
custom_type = "response_time_p50_lt"
is_valid = AssertionRegistry.validate_assertion_type(custom_type)
print(f"{custom_type} valid: {is_valid}")
```

### Using Regex Validation

```python
from sentinel_backend.common.assertion_registry import validate_assertion_type

# Dynamic percentile validation
assert validate_assertion_type("response_time_p50_lt") == True
assert validate_assertion_type("response_time_p75_lt") == True
assert validate_assertion_type("response_time_p99_9_lt") == True

# Invalid assertion types
assert validate_assertion_type("invalid_assertion") == False
assert validate_assertion_type("response_time_xyz") == False
```

### Suggesting Similar Assertions

```python
from sentinel_backend.common.assertion_registry import suggest_similar_assertions

# Find similar assertion types
suggestions = suggest_similar_assertions("response_time")
print(f"Response time assertions: {suggestions}")

# Output:
# ['response_time_lt', 'response_time_gt', 'response_time_eq',
#  'response_time_p50_lt', 'response_time_p75_lt', 'response_time_p90_lt',
#  'response_time_p95_lt', 'response_time_p99_lt', 'response_time_p99_9_lt']
```

---

## Integration Points

### Python Agents
- **Location**: `/workspaces/api-testing-agents/sentinel_backend/common/assertion_registry.py`
- **Import**: `from sentinel_backend.common.assertion_registry import AssertionRegistry`

### Rust Agents
- **Edge Cases Agent**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/agents/edge_cases.rs`
  - Deprecated: Now uses FunctionalAgent
- **Performance Planner**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/agents/performance_planner.rs`
  - Lines 438, 443, 448, 505, 510, 558, 563, 611, 616, 1258, 1261, 1300, 1303, 1336, 1341, 1546, 1554, 1561, 1568, 1576

### Test Generation
All assertion types are validated at test generation time to ensure:
1. **Type Safety**: Only supported assertion types are used
2. **Consistency**: Same assertions work across Python and Rust
3. **Documentation**: Auto-documentation from registry
4. **Migration**: Easy updates when adding new assertion types

---

## Migration Guide

### From Old Format to assertion_type

**Old Format (Deprecated)**:
```python
{
    "field": "status_code",
    "operator": "in",
    "expected": [200, 201]
}
```

**New Format (Current)**:
```python
{
    "assertion_type": "status_code_in",
    "expected": [200, 201]
}
```

### Adding New Assertion Types

1. **Update Registry** (`assertion_registry.py`):
```python
SUPPORTED_PATTERNS = {
    # ... existing patterns ...
    'new_assertion_type': {
        'operator': '==',
        'type': 'string',
        'description': 'New assertion description',
        'example': 'example_value'
    },
}
```

2. **Update Regex Patterns** (if dynamic):
```python
supported_patterns = [
    # ... existing patterns ...
    r"^new_pattern_\w+$",
]
```

3. **Update Documentation** (this file)

4. **Add Tests** (`test_assertion_registry.py`)

---

## References

- **Regression Risk Analysis**: `/workspaces/api-testing-agents/docs/REGRESSION_RISK_ANALYSIS_PR30.md` (lines 823-843)
- **Performance Planner Agent**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/agents/performance_planner.rs`
- **Types Definition**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/types.rs` (line 52)

---

## Support

For questions or issues with assertion types:
1. Check this reference document
2. Review `/workspaces/api-testing-agents/sentinel_backend/common/assertion_registry.py`
3. Open an issue with examples of the assertion type usage
