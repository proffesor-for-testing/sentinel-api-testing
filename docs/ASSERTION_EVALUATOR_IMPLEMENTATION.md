# Assertion Evaluator Implementation

**Document Version**: 1.0
**Date**: 2025-10-29
**Related**: [REGRESSION_RISK_ANALYSIS_PR30.md](./REGRESSION_RISK_ANALYSIS_PR30.md) - Line 282-289

---

## Executive Summary

This document addresses the **CRITICAL GAP** identified in the regression analysis: "We don't know how `assertion_type` is evaluated by the test execution engine."

**KEY FINDING**: The current execution service has **MINIMAL assertion evaluation** - it only validates `response_schema` assertions. All other assertion types (including the complex ones like `response_time_p95_lt`, `status_code_in`, etc.) are **STORED BUT NOT EVALUATED**.

---

## Overview

### Assertion Data Model

**Rust Type Definition** (`sentinel_backend/sentinel_rust_core/src/types.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub assertion_type: String,
    pub expected: serde_json::Value,
    pub path: Option<String>, // JSON path for response validation
}
```

**Key Fields**:
- `assertion_type`: String identifier (e.g., `"status_code_in"`, `"response_time_p95_lt"`)
- `expected`: Expected value (can be any JSON type: number, string, array, object)
- `path`: Optional JSON path for extracting values from response

---

## Current Evaluator Implementation

### Location
`sentinel_backend/execution_service/main.py` (lines 321-337)
`sentinel_backend/execution_service/app_factory.py` (lines 285-296)

### Implementation Analysis

```python
async def validate_assertion(assertion: Dict[str, Any], response: httpx.Response) -> Optional[Dict[str, Any]]:
    """Validate a single assertion against the response."""
    assertion_type = assertion.get("type")

    if assertion_type == "response_schema":
        # Basic schema validation (simplified for MVP)
        try:
            response.json()  # Just check if it's valid JSON
            return None
        except:
            return {
                "type": "response_schema",
                "message": "Response is not valid JSON"
            }

    # Add more assertion types as needed
    return None
```

### Critical Findings

1. ❌ **NO OPERATOR PARSING**: The function does NOT parse suffix operators from `assertion_type`
2. ❌ **NO LOOKUP TABLE**: No mapping exists from assertion types to evaluation functions
3. ❌ **NO COMPARISON LOGIC**: No less-than, greater-than, or "in" comparisons are implemented
4. ❌ **ONLY ONE TYPE SUPPORTED**: Only `response_schema` is validated (basic JSON check)
5. ❌ **ALL OTHER ASSERTIONS IGNORED**: Assertions like `status_code_in`, `response_time_p95_lt` are stored but not evaluated

---

## Supported Assertion Types (Generation Only)

The Rust agents **GENERATE** these assertion types, but the execution service **DOES NOT EVALUATE** them:

### 1. Status Code Assertions
| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `status_code_in` | `in` | Status code in list | `[200, 201, 204]` | Security-Auth |

**Generated In**:
- `security_auth.rs:61, 98, 135` - BOLA, BFLA, auth bypass tests

---

### 2. Performance Assertions

#### Response Time Assertions
| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `response_time_p95` | `==` | P95 response time equals | `"2000ms"` | Performance-Planner |
| `response_time_p99_lt` | `<` | P99 response time less than | `"5000ms"` | Performance-Planner |
| `response_time_p{N}_lt` | `<` | Pxx response time less than | `"3000ms"` (dynamic percentile) | Performance-Planner |

**Generated In**:
- `performance_planner.rs:438` - Load test assertions
- `performance_planner.rs:1258` - Volume test assertions
- `performance_planner.rs:1546` - Dynamic percentile assertions

#### Throughput Assertions
| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `throughput_min` | `>=` | Minimum throughput | `"100 rps"` | Performance-Planner |
| `throughput_gt` | `>` | Throughput greater than | `50` (numeric) | Performance-Planner |
| `throughput_rps_gt` | `>` | Throughput (RPS) greater than | `100` | Performance-Planner |

**Generated In**:
- `performance_planner.rs:448, 1261, 1554`

#### Error Rate Assertions
| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `error_rate` | `==` | Error rate equals | `"< 1%"` | Performance-Planner |
| `error_rate_lt` | `<` | Error rate less than | `0.05` | Performance-Planner |
| `error_rate_during_spike` | `<` | Error rate during spike | `"< 5%"` | Performance-Planner |

**Generated In**:
- `performance_planner.rs:443, 563, 1561`

---

### 3. Security Assertions

| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `access_control_check` | custom | Access control validation | `{"type": "bfla", "role": "user", "function": "delete"}` | Security-Auth |
| `privilege_escalation_check` | custom | Privilege escalation detection | `{"escalation_prevented": true}` | Security-Auth |
| `jwt_security_check` | custom | JWT token validation | `{"token_valid": false}` | Security-Auth |
| `session_security_check` | custom | Session security validation | `{"session_hijack_prevented": true}` | Security-Auth |
| `rate_limiting_check` | custom | Rate limiting enforcement | `{"rate_limit_enforced": true}` | Security-Auth |
| `mass_assignment_check` | custom | Mass assignment protection | `{"protected_fields": ["role", "admin"]}` | Security-Auth |
| `cors_security_check` | custom | CORS policy validation | `{"cors_properly_configured": true}` | Security-Auth |
| `security_check` | custom | Generic security validation | `{"vulnerable": false}` | Security-Injection |

**Generated In**:
- `security_auth.rs:167, 205, 244, 280, 319, 359, 395`
- `security_injection.rs:912, 973, 1062`

---

### 4. Workflow Assertions

| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `stateful_workflow` | custom | Multi-step workflow validation | `{"steps_completed": 5, "total_steps": 5}` | Functional-Stateful |
| `workflow_completion_rate` | `>=` | Workflow completion percentage | `"95%"` | Performance-Planner |
| `average_workflow_time` | `<` | Average workflow execution time | `"30s"` | Performance-Planner |

**Generated In**:
- `functional_stateful.rs:994`
- `performance_planner.rs:611, 616`

---

### 5. Stress & Capacity Assertions

| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `breaking_point_identified` | `==` | Breaking point detected | `true` | Performance-Planner |
| `recovery_time` | `<` | System recovery time | `"5m"` | Performance-Planner |
| `spike_handling` | custom | Spike handling capability | `"graceful_degradation"` | Performance-Planner |
| `memory_leak_detection_eq` | `==` | Memory leak detection | `false` | Performance-Planner |
| `performance_degradation_lt` | `<` | Performance degradation percentage | `10` | Performance-Planner |

**Generated In**:
- `performance_planner.rs:505, 510, 558, 1300, 1303`

---

### 6. User Experience Assertions

| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `user_experience_score_gt` | `>` | User experience score | `0.8` | Performance-Planner |
| `journey_completion_rate_gt` | `>` | User journey completion rate | `0.95` | Performance-Planner |
| `user_satisfaction_gt` | `>` | User satisfaction score | `0.9` | Performance-Planner |

**Generated In**:
- `performance_planner.rs:1336, 1341, 1568`

---

### 7. Dynamic Assertions

| assertion_type | Operator | Description | Example Expected Value | Agent |
|----------------|----------|-------------|------------------------|-------|
| `{metric}_gt` | `>` | Dynamic metric greater than | Variable | Performance-Planner |
| `{metric}_lt` | `<` | Dynamic metric less than | Variable | Performance-Planner |

**Pattern** (line 1576):
```rust
assertion_type: if slo.threshold.starts_with('>') {
    format!("{}_gt", slo.metric)
} else {
    format!("{}_lt", slo.metric)
}
```

This allows runtime generation of assertions like:
- `latency_p50_lt`
- `availability_gt`
- `saturation_lt`

---

## Evaluation Logic (MISSING IMPLEMENTATION)

### Expected Behavior (NOT IMPLEMENTED)

The evaluator SHOULD parse assertion types and extract operators:

```python
# EXAMPLE (NOT CURRENTLY IMPLEMENTED)
def evaluate_assertion(assertion: Assertion, response: httpx.Response) -> bool:
    assertion_type = assertion["assertion_type"]
    expected = assertion["expected"]

    # Parse operator suffix
    if assertion_type.endswith("_lt"):
        operator = "<"
        metric = assertion_type[:-3]
    elif assertion_type.endswith("_gt"):
        operator = ">"
        metric = assertion_type[:-3]
    elif assertion_type.endswith("_eq"):
        operator = "=="
        metric = assertion_type[:-3]
    elif assertion_type.endswith("_in"):
        operator = "in"
        metric = assertion_type[:-3]
    else:
        # No operator suffix, exact match
        operator = "=="
        metric = assertion_type

    # Extract actual value based on metric
    actual = extract_metric(response, metric, assertion.get("path"))

    # Perform comparison
    return compare(actual, operator, expected)
```

### Required Helper Functions (NOT IMPLEMENTED)

```python
def extract_metric(response: httpx.Response, metric: str, json_path: str = None) -> Any:
    """Extract metric value from response based on metric type."""

    if metric == "status_code":
        return response.status_code

    elif metric.startswith("response_time"):
        # Would need to be calculated during execution
        # Currently not tracked in execution_service/main.py
        return response.elapsed.total_seconds() * 1000

    elif metric in ["throughput", "error_rate", "memory_leak_detection"]:
        # These require aggregation across multiple requests
        # Not possible with single response validation
        raise NotImplementedError("Metric requires test run aggregation")

    elif json_path:
        # Extract from JSON response body
        body = response.json()
        return extract_json_path(body, json_path)

    else:
        raise ValueError(f"Unknown metric: {metric}")


def compare(actual: Any, operator: str, expected: Any) -> bool:
    """Perform comparison based on operator."""

    if operator == "<":
        return actual < expected
    elif operator == ">":
        return actual > expected
    elif operator == "==":
        return actual == expected
    elif operator == "in":
        return actual in expected
    else:
        raise ValueError(f"Unknown operator: {operator}")
```

---

## Backward Compatibility

### Question: Are old `field` + `operator` assertions still supported?

**ANSWER: NO**

1. **No legacy support code found** in execution service
2. **Assertion struct does NOT have `field` or `operator` fields** (see `types.rs:49-56`)
3. **All agents use `assertion_type` pattern** (no old-style assertions generated)

### Migration History

Based on PR #30 analysis, the migration was:
```
OLD (REMOVED):
{
  "field": "response_time",
  "operator": "lt",
  "expected": 2000
}

NEW (CURRENT):
{
  "assertion_type": "response_time_lt",
  "expected": 2000,
  "path": null
}
```

**NO backward compatibility layer exists** - old assertions would fail to deserialize.

---

## Code Locations

### Assertion Type Definitions
- **Rust Struct**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/types.rs:49-56`

### Assertion Generators (Rust Agents)
- **Security-Auth**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/agents/security_auth.rs`
  - Lines: 61, 98, 135, 167, 205, 244, 280, 319, 359, 395
- **Security-Injection**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/agents/security_injection.rs`
  - Lines: 912, 973, 1062
- **Performance-Planner**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/agents/performance_planner.rs`
  - Lines: 438, 443, 448, 505, 510, 558, 563, 611, 616, 1258, 1261, 1300, 1303, 1336, 1341, 1546, 1554, 1561, 1568, 1576
- **Functional-Stateful**: `/workspaces/api-testing-agents/sentinel_backend/sentinel_rust_core/src/agents/functional_stateful.rs`
  - Line: 994

### Assertion Evaluators (Python Execution Service)
- **Main Evaluator**: `/workspaces/api-testing-agents/sentinel_backend/execution_service/main.py:321-337`
- **Factory Evaluator**: `/workspaces/api-testing-agents/sentinel_backend/execution_service/app_factory.py:285-296`

---

## Regression Risk Assessment

### Critical Gaps Identified

1. **NO EVALUATION LOGIC** ⚠️
   - **Impact**: HIGH - All generated assertions except `response_schema` are ignored
   - **Risk**: Tests pass even when assertions should fail
   - **Evidence**: `validate_assertion()` returns `None` for all unknown types

2. **NO OPERATOR PARSING** ⚠️
   - **Impact**: HIGH - Cannot distinguish between `_lt`, `_gt`, `_eq`, `_in` operators
   - **Risk**: Cannot implement comparison logic without parser
   - **Evidence**: No string parsing code in evaluator

3. **NO METRIC EXTRACTION** ⚠️
   - **Impact**: CRITICAL - Cannot extract values like response time, throughput
   - **Risk**: Even if evaluator existed, no way to get actual values
   - **Evidence**: Execution service doesn't track response times or aggregated metrics

4. **NO BACKWARD COMPATIBILITY** ⚠️
   - **Impact**: MEDIUM - Old assertions will fail deserialization
   - **Risk**: Any legacy test data becomes invalid
   - **Evidence**: No `field`/`operator` fields in Assertion struct

---

## Recommendations

### Immediate Actions (Critical)

1. **Implement Basic Assertion Evaluator** (HIGHEST PRIORITY)
   ```python
   # Implement for critical assertion types:
   # - status_code_in
   # - response_time_lt/gt
   # - error_rate_lt
   ```

2. **Add Response Time Tracking**
   ```python
   # Modify execute_single_test_case() to track:
   # - Total response time (already done at line 279)
   # - Need to make available to validate_assertion()
   ```

3. **Implement Operator Parser**
   ```python
   # Add function to parse assertion_type:
   # "response_time_p95_lt" → ("response_time_p95", "lt")
   ```

### Short-Term Actions (High Priority)

4. **Add Aggregation Support**
   - Throughput requires counting requests
   - Error rate requires tracking failures
   - Percentiles require collecting all response times

5. **Create Assertion Type Registry**
   ```python
   ASSERTION_EVALUATORS = {
       "status_code_in": evaluate_status_code_in,
       "response_time_lt": evaluate_response_time_lt,
       "response_time_p95_lt": evaluate_response_time_percentile_lt,
       # ... etc
   }
   ```

### Long-Term Actions (Medium Priority)

6. **Consider Backward Compatibility Layer** (if needed)
   ```python
   def migrate_legacy_assertion(field: str, operator: str, expected: Any) -> Assertion:
       return Assertion(
           assertion_type=f"{field}_{operator}",
           expected=expected,
           path=None
       )
   ```

7. **Add Assertion Validation Tests**
   - Test each assertion type with known good/bad values
   - Verify operator parsing works correctly
   - Check edge cases (malformed assertion types)

---

## Lookup Table: Complete Assertion Type Reference

### Category: Status & Response (1 type)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `status_code_in` | `in` | ❌ NO | Security-Auth | 🔴 CRITICAL |

### Category: Performance - Response Time (4 types)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `response_time_p95` | `==` | ❌ NO | Performance-Planner | 🔴 CRITICAL |
| `response_time_p99_lt` | `<` | ❌ NO | Performance-Planner | 🔴 CRITICAL |
| `response_time_p{N}_lt` | `<` | ❌ NO | Performance-Planner | 🟡 HIGH |
| `response_schema` | validate | ✅ YES | All | ✅ DONE |

### Category: Performance - Throughput (3 types)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `throughput_min` | `>=` | ❌ NO | Performance-Planner | 🔴 CRITICAL |
| `throughput_gt` | `>` | ❌ NO | Performance-Planner | 🔴 CRITICAL |
| `throughput_rps_gt` | `>` | ❌ NO | Performance-Planner | 🔴 CRITICAL |

### Category: Performance - Error Rate (3 types)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `error_rate` | `==` | ❌ NO | Performance-Planner | 🔴 CRITICAL |
| `error_rate_lt` | `<` | ❌ NO | Performance-Planner | 🔴 CRITICAL |
| `error_rate_during_spike` | `<` | ❌ NO | Performance-Planner | 🟡 HIGH |

### Category: Security (8 types)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `access_control_check` | custom | ❌ NO | Security-Auth | 🔴 CRITICAL |
| `privilege_escalation_check` | custom | ❌ NO | Security-Auth | 🔴 CRITICAL |
| `jwt_security_check` | custom | ❌ NO | Security-Auth | 🔴 CRITICAL |
| `session_security_check` | custom | ❌ NO | Security-Auth | 🟡 HIGH |
| `rate_limiting_check` | custom | ❌ NO | Security-Auth | 🟡 HIGH |
| `mass_assignment_check` | custom | ❌ NO | Security-Auth | 🟡 HIGH |
| `cors_security_check` | custom | ❌ NO | Security-Auth | 🟢 MEDIUM |
| `security_check` | custom | ❌ NO | Security-Injection | 🟡 HIGH |

### Category: Workflow (3 types)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `stateful_workflow` | custom | ❌ NO | Functional-Stateful | 🔴 CRITICAL |
| `workflow_completion_rate` | `>=` | ❌ NO | Performance-Planner | 🟡 HIGH |
| `average_workflow_time` | `<` | ❌ NO | Performance-Planner | 🟡 HIGH |

### Category: Stress & Capacity (5 types)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `breaking_point_identified` | `==` | ❌ NO | Performance-Planner | 🟡 HIGH |
| `recovery_time` | `<` | ❌ NO | Performance-Planner | 🟡 HIGH |
| `spike_handling` | custom | ❌ NO | Performance-Planner | 🟡 HIGH |
| `memory_leak_detection_eq` | `==` | ❌ NO | Performance-Planner | 🔴 CRITICAL |
| `performance_degradation_lt` | `<` | ❌ NO | Performance-Planner | 🟡 HIGH |

### Category: User Experience (3 types)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `user_experience_score_gt` | `>` | ❌ NO | Performance-Planner | 🟢 MEDIUM |
| `journey_completion_rate_gt` | `>` | ❌ NO | Performance-Planner | 🟢 MEDIUM |
| `user_satisfaction_gt` | `>` | ❌ NO | Performance-Planner | 🟢 MEDIUM |

### Category: Dynamic Assertions (2 patterns)
| assertion_type | Operator | Implemented? | Agent | Priority |
|----------------|----------|--------------|-------|----------|
| `{metric}_gt` | `>` | ❌ NO | Performance-Planner | 🟡 HIGH |
| `{metric}_lt` | `<` | ❌ NO | Performance-Planner | 🟡 HIGH |

---

## Summary Statistics

- **Total Assertion Types**: 31+ (including dynamic patterns)
- **Implemented**: 1 (`response_schema`)
- **Not Implemented**: 30+
- **Implementation Coverage**: **3.2%**
- **Critical Priority**: 13 assertion types
- **High Priority**: 13 assertion types
- **Medium Priority**: 5 assertion types

---

## Conclusion

**The execution service currently has a CRITICAL GAP**: it generates comprehensive assertions but evaluates almost none of them. This represents a **96.8% evaluation gap** that poses significant risk to test reliability.

**The three key questions from the risk analysis are answered**:

1. ❌ **Does the evaluator parse `assertion_type` string and extract operator?**
   → **NO** - No parsing logic exists

2. ❌ **Is there a lookup table mapping assertion types to evaluation functions?**
   → **NO** - Only hardcoded check for `response_schema`

3. ❌ **Are old `field` + `operator` assertions still supported?**
   → **NO** - No backward compatibility layer

**Recommendation**: Implement assertion evaluator as HIGHEST PRIORITY before relying on test results for production decisions.
