# Sentinel Common Utilities

This package provides common utilities and registries used across the Sentinel backend services.

## Assertion Registry

The `AssertionRegistry` provides centralized validation and documentation for all supported assertion types used in test case generation.

### Quick Start

```python
from sentinel_backend.common.assertion_registry import (
    AssertionRegistry,
    validate_assertion_type,
    get_assertion_info,
    suggest_similar_assertions,
)

# Validate assertion type
if AssertionRegistry.validate_assertion_type('response_time_p95_lt'):
    print("Valid assertion type!")

# Get operator for assertion type
operator = AssertionRegistry.get_operator('status_code_in')  # Returns 'in'

# Get complete info
info = get_assertion_info('response_time_p95_lt')
print(f"Operator: {info['operator']}")
print(f"Type: {info['type']}")
print(f"Description: {info['description']}")
print(f"Example: {info['example']}")

# List all supported types
all_types = AssertionRegistry.list_all()
print(f"Total assertion types: {len(all_types)}")

# Get suggestions for similar assertions
suggestions = suggest_similar_assertions('response_time')
print(f"Response time assertions: {suggestions}")
```

### Supported Assertion Types

The registry includes **31+ assertion types** across 9 categories:

- **Status Code** (5): `status_code_in`, `status_code_eq`, `status_code_ne`, etc.
- **Response Time** (9): `response_time_lt`, `response_time_p50_lt`, `response_time_p95_lt`, etc.
- **Throughput** (4): `throughput_gt`, `throughput_lt`, `throughput_min`, `throughput_rps_gt`
- **Error Rate** (3): `error_rate_lt`, `error_rate`, `error_rate_during_spike`
- **Performance** (2): `memory_leak_detection_eq`, `performance_degradation_lt`
- **User Experience** (2): `user_experience_score_gt`, `user_satisfaction_gt`
- **Stress Test** (2): `breaking_point_identified`, `recovery_time`
- **Spike Test** (1): `spike_handling`
- **Workflow** (3): `workflow_completion_rate`, `average_workflow_time`, `journey_completion_rate_gt`

### Documentation

For complete documentation including all assertion types, examples, and usage patterns, see:

- **Full Reference**: `/workspaces/api-testing-agents/docs/ASSERTION_TYPE_REFERENCE.md`
- **Regression Analysis**: `/workspaces/api-testing-agents/docs/REGRESSION_RISK_ANALYSIS_PR30.md`

### Testing

Unit tests are located in `/workspaces/api-testing-agents/sentinel_backend/tests/common/test_assertion_registry.py`

Run tests:
```bash
cd sentinel_backend
source venv/bin/activate
pytest tests/common/test_assertion_registry.py -v
```

### Integration with Rust Agents

The assertion types defined in this registry are used by both Python and Rust agent implementations:

- **Performance Planner Agent**: `sentinel_rust_core/src/agents/performance_planner.rs`
- **Functional Agent**: `sentinel_rust_core/src/agents/functional_agent.rs`
- **Type Definitions**: `sentinel_rust_core/src/types.rs`

Example Rust usage:
```rust
use crate::types::Assertion;

let assertion = Assertion {
    assertion_type: "response_time_p95_lt".to_string(),
    expected: json!("500ms"),
    path: None,
};
```

### Migration from Old Format

**Old format (deprecated)**:
```python
{
    "field": "status_code",
    "operator": "in",
    "expected": [200, 201]
}
```

**New format (current)**:
```python
{
    "assertion_type": "status_code_in",
    "expected": [200, 201]
}
```

The `validate_assertion_type()` function supports both exact matches and regex patterns for dynamic assertions like percentile response times.
