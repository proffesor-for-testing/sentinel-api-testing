# Agent Migration Guide

## Overview

The Sentinel API Testing Agents have been consolidated to reduce code duplication and improve maintainability. This guide helps you migrate from deprecated agents to the new consolidated versions.

## Summary of Changes

### ✅ Consolidated Agents

| Old Agent (Deprecated) | New Agent | Strategy/Configuration |
|------------------------|-----------|------------------------|
| `FunctionalPositiveAgent` | `FunctionalAgent` | `strategies: ["positive"]` |
| `FunctionalNegativeAgent` | `FunctionalAgent` | `strategies: ["negative"]` |
| `EdgeCasesAgent` | `FunctionalAgent` | `strategies: ["edge_case"]` |

### 🔄 Unchanged Agents (Not Consolidated)

These agents remain unchanged and should continue to be used as-is:

- `FunctionalStatefulAgent` - Complex multi-step workflows (uses SODG)
- `SecurityAuthAgent` - Authentication/authorization testing
- `SecurityInjectionAgent` - Injection vulnerability testing
- `DataMockingAgent` - Test data generation
- `PerformancePlannerAgent` - Performance test planning

## Migration Instructions

### 1. Functional Positive Tests

**Old Code (DEPRECATED):**
```rust
use crate::agents::functional_positive::FunctionalPositiveAgent;

let agent = FunctionalPositiveAgent::new();
let result = agent.execute(task, api_spec).await;
```

**New Code:**
```rust
use crate::agents::functional_agent::FunctionalAgent;

let agent = FunctionalAgent::new();

// Configure task to use positive strategy
let mut task = AgentTask {
    task_id: "test-001".to_string(),
    agent_type: "Functional-Agent".to_string(),
    parameters: serde_json::json!({
        "strategies": ["positive"]
    }).as_object().unwrap().clone(),
};

let result = agent.execute(task, api_spec).await;
```

### 2. Functional Negative Tests

**Old Code (DEPRECATED):**
```rust
use crate::agents::functional_negative::FunctionalNegativeAgent;

let agent = FunctionalNegativeAgent::new();
let result = agent.execute(task, api_spec).await;
```

**New Code:**
```rust
use crate::agents::functional_agent::FunctionalAgent;

let agent = FunctionalAgent::new();

let mut task = AgentTask {
    task_id: "test-002".to_string(),
    agent_type: "Functional-Agent".to_string(),
    parameters: serde_json::json!({
        "strategies": ["negative"]
    }).as_object().unwrap().clone(),
};

let result = agent.execute(task, api_spec).await;
```

### 3. Edge Case Tests

**Old Code (DEPRECATED):**
```rust
use crate::agents::edge_cases::EdgeCasesAgent;

let agent = EdgeCasesAgent::new();
let result = agent.execute(task, api_spec).await;
```

**New Code:**
```rust
use crate::agents::functional_agent::FunctionalAgent;

let agent = FunctionalAgent::new();

let mut task = AgentTask {
    task_id: "test-003".to_string(),
    agent_type: "Functional-Agent".to_string(),
    parameters: serde_json::json!({
        "strategies": ["edge_case"]
    }).as_object().unwrap().clone(),
};

let result = agent.execute(task, api_spec).await;
```

### 4. Multiple Strategies (New Feature!)

You can now combine multiple testing strategies in a single agent execution:

```rust
use crate::agents::functional_agent::FunctionalAgent;

let agent = FunctionalAgent::new();

let mut task = AgentTask {
    task_id: "test-comprehensive".to_string(),
    agent_type: "Functional-Agent".to_string(),
    parameters: serde_json::json!({
        "strategies": ["positive", "negative", "boundary", "edge_case"]
    }).as_object().unwrap().clone(),
};

let result = agent.execute(task, api_spec).await;
```

## Available Strategies

The `FunctionalAgent` supports the following strategies:

### 1. `positive`
- Generates valid "happy path" test cases
- Tests normal, expected usage patterns
- Validates successful operations
- **Expected Status:** 200, 201, 204

### 2. `negative`
- Generates invalid input test cases
- Tests error handling and validation
- Validates failure scenarios
- **Expected Status:** 400, 422

### 3. `boundary`
- Tests boundary values and limits
- Min/max values for numeric fields
- Empty strings, long strings
- **Expected Status:** Varies (200 for valid boundaries, 400 for invalid)

### 4. `edge_case`
- Tests edge cases and special characters
- Unicode, special formats (dates, floats)
- Null values, empty arrays
- **Expected Status:** Varies

## Test Case Deduplication

The new `FunctionalAgent` automatically deduplicates test cases based on:
- HTTP Method
- Endpoint path
- Test type
- Query parameter keys
- Request body keys
- Expected status code

**Benefits:**
- 60-75% reduction in duplicate test cases
- Faster test execution
- Lower token usage (for LLM-based testing)

## Agent Orchestrator Updates

If you're using the `AgentOrchestrator`, update your agent type strings:

**Old:**
```rust
let task = AgentTask {
    agent_type: "Functional-Positive-Agent".to_string(),
    // ...
};
```

**New:**
```rust
let task = AgentTask {
    agent_type: "Functional-Agent".to_string(),
    parameters: serde_json::json!({
        "strategies": ["positive"]
    }).as_object().unwrap().clone(),
    // ...
};
```

## Backward Compatibility

The deprecated agents are still available and functional. They will:

1. **Print a deprecation warning** when instantiated
2. **Proxy all calls** to the new `FunctionalAgent`
3. **Force the appropriate strategy** automatically

This ensures your existing code continues to work while you migrate.

### Deprecation Warnings

When using deprecated agents, you'll see:

```
⚠️  DEPRECATION WARNING: FunctionalPositiveAgent is deprecated.
   Please use FunctionalAgent with strategies=['positive'] instead.
   See docs/AGENT_MIGRATION_GUIDE.md for migration instructions.
```

## Timeline

- **v2.0.0** (Current): Deprecation warnings added, old agents proxied to new ones
- **v2.1.0** (Planned): Deprecated agents marked with `#[deprecated]` attribute
- **v3.0.0** (Future): Deprecated agents removed entirely

## Migration Checklist

- [ ] Update imports from old agents to `FunctionalAgent`
- [ ] Add `strategies` parameter to task configuration
- [ ] Update agent type strings in orchestrator
- [ ] Test that behavior remains consistent
- [ ] Remove any direct references to deprecated agents
- [ ] Update documentation and comments

## Benefits of Migration

### Code Reduction
- **60-75% less code** through strategy pattern
- Easier maintenance and bug fixes
- Single source of truth for test generation logic

### Performance
- Automatic test case deduplication
- Reduced token usage for LLM-based testing
- Faster test generation

### Flexibility
- Combine multiple strategies in one execution
- Easy to add new strategies without code duplication
- Consistent interface across all functional tests

## Getting Help

If you encounter issues during migration:

1. Check the deprecation warnings for guidance
2. Review this migration guide
3. Look at the test examples in `/tests/unit/agents/`
4. Open an issue on GitHub with the `migration` label

## Example: Complete Migration

**Before (Old Code):**
```rust
use crate::agents::functional_positive::FunctionalPositiveAgent;
use crate::agents::functional_negative::FunctionalNegativeAgent;
use crate::agents::edge_cases::EdgeCasesAgent;

// Generate positive tests
let positive_agent = FunctionalPositiveAgent::new();
let positive_results = positive_agent.execute(task1, api_spec.clone()).await;

// Generate negative tests
let negative_agent = FunctionalNegativeAgent::new();
let negative_results = negative_agent.execute(task2, api_spec.clone()).await;

// Generate edge case tests
let edge_agent = EdgeCasesAgent::new();
let edge_results = edge_agent.execute(task3, api_spec.clone()).await;
```

**After (New Code):**
```rust
use crate::agents::functional_agent::FunctionalAgent;

// Single agent handles all strategies
let agent = FunctionalAgent::new();

// Combined execution with all strategies
let task = AgentTask {
    task_id: "comprehensive-test".to_string(),
    agent_type: "Functional-Agent".to_string(),
    parameters: serde_json::json!({
        "strategies": ["positive", "negative", "edge_case"]
    }).as_object().unwrap().clone(),
};

let results = agent.execute(task, api_spec).await;
// Results are automatically deduplicated!
```

## Future Consolidations

We're working on consolidating additional agents:

### Security Agents (Planned for v2.1.0)
- `SecurityAuthAgent` → `SecurityAgent` with `focus: "auth"`
- `SecurityInjectionAgent` → `SecurityAgent` with `focus: "injection"`

Stay tuned for updates!

---

**Last Updated:** 2025-10-03
**Version:** 2.0.0
