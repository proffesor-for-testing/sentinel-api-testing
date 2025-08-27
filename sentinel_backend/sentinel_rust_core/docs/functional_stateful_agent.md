# Functional-Stateful-Agent Documentation

## Overview

The Functional-Stateful-Agent is a sophisticated AI testing agent that generates complex, multi-step test scenarios by building and analyzing a Semantic Operation Dependency Graph (SODG). It specializes in creating stateful test cases that validate business workflows spanning multiple API operations with proper state management.

## Key Features

### 1. Semantic Operation Dependency Graph (SODG)
- **Automatic Graph Construction**: Builds dependency relationships between API operations
- **Pattern Recognition**: Identifies common workflow patterns (CRUD, parent-child, filtering)
- **State Tracking**: Manages data flow between operations using extract/inject rules

### 2. Dependency Types
The agent recognizes five types of operation dependencies:

- **RESOURCE_ID**: `POST /users → GET /users/{id}`
- **PARENT_CHILD**: `POST /users → POST /users/{userId}/posts`
- **FILTER_REFERENCE**: `POST /users → GET /posts?userId={id}`
- **UPDATE_REFERENCE**: `POST /users → PUT /users/{id}`
- **DELETE_REFERENCE**: `POST /users → DELETE /users/{id}`

### 3. Workflow Patterns
The agent automatically identifies and generates test scenarios for:

- **CRUD Lifecycles**: Complete create-read-update-delete workflows
- **Parent-Child Resources**: Hierarchical resource creation and management
- **Filtered Queries**: Resource creation followed by filtered retrieval

### 4. State Management
- **Extract Rules**: Define how to extract data from API responses
- **Inject Rules**: Specify how to inject extracted data into subsequent requests
- **Variable Tracking**: Maintain state variables throughout test execution
- **Cleanup Operations**: Automatically generate cleanup steps for created resources

## Data Structures

### OperationNode
Represents an API operation in the dependency graph:
```rust
pub struct OperationNode {
    pub operation_id: String,
    pub path: String,
    pub method: String,
    pub operation_spec: Value,
    pub dependencies: Vec<OperationEdge>,
    pub dependents: Vec<OperationEdge>,
}
```

### OperationEdge
Defines dependency relationships between operations:
```rust
pub struct OperationEdge {
    pub from_operation: String,
    pub to_operation: String,
    pub dependency_type: DependencyType,
    pub extract_rules: Vec<ExtractRule>,
    pub inject_rules: Vec<InjectRule>,
    pub description: String,
}
```

### ExtractRule
Defines how to extract data from responses:
```rust
pub struct ExtractRule {
    pub source_field: String,      // "id", "data.userId"
    pub target_variable: String,   // "resource_id"
    pub description: String,
}
```

### InjectRule
Defines how to inject data into requests:
```rust
pub struct InjectRule {
    pub target_location: String,   // "path", "query", "body", "header"
    pub target_field: String,      // Field name or parameter name
    pub source_variable: String,   // Variable containing the value
    pub description: String,
}
```

## Example Workflow

### 1. CRUD Lifecycle Test
```json
{
  "scenario_id": "create_read_users_3_steps",
  "description": "Create and read users workflow",
  "operations": [
    {
      "operation_id": "createUser",
      "method": "POST",
      "path": "/users",
      "description": "Step 1: POST /users",
      "extract_rules": [{
        "source_field": "id",
        "target_variable": "resource_id",
        "description": "Extract user ID from creation response"
      }],
      "request_body": {
        "name": "Stateful Test Resource",
        "email": "stateful.test@example.com"
      }
    },
    {
      "operation_id": "getUserById",
      "method": "GET",
      "path": "/users/{id}",
      "description": "Step 2: GET /users/{id}",
      "inject_rules": [{
        "target_location": "path",
        "target_field": "id",
        "source_variable": "resource_id",
        "description": "Inject user ID into path"
      }]
    }
  ],
  "cleanup_operations": [
    {
      "operation_id": "deleteUser",
      "method": "DELETE",
      "path": "/users/{id}",
      "description": "Cleanup: Delete created user"
    }
  ]
}
```

### 2. Parent-Child Resource Test
```json
{
  "scenario_id": "parent_child_users_posts",
  "description": "Create parent users then child posts",
  "operations": [
    {
      "operation_id": "createUser",
      "method": "POST",
      "path": "/users",
      "extract_rules": [{
        "source_field": "id",
        "target_variable": "userId",
        "description": "Extract parent user ID"
      }]
    },
    {
      "operation_id": "createPost",
      "method": "POST",
      "path": "/users/{userId}/posts",
      "inject_rules": [{
        "target_location": "path",
        "target_field": "userId",
        "source_variable": "userId",
        "description": "Inject parent user ID into child resource path"
      }]
    }
  ]
}
```

## Test Case Generation

The agent generates test cases with the following structure:
- **Method**: `STATEFUL` (special marker)
- **Path**: `multi-step` (special marker)
- **Test Type**: `Functional-Stateful-Agent`
- **Assertions**: Contains the complete workflow scenario

## Integration

The agent is automatically registered in the `AgentOrchestrator` and can be invoked with:

```rust
let task = AgentTask {
    task_id: "test-001".to_string(),
    spec_id: "api-spec".to_string(),
    agent_type: "Functional-Stateful-Agent".to_string(),
    parameters: HashMap::new(),
    target_environment: None,
};

let result = orchestrator.execute_task(task, api_spec).await;
```

## Metadata Output

The agent provides comprehensive metadata about the generated tests:
- `total_operations`: Number of operations in the SODG
- `workflow_patterns`: Number of workflow patterns identified
- `total_scenarios`: Number of test scenarios generated
- `total_test_cases`: Total test cases created
- `generation_strategy`: "sodg_based_stateful_workflows"
- `supported_patterns`: List of workflow pattern types found

## Benefits

1. **Comprehensive Coverage**: Tests complex business workflows, not just individual endpoints
2. **Realistic Testing**: Validates actual user journeys and data flows
3. **Automatic State Management**: Handles data dependencies between operations automatically
4. **Pattern Recognition**: Identifies common API patterns without manual configuration
5. **Clean Architecture**: Provides proper cleanup for created resources
6. **Rich Metadata**: Offers detailed insights into the testing strategy and coverage

## Future Enhancements

- LLM integration for more sophisticated workflow generation
- Support for conditional workflows and branching logic
- Advanced error recovery and retry mechanisms
- Performance testing integration for multi-step scenarios
- Support for complex data transformations between steps