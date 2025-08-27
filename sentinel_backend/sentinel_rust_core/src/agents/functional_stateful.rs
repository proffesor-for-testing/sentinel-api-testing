//! Functional-Stateful-Agent: Generates complex, multi-step test scenarios.
//! 
//! This agent focuses on creating test cases that validate complex business workflows
//! spanning multiple API calls, using a Semantic Operation Dependency Graph (SODG)
//! to manage state between operations and create realistic end-to-end test scenarios.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use crate::agents::{Agent, BaseAgent};
use crate::agents::utils::*;
use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo, Assertion};

/// Types of dependencies between operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DependencyType {
    #[serde(rename = "resource_id")]
    ResourceId, // POST /users -> GET /users/{id}
    #[serde(rename = "parent_child")]
    ParentChild, // POST /users -> POST /users/{id}/posts
    #[serde(rename = "filter_reference")]
    FilterReference, // POST /users -> GET /posts?userId={id}
    #[serde(rename = "update_reference")]
    UpdateReference, // POST /users -> PUT /users/{id}
    #[serde(rename = "delete_reference")]
    DeleteReference, // POST /users -> DELETE /users/{id}
}

/// Rule for extracting data from a response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractRule {
    pub source_field: String, // JSON path to extract from (e.g., "id", "data.userId")
    pub target_variable: String, // Variable name to store the extracted value
    pub description: String,
}

/// Rule for injecting extracted data into a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectRule {
    pub target_location: String, // Where to inject: "path", "query", "body", "header"
    pub target_field: String,    // Field name or path parameter name
    pub source_variable: String, // Variable name containing the value to inject
    pub description: String,
}

/// Represents an operation in the SODG
#[derive(Debug, Clone)]
pub struct OperationNode {
    pub operation_id: String,
    pub path: String,
    pub method: String,
    pub operation_spec: Value,
    pub dependencies: Vec<OperationEdge>,
    pub dependents: Vec<OperationEdge>,
}

/// Represents a dependency edge between operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationEdge {
    pub from_operation: String,
    pub to_operation: String,
    pub dependency_type: DependencyType,
    pub extract_rules: Vec<ExtractRule>,
    pub inject_rules: Vec<InjectRule>,
    pub description: String,
}

/// Represents a complete stateful test scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulTestScenario {
    pub scenario_id: String,
    pub description: String,
    pub operations: Vec<Value>, // Ordered list of operations to execute
    pub state_variables: HashMap<String, Value>, // Initial state variables
    pub cleanup_operations: Vec<Value>, // Operations to clean up after test
}

/// Workflow pattern for organizing scenarios
#[derive(Debug, Clone)]
pub struct WorkflowPattern {
    pub pattern_type: String,
    pub resource: Option<String>,
    pub parent_resource: Option<String>,
    pub child_resource: Option<String>,
    pub source_resource: Option<String>,
    pub filter_resource: Option<String>,
    pub operations: Vec<OperationNode>,
    pub description: String,
}

/// Agent responsible for generating stateful functional test cases
pub struct FunctionalStatefulAgent {
    base: BaseAgent,
    sodg: HashMap<String, OperationNode>,
}

impl FunctionalStatefulAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Functional-Stateful-Agent".to_string()),
            sodg: HashMap::new(),
        }
    }

    /// Build the Semantic Operation Dependency Graph from the API specification
    fn build_sodg(&mut self, api_spec: &Value) -> HashMap<String, OperationNode> {
        let mut sodg = HashMap::new();

        // Step 1: Create nodes for all operations
        let endpoints = self.base.extract_endpoints(api_spec);
        for endpoint in &endpoints {
            let operation_id = self.generate_operation_id(endpoint);
            let node = OperationNode {
                operation_id: operation_id.clone(),
                path: endpoint.path.clone(),
                method: endpoint.method.clone(),
                operation_spec: endpoint.operation.clone(),
                dependencies: Vec::new(),
                dependents: Vec::new(),
            };
            sodg.insert(operation_id, node);
        }

        // Step 2: Identify and create edges between operations
        let node_ids: Vec<String> = sodg.keys().cloned().collect();
        for from_id in &node_ids {
            for to_id in &node_ids {
                if from_id != to_id {
                    if let (Some(from_node), Some(to_node)) = (sodg.get(from_id), sodg.get(to_id)) {
                        if let Some(_edge) = self.identify_dependency(from_node, to_node) {
                            // We need to update the nodes with the edges
                            // This is a bit tricky with Rust's borrow checker, so we'll handle it differently
                            // For now, we'll collect the edges and add them in a separate pass
                        }
                    }
                }
            }
        }

        self.sodg = sodg.clone();
        sodg
    }

    /// Generate a unique operation ID for an endpoint
    fn generate_operation_id(&self, endpoint: &EndpointInfo) -> String {
        let method = endpoint.method.to_lowercase();
        
        // Use operationId if available
        if let Some(operation_id) = endpoint.operation.get("operationId").and_then(|id| id.as_str()) {
            return operation_id.to_string();
        }

        // Generate ID from method and path
        let path_parts: Vec<&str> = endpoint.path
            .split('/')
            .filter(|part| !part.is_empty() && !part.starts_with('{'))
            .collect();
        
        if let Some(resource) = path_parts.last() {
            format!("{}_{}", method, resource)
        } else {
            format!("{}_root", method)
        }
    }

    /// Identify if there's a dependency relationship between two operations
    fn identify_dependency(&self, from_node: &OperationNode, to_node: &OperationNode) -> Option<OperationEdge> {
        let from_path = &from_node.path;
        let from_method = &from_node.method;
        let to_path = &to_node.path;
        let to_method = &to_node.method;

        // Pattern 1: Resource creation -> Resource access
        // POST /users -> GET /users/{id}
        if from_method == "POST" && to_method == "GET" && self.is_resource_access_pattern(from_path, to_path) {
            let extract_rules = vec![ExtractRule {
                source_field: "id".to_string(),
                target_variable: "resource_id".to_string(),
                description: format!("Extract resource ID from {} {}", from_method, from_path),
            }];

            let inject_rules = vec![InjectRule {
                target_location: "path".to_string(),
                target_field: "id".to_string(),
                source_variable: "resource_id".to_string(),
                description: format!("Inject resource ID into {} {}", to_method, to_path),
            }];

            return Some(OperationEdge {
                from_operation: from_node.operation_id.clone(),
                to_operation: to_node.operation_id.clone(),
                dependency_type: DependencyType::ResourceId,
                extract_rules,
                inject_rules,
                description: format!("Resource creation to access: {} -> {}", from_path, to_path),
            });
        }

        // Pattern 2: Resource creation -> Resource update
        // POST /users -> PUT /users/{id}
        if from_method == "POST" && ["PUT", "PATCH"].contains(&to_method.as_str()) && 
           self.is_resource_access_pattern(from_path, to_path) {
            let extract_rules = vec![ExtractRule {
                source_field: "id".to_string(),
                target_variable: "resource_id".to_string(),
                description: format!("Extract resource ID from {} {}", from_method, from_path),
            }];

            let inject_rules = vec![InjectRule {
                target_location: "path".to_string(),
                target_field: "id".to_string(),
                source_variable: "resource_id".to_string(),
                description: format!("Inject resource ID into {} {}", to_method, to_path),
            }];

            return Some(OperationEdge {
                from_operation: from_node.operation_id.clone(),
                to_operation: to_node.operation_id.clone(),
                dependency_type: DependencyType::UpdateReference,
                extract_rules,
                inject_rules,
                description: format!("Resource creation to update: {} -> {}", from_path, to_path),
            });
        }

        // Pattern 3: Resource creation -> Resource deletion
        // POST /users -> DELETE /users/{id}
        if from_method == "POST" && to_method == "DELETE" && 
           self.is_resource_access_pattern(from_path, to_path) {
            let extract_rules = vec![ExtractRule {
                source_field: "id".to_string(),
                target_variable: "resource_id".to_string(),
                description: format!("Extract resource ID from {} {}", from_method, from_path),
            }];

            let inject_rules = vec![InjectRule {
                target_location: "path".to_string(),
                target_field: "id".to_string(),
                source_variable: "resource_id".to_string(),
                description: format!("Inject resource ID into {} {}", to_method, to_path),
            }];

            return Some(OperationEdge {
                from_operation: from_node.operation_id.clone(),
                to_operation: to_node.operation_id.clone(),
                dependency_type: DependencyType::DeleteReference,
                extract_rules,
                inject_rules,
                description: format!("Resource creation to deletion: {} -> {}", from_path, to_path),
            });
        }

        // Pattern 4: Parent resource -> Child resource
        // POST /users -> POST /users/{userId}/posts
        if from_method == "POST" && to_method == "POST" && 
           self.is_parent_child_pattern(from_path, to_path) {
            let parent_resource = self.extract_resource_name(from_path);
            let parent_id_param = if let Some(ref resource) = parent_resource {
                if resource.ends_with('s') {
                    format!("{}Id", &resource[..resource.len()-1])
                } else {
                    format!("{}Id", resource)
                }
            } else {
                "parentId".to_string()
            };

            let extract_rules = vec![ExtractRule {
                source_field: "id".to_string(),
                target_variable: parent_id_param.clone(),
                description: format!("Extract parent resource ID from {} {}", from_method, from_path),
            }];

            let inject_rules = vec![InjectRule {
                target_location: "path".to_string(),
                target_field: parent_id_param.clone(),
                source_variable: parent_id_param,
                description: format!("Inject parent resource ID into {} {}", to_method, to_path),
            }];

            return Some(OperationEdge {
                from_operation: from_node.operation_id.clone(),
                to_operation: to_node.operation_id.clone(),
                dependency_type: DependencyType::ParentChild,
                extract_rules,
                inject_rules,
                description: format!("Parent-child resource creation: {} -> {}", from_path, to_path),
            });
        }

        // Pattern 5: Resource creation -> Filter by resource
        // POST /users -> GET /posts?userId={id}
        if from_method == "POST" && to_method == "GET" && 
           self.is_filter_reference_pattern(from_node, to_node) {
            let resource_name = self.extract_resource_name(from_path);
            let filter_param = if let Some(ref resource) = resource_name {
                if resource.ends_with('s') {
                    format!("{}Id", &resource[..resource.len()-1])
                } else {
                    format!("{}Id", resource)
                }
            } else {
                "filterId".to_string()
            };

            let extract_rules = vec![ExtractRule {
                source_field: "id".to_string(),
                target_variable: filter_param.clone(),
                description: format!("Extract resource ID from {} {}", from_method, from_path),
            }];

            let inject_rules = vec![InjectRule {
                target_location: "query".to_string(),
                target_field: filter_param.clone(),
                source_variable: filter_param,
                description: format!("Inject resource ID as filter in {} {}", to_method, to_path),
            }];

            return Some(OperationEdge {
                from_operation: from_node.operation_id.clone(),
                to_operation: to_node.operation_id.clone(),
                dependency_type: DependencyType::FilterReference,
                extract_rules,
                inject_rules,
                description: format!("Resource creation to filtered query: {} -> {}", from_path, to_path),
            });
        }

        None
    }

    /// Check if paths follow resource creation -> resource access pattern
    fn is_resource_access_pattern(&self, from_path: &str, to_path: &str) -> bool {
        let from_parts: Vec<&str> = from_path.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();
        let to_parts: Vec<&str> = to_path.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();

        // Basic pattern: /users -> /users/{id}
        if to_parts.len() == from_parts.len() + 1 {
            // Check if all parts except the last match
            for i in 0..from_parts.len() {
                if from_parts[i] != to_parts[i] {
                    return false;
                }
            }
            // Check if the last part is a path parameter
            return to_parts.last().map_or(false, |part| part.starts_with('{') && part.ends_with('}'));
        }

        false
    }

    /// Check if paths follow parent -> child resource pattern
    fn is_parent_child_pattern(&self, from_path: &str, to_path: &str) -> bool {
        let from_parts: Vec<&str> = from_path.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();
        let to_parts: Vec<&str> = to_path.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();

        if to_parts.len() >= from_parts.len() + 2 {
            // Check if from_path is a prefix of to_path
            for i in 0..from_parts.len() {
                if from_parts[i] != to_parts[i] {
                    return false;
                }
            }

            // Check if there's a path parameter after the parent resource
            if to_parts.len() > from_parts.len() {
                let param_part = to_parts[from_parts.len()];
                return param_part.starts_with('{') && param_part.ends_with('}');
            }
        }

        false
    }

    /// Check if operations follow resource creation -> filtered query pattern
    fn is_filter_reference_pattern(&self, from_node: &OperationNode, to_node: &OperationNode) -> bool {
        // Check if the target operation has query parameters that could reference the source resource
        let to_params = to_node.operation_spec.get("parameters")
            .and_then(|p| p.as_array())
            .map(|arr| arr.clone())
            .unwrap_or_default();
        
        let from_resource = self.extract_resource_name(&from_node.path);
        
        if from_resource.is_none() {
            return false;
        }

        let resource = from_resource.unwrap();
        let expected_param_names = vec![
            if resource.ends_with('s') {
                format!("{}Id", &resource[..resource.len()-1])
            } else {
                format!("{}Id", &resource)
            },
            format!("{}_id", resource),
            format!("{}_id", resource.to_lowercase()),
        ];

        for param in to_params {
            if let (Some(param_in), Some(param_name)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str())
            ) {
                if param_in == "query" && expected_param_names.iter().any(|name| name.to_lowercase() == param_name.to_lowercase()) {
                    return true;
                }
            }
        }

        false
    }

    /// Extract the main resource name from a path
    fn extract_resource_name(&self, path: &str) -> Option<String> {
        let parts: Vec<&str> = path.trim_matches('/').split('/')
            .filter(|p| !p.is_empty() && !p.starts_with('{'))
            .collect();
        parts.last().map(|s| s.to_string())
    }

    /// Identify common workflow patterns in the SODG
    fn identify_workflow_patterns(&self) -> Vec<WorkflowPattern> {
        let mut patterns = Vec::new();

        // Pattern 1: CRUD lifecycle patterns
        patterns.extend(self.find_crud_patterns());

        // Pattern 2: Parent-child resource patterns
        patterns.extend(self.find_parent_child_patterns());

        // Pattern 3: Resource filtering patterns
        patterns.extend(self.find_filter_patterns());

        patterns
    }

    /// Find Create-Read-Update-Delete workflow patterns
    fn find_crud_patterns(&self) -> Vec<WorkflowPattern> {
        let mut patterns = Vec::new();

        // Group operations by resource
        let mut resource_operations: HashMap<String, Vec<&OperationNode>> = HashMap::new();
        for (_op_id, node) in &self.sodg {
            if let Some(resource) = self.extract_resource_name(&node.path) {
                resource_operations.entry(resource).or_default().push(node);
            }
        }

        // For each resource, identify CRUD patterns
        for (resource, operations) in resource_operations {
            let mut crud_ops = HashMap::new();

            for op in &operations {
                let method = op.method.to_uppercase();
                match method.as_str() {
                    "POST" if !self.has_path_parameters(&op.path) => {
                        crud_ops.insert("create", (*op).clone());
                    }
                    "GET" if self.has_path_parameters(&op.path) => {
                        crud_ops.insert("read", (*op).clone());
                    }
                    "PUT" | "PATCH" if self.has_path_parameters(&op.path) => {
                        crud_ops.insert("update", (*op).clone());
                    }
                    "DELETE" if self.has_path_parameters(&op.path) => {
                        crud_ops.insert("delete", (*op).clone());
                    }
                    _ => {}
                }
            }

            // Create patterns based on available operations
            if let (Some(create), Some(read)) = (crud_ops.get("create"), crud_ops.get("read")) {
                patterns.push(WorkflowPattern {
                    pattern_type: "create_read".to_string(),
                    resource: Some(resource.clone()),
                    parent_resource: None,
                    child_resource: None,
                    source_resource: None,
                    filter_resource: None,
                    operations: vec![(*create).clone(), (*read).clone()],
                    description: format!("Create and read {} workflow", resource),
                });
            }

            if let (Some(create), Some(update)) = (crud_ops.get("create"), crud_ops.get("update")) {
                patterns.push(WorkflowPattern {
                    pattern_type: "create_update".to_string(),
                    resource: Some(resource.clone()),
                    parent_resource: None,
                    child_resource: None,
                    source_resource: None,
                    filter_resource: None,
                    operations: vec![(*create).clone(), (*update).clone()],
                    description: format!("Create and update {} workflow", resource),
                });
            }

            if let (Some(create), Some(delete)) = (crud_ops.get("create"), crud_ops.get("delete")) {
                patterns.push(WorkflowPattern {
                    pattern_type: "create_delete".to_string(),
                    resource: Some(resource.clone()),
                    parent_resource: None,
                    child_resource: None,
                    source_resource: None,
                    filter_resource: None,
                    operations: vec![(*create).clone(), (*delete).clone()],
                    description: format!("Create and delete {} workflow", resource),
                });
            }

            if let (Some(create), Some(read), Some(update)) = (
                crud_ops.get("create"),
                crud_ops.get("read"),
                crud_ops.get("update")
            ) {
                patterns.push(WorkflowPattern {
                    pattern_type: "full_crud".to_string(),
                    resource: Some(resource.clone()),
                    parent_resource: None,
                    child_resource: None,
                    source_resource: None,
                    filter_resource: None,
                    operations: vec![(*create).clone(), (*read).clone(), (*update).clone()],
                    description: format!("Full CRUD workflow for {}", resource),
                });
            }
        }

        patterns
    }

    /// Find parent-child resource workflow patterns
    fn find_parent_child_patterns(&self) -> Vec<WorkflowPattern> {
        let mut patterns = Vec::new();

        // Look for parent-child relationships by examining path structures
        for (_from_id, from_node) in &self.sodg {
            for (_to_id, to_node) in &self.sodg {
                if from_node.operation_id != to_node.operation_id &&
                   self.is_parent_child_pattern(&from_node.path, &to_node.path) {
                    let parent_resource = self.extract_resource_name(&from_node.path);
                    let child_resource = self.extract_resource_name(&to_node.path);

                    patterns.push(WorkflowPattern {
                        pattern_type: "parent_child".to_string(),
                        resource: None,
                        parent_resource: parent_resource.clone(),
                        child_resource: child_resource.clone(),
                        source_resource: None,
                        filter_resource: None,
                        operations: vec![from_node.clone(), to_node.clone()],
                        description: format!(
                            "Create parent {} then child {}",
                            parent_resource.as_deref().unwrap_or("resource"),
                            child_resource.as_deref().unwrap_or("resource")
                        ),
                    });
                }
            }
        }

        patterns
    }

    /// Find resource filtering workflow patterns
    fn find_filter_patterns(&self) -> Vec<WorkflowPattern> {
        let mut patterns = Vec::new();

        // Look for filter relationships
        for (_from_id, from_node) in &self.sodg {
            for (_to_id, to_node) in &self.sodg {
                if from_node.operation_id != to_node.operation_id &&
                   self.is_filter_reference_pattern(from_node, to_node) {
                    let source_resource = self.extract_resource_name(&from_node.path);
                    let filter_resource = self.extract_resource_name(&to_node.path);

                    patterns.push(WorkflowPattern {
                        pattern_type: "create_filter".to_string(),
                        resource: None,
                        parent_resource: None,
                        child_resource: None,
                        source_resource: source_resource.clone(),
                        filter_resource: filter_resource.clone(),
                        operations: vec![from_node.clone(), to_node.clone()],
                        description: format!(
                            "Create {} then filter {}",
                            source_resource.as_deref().unwrap_or("resource"),
                            filter_resource.as_deref().unwrap_or("results")
                        ),
                    });
                }
            }
        }

        patterns
    }

    /// Check if a path contains path parameters
    fn has_path_parameters(&self, path: &str) -> bool {
        path.contains('{') && path.contains('}')
    }

    /// Generate test scenarios for a specific workflow pattern
    async fn generate_scenarios_for_pattern(
        &self,
        pattern: &WorkflowPattern,
        api_spec: &Value,
    ) -> Vec<StatefulTestScenario> {
        let mut scenarios = Vec::new();

        match pattern.pattern_type.as_str() {
            "create_read" | "create_update" | "create_delete" | "full_crud" => {
                if let Some(scenario) = self.generate_crud_scenario(pattern, api_spec).await {
                    scenarios.push(scenario);
                }
            }
            "parent_child" => {
                if let Some(scenario) = self.generate_parent_child_scenario(pattern, api_spec).await {
                    scenarios.push(scenario);
                }
            }
            "create_filter" => {
                if let Some(scenario) = self.generate_filter_scenario(pattern, api_spec).await {
                    scenarios.push(scenario);
                }
            }
            _ => {}
        }

        scenarios
    }

    /// Generate a CRUD workflow scenario
    async fn generate_crud_scenario(
        &self,
        pattern: &WorkflowPattern,
        api_spec: &Value,
    ) -> Option<StatefulTestScenario> {
        let operations = &pattern.operations;
        let resource = pattern.resource.as_deref().unwrap_or("resource");
        let pattern_type = &pattern.pattern_type;

        let mut scenario_operations = Vec::new();
        let mut cleanup_operations = Vec::new();

        // Build the operation sequence
        for (i, op_node) in operations.iter().enumerate() {
            let mut extract_rules = Vec::new();
            let mut inject_rules = Vec::new();

            if i > 0 {
                // Not the first operation - find dependency edge
                let prev_op = &operations[i - 1];
                if let Some(edge) = self.identify_dependency(prev_op, op_node) {
                    extract_rules = edge.extract_rules;
                    inject_rules = edge.inject_rules;
                }
            }

            // Generate operation definition
            let operation_def = serde_json::json!({
                "operation_id": op_node.operation_id,
                "method": op_node.method,
                "path": op_node.path,
                "description": format!("Step {}: {} {}", i + 1, op_node.method, op_node.path),
                "extract_rules": extract_rules,
                "inject_rules": inject_rules,
                "request_body": self.generate_request_body_for_operation(op_node, api_spec),
                "expected_status": self.get_expected_status_for_operation(op_node),
                "assertions": self.generate_assertions_for_operation(op_node)
            });

            scenario_operations.push(operation_def);
        }

        // Add cleanup if we created resources
        if let Some(create_op) = operations.first() {
            if create_op.method.to_uppercase() == "POST" {
                // Look for a corresponding DELETE operation
                for (_op_id, node) in &self.sodg {
                    if node.method.to_uppercase() == "DELETE" &&
                       self.is_resource_access_pattern(&create_op.path, &node.path) {
                        let cleanup_op = serde_json::json!({
                            "operation_id": node.operation_id,
                            "method": node.method,
                            "path": node.path,
                            "description": format!("Cleanup: Delete created {}", resource),
                            "inject_rules": [{
                                "target_location": "path",
                                "target_field": "id",
                                "source_variable": "resource_id",
                                "description": "Inject resource ID for cleanup"
                            }],
                            "expected_status": 204
                        });
                        cleanup_operations.push(cleanup_op);
                        break;
                    }
                }
            }
        }

        let scenario_id = format!("{}_{}_{}_steps", pattern_type, resource, scenario_operations.len());

        Some(StatefulTestScenario {
            scenario_id,
            description: pattern.description.clone(),
            operations: scenario_operations,
            state_variables: HashMap::new(),
            cleanup_operations,
        })
    }

    /// Generate a parent-child resource scenario
    async fn generate_parent_child_scenario(
        &self,
        pattern: &WorkflowPattern,
        api_spec: &Value,
    ) -> Option<StatefulTestScenario> {
        let operations = &pattern.operations;
        let parent_resource = pattern.parent_resource.as_deref().unwrap_or("parent");
        let child_resource = pattern.child_resource.as_deref().unwrap_or("child");

        let mut scenario_operations = Vec::new();

        for (i, op_node) in operations.iter().enumerate() {
            let mut extract_rules = Vec::new();
            let mut inject_rules = Vec::new();

            if i > 0 {
                // Child operation
                let parent_op = &operations[0];
                if let Some(edge) = self.identify_dependency(parent_op, op_node) {
                    extract_rules = edge.extract_rules;
                    inject_rules = edge.inject_rules;
                }
            }

            let operation_def = serde_json::json!({
                "operation_id": op_node.operation_id,
                "method": op_node.method,
                "path": op_node.path,
                "description": format!("Step {}: Create {} resource", i + 1, if i == 0 { "parent" } else { "child" }),
                "extract_rules": extract_rules,
                "inject_rules": inject_rules,
                "request_body": self.generate_request_body_for_operation(op_node, api_spec),
                "expected_status": self.get_expected_status_for_operation(op_node),
                "assertions": self.generate_assertions_for_operation(op_node)
            });

            scenario_operations.push(operation_def);
        }

        let scenario_id = format!("parent_child_{}_{}", parent_resource, child_resource);

        Some(StatefulTestScenario {
            scenario_id,
            description: pattern.description.clone(),
            operations: scenario_operations,
            state_variables: HashMap::new(),
            cleanup_operations: Vec::new(),
        })
    }

    /// Generate a create-then-filter scenario
    async fn generate_filter_scenario(
        &self,
        pattern: &WorkflowPattern,
        api_spec: &Value,
    ) -> Option<StatefulTestScenario> {
        let operations = &pattern.operations;
        let source_resource = pattern.source_resource.as_deref().unwrap_or("source");
        let filter_resource = pattern.filter_resource.as_deref().unwrap_or("filter");

        let mut scenario_operations = Vec::new();

        for (i, op_node) in operations.iter().enumerate() {
            let mut extract_rules = Vec::new();
            let mut inject_rules = Vec::new();

            if i > 0 {
                // Filter operation
                let source_op = &operations[0];
                if let Some(edge) = self.identify_dependency(source_op, op_node) {
                    extract_rules = edge.extract_rules;
                    inject_rules = edge.inject_rules;
                }
            }

            let operation_def = serde_json::json!({
                "operation_id": op_node.operation_id,
                "method": op_node.method,
                "path": op_node.path,
                "description": format!("Step {}: {} {}", i + 1, if i == 0 { "Create" } else { "Filter" }, op_node.path),
                "extract_rules": extract_rules,
                "inject_rules": inject_rules,
                "request_body": if i == 0 { self.generate_request_body_for_operation(op_node, api_spec) } else { None },
                "expected_status": self.get_expected_status_for_operation(op_node),
                "assertions": self.generate_assertions_for_operation(op_node)
            });

            scenario_operations.push(operation_def);
        }

        let scenario_id = format!("create_filter_{}_{}", source_resource, filter_resource);

        Some(StatefulTestScenario {
            scenario_id,
            description: pattern.description.clone(),
            operations: scenario_operations,
            state_variables: HashMap::new(),
            cleanup_operations: Vec::new(),
        })
    }

    /// Generate a request body for an operation if needed
    fn generate_request_body_for_operation(&self, op_node: &OperationNode, api_spec: &Value) -> Option<Value> {
        if !["POST", "PUT", "PATCH"].contains(&op_node.method.to_uppercase().as_str()) {
            return None;
        }

        let request_body = op_node.operation_spec.get("requestBody")?;
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")?;
        let schema = json_content.get("schema")?;
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        Some(self.generate_realistic_object(&resolved_schema))
    }

    /// Generate a realistic object based on schema
    fn generate_realistic_object(&self, schema: &Value) -> Value {
        if schema.get("type").and_then(|t| t.as_str()) != Some("object") {
            return generate_schema_example(schema);
        }

        let properties = schema.get("properties").and_then(|p| p.as_object());
        let required = schema.get("required")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();

        let mut obj = serde_json::Map::new();

        if let Some(props) = properties {
            for (prop_name, prop_schema) in props {
                // Always include required properties, sometimes include optional ones (if few properties)
                if required.contains(prop_name.as_str()) || props.len() <= 5 {
                    obj.insert(
                        prop_name.clone(),
                        self.generate_realistic_property_value(prop_name, prop_schema),
                    );
                }
            }
        }

        Value::Object(obj)
    }

    /// Generate realistic values based on property names and schemas
    fn generate_realistic_property_value(&self, prop_name: &str, schema: &Value) -> Value {
        let prop_name_lower = prop_name.to_lowercase();

        // Use existing example if available
        if let Some(example) = schema.get("example") {
            return example.clone();
        }

        // Generate realistic values based on property names
        if prop_name_lower.contains("email") {
            return Value::String("stateful.test@example.com".to_string());
        } else if prop_name_lower.contains("name") {
            if prop_name_lower.contains("first") {
                return Value::String("Stateful".to_string());
            } else if prop_name_lower.contains("last") {
                return Value::String("Tester".to_string());
            } else {
                return Value::String("Stateful Test Resource".to_string());
            }
        } else if prop_name_lower.contains("title") {
            return Value::String("Test Resource for Stateful Workflow".to_string());
        } else if prop_name_lower.contains("description") || prop_name_lower.contains("body") {
            return Value::String("This resource was created as part of a stateful test workflow to validate multi-step API operations.".to_string());
        } else if prop_name_lower.contains("phone") {
            return Value::String("+1-555-STATEFUL".to_string());
        } else if prop_name_lower.contains("age") {
            return Value::Number(serde_json::Number::from(25));
        } else if prop_name_lower.contains("price") || prop_name_lower.contains("amount") {
            return Value::Number(serde_json::Number::from_f64(99.99).unwrap());
        } else if prop_name_lower.contains("date") {
            return Value::String("2024-01-01T00:00:00Z".to_string());
        } else if prop_name_lower.contains("url") {
            return Value::String("https://example.com/stateful-test".to_string());
        }

        // Fall back to schema-based generation
        generate_schema_example(schema)
    }

    /// Determine the expected success status code for an operation
    fn get_expected_status_for_operation(&self, op_node: &OperationNode) -> u16 {
        let responses = op_node.operation_spec
            .get("responses")
            .and_then(|r| r.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<HashMap<String, Value>>()
            })
            .unwrap_or_default();

        // Look for success responses (2xx)
        for code in responses.keys() {
            if code.starts_with('2') {
                if let Ok(status_code) = code.parse::<u16>() {
                    return status_code;
                }
            }
        }

        // Default success codes by method
        match op_node.method.to_uppercase().as_str() {
            "GET" => 200,
            "POST" => 201,
            "PUT" => 200,
            "PATCH" => 200,
            "DELETE" => 204,
            _ => 200,
        }
    }

    /// Generate assertions for validating an operation's response
    fn generate_assertions_for_operation(&self, op_node: &OperationNode) -> Vec<Value> {
        let mut assertions = Vec::new();

        // Basic status code assertion
        let expected_status = self.get_expected_status_for_operation(op_node);
        assertions.push(serde_json::json!({
            "type": "status_code",
            "expected": expected_status
        }));

        // Response schema assertion if available
        let empty_map = serde_json::Map::new();
        let responses = op_node.operation_spec
            .get("responses")
            .and_then(|r| r.as_object())
            .unwrap_or(&empty_map);

        if let Some(success_response) = responses.get(&expected_status.to_string()) {
            if let Some(content) = success_response.get("content") {
                if let Some(json_content) = content.get("application/json") {
                    if let Some(schema) = json_content.get("schema") {
                        assertions.push(serde_json::json!({
                            "type": "response_schema",
                            "schema": schema
                        }));
                    }
                }
            }
        }

        // For POST operations, assert that an ID is returned
        if op_node.method.to_uppercase() == "POST" {
            assertions.push(serde_json::json!({
                "type": "response_field_exists",
                "field": "id",
                "description": "Verify that created resource has an ID"
            }));
        }

        assertions
    }

    /// Convert a StatefulTestScenario to a test case format
    fn convert_scenario_to_test_case(&self, scenario: &StatefulTestScenario) -> TestCase {
        self.base.create_test_case(
            "multi-step".to_string(), // Special marker for stateful tests
            "STATEFUL".to_string(),
            scenario.description.clone(),
            None,
            None,
            None,
            200, // Will be overridden by individual operations
            Some(vec![Assertion {
                assertion_type: "stateful_workflow".to_string(),
                expected: serde_json::json!({
                    "scenario": {
                        "scenario_id": scenario.scenario_id,
                        "operations": scenario.operations,
                        "state_variables": scenario.state_variables,
                        "cleanup_operations": scenario.cleanup_operations
                    }
                }),
                path: None,
            }]),
        )
    }
}

#[async_trait]
impl Agent for FunctionalStatefulAgent {
    fn agent_type(&self) -> &str {
        &self.base.agent_type
    }

    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        let start_time = std::time::Instant::now();

        match self.execute_internal(task.clone(), api_spec).await {
            Ok(mut result) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                result.metadata.insert(
                    "processing_time_ms".to_string(),
                    Value::Number(serde_json::Number::from(processing_time)),
                );
                result
            }
            Err(e) => AgentResult {
                task_id: task.task_id,
                agent_type: self.agent_type().to_string(),
                status: "failed".to_string(),
                test_cases: vec![],
                metadata: HashMap::new(),
                error_message: Some(e),
            },
        }
    }
}

impl FunctionalStatefulAgent {
    async fn execute_internal(&self, task: AgentTask, api_spec: Value) -> Result<AgentResult, String> {
        // Step 1: Build the Semantic Operation Dependency Graph
        let mut agent = Self {
            base: BaseAgent::new("Functional-Stateful-Agent".to_string()),
            sodg: HashMap::new(),
        };
        agent.sodg = agent.build_sodg(&api_spec);

        // Step 2: Identify workflow patterns
        let workflow_patterns = agent.identify_workflow_patterns();

        // Step 3: Generate test scenarios for each pattern
        let mut test_scenarios = Vec::new();
        for pattern in &workflow_patterns {
            let scenarios = agent.generate_scenarios_for_pattern(pattern, &api_spec).await;
            test_scenarios.extend(scenarios);
        }

        // Step 4: Convert scenarios to test cases
        let mut test_cases = Vec::new();
        for scenario in &test_scenarios {
            let test_case = agent.convert_scenario_to_test_case(scenario);
            test_cases.push(test_case);
        }

        let mut metadata = HashMap::new();
        metadata.insert(
            "total_operations".to_string(),
            Value::Number(serde_json::Number::from(agent.sodg.len())),
        );
        metadata.insert(
            "workflow_patterns".to_string(),
            Value::Number(serde_json::Number::from(workflow_patterns.len())),
        );
        metadata.insert(
            "total_scenarios".to_string(),
            Value::Number(serde_json::Number::from(test_scenarios.len())),
        );
        metadata.insert(
            "total_test_cases".to_string(),
            Value::Number(serde_json::Number::from(test_cases.len())),
        );
        metadata.insert(
            "generation_strategy".to_string(),
            Value::String("sodg_based_stateful_workflows".to_string()),
        );
        metadata.insert(
            "supported_patterns".to_string(),
            Value::Array(
                workflow_patterns.iter()
                    .map(|p| Value::String(p.pattern_type.clone()))
                    .collect()
            ),
        );

        Ok(AgentResult {
            task_id: task.task_id,
            agent_type: self.agent_type().to_string(),
            status: "success".to_string(),
            test_cases,
            metadata,
            error_message: None,
        })
    }
}