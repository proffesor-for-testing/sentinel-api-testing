//! Agent system for Sentinel Rust Core
//! 
//! This module provides the agent trait and implementations for different types of testing agents.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::time::Instant;

use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo, Assertion};

pub mod functional_positive;
pub mod data_mocking;
pub mod security_auth;
pub mod utils;

/// Base trait that all agents must implement
#[async_trait]
pub trait Agent: Send + Sync {
    /// Returns the agent type identifier
    fn agent_type(&self) -> &str;
    
    /// Execute the agent's primary function
    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult;
    
    /// Validate that the agent can handle the given task
    fn can_handle(&self, agent_type: &str) -> bool {
        self.agent_type() == agent_type
    }
}

/// Agent orchestrator that manages and delegates tasks to appropriate agents
pub struct AgentOrchestrator {
    agents: HashMap<String, Box<dyn Agent>>,
}

impl AgentOrchestrator {
    /// Create a new orchestrator with all available agents
    pub fn new() -> Self {
        let mut agents: HashMap<String, Box<dyn Agent>> = HashMap::new();
        
        // Register all available agents
        agents.insert(
            "Functional-Positive-Agent".to_string(),
            Box::new(functional_positive::FunctionalPositiveAgent::new()),
        );
        agents.insert(
            "data-mocking".to_string(),
            Box::new(data_mocking::DataMockingAgent::new()),
        );
        agents.insert(
            "Security-Auth-Agent".to_string(),
            Box::new(security_auth::SecurityAuthAgent::new()),
        );
        
        Self { agents }
    }
    
    /// Execute a task using the appropriate agent
    pub async fn execute_task(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        let start_time = Instant::now();
        
        match self.agents.get(&task.agent_type) {
            Some(agent) => {
                let mut result = agent.execute(task, api_spec).await;
                
                // Add processing time to metadata
                let processing_time = start_time.elapsed().as_millis() as u64;
                result.metadata.insert(
                    "processing_time_ms".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(processing_time)),
                );
                
                result
            }
            None => AgentResult {
                task_id: task.task_id.clone(),
                agent_type: task.agent_type.clone(),
                status: "failed".to_string(),
                test_cases: vec![],
                metadata: HashMap::new(),
                error_message: Some(format!("Unknown agent type: {}", task.agent_type)),
            },
        }
    }
    
    /// Get list of available agent types
    pub fn available_agents(&self) -> Vec<String> {
        self.agents.keys().cloned().collect()
    }
}

/// Base agent implementation with common functionality
pub struct BaseAgent {
    pub agent_type: String,
}

impl BaseAgent {
    pub fn new(agent_type: String) -> Self {
        Self { agent_type }
    }
    
    /// Create a standardized test case
    pub fn create_test_case(
        &self,
        endpoint: String,
        method: String,
        description: String,
        headers: Option<HashMap<String, String>>,
        query_params: Option<HashMap<String, Value>>,
        body: Option<Value>,
        expected_status: u16,
        assertions: Option<Vec<Assertion>>,
    ) -> TestCase {
        TestCase {
            test_name: description,
            test_type: self.agent_type.clone(),
            method: method.to_uppercase(),
            path: endpoint,
            headers: headers.unwrap_or_default(),
            query_params: query_params.unwrap_or_default(),
            body,
            timeout: 600, // Default timeout in seconds
            expected_status_codes: vec![expected_status],
            assertions: assertions.unwrap_or_default(),
            tags: vec!["functional".to_string(), method.to_lowercase()],
        }
    }
    
    /// Extract endpoints from API specification
    pub fn extract_endpoints(&self, api_spec: &Value) -> Vec<EndpointInfo> {
        let mut endpoints = Vec::new();
        
        if let Some(paths) = api_spec.get("paths").and_then(|p| p.as_object()) {
            for (path, path_item) in paths {
                if let Some(path_obj) = path_item.as_object() {
                    for (method, operation) in path_obj {
                        if ["get", "post", "put", "patch", "delete", "head", "options"]
                            .contains(&method.to_lowercase().as_str())
                        {
                            let summary = operation
                                .get("summary")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string();
                            
                            let description = operation
                                .get("description")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string();
                            
                            let parameters = operation
                                .get("parameters")
                                .and_then(|p| p.as_array())
                                .map(|arr| arr.clone())
                                .unwrap_or_default();
                            
                            let request_body = operation.get("requestBody").cloned();
                            
                            let responses = operation
                                .get("responses")
                                .and_then(|r| r.as_object())
                                .map(|obj| {
                                    obj.iter()
                                        .map(|(k, v)| (k.clone(), v.clone()))
                                        .collect()
                                })
                                .unwrap_or_default();
                            
                            endpoints.push(EndpointInfo {
                                path: path.clone(),
                                method: method.to_uppercase(),
                                operation: operation.clone(),
                                summary,
                                description,
                                parameters,
                                request_body,
                                responses,
                            });
                        }
                    }
                }
            }
        }
        
        endpoints
    }
    
    /// Generate example value from JSON schema
    pub fn get_schema_example(&self, schema: &Value) -> Value {
        if let Some(example) = schema.get("example") {
            return example.clone();
        }
        
        let schema_type = schema
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("string");
        
        match schema_type {
            "string" => {
                if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
                    return enum_values.first().unwrap_or(&Value::String("example".to_string())).clone();
                }
                Value::String("example_string".to_string())
            }
            "integer" => {
                let min = schema.get("minimum").and_then(|m| m.as_i64()).unwrap_or(1);
                Value::Number(serde_json::Number::from(min))
            }
            "number" => {
                let min = schema.get("minimum").and_then(|m| m.as_f64()).unwrap_or(1.0);
                Value::Number(serde_json::Number::from_f64(min).unwrap_or(serde_json::Number::from(1)))
            }
            "boolean" => Value::Bool(true),
            "array" => {
                if let Some(items) = schema.get("items") {
                    Value::Array(vec![self.get_schema_example(items)])
                } else {
                    Value::Array(vec![])
                }
            }
            "object" => {
                let mut obj = serde_json::Map::new();
                if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                    let required = schema
                        .get("required")
                        .and_then(|r| r.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    
                    for (prop_name, prop_schema) in properties {
                        if required.contains(&prop_name.as_str()) || properties.len() <= 3 {
                            obj.insert(prop_name.clone(), self.get_schema_example(prop_schema));
                        }
                    }
                }
                Value::Object(obj)
            }
            _ => Value::Null,
        }
    }
}