//! Functional-Positive-Agent: Generates valid, "happy path" test cases.
//! 
//! This agent focuses on creating test cases that should succeed under normal conditions,
//! validating that the API works correctly for valid inputs and expected usage patterns.

use async_trait::async_trait;
use rand::prelude::*;
use serde_json::Value;
use std::collections::HashMap;

use crate::agents::{Agent, BaseAgent};
use crate::agents::utils::*;
use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo, Assertion};

/// Agent responsible for generating positive functional test cases
pub struct FunctionalPositiveAgent {
    base: BaseAgent,
}

impl FunctionalPositiveAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Functional-Positive-Agent".to_string()),
        }
    }
    
    /// Generate positive test cases for a specific endpoint
    async fn generate_endpoint_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        
        // Generate basic positive test case
        if let Some(basic_test) = self.generate_basic_positive_test(endpoint, api_spec).await {
            test_cases.push(basic_test);
        }
        
        // Generate test cases with different parameter combinations
        if ["GET", "DELETE"].contains(&endpoint.method.as_str()) {
            let param_tests = self.generate_parameter_variation_tests(endpoint, api_spec).await;
            test_cases.extend(param_tests);
        }
        
        // Generate test cases with different request body variations
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            let body_tests = self.generate_body_variation_tests(endpoint, api_spec).await;
            test_cases.extend(body_tests);
        }
        
        test_cases
    }
    
    /// Generate a basic positive test case for an endpoint
    async fn generate_basic_positive_test(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Option<TestCase> {
        // Build test case components
        let headers = self.generate_headers(&endpoint.operation);
        let query_params = self.generate_query_parameters(&endpoint.parameters);
        let path_params = self.generate_path_parameters(&endpoint.parameters);
        
        // Replace path parameters in the URL
        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        
        // Generate request body if needed
        let body = if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            endpoint.request_body.as_ref().and_then(|rb| {
                self.generate_request_body(rb, api_spec)
            })
        } else {
            None
        };
        
        // Determine expected status code
        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);
        
        // Create description
        let summary = if endpoint.summary.is_empty() {
            format!("{} {}", endpoint.method, endpoint.path)
        } else {
            endpoint.summary.clone()
        };
        let description = format!("Positive test: {}", summary);
        
        // Generate assertions based on response schema
        let assertions = self.generate_response_assertions(&endpoint.responses, expected_status);
        
        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            description,
            Some(headers),
            Some(query_params),
            body,
            expected_status,
            Some(assertions),
        ))
    }
    
    /// Generate headers for the request
    fn generate_headers(&self, operation: &Value) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());
        
        // Add any required headers from the operation
        if let Some(parameters) = operation.get("parameters").and_then(|p| p.as_array()) {
            for param in parameters {
                if let (Some(param_in), Some(param_name), Some(required)) = (
                    param.get("in").and_then(|i| i.as_str()),
                    param.get("name").and_then(|n| n.as_str()),
                    param.get("required").and_then(|r| r.as_bool()),
                ) {
                    if param_in == "header" && required {
                        let value = generate_parameter_value(param_name, &param.get("schema").unwrap_or(&Value::Null));
                        headers.insert(param_name.to_string(), value.to_string());
                    }
                }
            }
        }
        
        headers
    }
    
    /// Generate query parameters from the parameter definitions
    fn generate_query_parameters(&self, parameters: &[Value]) -> HashMap<String, Value> {
        let mut query_params = HashMap::new();
        let mut rng = thread_rng();
        
        for param in parameters {
            if let (Some(param_in), Some(param_name)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str()),
            ) {
                if param_in == "query" {
                    let required = param.get("required").and_then(|r| r.as_bool()).unwrap_or(false);
                    // Always include required parameters, sometimes include optional ones
                    if required || rng.gen_bool(0.7) {
                        let schema = param.get("schema").unwrap_or(&Value::Null);
                        query_params.insert(
                            param_name.to_string(),
                            generate_parameter_value(param_name, schema),
                        );
                    }
                }
            }
        }
        
        query_params
    }
    
    /// Generate path parameters from the parameter definitions
    fn generate_path_parameters(&self, parameters: &[Value]) -> HashMap<String, Value> {
        let mut path_params = HashMap::new();
        
        for param in parameters {
            if let (Some(param_in), Some(param_name)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str()),
            ) {
                if param_in == "path" {
                    let schema = param.get("schema").unwrap_or(&Value::Null);
                    path_params.insert(
                        param_name.to_string(),
                        generate_parameter_value(param_name, schema),
                    );
                }
            }
        }
        
        path_params
    }
    
    /// Generate a request body based on the request body schema
    fn generate_request_body(&self, request_body: &Value, api_spec: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        
        // Look for JSON content type
        let json_content = content.get("application/json")
            .or_else(|| content.as_object()?.values().next())?;
        
        let schema = json_content.get("schema")?;
        
        // Resolve schema references
        let resolved_schema = resolve_schema_ref(schema, api_spec);
        
        Some(self.generate_realistic_object(&resolved_schema))
    }
    
    /// Generate a realistic object based on schema with enhanced data generation
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
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        
        let mut obj = serde_json::Map::new();
        let mut rng = thread_rng();
        
        if let Some(props) = properties {
            for (prop_name, prop_schema) in props {
                // Always include required properties, sometimes include optional ones
                if required.contains(&prop_name.as_str()) || rng.gen_bool(0.8) {
                    obj.insert(
                        prop_name.clone(),
                        generate_realistic_property_value(prop_name, prop_schema),
                    );
                }
            }
        }
        
        Value::Object(obj)
    }
    
    /// Generate assertions to validate the response
    fn generate_response_assertions(&self, responses: &HashMap<String, Value>, expected_status: u16) -> Vec<Assertion> {
        let mut assertions = Vec::new();
        
        // Basic status code assertion
        assertions.push(Assertion {
            assertion_type: "status_code".to_string(),
            expected: Value::Number(serde_json::Number::from(expected_status)),
            path: None,
        });
        
        // Look for response schema to generate content assertions
        if let Some(response_def) = responses.get(&expected_status.to_string()) {
            if let Some(content) = response_def.get("content") {
                if let Some(json_content) = content.get("application/json") {
                    if let Some(schema) = json_content.get("schema") {
                        assertions.push(Assertion {
                            assertion_type: "response_schema".to_string(),
                            expected: schema.clone(),
                            path: None,
                        });
                    }
                }
            }
        }
        
        assertions
    }
    
    /// Generate test cases with different parameter combinations
    async fn generate_parameter_variation_tests(
        &self,
        endpoint: &EndpointInfo,
        _api_spec: &Value,
    ) -> Vec<TestCase> {
        let test_cases = Vec::new();
        
        // Find optional query parameters
        let optional_params: Vec<_> = endpoint.parameters
            .iter()
            .filter(|p| {
                p.get("in").and_then(|i| i.as_str()) == Some("query") &&
                !p.get("required").and_then(|r| r.as_bool()).unwrap_or(false)
            })
            .collect();
        
        // For now, we'll implement minimal variations
        // This can be expanded with more sophisticated parameter combination logic
        if optional_params.len() > 1 {
            // Could add minimal and maximal parameter tests here
            // For MVP, we'll keep it simple
        }
        
        test_cases
    }
    
    /// Generate test cases with different request body variations
    async fn generate_body_variation_tests(
        &self,
        _endpoint: &EndpointInfo,
        _api_spec: &Value,
    ) -> Vec<TestCase> {
        let test_cases = Vec::new();
        
        // For now, we'll implement minimal body variations
        // This can be expanded with more sophisticated body generation logic
        // Could add minimal body tests (only required fields) here
        
        test_cases
    }
}

#[async_trait]
impl Agent for FunctionalPositiveAgent {
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

impl FunctionalPositiveAgent {
    async fn execute_internal(&self, task: AgentTask, api_spec: Value) -> Result<AgentResult, String> {
        // Extract all endpoints from the specification
        let endpoints = self.base.extract_endpoints(&api_spec);
        
        let mut test_cases = Vec::new();
        
        // Generate test cases for each endpoint
        for endpoint in &endpoints {
            let endpoint_tests = self.generate_endpoint_tests(endpoint, &api_spec).await;
            test_cases.extend(endpoint_tests);
        }
        
        let mut metadata = HashMap::new();
        metadata.insert(
            "total_endpoints".to_string(),
            Value::Number(serde_json::Number::from(endpoints.len())),
        );
        metadata.insert(
            "total_test_cases".to_string(),
            Value::Number(serde_json::Number::from(test_cases.len())),
        );
        metadata.insert(
            "generation_strategy".to_string(),
            Value::String("schema_based_with_realistic_data".to_string()),
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