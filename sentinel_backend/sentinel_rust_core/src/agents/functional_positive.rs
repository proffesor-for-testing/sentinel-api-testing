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
                    // Always include required parameters, include optional ones based on test strategy
                    if required || self.should_include_optional_param(param_name) {
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
        
        Some(self.generate_realistic_object(&resolved_schema, api_spec))
    }
    
    /// Generate a realistic object based on schema with enhanced data generation
    fn generate_realistic_object(&self, schema: &Value, api_spec: &Value) -> Value {
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
                // Always include required properties, include optional ones based on strategy
                if required.contains(&prop_name.as_str()) || self.should_include_optional_property(prop_name) {
                    // Resolve any schema references before generating the value
                    let resolved_prop_schema = resolve_schema_ref(prop_schema, api_spec);
                    obj.insert(
                        prop_name.clone(),
                        generate_realistic_property_value_with_spec(prop_name, &resolved_prop_schema, Some(api_spec)),
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
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Find optional query parameters
        let optional_params: Vec<_> = endpoint.parameters
            .iter()
            .filter(|p| {
                p.get("in").and_then(|i| i.as_str()) == Some("query") &&
                !p.get("required").and_then(|r| r.as_bool()).unwrap_or(false)
            })
            .collect();

        if optional_params.is_empty() {
            return test_cases;
        }

        // Test 1: Minimal parameters (only required ones)
        if let Some(minimal_test) = self.generate_minimal_parameter_test(endpoint, api_spec).await {
            test_cases.push(minimal_test);
        }

        // Test 2: Maximal parameters (all parameters including optional)
        if let Some(maximal_test) = self.generate_maximal_parameter_test(endpoint, api_spec).await {
            test_cases.push(maximal_test);
        }

        // Test 3: Boundary values for numeric parameters
        test_cases.extend(self.generate_numeric_boundary_variations(endpoint, api_spec).await);

        // Test 4: Enum exhaustive testing
        test_cases.extend(self.generate_enum_variation_tests(endpoint, api_spec).await);

        // Test 5: String length variations (min, max, typical)
        test_cases.extend(self.generate_string_length_variations(endpoint, api_spec).await);

        test_cases
    }
    
    /// Generate test cases with different request body variations
    async fn generate_body_variation_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if endpoint.request_body.is_none() {
            return test_cases;
        }

        // Test 1: Minimal body (only required fields)
        if let Some(minimal_test) = self.generate_minimal_body_test(endpoint, api_spec).await {
            test_cases.push(minimal_test);
        }

        // Test 2: Complete body (all fields including optional)
        if let Some(complete_test) = self.generate_complete_body_test(endpoint, api_spec).await {
            test_cases.push(complete_test);
        }

        // Test 3: Body with boundary values
        test_cases.extend(self.generate_body_boundary_variations(endpoint, api_spec).await);

        // Test 4: Body with enum variations
        test_cases.extend(self.generate_body_enum_variations(endpoint, api_spec).await);

        // Test 5: Body with different data type representations
        test_cases.extend(self.generate_body_type_variations(endpoint, api_spec).await);

        test_cases
    }

    /// Determine if optional parameter should be included based on systematic strategy
    fn should_include_optional_param(&self, param_name: &str) -> bool {
        // Use deterministic approach based on parameter name hash for consistency
        let hash = param_name.len() % 3;
        hash != 0 // Include ~66% of optional parameters
    }

    /// Determine if optional property should be included based on systematic strategy
    fn should_include_optional_property(&self, prop_name: &str) -> bool {
        // Use deterministic approach based on property name hash for consistency
        let hash = prop_name.len() % 4;
        hash != 0 // Include ~75% of optional properties
    }

    /// Generate test with minimal parameters (only required)
    async fn generate_minimal_parameter_test(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<TestCase> {
        let headers = self.generate_headers(&endpoint.operation);
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

        // Only include required parameters
        for param in &endpoint.parameters {
            if let (Some(param_in), Some(param_name), Some(required)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str()),
                param.get("required").and_then(|r| r.as_bool()),
            ) {
                if required {
                    let schema = param.get("schema").unwrap_or(&Value::Null);
                    let value = generate_parameter_value(param_name, schema);

                    match param_in {
                        "query" => { query_params.insert(param_name.to_string(), value); }
                        "path" => { path_params.insert(param_name.to_string(), value); }
                        _ => {}
                    }
                }
            }
        }

        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        let body = if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            endpoint.request_body.as_ref().and_then(|rb| {
                self.generate_request_body(rb, api_spec)
            })
        } else {
            None
        };

        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);
        let assertions = self.generate_response_assertions(&endpoint.responses, expected_status);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Minimal parameters test: {} {}", endpoint.method, endpoint.path),
            Some(headers),
            Some(query_params),
            body,
            expected_status,
            Some(assertions),
        ))
    }

    /// Generate test with maximal parameters (all including optional)
    async fn generate_maximal_parameter_test(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<TestCase> {
        let headers = self.generate_headers(&endpoint.operation);
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

        // Include all parameters
        for param in &endpoint.parameters {
            if let (Some(param_in), Some(param_name)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str()),
            ) {
                let schema = param.get("schema").unwrap_or(&Value::Null);
                let value = generate_parameter_value(param_name, schema);

                match param_in {
                    "query" => { query_params.insert(param_name.to_string(), value); }
                    "path" => { path_params.insert(param_name.to_string(), value); }
                    _ => {}
                }
            }
        }

        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        let body = if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            endpoint.request_body.as_ref().and_then(|rb| {
                self.generate_request_body(rb, api_spec)
            })
        } else {
            None
        };

        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);
        let assertions = self.generate_response_assertions(&endpoint.responses, expected_status);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Maximal parameters test: {} {}", endpoint.method, endpoint.path),
            Some(headers),
            Some(query_params),
            body,
            expected_status,
            Some(assertions),
        ))
    }

    /// Generate numeric boundary variation tests
    async fn generate_numeric_boundary_variations(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for param in &endpoint.parameters {
            if let Some(schema) = param.get("schema") {
                let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                if ["integer", "number"].contains(&param_type) {
                    let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

                    // Test minimum value
                    if let Some(min_val) = schema.get("minimum").and_then(|m| m.as_i64()) {
                        if let Some(test_case) = self.create_boundary_test_case(
                            endpoint, api_spec, param, Value::Number(serde_json::Number::from(min_val)),
                            &format!("Boundary test: {} minimum value", param_name)
                        ).await {
                            test_cases.push(test_case);
                        }
                    }

                    // Test maximum value
                    if let Some(max_val) = schema.get("maximum").and_then(|m| m.as_i64()) {
                        if let Some(test_case) = self.create_boundary_test_case(
                            endpoint, api_spec, param, Value::Number(serde_json::Number::from(max_val)),
                            &format!("Boundary test: {} maximum value", param_name)
                        ).await {
                            test_cases.push(test_case);
                        }
                    }
                }
            }
        }

        test_cases
    }

    /// Generate enum variation tests (test all enum values)
    async fn generate_enum_variation_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for param in &endpoint.parameters {
            if let Some(schema) = param.get("schema") {
                if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
                    let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

                    for (i, enum_val) in enum_values.iter().enumerate() {
                        if let Some(test_case) = self.create_boundary_test_case(
                            endpoint, api_spec, param, enum_val.clone(),
                            &format!("Enum test: {} value {} of {}", param_name, i + 1, enum_values.len())
                        ).await {
                            test_cases.push(test_case);
                        }
                    }
                }
            }
        }

        test_cases
    }

    /// Generate string length variation tests
    async fn generate_string_length_variations(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for param in &endpoint.parameters {
            if let Some(schema) = param.get("schema") {
                let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
                if param_type == "string" {
                    let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

                    // Test minimum length
                    if let Some(min_len) = schema.get("minLength").and_then(|m| m.as_u64()) {
                        let min_str = "x".repeat(min_len as usize);
                        if let Some(test_case) = self.create_boundary_test_case(
                            endpoint, api_spec, param, Value::String(min_str),
                            &format!("String length test: {} minimum length", param_name)
                        ).await {
                            test_cases.push(test_case);
                        }
                    }

                    // Test maximum length
                    if let Some(max_len) = schema.get("maxLength").and_then(|m| m.as_u64()) {
                        let max_str = "x".repeat(max_len as usize);
                        if let Some(test_case) = self.create_boundary_test_case(
                            endpoint, api_spec, param, Value::String(max_str),
                            &format!("String length test: {} maximum length", param_name)
                        ).await {
                            test_cases.push(test_case);
                        }
                    }
                }
            }
        }

        test_cases
    }

    /// Create a boundary test case with specific parameter value
    async fn create_boundary_test_case(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
        target_param: &Value,
        test_value: Value,
        description: &str,
    ) -> Option<TestCase> {
        let headers = self.generate_headers(&endpoint.operation);
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

        let target_name = target_param.get("name").and_then(|n| n.as_str())?;
        let target_in = target_param.get("in").and_then(|i| i.as_str()).unwrap_or("query");

        // Generate all parameters, using test_value for target parameter
        for param in &endpoint.parameters {
            if let (Some(param_in), Some(param_name)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str()),
            ) {
                let value = if param_name == target_name {
                    test_value.clone()
                } else {
                    let schema = param.get("schema").unwrap_or(&Value::Null);
                    generate_parameter_value(param_name, schema)
                };

                match param_in {
                    "query" => { query_params.insert(param_name.to_string(), value); }
                    "path" => { path_params.insert(param_name.to_string(), value); }
                    _ => {}
                }
            }
        }

        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        let body = if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            endpoint.request_body.as_ref().and_then(|rb| {
                self.generate_request_body(rb, api_spec)
            })
        } else {
            None
        };

        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);
        let assertions = self.generate_response_assertions(&endpoint.responses, expected_status);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            description.to_string(),
            Some(headers),
            Some(query_params),
            body,
            expected_status,
            Some(assertions),
        ))
    }

    /// Generate minimal body test (only required fields)
    async fn generate_minimal_body_test(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<TestCase> {
        let request_body = endpoint.request_body.as_ref()?;
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")
            .or_else(|| content.as_object()?.values().next())?;
        let schema = json_content.get("schema")?;
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        let minimal_body = self.generate_minimal_body_from_schema(&resolved_schema, api_spec);
        let headers = self.generate_headers(&endpoint.operation);
        let path_params = self.generate_path_parameters(&endpoint.parameters);
        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);
        let assertions = self.generate_response_assertions(&endpoint.responses, expected_status);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Minimal body test: {} {}", endpoint.method, endpoint.path),
            Some(headers),
            None,
            Some(minimal_body),
            expected_status,
            Some(assertions),
        ))
    }

    /// Generate complete body test (all fields including optional)
    async fn generate_complete_body_test(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<TestCase> {
        let request_body = endpoint.request_body.as_ref()?;
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")
            .or_else(|| content.as_object()?.values().next())?;
        let schema = json_content.get("schema")?;
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        let complete_body = self.generate_complete_body_from_schema(&resolved_schema, api_spec);
        let headers = self.generate_headers(&endpoint.operation);
        let path_params = self.generate_path_parameters(&endpoint.parameters);
        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);
        let assertions = self.generate_response_assertions(&endpoint.responses, expected_status);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Complete body test: {} {}", endpoint.method, endpoint.path),
            Some(headers),
            None,
            Some(complete_body),
            expected_status,
            Some(assertions),
        ))
    }

    /// Generate body with boundary values
    async fn generate_body_boundary_variations(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if let Some(request_body) = &endpoint.request_body {
            if let Some(content) = request_body.get("content") {
                if let Some(json_content) = content.get("application/json") {
                    if let Some(schema) = json_content.get("schema") {
                        let resolved_schema = resolve_schema_ref(schema, api_spec);
                        test_cases.extend(self.generate_body_boundary_tests(&resolved_schema, endpoint, api_spec));
                    }
                }
            }
        }

        test_cases
    }

    /// Generate body enum variations
    async fn generate_body_enum_variations(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if let Some(request_body) = &endpoint.request_body {
            if let Some(content) = request_body.get("content") {
                if let Some(json_content) = content.get("application/json") {
                    if let Some(schema) = json_content.get("schema") {
                        let resolved_schema = resolve_schema_ref(schema, api_spec);
                        test_cases.extend(self.generate_body_enum_tests(&resolved_schema, endpoint, api_spec));
                    }
                }
            }
        }

        test_cases
    }

    /// Generate body type variations
    async fn generate_body_type_variations(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if let Some(request_body) = &endpoint.request_body {
            if let Some(content) = request_body.get("content") {
                if let Some(json_content) = content.get("application/json") {
                    if let Some(schema) = json_content.get("schema") {
                        let resolved_schema = resolve_schema_ref(schema, api_spec);
                        test_cases.extend(self.generate_body_type_tests(&resolved_schema, endpoint, api_spec));
                    }
                }
            }
        }

        test_cases
    }

    /// Generate minimal body from schema (only required fields)
    fn generate_minimal_body_from_schema(&self, schema: &Value, api_spec: &Value) -> Value {
        if schema.get("type").and_then(|t| t.as_str()) != Some("object") {
            return generate_schema_example(schema);
        }

        let mut obj = serde_json::Map::new();

        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            let required = schema.get("required")
                .and_then(|r| r.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                .unwrap_or_default();

            for (prop_name, prop_schema) in properties {
                if required.contains(&prop_name.as_str()) {
                    let resolved_prop_schema = resolve_schema_ref(prop_schema, api_spec);
                    obj.insert(
                        prop_name.clone(),
                        generate_realistic_property_value_with_spec(prop_name, &resolved_prop_schema, Some(api_spec)),
                    );
                }
            }
        }

        Value::Object(obj)
    }

    /// Generate complete body from schema (all fields)
    fn generate_complete_body_from_schema(&self, schema: &Value, api_spec: &Value) -> Value {
        if schema.get("type").and_then(|t| t.as_str()) != Some("object") {
            return generate_schema_example(schema);
        }

        let mut obj = serde_json::Map::new();

        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (prop_name, prop_schema) in properties {
                let resolved_prop_schema = resolve_schema_ref(prop_schema, api_spec);
                obj.insert(
                    prop_name.clone(),
                    generate_realistic_property_value_with_spec(prop_name, &resolved_prop_schema, Some(api_spec)),
                );
            }
        }

        Value::Object(obj)
    }

    /// Generate boundary tests for body properties
    fn generate_body_boundary_tests(&self, schema: &Value, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (prop_name, prop_schema) in properties {
                let prop_type = prop_schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

                if ["integer", "number"].contains(&prop_type) {
                    // Test numeric boundaries
                    if let Some(min_val) = prop_schema.get("minimum").and_then(|m| m.as_i64()) {
                        if let Some(test_case) = self.create_body_boundary_test(
                            endpoint, api_spec, schema, prop_name,
                            Value::Number(serde_json::Number::from(min_val)),
                            &format!("Body boundary: {} minimum", prop_name)
                        ) {
                            test_cases.push(test_case);
                        }
                    }

                    if let Some(max_val) = prop_schema.get("maximum").and_then(|m| m.as_i64()) {
                        if let Some(test_case) = self.create_body_boundary_test(
                            endpoint, api_spec, schema, prop_name,
                            Value::Number(serde_json::Number::from(max_val)),
                            &format!("Body boundary: {} maximum", prop_name)
                        ) {
                            test_cases.push(test_case);
                        }
                    }
                } else if prop_type == "string" {
                    // Test string length boundaries
                    if let Some(min_len) = prop_schema.get("minLength").and_then(|m| m.as_u64()) {
                        let min_str = "x".repeat(min_len as usize);
                        if let Some(test_case) = self.create_body_boundary_test(
                            endpoint, api_spec, schema, prop_name,
                            Value::String(min_str),
                            &format!("Body boundary: {} min length", prop_name)
                        ) {
                            test_cases.push(test_case);
                        }
                    }

                    if let Some(max_len) = prop_schema.get("maxLength").and_then(|m| m.as_u64()) {
                        let max_str = "x".repeat(max_len as usize);
                        if let Some(test_case) = self.create_body_boundary_test(
                            endpoint, api_spec, schema, prop_name,
                            Value::String(max_str),
                            &format!("Body boundary: {} max length", prop_name)
                        ) {
                            test_cases.push(test_case);
                        }
                    }
                }
            }
        }

        test_cases
    }

    /// Generate enum tests for body properties
    fn generate_body_enum_tests(&self, schema: &Value, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (prop_name, prop_schema) in properties {
                if let Some(enum_values) = prop_schema.get("enum").and_then(|e| e.as_array()) {
                    for (i, enum_val) in enum_values.iter().enumerate() {
                        if let Some(test_case) = self.create_body_boundary_test(
                            endpoint, api_spec, schema, prop_name,
                            enum_val.clone(),
                            &format!("Body enum: {} value {} of {}", prop_name, i + 1, enum_values.len())
                        ) {
                            test_cases.push(test_case);
                        }
                    }
                }
            }
        }

        test_cases
    }

    /// Generate type variation tests for body properties
    fn generate_body_type_tests(&self, schema: &Value, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (prop_name, prop_schema) in properties {
                let prop_type = prop_schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

                // Test alternative valid representations
                match prop_type {
                    "number" => {
                        // Test both integer and float representations
                        if let Some(test_case) = self.create_body_boundary_test(
                            endpoint, api_spec, schema, prop_name,
                            Value::Number(serde_json::Number::from(42)),
                            &format!("Body type: {} as integer", prop_name)
                        ) {
                            test_cases.push(test_case);
                        }

                        if let Some(test_case) = self.create_body_boundary_test(
                            endpoint, api_spec, schema, prop_name,
                            Value::Number(serde_json::Number::from_f64(42.5).unwrap()),
                            &format!("Body type: {} as float", prop_name)
                        ) {
                            test_cases.push(test_case);
                        }
                    }
                    "boolean" => {
                        // Test both true and false
                        for (val, desc) in [(true, "true"), (false, "false")] {
                            if let Some(test_case) = self.create_body_boundary_test(
                                endpoint, api_spec, schema, prop_name,
                                Value::Bool(val),
                                &format!("Body type: {} as {}", prop_name, desc)
                            ) {
                                test_cases.push(test_case);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        test_cases
    }

    /// Create body boundary test case
    fn create_body_boundary_test(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
        base_schema: &Value,
        target_prop: &str,
        test_value: Value,
        description: &str,
    ) -> Option<TestCase> {
        let mut body = self.generate_realistic_object(base_schema, api_spec);

        if let Value::Object(ref mut obj) = body {
            obj.insert(target_prop.to_string(), test_value);
        }

        let headers = self.generate_headers(&endpoint.operation);
        let path_params = self.generate_path_parameters(&endpoint.parameters);
        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);
        let assertions = self.generate_response_assertions(&endpoint.responses, expected_status);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            description.to_string(),
            Some(headers),
            None,
            Some(body),
            expected_status,
            Some(assertions),
        ))
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