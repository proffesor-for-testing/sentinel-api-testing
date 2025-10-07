//! Unified Functional Agent: Generates test cases with configurable strategies.
//!
//! This agent supports multiple testing strategies through the `strategy` parameter:
//! - "positive": Valid happy path test cases
//! - "negative": Invalid inputs and error scenarios
//! - "boundary": Boundary value analysis tests
//! - "edge_case": Edge cases and corner scenarios
//!
//! The agent consolidates all functional testing logic into a single implementation,
//! matching the Python architecture for consistency.

use async_trait::async_trait;
use rand::prelude::*;
use serde_json::{Value, Number};
use std::collections::HashMap;

use crate::agents::{Agent, BaseAgent};
use crate::agents::utils::*;
use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo};

/// Unified agent responsible for generating functional test cases with configurable strategies
pub struct FunctionalAgent {
    base: BaseAgent,
}

impl FunctionalAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Functional-Agent".to_string()),
        }
    }

    /// Generate test cases based on the specified strategy
    async fn generate_endpoint_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
        strategy: &str,
    ) -> Vec<TestCase> {
        match strategy {
            "positive" => self.generate_positive_tests(endpoint, api_spec).await,
            "negative" => self.generate_negative_tests(endpoint, api_spec).await,
            "boundary" => self.generate_boundary_tests(endpoint, api_spec).await,
            "edge_case" => self.generate_edge_case_tests(endpoint, api_spec).await,
            _ => self.generate_positive_tests(endpoint, api_spec).await, // Default to positive
        }
    }

    /// Generate positive test cases (happy path)
    async fn generate_positive_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Generate basic positive test case
        if let Some(basic_test) = self.generate_basic_positive_test(endpoint, api_spec).await {
            test_cases.push(basic_test);
        }

        // Generate parameter variations for GET/DELETE
        if ["GET", "DELETE"].contains(&endpoint.method.as_str()) {
            let param_tests = self.generate_parameter_variation_tests(endpoint, api_spec).await;
            test_cases.extend(param_tests);
        }

        // Generate body variations for POST/PUT/PATCH
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            let body_tests = self.generate_body_variation_tests(endpoint, api_spec).await;
            test_cases.extend(body_tests);
        }

        test_cases
    }

    /// Generate negative test cases (error scenarios)
    async fn generate_negative_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Wrong data type tests
        let type_tests = self.generate_wrong_type_tests(endpoint, api_spec);
        test_cases.extend(type_tests);

        // Missing required field tests
        let missing_tests = self.generate_missing_required_tests(endpoint, api_spec);
        test_cases.extend(missing_tests);

        // Extra field tests
        let extra_tests = self.generate_extra_field_tests(endpoint, api_spec);
        test_cases.extend(extra_tests);

        // Semantic violation tests
        let semantic_tests = self.generate_semantic_violation_tests(endpoint, api_spec);
        test_cases.extend(semantic_tests);

        test_cases
    }

    /// Generate boundary value analysis tests
    async fn generate_boundary_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Test parameter boundaries
        for param in &endpoint.parameters {
            let param_tests = self.generate_parameter_boundary_tests(param, endpoint);
            test_cases.extend(param_tests);
        }

        // Test request body boundaries
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if let Some(_request_body) = &endpoint.request_body {
                let body_tests = self.generate_body_boundary_tests(endpoint, api_spec).await;
                test_cases.extend(body_tests);
            }
        }

        test_cases
    }

    /// Generate edge case tests
    async fn generate_edge_case_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Structural malformation tests
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            let structural_tests = self.generate_structural_malformation_tests(endpoint).await;
            test_cases.extend(structural_tests);
        }

        // Format violation tests
        let format_tests = self.generate_format_violation_tests(endpoint, api_spec);
        test_cases.extend(format_tests);

        // Nested object corruption tests
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            let nested_tests = self.generate_nested_object_corruption_tests(endpoint, api_spec);
            test_cases.extend(nested_tests);
        }

        test_cases
    }

    /// Generate basic positive test case
    async fn generate_basic_positive_test(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Option<TestCase> {
        let headers = self.get_default_headers();
        let query_params = self.generate_query_parameters(&endpoint.parameters);
        let path_params = self.generate_path_parameters(&endpoint.parameters);

        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);

        let body = if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            endpoint.request_body.as_ref().and_then(|rb| {
                self.generate_request_body(rb, api_spec)
            })
        } else {
            None
        };

        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);

        let summary = if endpoint.summary.is_empty() {
            format!("{} {}", endpoint.method, endpoint.path)
        } else {
            endpoint.summary.clone()
        };
        let description = format!("Positive test: {}", summary);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            description,
            Some(headers),
            Some(query_params),
            body,
            expected_status,
            None,
        ))
    }

    /// Generate parameter variation tests
    async fn generate_parameter_variation_tests(
        &self,
        endpoint: &EndpointInfo,
        _api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

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

        // Minimal parameters test (only required)
        if let Some(minimal_test) = self.generate_minimal_parameter_test(endpoint) {
            test_cases.push(minimal_test);
        }

        // Maximal parameters test (all including optional)
        if let Some(maximal_test) = self.generate_maximal_parameter_test(endpoint) {
            test_cases.push(maximal_test);
        }

        test_cases
    }

    /// Generate body variation tests
    async fn generate_body_variation_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if endpoint.request_body.is_none() {
            return test_cases;
        }

        // Minimal body test
        if let Some(minimal_test) = self.generate_minimal_body_test(endpoint, api_spec) {
            test_cases.push(minimal_test);
        }

        test_cases
    }

    /// Generate boundary tests for a parameter using consolidated boundary value logic
    fn generate_parameter_boundary_tests(
        &self,
        param: &Value,
        endpoint: &EndpointInfo,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        let param_name = match param.get("name").and_then(|n| n.as_str()) {
            Some(name) => name,
            None => return test_cases,
        };

        let schema = param.get("schema").unwrap_or(&Value::Null);
        let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        // Get boundary values using consolidated logic
        let boundary_values = get_boundary_values(schema);

        for (value, description) in boundary_values {
            if let Some(test_case) = self.create_parameter_test_case(
                endpoint,
                param,
                value,
                &format!("Boundary: {} - {}", param_name, description),
                200
            ) {
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate boundary tests for request body
    async fn generate_body_boundary_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        let request_body = match &endpoint.request_body {
            Some(rb) => rb,
            None => return test_cases,
        };

        let content = request_body.get("content").unwrap_or(&Value::Null);
        let json_content = content.get("application/json").unwrap_or(&Value::Null);
        if json_content.is_null() {
            return test_cases;
        }

        let schema = json_content.get("schema").unwrap_or(&Value::Null);
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        if resolved_schema.get("type").and_then(|t| t.as_str()) == Some("object") {
            if let Some(properties) = resolved_schema.get("properties").and_then(|p| p.as_object()) {
                for (prop_name, prop_schema) in properties {
                    let boundary_values = get_boundary_values(prop_schema);

                    for (value, description) in boundary_values {
                        let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
                            Some(body) => body,
                            None => continue,
                        };

                        let mut test_body = base_body.clone();
                        if let Value::Object(ref mut map) = test_body {
                            map.insert(prop_name.clone(), value);
                        }

                        let test_case = self.base.create_test_case(
                            self.build_endpoint_path(endpoint),
                            endpoint.method.clone(),
                            format!("Boundary: {} - {}", prop_name, description),
                            Some(self.get_default_headers()),
                            None,
                            Some(test_body),
                            200,
                            None,
                        );
                        test_cases.push(test_case);
                    }
                }
            }
        }

        test_cases
    }

    /// Generate wrong type tests (negative)
    fn generate_wrong_type_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Test wrong types in parameters
        for param in &endpoint.parameters {
            let schema = param.get("schema").unwrap_or(&Value::Null);
            let expected_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

            if let Some(wrong_value) = get_wrong_type_value(expected_type) {
                let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                let description = format!("Wrong type: {} (expected {}, got {})", param_name, expected_type, get_value_type(&wrong_value));

                if let Some(test_case) = self.create_parameter_test_case(endpoint, param, wrong_value, &description, 400) {
                    test_cases.push(test_case);
                }
            }
        }

        // Test wrong types in body
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if endpoint.request_body.is_some() {
                let body_tests = self.generate_body_wrong_type_tests(endpoint, api_spec);
                test_cases.extend(body_tests);
            }
        }

        test_cases
    }

    /// Generate body wrong type tests
    fn generate_body_wrong_type_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
            Some(body) => body,
            None => return test_cases,
        };

        let request_body = match &endpoint.request_body {
            Some(rb) => rb,
            None => return test_cases,
        };

        let content = request_body.get("content").unwrap_or(&Value::Null);
        let json_content = content.get("application/json").unwrap_or(&Value::Null);
        let schema = json_content.get("schema").unwrap_or(&Value::Null);
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        if resolved_schema.get("type").and_then(|t| t.as_str()) == Some("object") {
            if let Some(properties) = resolved_schema.get("properties").and_then(|p| p.as_object()) {
                for (prop_name, prop_schema) in properties {
                    let expected_type = prop_schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

                    if let Some(wrong_value) = get_wrong_type_value(expected_type) {
                        let mut invalid_body = base_body.clone();
                        if let Value::Object(ref mut map) = invalid_body {
                            map.insert(prop_name.clone(), wrong_value);
                        }

                        let test_case = self.base.create_test_case(
                            self.build_endpoint_path(endpoint),
                            endpoint.method.clone(),
                            format!("Wrong type in body: {} (expected {})", prop_name, expected_type),
                            Some(self.get_default_headers()),
                            None,
                            Some(invalid_body),
                            400,
                            None,
                        );
                        test_cases.push(test_case);
                    }
                }
            }
        }

        test_cases
    }

    /// Generate missing required field tests
    fn generate_missing_required_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Missing required parameters
        let required_params: Vec<&Value> = endpoint.parameters
            .iter()
            .filter(|p| p.get("required").and_then(|r| r.as_bool()).unwrap_or(false))
            .collect();

        for param in required_params {
            if let Some(test_case) = self.create_missing_parameter_test(endpoint, param) {
                test_cases.push(test_case);
            }
        }

        // Missing required body fields
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if endpoint.request_body.is_some() {
                let body_tests = self.generate_missing_body_field_tests(endpoint, api_spec);
                test_cases.extend(body_tests);
            }
        }

        test_cases
    }

    /// Generate missing body field tests
    fn generate_missing_body_field_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        let request_body = match &endpoint.request_body {
            Some(rb) => rb,
            None => return test_cases,
        };

        let content = request_body.get("content").unwrap_or(&Value::Null);
        let json_content = content.get("application/json").unwrap_or(&Value::Null);
        let schema = json_content.get("schema").unwrap_or(&Value::Null);
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        if resolved_schema.get("type").and_then(|t| t.as_str()) == Some("object") {
            let required_fields = resolved_schema
                .get("required")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            for required_field in required_fields {
                let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
                    Some(body) => body,
                    None => continue,
                };

                if let Value::Object(mut map) = base_body {
                    if map.contains_key(required_field) {
                        map.remove(required_field);
                        let invalid_body = Value::Object(map);

                        let test_case = self.base.create_test_case(
                            self.build_endpoint_path(endpoint),
                            endpoint.method.clone(),
                            format!("Missing required field: {}", required_field),
                            Some(self.get_default_headers()),
                            None,
                            Some(invalid_body),
                            400,
                            None,
                        );
                        test_cases.push(test_case);
                    }
                }
            }
        }

        test_cases
    }

    /// Generate extra field tests
    fn generate_extra_field_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if endpoint.request_body.is_some() {
                let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
                    Some(body) => body,
                    None => return test_cases,
                };

                if let Value::Object(mut map) = base_body {
                    map.insert("unexpected_field".to_string(), Value::String("unexpected_value".to_string()));
                    let invalid_body = Value::Object(map);

                    let test_case = self.base.create_test_case(
                        self.build_endpoint_path(endpoint),
                        endpoint.method.clone(),
                        "Extra unexpected fields in body".to_string(),
                        Some(self.get_default_headers()),
                        None,
                        Some(invalid_body),
                        400,
                        None,
                    );
                    test_cases.push(test_case);
                }
            }
        }

        test_cases
    }

    /// Generate semantic violation tests
    fn generate_semantic_violation_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) && endpoint.request_body.is_some() {
            let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
                Some(body) => body,
                None => return test_cases,
            };

            // Test with negative IDs
            if let Value::Object(mut map) = base_body.clone() {
                if map.contains_key("id") {
                    map.insert("id".to_string(), Value::Number(Number::from(-1)));
                    let test_case = self.base.create_test_case(
                        self.build_endpoint_path(endpoint),
                        endpoint.method.clone(),
                        "Semantic violation: negative ID".to_string(),
                        Some(self.get_default_headers()),
                        None,
                        Some(Value::Object(map)),
                        400,
                        None,
                    );
                    test_cases.push(test_case);
                }
            }
        }

        test_cases
    }

    /// Generate structural malformation tests
    async fn generate_structural_malformation_tests(
        &self,
        endpoint: &EndpointInfo,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if endpoint.request_body.is_some() {
            // Empty body test
            let test_case = self.base.create_test_case(
                self.build_endpoint_path(endpoint),
                endpoint.method.clone(),
                "Structural: empty request body".to_string(),
                Some(self.get_default_headers()),
                None,
                None,
                400,
                None,
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate format violation tests
    fn generate_format_violation_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Check parameters for format constraints
        for param in &endpoint.parameters {
            if let Some(schema) = param.get("schema") {
                if let Some(format) = schema.get("format").and_then(|f| f.as_str()) {
                    let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                    let invalid_value = get_invalid_format_value(format);

                    if let Some(test_case) = self.create_parameter_test_case(
                        endpoint,
                        param,
                        Value::String(invalid_value.clone()),
                        &format!("Format violation: {} (invalid {})", param_name, format),
                        400
                    ) {
                        test_cases.push(test_case);
                    }
                }
            }
        }

        test_cases
    }

    /// Generate nested object corruption tests
    fn generate_nested_object_corruption_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
            Some(body) => body,
            None => return test_cases,
        };

        // Deep nesting test
        let mut deep_nested = serde_json::Map::new();
        let mut current_map = &mut deep_nested;

        for i in 0..50 {
            let mut new_map = serde_json::Map::new();
            new_map.insert("value".to_string(), Value::String("deep".to_string()));
            current_map.insert(format!("level_{}", i), Value::Object(new_map));

            if let Some(Value::Object(ref mut next)) = current_map.get_mut(&format!("level_{}", i)) {
                current_map = next;
            }
        }

        let test_case = self.base.create_test_case(
            self.build_endpoint_path(endpoint),
            endpoint.method.clone(),
            "Deep nested object (50 levels)".to_string(),
            Some(self.get_default_headers()),
            None,
            Some(Value::Object(deep_nested)),
            400,
            None,
        );
        test_cases.push(test_case);

        test_cases
    }

    // Helper methods

    fn get_default_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());
        headers
    }

    fn generate_query_parameters(&self, parameters: &[Value]) -> HashMap<String, Value> {
        let mut query_params = HashMap::new();

        for param in parameters {
            if let (Some(param_in), Some(param_name)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str()),
            ) {
                if param_in == "query" {
                    let required = param.get("required").and_then(|r| r.as_bool()).unwrap_or(false);
                    if required || should_include_optional(param_name) {
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

    fn generate_request_body(&self, request_body: &Value, api_spec: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")
            .or_else(|| content.as_object()?.values().next())?;
        let schema = json_content.get("schema")?;
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        Some(generate_realistic_object(&resolved_schema, api_spec))
    }

    fn generate_base_valid_body(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<Value> {
        let request_body = endpoint.request_body.as_ref()?;
        self.generate_request_body(request_body, api_spec)
    }

    fn build_endpoint_path(&self, endpoint: &EndpointInfo) -> String {
        let mut path = endpoint.path.clone();

        for param in &endpoint.parameters {
            if param.get("in").and_then(|i| i.as_str()) == Some("path") {
                if let Some(param_name) = param.get("name").and_then(|n| n.as_str()) {
                    let schema = param.get("schema").unwrap_or(&Value::Null);
                    let param_value = generate_parameter_value(param_name, schema);
                    let value_str = match param_value {
                        Value::String(s) => s,
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => "unknown".to_string(),
                    };
                    path = path.replace(&format!("{{{}}}", param_name), &value_str);
                }
            }
        }

        path
    }

    fn create_parameter_test_case(
        &self,
        endpoint: &EndpointInfo,
        param: &Value,
        test_value: Value,
        description: &str,
        expected_status: u16,
    ) -> Option<TestCase> {
        let param_name = param.get("name").and_then(|n| n.as_str())?;
        let mut headers = self.get_default_headers();
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

        for p in &endpoint.parameters {
            let p_name = p.get("name").and_then(|n| n.as_str())?;
            let value = if p_name == param_name {
                test_value.clone()
            } else {
                let schema = p.get("schema").unwrap_or(&Value::Null);
                generate_parameter_value(p_name, schema)
            };

            let p_in = p.get("in").and_then(|i| i.as_str()).unwrap_or("query");
            match p_in {
                "query" => { query_params.insert(p_name.to_string(), value); }
                "path" => { path_params.insert(p_name.to_string(), value); }
                "header" => {
                    if let Value::String(s) = value {
                        headers.insert(p_name.to_string(), s);
                    }
                }
                _ => {}
            }
        }

        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            description.to_string(),
            Some(headers),
            Some(query_params),
            None,
            expected_status,
            None,
        ))
    }

    fn create_missing_parameter_test(
        &self,
        endpoint: &EndpointInfo,
        missing_param: &Value,
    ) -> Option<TestCase> {
        let missing_param_name = missing_param.get("name").and_then(|n| n.as_str())?;

        let mut headers = self.get_default_headers();
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

        for param in &endpoint.parameters {
            let param_name = param.get("name").and_then(|n| n.as_str())?;
            if param_name != missing_param_name {
                let param_in = param.get("in").and_then(|i| i.as_str()).unwrap_or("query");
                let schema = param.get("schema").unwrap_or(&Value::Null);
                let param_value = generate_parameter_value(param_name, schema);

                match param_in {
                    "query" => { query_params.insert(param_name.to_string(), param_value); }
                    "path" => { path_params.insert(param_name.to_string(), param_value); }
                    "header" => {
                        if let Value::String(s) = param_value {
                            headers.insert(param_name.to_string(), s);
                        }
                    }
                    _ => {}
                }
            }
        }

        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Missing required parameter: {}", missing_param_name),
            Some(headers),
            Some(query_params),
            None,
            400,
            None,
        ))
    }

    fn generate_minimal_parameter_test(&self, endpoint: &EndpointInfo) -> Option<TestCase> {
        let headers = self.get_default_headers();
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

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
        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Minimal parameters: {} {}", endpoint.method, endpoint.path),
            Some(headers),
            Some(query_params),
            None,
            expected_status,
            None,
        ))
    }

    fn generate_maximal_parameter_test(&self, endpoint: &EndpointInfo) -> Option<TestCase> {
        let headers = self.get_default_headers();
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

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
        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Maximal parameters: {} {}", endpoint.method, endpoint.path),
            Some(headers),
            Some(query_params),
            None,
            expected_status,
            None,
        ))
    }

    fn generate_minimal_body_test(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<TestCase> {
        let request_body = endpoint.request_body.as_ref()?;
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")
            .or_else(|| content.as_object()?.values().next())?;
        let schema = json_content.get("schema")?;
        let resolved_schema = resolve_schema_ref(schema, api_spec);

        let minimal_body = generate_minimal_object(&resolved_schema, api_spec);
        let headers = self.get_default_headers();
        let path_params = self.generate_path_parameters(&endpoint.parameters);
        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);
        let expected_status = get_expected_success_status(&endpoint.responses, &endpoint.method);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Minimal body: {} {}", endpoint.method, endpoint.path),
            Some(headers),
            None,
            Some(minimal_body),
            expected_status,
            None,
        ))
    }
}

#[async_trait]
impl Agent for FunctionalAgent {
    fn agent_type(&self) -> &str {
        &self.base.agent_type
    }

    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        let start_time = std::time::Instant::now();

        // Extract strategy from task parameters, default to "positive"
        let strategy = task.parameters
            .get("strategy")
            .and_then(|s| s.as_str())
            .unwrap_or("positive");

        match self.execute_internal(task.clone(), api_spec, strategy).await {
            Ok(mut result) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                result.metadata.insert(
                    "processing_time_ms".to_string(),
                    Value::Number(Number::from(processing_time)),
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

impl FunctionalAgent {
    async fn execute_internal(&self, task: AgentTask, api_spec: Value, strategy: &str) -> Result<AgentResult, String> {
        let endpoints = self.base.extract_endpoints(&api_spec);
        let mut test_cases = Vec::new();

        for endpoint in &endpoints {
            let endpoint_tests = self.generate_endpoint_tests(endpoint, &api_spec, strategy).await;
            test_cases.extend(endpoint_tests);
        }

        let mut metadata = HashMap::new();
        metadata.insert(
            "total_endpoints".to_string(),
            Value::Number(Number::from(endpoints.len())),
        );
        metadata.insert(
            "total_test_cases".to_string(),
            Value::Number(Number::from(test_cases.len())),
        );
        metadata.insert(
            "strategy".to_string(),
            Value::String(strategy.to_string()),
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
