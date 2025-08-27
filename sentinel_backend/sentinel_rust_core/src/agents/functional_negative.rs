//! Functional-Negative-Agent: Generates tests to trigger errors and validate failure paths.
//!
//! This agent focuses on creating test cases that should fail under various conditions,
//! validating that the API properly handles invalid inputs and edge cases using a hybrid
//! approach of deterministic Boundary Value Analysis and creative generation.

use async_trait::async_trait;
use rand::prelude::*;
use serde_json::{Value, Number};
use std::collections::HashMap;

use crate::agents::{Agent, BaseAgent};
use crate::agents::utils::*;
use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo};

/// Agent responsible for generating negative functional test cases
pub struct FunctionalNegativeAgent {
    base: BaseAgent,
}

impl FunctionalNegativeAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Functional-Negative-Agent".to_string()),
        }
    }

    /// Generate negative test cases for a specific endpoint
    async fn generate_endpoint_negative_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Stage 1: Deterministic Boundary Value Analysis
        let bva_tests = self.generate_bva_tests(endpoint, api_spec).await;
        test_cases.extend(bva_tests);

        // Stage 2: Creative Invalid Data Generation
        let creative_tests = self.generate_creative_invalid_tests(endpoint, api_spec).await;
        test_cases.extend(creative_tests);

        // Stage 3: Structural Malformation Tests
        let structural_tests = self.generate_structural_malformation_tests(endpoint, api_spec).await;
        test_cases.extend(structural_tests);

        test_cases
    }

    /// Generate boundary value analysis tests using deterministic algorithms
    async fn generate_bva_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Test parameter boundary violations
        for param in &endpoint.parameters {
            let param_bva_tests = self.generate_parameter_bva_tests(param, endpoint, api_spec);
            test_cases.extend(param_bva_tests);
        }

        // Test request body boundary violations
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if let Some(_request_body) = &endpoint.request_body {
                let body_bva_tests = self.generate_body_bva_tests(endpoint, api_spec).await;
                test_cases.extend(body_bva_tests);
            }
        }

        test_cases
    }

    /// Generate BVA tests for a specific parameter
    fn generate_parameter_bva_tests(
        &self,
        param: &Value,
        endpoint: &EndpointInfo,
        _api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        
        let _param_name = match param.get("name").and_then(|n| n.as_str()) {
            Some(name) => name,
            None => return test_cases,
        };

        let schema = param.get("schema").unwrap_or(&Value::Null);
        let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        // Test numeric boundaries
        if ["integer", "number"].contains(&param_type) {
            let numeric_tests = self.generate_numeric_boundary_tests(param, endpoint);
            test_cases.extend(numeric_tests);
        }

        // Test string length boundaries
        if param_type == "string" {
            let string_tests = self.generate_string_boundary_tests(param, endpoint);
            test_cases.extend(string_tests);
        }

        // Test array size boundaries
        if param_type == "array" {
            let array_tests = self.generate_array_boundary_tests(param, endpoint);
            test_cases.extend(array_tests);
        }

        // Test enum violations
        if schema.get("enum").is_some() {
            let enum_tests = self.generate_enum_violation_tests(param, endpoint);
            test_cases.extend(enum_tests);
        }

        test_cases
    }

    /// Generate boundary tests for numeric parameters
    fn generate_numeric_boundary_tests(
        &self,
        param: &Value,
        endpoint: &EndpointInfo,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let schema = param.get("schema").unwrap_or(&Value::Null);
        let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

        // Test minimum boundary violations
        if let Some(minimum) = schema.get("minimum").and_then(|m| m.as_f64()) {
            let exclusive = schema.get("exclusiveMinimum").and_then(|e| e.as_bool()).unwrap_or(false);

            let invalid_value = if exclusive {
                minimum
            } else {
                minimum - 1.0
            };

            let description = if exclusive {
                format!("Test {} with exclusive minimum boundary violation (value = {})", param_name, invalid_value)
            } else {
                format!("Test {} below minimum boundary (value = {})", param_name, invalid_value)
            };

            if let Some(test_case) = self.create_parameter_test_case(endpoint, param, Value::Number(Number::from_f64(invalid_value).unwrap()), &description, 400) {
                test_cases.push(test_case);
            }
        }

        // Test maximum boundary violations
        if let Some(maximum) = schema.get("maximum").and_then(|m| m.as_f64()) {
            let exclusive = schema.get("exclusiveMaximum").and_then(|e| e.as_bool()).unwrap_or(false);

            let invalid_value = if exclusive {
                maximum
            } else {
                maximum + 1.0
            };

            let description = if exclusive {
                format!("Test {} with exclusive maximum boundary violation (value = {})", param_name, invalid_value)
            } else {
                format!("Test {} above maximum boundary (value = {})", param_name, invalid_value)
            };

            if let Some(test_case) = self.create_parameter_test_case(endpoint, param, Value::Number(Number::from_f64(invalid_value).unwrap()), &description, 400) {
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate boundary tests for string parameters
    fn generate_string_boundary_tests(
        &self,
        param: &Value,
        endpoint: &EndpointInfo,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let schema = param.get("schema").unwrap_or(&Value::Null);
        let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

        // Test minLength violations
        if let Some(min_length) = schema.get("minLength").and_then(|m| m.as_u64()) {
            if min_length > 0 {
                let invalid_value = "x".repeat((min_length - 1) as usize);
                let description = format!("Test {} below minimum length (length = {})", param_name, invalid_value.len());
                
                if let Some(test_case) = self.create_parameter_test_case(endpoint, param, Value::String(invalid_value), &description, 400) {
                    test_cases.push(test_case);
                }
            }
        }

        // Test maxLength violations
        if let Some(max_length) = schema.get("maxLength").and_then(|m| m.as_u64()) {
            let invalid_value = "x".repeat((max_length + 1) as usize);
            let description = format!("Test {} above maximum length (length = {})", param_name, invalid_value.len());
            
            if let Some(test_case) = self.create_parameter_test_case(endpoint, param, Value::String(invalid_value), &description, 400) {
                test_cases.push(test_case);
            }
        }

        // Test pattern violations
        if schema.get("pattern").is_some() {
            let invalid_value = "INVALID_PATTERN_123!@#".to_string();
            let description = format!("Test {} with pattern violation", param_name);
            
            if let Some(test_case) = self.create_parameter_test_case(endpoint, param, Value::String(invalid_value), &description, 400) {
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate boundary tests for array parameters
    fn generate_array_boundary_tests(
        &self,
        param: &Value,
        endpoint: &EndpointInfo,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let schema = param.get("schema").unwrap_or(&Value::Null);
        let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

        // Test minItems violations
        if let Some(min_items) = schema.get("minItems").and_then(|m| m.as_u64()) {
            if min_items > 0 {
                let invalid_value = Value::Array(vec![Value::String("item".to_string()); (min_items - 1) as usize]);
                let description = format!("Test {} below minimum items (count = {})", param_name, min_items - 1);
                
                if let Some(test_case) = self.create_parameter_test_case(endpoint, param, invalid_value, &description, 400) {
                    test_cases.push(test_case);
                }
            }
        }

        // Test maxItems violations
        if let Some(max_items) = schema.get("maxItems").and_then(|m| m.as_u64()) {
            let invalid_value = Value::Array(vec![Value::String("item".to_string()); (max_items + 1) as usize]);
            let description = format!("Test {} above maximum items (count = {})", param_name, max_items + 1);
            
            if let Some(test_case) = self.create_parameter_test_case(endpoint, param, invalid_value, &description, 400) {
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate tests that violate enum constraints
    fn generate_enum_violation_tests(
        &self,
        param: &Value,
        endpoint: &EndpointInfo,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

        let invalid_value = Value::String("INVALID_ENUM_VALUE_XYZ".to_string());
        let description = format!("Test {} with invalid enum value", param_name);
        
        if let Some(test_case) = self.create_parameter_test_case(endpoint, param, invalid_value, &description, 400) {
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate BVA tests for request body constraints
    async fn generate_body_bva_tests(
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

        // Generate tests for object property constraints
        if resolved_schema.get("type").and_then(|t| t.as_str()) == Some("object") {
            if let Some(properties) = resolved_schema.get("properties").and_then(|p| p.as_object()) {
                for (prop_name, prop_schema) in properties {
                    let prop_tests = self.generate_property_bva_tests(prop_name, prop_schema, endpoint, api_spec);
                    test_cases.extend(prop_tests);
                }
            }
        }

        test_cases
    }

    /// Generate BVA tests for a specific object property
    fn generate_property_bva_tests(
        &self,
        prop_name: &str,
        prop_schema: &Value,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Create a base valid body
        let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
            Some(body) => body,
            None => return test_cases,
        };

        let prop_type = prop_schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        // Test numeric property boundaries
        if ["integer", "number"].contains(&prop_type) {
            if let Some(minimum) = prop_schema.get("minimum").and_then(|m| m.as_f64()) {
                let mut invalid_body = base_body.clone();
                if let Value::Object(ref mut map) = invalid_body {
                    map.insert(prop_name.to_string(), Value::Number(Number::from_f64(minimum - 1.0).unwrap()));
                }

                let test_case = self.base.create_test_case(
                    self.build_endpoint_path(endpoint),
                    endpoint.method.clone(),
                    format!("Test {} below minimum in request body", prop_name),
                    Some(self.get_default_headers()),
                    None,
                    Some(invalid_body),
                    400,
                    None,
                );
                test_cases.push(test_case);
            }

            if let Some(maximum) = prop_schema.get("maximum").and_then(|m| m.as_f64()) {
                let mut invalid_body = base_body.clone();
                if let Value::Object(ref mut map) = invalid_body {
                    map.insert(prop_name.to_string(), Value::Number(Number::from_f64(maximum + 1.0).unwrap()));
                }

                let test_case = self.base.create_test_case(
                    self.build_endpoint_path(endpoint),
                    endpoint.method.clone(),
                    format!("Test {} above maximum in request body", prop_name),
                    Some(self.get_default_headers()),
                    None,
                    Some(invalid_body),
                    400,
                    None,
                );
                test_cases.push(test_case);
            }
        }
        // Test string property boundaries
        else if prop_type == "string" {
            if let Some(min_length) = prop_schema.get("minLength").and_then(|m| m.as_u64()) {
                if min_length > 0 {
                    let mut invalid_body = base_body.clone();
                    if let Value::Object(ref mut map) = invalid_body {
                        map.insert(prop_name.to_string(), Value::String("x".repeat((min_length - 1) as usize)));
                    }

                    let test_case = self.base.create_test_case(
                        self.build_endpoint_path(endpoint),
                        endpoint.method.clone(),
                        format!("Test {} below minimum length in request body", prop_name),
                        Some(self.get_default_headers()),
                        None,
                        Some(invalid_body),
                        400,
                        None,
                    );
                    test_cases.push(test_case);
                }
            }

            if let Some(max_length) = prop_schema.get("maxLength").and_then(|m| m.as_u64()) {
                let mut invalid_body = base_body.clone();
                if let Value::Object(ref mut map) = invalid_body {
                    map.insert(prop_name.to_string(), Value::String("x".repeat((max_length + 1) as usize)));
                }

                let test_case = self.base.create_test_case(
                    self.build_endpoint_path(endpoint),
                    endpoint.method.clone(),
                    format!("Test {} above maximum length in request body", prop_name),
                    Some(self.get_default_headers()),
                    None,
                    Some(invalid_body),
                    400,
                    None,
                );
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate creative invalid test cases
    async fn generate_creative_invalid_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Generate wrong data type tests
        let type_tests = self.generate_wrong_type_tests(endpoint, api_spec);
        test_cases.extend(type_tests);

        // Generate missing required field tests
        let missing_tests = self.generate_missing_required_tests(endpoint, api_spec);
        test_cases.extend(missing_tests);

        // Generate unexpected extra field tests
        let extra_field_tests = self.generate_extra_field_tests(endpoint, api_spec);
        test_cases.extend(extra_field_tests);

        // Generate semantic violation tests
        let semantic_tests = self.generate_semantic_violation_tests(endpoint, api_spec);
        test_cases.extend(semantic_tests);

        test_cases
    }

    /// Generate tests with wrong data types
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
            
            if let Some(wrong_value) = self.get_wrong_type_value(expected_type) {
                let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                let description = format!("Test {} with wrong data type", param_name);
                
                if let Some(test_case) = self.create_parameter_test_case(endpoint, param, wrong_value, &description, 400) {
                    test_cases.push(test_case);
                }
            }
        }

        // Test wrong types in request body
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if endpoint.request_body.is_some() {
                let body_type_tests = self.generate_body_wrong_type_tests(endpoint, api_spec);
                test_cases.extend(body_type_tests);
            }
        }

        test_cases
    }

    /// Get a value of the wrong type for testing
    fn get_wrong_type_value(&self, expected_type: &str) -> Option<Value> {
        match expected_type {
            "string" => Some(Value::Number(Number::from(12345))), // Number instead of string
            "integer" => Some(Value::String("not_a_number".to_string())), // String instead of integer
            "number" => Some(Value::String("not_a_number".to_string())), // String instead of number
            "boolean" => Some(Value::String("not_a_boolean".to_string())), // String instead of boolean
            "array" => {
                let mut obj = serde_json::Map::new();
                obj.insert("not".to_string(), Value::String("an_array".to_string()));
                Some(Value::Object(obj)) // Object instead of array
            }
            "object" => Some(Value::String("not_an_object".to_string())), // String instead of object
            _ => None,
        }
    }

    /// Generate wrong type tests for request body properties
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
                    
                    if let Some(wrong_value) = self.get_wrong_type_value(expected_type) {
                        let mut invalid_body = base_body.clone();
                        if let Value::Object(ref mut map) = invalid_body {
                            map.insert(prop_name.clone(), wrong_value);
                        }

                        let test_case = self.base.create_test_case(
                            self.build_endpoint_path(endpoint),
                            endpoint.method.clone(),
                            format!("Test {} with wrong data type in request body", prop_name),
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

    /// Generate tests with missing required fields
    fn generate_missing_required_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Test missing required parameters
        let required_params: Vec<&Value> = endpoint.parameters
            .iter()
            .filter(|p| p.get("required").and_then(|r| r.as_bool()).unwrap_or(false))
            .collect();

        for param in required_params {
            if let Some(test_case) = self.create_missing_parameter_test(endpoint, param) {
                test_cases.push(test_case);
            }
        }

        // Test missing required body fields
        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if endpoint.request_body.is_some() {
                let body_missing_tests = self.generate_missing_body_field_tests(endpoint, api_spec);
                test_cases.extend(body_missing_tests);
            }
        }

        test_cases
    }

    /// Create a test case with a missing required parameter
    fn create_missing_parameter_test(
        &self,
        endpoint: &EndpointInfo,
        missing_param: &Value,
    ) -> Option<TestCase> {
        let missing_param_name = missing_param.get("name").and_then(|n| n.as_str())?;
        
        // Build parameters excluding the missing one
        let mut headers = self.get_default_headers();
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

        for param in &endpoint.parameters {
            let param_name = param.get("name").and_then(|n| n.as_str())?;
            if param_name != missing_param_name {
                let param_in = param.get("in").and_then(|i| i.as_str()).unwrap_or("query");
                let param_value = self.generate_valid_param_value(param);

                match param_in {
                    "query" => {
                        query_params.insert(param_name.to_string(), param_value);
                    }
                    "path" => {
                        path_params.insert(param_name.to_string(), param_value);
                    }
                    "header" => {
                        if let Value::String(s) = param_value {
                            headers.insert(param_name.to_string(), s);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Build the endpoint path
        let actual_path = substitute_path_parameters(&endpoint.path, &path_params);

        Some(self.base.create_test_case(
            actual_path,
            endpoint.method.clone(),
            format!("Test missing required parameter: {}", missing_param_name),
            Some(headers),
            Some(query_params),
            None,
            400,
            None,
        ))
    }

    /// Generate tests with missing required body fields
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
                        // Remove the required field
                        map.remove(required_field);
                        let invalid_body = Value::Object(map);

                        let test_case = self.base.create_test_case(
                            self.build_endpoint_path(endpoint),
                            endpoint.method.clone(),
                            format!("Test missing required field: {}", required_field),
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

    /// Generate tests with unexpected extra fields
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
                    // Add unexpected fields
                    map.insert("unexpected_field_1".to_string(), Value::String("unexpected_value".to_string()));
                    map.insert("malicious_script".to_string(), Value::String("<script>alert('xss')</script>".to_string()));
                    map.insert("sql_injection".to_string(), Value::String("'; DROP TABLE users; --".to_string()));

                    let invalid_body = Value::Object(map);

                    let test_case = self.base.create_test_case(
                        self.build_endpoint_path(endpoint),
                        endpoint.method.clone(),
                        "Test with unexpected extra fields in request body".to_string(),
                        Some(self.get_default_headers()),
                        None,
                        Some(invalid_body),
                        400, // or 422, depending on API design
                        None,
                    );
                    test_cases.push(test_case);
                }
            }
        }

        test_cases
    }

    /// Generate tests that violate semantic expectations
    fn generate_semantic_violation_tests(
        &self,
        endpoint: &EndpointInfo,
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Generate tests based on common semantic violations
        let semantic_violations = vec![
            (
                "Test with negative ID where positive expected",
                vec![("id", Value::Number(Number::from(-1))), ("user_id", Value::Number(Number::from(-999))), ("product_id", Value::Number(Number::from(-123)))],
            ),
            (
                "Test with future date where past date expected",
                vec![("birth_date", Value::String("2050-01-01".to_string())), ("created_at", Value::String("2099-12-31".to_string()))],
            ),
            (
                "Test with invalid email format",
                vec![("email", Value::String("not-an-email".to_string())), ("contact_email", Value::String("invalid@".to_string()))],
            ),
            (
                "Test with empty string where meaningful content expected",
                vec![("name", Value::String("".to_string())), ("title", Value::String("".to_string())), ("description", Value::String("".to_string()))],
            ),
            (
                "Test with extremely long strings",
                vec![
                    ("name", Value::String("x".repeat(1000))),
                    ("description", Value::String("y".repeat(5000))),
                    ("title", Value::String("z".repeat(500))),
                ],
            ),
        ];

        for (description, modifications) in semantic_violations {
            if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
                if endpoint.request_body.is_some() {
                    let base_body = match self.generate_base_valid_body(endpoint, api_spec) {
                        Some(body) => body,
                        None => continue,
                    };

                    if let Value::Object(mut map) = base_body.clone() {
                        let mut modified = false;
                        
                        // Apply modifications that exist in the body
                        for (field, value) in modifications {
                            if map.contains_key(field) {
                                map.insert(field.to_string(), value);
                                modified = true;
                                break; // Apply only one modification per test
                            }
                        }

                        if modified {
                            let invalid_body = Value::Object(map);
                            let test_case = self.base.create_test_case(
                                self.build_endpoint_path(endpoint),
                                endpoint.method.clone(),
                                description.to_string(),
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
        }

        test_cases
    }

    /// Generate tests with structurally malformed requests
    async fn generate_structural_malformation_tests(
        &self,
        endpoint: &EndpointInfo,
        _api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            if endpoint.request_body.is_some() {
                let malformed_tests = vec![
                    ("Test with empty request body", None, "application/json"),
                    ("Test with wrong content type", Some(Value::Object(serde_json::Map::from_iter([("name".to_string(), Value::String("test".to_string()))]))), "text/plain"),
                ];

                for (description, body, content_type) in malformed_tests {
                    let mut headers = HashMap::new();
                    headers.insert("Content-Type".to_string(), content_type.to_string());
                    headers.insert("Accept".to_string(), "application/json".to_string());

                    let test_case = self.base.create_test_case(
                        self.build_endpoint_path(endpoint),
                        endpoint.method.clone(),
                        description.to_string(),
                        Some(headers),
                        None,
                        body,
                        400,
                        None,
                    );
                    test_cases.push(test_case);
                }
            }
        }

        test_cases
    }

    /// Create a test case with an invalid parameter value
    fn create_parameter_test_case(
        &self,
        endpoint: &EndpointInfo,
        param: &Value,
        invalid_value: Value,
        description: &str,
        expected_status: u16,
    ) -> Option<TestCase> {
        let param_name = param.get("name").and_then(|n| n.as_str())?;
        let mut headers = self.get_default_headers();
        let mut query_params = HashMap::new();
        let mut path_params = HashMap::new();

        // Build all parameters, using the invalid value for the target parameter
        for p in &endpoint.parameters {
            let p_name = p.get("name").and_then(|n| n.as_str())?;
            let value = if p_name == param_name {
                invalid_value.clone()
            } else {
                self.generate_valid_param_value(p)
            };

            let p_in = p.get("in").and_then(|i| i.as_str()).unwrap_or("query");
            match p_in {
                "query" => {
                    query_params.insert(p_name.to_string(), value);
                }
                "path" => {
                    path_params.insert(p_name.to_string(), value);
                }
                "header" => {
                    if let Value::String(s) = value {
                        headers.insert(p_name.to_string(), s);
                    }
                }
                _ => {}
            }
        }

        // Build the endpoint path
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

    /// Generate a valid value for a parameter (used when testing other invalid parameters)
    fn generate_valid_param_value(&self, param: &Value) -> Value {
        // Use example if provided
        if let Some(example) = param.get("example") {
            return example.clone();
        }

        let schema = param.get("schema").unwrap_or(&Value::Null);
        if let Some(example) = schema.get("example") {
            return example.clone();
        }

        // Generate based on type
        let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        match param_type {
            "string" => {
                if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
                    return enum_values.first().unwrap_or(&Value::String("valid_string".to_string())).clone();
                }
                Value::String("valid_string".to_string())
            }
            "integer" => {
                let minimum = schema.get("minimum").and_then(|m| m.as_i64()).unwrap_or(1);
                let maximum = schema.get("maximum").and_then(|m| m.as_i64()).unwrap_or(100);
                Value::Number(Number::from(minimum.max(1).min(maximum).min(42)))
            }
            "number" => {
                let minimum = schema.get("minimum").and_then(|m| m.as_f64()).unwrap_or(1.0);
                let maximum = schema.get("maximum").and_then(|m| m.as_f64()).unwrap_or(100.0);
                Value::Number(Number::from_f64(minimum.max(1.0).min(maximum).min(42.5)).unwrap())
            }
            "boolean" => Value::Bool(true),
            "array" => Value::Array(vec![Value::String("valid_item".to_string())]),
            _ => Value::String("valid_value".to_string()),
        }
    }

    /// Generate a base valid request body for the endpoint
    fn generate_base_valid_body(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<Value> {
        let request_body = endpoint.request_body.as_ref()?;
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")
            .or_else(|| content.as_object()?.values().next())?;
        let schema = json_content.get("schema")?;

        // Resolve schema references
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

    /// Build the endpoint path with valid path parameters
    fn build_endpoint_path(&self, endpoint: &EndpointInfo) -> String {
        let mut path = endpoint.path.clone();
        
        // Replace path parameters with valid values
        for param in &endpoint.parameters {
            if param.get("in").and_then(|i| i.as_str()) == Some("path") {
                if let Some(param_name) = param.get("name").and_then(|n| n.as_str()) {
                    let param_value = self.generate_valid_param_value(param);
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

    /// Get default headers for requests
    fn get_default_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());
        headers
    }
}

#[async_trait]
impl Agent for FunctionalNegativeAgent {
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

impl FunctionalNegativeAgent {
    async fn execute_internal(&self, task: AgentTask, api_spec: Value) -> Result<AgentResult, String> {
        // Extract all endpoints from the specification
        let endpoints = self.base.extract_endpoints(&api_spec);

        let mut test_cases = Vec::new();

        // Generate test cases for each endpoint
        for endpoint in &endpoints {
            let endpoint_tests = self.generate_endpoint_negative_tests(endpoint, &api_spec).await;
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
            "generation_strategy".to_string(),
            Value::String("hybrid_bva_and_creative".to_string()),
        );

        let test_categories = vec![
            "boundary_value_analysis",
            "invalid_data_types", 
            "missing_required_fields",
            "malformed_requests",
            "constraint_violations"
        ];
        metadata.insert(
            "test_categories".to_string(),
            Value::Array(test_categories.iter().map(|s| Value::String(s.to_string())).collect()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_functional_negative_agent_creation() {
        let agent = FunctionalNegativeAgent::new();
        assert_eq!(agent.agent_type(), "Functional-Negative-Agent");
    }

    #[tokio::test]
    async fn test_get_wrong_type_value() {
        let agent = FunctionalNegativeAgent::new();
        
        // Test wrong type mapping
        assert!(agent.get_wrong_type_value("string").is_some());
        assert!(agent.get_wrong_type_value("integer").is_some());
        assert!(agent.get_wrong_type_value("number").is_some());
        assert!(agent.get_wrong_type_value("boolean").is_some());
        assert!(agent.get_wrong_type_value("array").is_some());
        assert!(agent.get_wrong_type_value("object").is_some());
        assert!(agent.get_wrong_type_value("unknown_type").is_none());
    }

    #[tokio::test]
    async fn test_execute_with_simple_spec() {
        let agent = FunctionalNegativeAgent::new();
        
        let api_spec = json!({
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": true,
                                "schema": {
                                    "type": "integer",
                                    "minimum": 1
                                }
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "User found"
                            },
                            "400": {
                                "description": "Bad request"
                            }
                        }
                    }
                },
                "/users": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {
                                                "type": "string",
                                                "minLength": 1,
                                                "maxLength": 50
                                            },
                                            "email": {
                                                "type": "string",
                                                "pattern": "^[^@]+@[^@]+\\.[^@]+$"
                                            }
                                        },
                                        "required": ["name", "email"]
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {
                                "description": "User created"
                            },
                            "400": {
                                "description": "Bad request"
                            }
                        }
                    }
                }
            }
        });

        let task = AgentTask {
            task_id: "test-task-1".to_string(),
            spec_id: "test-spec-1".to_string(),
            agent_type: "Functional-Negative-Agent".to_string(),
            parameters: HashMap::new(),
            target_environment: Some("test".to_string()),
        };

        let result = agent.execute(task, api_spec).await;
        
        assert_eq!(result.status, "success");
        assert!(!result.test_cases.is_empty());
        assert!(result.metadata.contains_key("total_endpoints"));
        assert!(result.metadata.contains_key("total_test_cases"));
        assert!(result.metadata.contains_key("generation_strategy"));
        
        // Verify we generated negative test cases
        let has_boundary_test = result.test_cases.iter().any(|tc| {
            tc.test_name.contains("minimum") || tc.test_name.contains("maximum") ||
            tc.test_name.contains("length") || tc.test_name.contains("missing") ||
            tc.test_name.contains("wrong") || tc.test_name.contains("pattern")
        });
        assert!(has_boundary_test, "Should generate boundary or validation tests");
        
        // Verify all test cases expect error status codes
        for test_case in &result.test_cases {
            assert!(test_case.expected_status_codes.iter().all(|&status| status >= 400),
                   "All negative tests should expect 4xx or 5xx status codes");
        }
    }

    #[tokio::test]
    async fn test_boundary_value_analysis() {
        let agent = FunctionalNegativeAgent::new();
        
        // Test numeric boundary violation
        let param = json!({
            "name": "age",
            "in": "query",
            "schema": {
                "type": "integer",
                "minimum": 18,
                "maximum": 100
            }
        });
        
        let endpoint = EndpointInfo {
            path: "/test".to_string(),
            method: "GET".to_string(),
            operation: json!({}),
            summary: "Test endpoint".to_string(),
            description: "Test".to_string(),
            parameters: vec![param],
            request_body: None,
            responses: HashMap::new(),
        };

        let boundary_tests = agent.generate_parameter_bva_tests(&endpoint.parameters[0], &endpoint, &json!({}));
        
        assert!(!boundary_tests.is_empty(), "Should generate boundary tests");
        
        // Should have both minimum and maximum boundary violation tests
        let has_min_test = boundary_tests.iter().any(|tc| tc.test_name.contains("minimum"));
        let has_max_test = boundary_tests.iter().any(|tc| tc.test_name.contains("maximum"));
        
        assert!(has_min_test, "Should generate minimum boundary test");
        assert!(has_max_test, "Should generate maximum boundary test");
    }

    #[tokio::test]
    async fn test_string_boundary_tests() {
        let agent = FunctionalNegativeAgent::new();
        
        let param = json!({
            "name": "username",
            "in": "query", 
            "schema": {
                "type": "string",
                "minLength": 3,
                "maxLength": 20,
                "pattern": "^[a-zA-Z0-9]+$"
            }
        });
        
        let endpoint = EndpointInfo {
            path: "/test".to_string(),
            method: "GET".to_string(),
            operation: json!({}),
            summary: "Test endpoint".to_string(),
            description: "Test".to_string(),
            parameters: vec![param],
            request_body: None,
            responses: HashMap::new(),
        };

        let string_tests = agent.generate_parameter_bva_tests(&endpoint.parameters[0], &endpoint, &json!({}));
        
        assert!(!string_tests.is_empty(), "Should generate string boundary tests");
        
        let has_min_length_test = string_tests.iter().any(|tc| tc.test_name.contains("minimum length"));
        let has_max_length_test = string_tests.iter().any(|tc| tc.test_name.contains("maximum length"));
        let has_pattern_test = string_tests.iter().any(|tc| tc.test_name.contains("pattern"));
        
        assert!(has_min_length_test, "Should generate minimum length test");
        assert!(has_max_length_test, "Should generate maximum length test"); 
        assert!(has_pattern_test, "Should generate pattern violation test");
    }
}