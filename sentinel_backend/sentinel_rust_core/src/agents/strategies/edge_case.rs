//! Edge Case Strategy: Generate edge case tests (unicode, floats, dates, empty values)

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{TestStrategy, create_test_case};
use crate::types::{EndpointInfo, TestCase};

pub struct EdgeCaseStrategy;

impl EdgeCaseStrategy {
    pub fn new() -> Self {
        Self
    }

    /// Substitute path parameters
    fn substitute_path_params(&self, endpoint: &EndpointInfo) -> String {
        let mut path = endpoint.path.clone();
        for param in &endpoint.parameters {
            if param.get("in").and_then(|i| i.as_str()) == Some("path") {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    let schema = param.get("schema").unwrap_or(param);
                    let value = if schema.get("type").and_then(|t| t.as_str()) == Some("integer") {
                        "123"
                    } else {
                        "test_id"
                    };
                    path = path.replace(&format!("{{{}}}", name), value);
                }
            }
        }
        path
    }
}

#[async_trait]
impl TestStrategy for EdgeCaseStrategy {
    async fn generate_tests(
        &self,
        endpoints: &[EndpointInfo],
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Unicode test cases
        let unicode_cases = vec![
            ("🚀", "emoji"),
            ("مرحبا", "arabic"),
            ("test\u{0000}null", "null_char"),
            ("café", "accented"),
        ];

        // Floating point edge cases
        let float_cases = vec![
            (0.0, "zero"),
            (0.1 + 0.2, "precision"),
            (1e-15, "small"),
        ];

        for endpoint in endpoints {
            // Unicode and special characters
            for param in &endpoint.parameters {
                let schema = param.get("schema").unwrap_or(param);
                if schema.get("type").and_then(|t| t.as_str()) == Some("string") {
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

                    for (unicode_str, case_type) in unicode_cases.iter().take(2) {
                        let mut params = HashMap::new();
                        params.insert(name.to_string(), Value::String(unicode_str.to_string()));

                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Unicode test: {} with {}", name, case_type),
                            "functional-edge_case".to_string(),
                            "unicode".to_string(),
                            None,
                            Some(params),
                            None,
                            200,
                            None,
                        ));
                    }
                }
            }

            // Floating point edge cases
            for param in &endpoint.parameters {
                let schema = param.get("schema").unwrap_or(param);
                let param_type = schema.get("type").and_then(|t| t.as_str());

                if param_type == Some("number") || param_type == Some("float") {
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");

                    for (float_val, case_type) in float_cases.iter().take(2) {
                        let mut params = HashMap::new();
                        params.insert(
                            name.to_string(),
                            Value::Number(serde_json::Number::from_f64(*float_val).unwrap_or(serde_json::Number::from(0))),
                        );

                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Float test: {} with {}", name, case_type),
                            "functional-edge_case".to_string(),
                            "float".to_string(),
                            None,
                            Some(params),
                            None,
                            200,
                            None,
                        ));
                    }
                }
            }

            // Empty/null values (only for optional parameters)
            for param in &endpoint.parameters {
                let is_required = param.get("required").and_then(|r| r.as_bool()).unwrap_or(false);
                if !is_required {
                    let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                    let mut params = HashMap::new();
                    params.insert(name.to_string(), Value::String("".to_string()));

                    test_cases.push(create_test_case(
                        self.substitute_path_params(endpoint),
                        endpoint.method.clone(),
                        format!("Empty value test: {}", name),
                        "functional-edge_case".to_string(),
                        "empty".to_string(),
                        None,
                        Some(params),
                        None,
                        200,
                        None,
                    ));
                }
            }
        }

        test_cases
    }

    fn strategy_name(&self) -> &str {
        "edge_case"
    }
}
