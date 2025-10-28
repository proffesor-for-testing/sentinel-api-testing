//! Boundary Strategy: Generate boundary value tests (min, max, min-1, max+1)

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{TestStrategy, create_test_case};
use crate::types::{EndpointInfo, TestCase};

pub struct BoundaryStrategy;

impl BoundaryStrategy {
    pub fn new() -> Self {
        Self
    }

    /// Resolve $ref references
    fn resolve_schema_ref(&self, schema: &Value, api_spec: &Value) -> Value {
        if let Some(ref_path) = schema.get("$ref").and_then(|r| r.as_str()) {
            if ref_path.starts_with("#/") {
                let parts: Vec<&str> = ref_path[2..].split('/').collect();
                let mut resolved = api_spec.clone();
                for part in parts {
                    resolved = resolved.get(part).unwrap_or(&Value::Null).clone();
                }
                return resolved;
            }
        }
        schema.clone()
    }

    /// Substitute all path parameters with valid values
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
impl TestStrategy for BoundaryStrategy {
    async fn generate_tests(
        &self,
        endpoints: &[EndpointInfo],
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for endpoint in endpoints {
            // Integer boundaries
            for param in &endpoint.parameters {
                let schema = param.get("schema").unwrap_or(param);
                if schema.get("type").and_then(|t| t.as_str()) != Some("integer") {
                    continue;
                }

                let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                let param_in = param.get("in").and_then(|i| i.as_str()).unwrap_or("query");

                if let Some(minimum) = schema.get("minimum").and_then(|m| m.as_i64()) {
                    // Test exact minimum (should pass)
                    let mut params = HashMap::new();
                    params.insert(name.to_string(), Value::Number(serde_json::Number::from(minimum)));

                    if param_in == "query" {
                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Boundary test: {} at min ({})", name, minimum),
                            "functional-boundary".to_string(),
                            "min".to_string(),
                            None,
                            Some(params),
                            None,
                            200,
                            None,
                        ));
                    }

                    // Test below minimum (should fail)
                    if minimum > 0 {
                        let mut params = HashMap::new();
                        params.insert(name.to_string(), Value::Number(serde_json::Number::from(minimum - 1)));

                        if param_in == "query" {
                            test_cases.push(create_test_case(
                                self.substitute_path_params(endpoint),
                                endpoint.method.clone(),
                                format!("Boundary test: {} at below_min ({})", name, minimum - 1),
                                "functional-boundary".to_string(),
                                "below_min".to_string(),
                                None,
                                Some(params),
                                None,
                                400,
                                None,
                            ));
                        }
                    }
                }

                if let Some(maximum) = schema.get("maximum").and_then(|m| m.as_i64()) {
                    // Test exact maximum (should pass)
                    let mut params = HashMap::new();
                    params.insert(name.to_string(), Value::Number(serde_json::Number::from(maximum)));

                    if param_in == "query" {
                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Boundary test: {} at max ({})", name, maximum),
                            "functional-boundary".to_string(),
                            "max".to_string(),
                            None,
                            Some(params),
                            None,
                            200,
                            None,
                        ));
                    }

                    // Test above maximum (should fail)
                    let mut params = HashMap::new();
                    params.insert(name.to_string(), Value::Number(serde_json::Number::from(maximum + 1)));

                    if param_in == "query" {
                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Boundary test: {} at above_max ({})", name, maximum + 1),
                            "functional-boundary".to_string(),
                            "above_max".to_string(),
                            None,
                            Some(params),
                            None,
                            400,
                            None,
                        ));
                    }
                }
            }

            // String length boundaries
            for param in &endpoint.parameters {
                let schema = param.get("schema").unwrap_or(param);
                if schema.get("type").and_then(|t| t.as_str()) != Some("string") {
                    continue;
                }

                let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                let param_in = param.get("in").and_then(|i| i.as_str()).unwrap_or("query");

                if let Some(min_length) = schema.get("minLength").and_then(|m| m.as_u64()) {
                    // Test exact minLength (should pass)
                    let mut params = HashMap::new();
                    params.insert(name.to_string(), Value::String("a".repeat(min_length as usize)));

                    if param_in == "query" {
                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Boundary test: {} at minLength ({})", name, min_length),
                            "functional-boundary".to_string(),
                            "minLength".to_string(),
                            None,
                            Some(params),
                            None,
                            200,
                            None,
                        ));
                    }

                    // Test below minLength (should fail)
                    if min_length > 0 {
                        let mut params = HashMap::new();
                        params.insert(name.to_string(), Value::String("a".repeat((min_length - 1) as usize)));

                        if param_in == "query" {
                            test_cases.push(create_test_case(
                                self.substitute_path_params(endpoint),
                                endpoint.method.clone(),
                                format!("Boundary test: {} at below_minLength ({})", name, min_length - 1),
                                "functional-boundary".to_string(),
                                "below_minLength".to_string(),
                                None,
                                Some(params),
                                None,
                                400,
                                None,
                            ));
                        }
                    }
                }

                if let Some(max_length) = schema.get("maxLength").and_then(|m| m.as_u64()) {
                    // Test exact maxLength (should pass)
                    let mut params = HashMap::new();
                    params.insert(name.to_string(), Value::String("a".repeat(max_length as usize)));

                    if param_in == "query" {
                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Boundary test: {} at maxLength ({})", name, max_length),
                            "functional-boundary".to_string(),
                            "maxLength".to_string(),
                            None,
                            Some(params),
                            None,
                            200,
                            None,
                        ));
                    }

                    // Test above maxLength (should fail)
                    let mut params = HashMap::new();
                    params.insert(name.to_string(), Value::String("a".repeat((max_length + 1) as usize)));

                    if param_in == "query" {
                        test_cases.push(create_test_case(
                            self.substitute_path_params(endpoint),
                            endpoint.method.clone(),
                            format!("Boundary test: {} at above_maxLength ({})", name, max_length + 1),
                            "functional-boundary".to_string(),
                            "above_maxLength".to_string(),
                            None,
                            Some(params),
                            None,
                            400,
                            None,
                        ));
                    }
                }
            }

            // Array size boundaries (for request bodies)
            if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
                if let Some(request_body) = &endpoint.request_body {
                    if let Some(content) = request_body.get("content") {
                        if let Some(json_content) = content.get("application/json") {
                            if let Some(schema) = json_content.get("schema") {
                                let resolved_schema = self.resolve_schema_ref(schema, api_spec);

                                if resolved_schema.get("type").and_then(|t| t.as_str()) == Some("object") {
                                    if let Some(properties) = resolved_schema.get("properties").and_then(|p| p.as_object()) {
                                        for (prop_name, prop_schema) in properties {
                                            if prop_schema.get("type").and_then(|t| t.as_str()) == Some("array") {
                                                if let Some(min_items) = prop_schema.get("minItems").and_then(|m| m.as_u64()) {
                                                    let mut body = serde_json::Map::new();
                                                    body.insert(
                                                        prop_name.clone(),
                                                        Value::Array(vec![Value::String("item".to_string()); min_items as usize]),
                                                    );

                                                    test_cases.push(create_test_case(
                                                        self.substitute_path_params(endpoint),
                                                        endpoint.method.clone(),
                                                        format!("Array {} at minItems ({})", prop_name, min_items),
                                                        "functional-boundary".to_string(),
                                                        "minItems".to_string(),
                                                        None,
                                                        None,
                                                        Some(Value::Object(body)),
                                                        200,
                                                        None,
                                                    ));
                                                }

                                                if let Some(max_items) = prop_schema.get("maxItems").and_then(|m| m.as_u64()) {
                                                    let mut body = serde_json::Map::new();
                                                    body.insert(
                                                        prop_name.clone(),
                                                        Value::Array(vec![Value::String("item".to_string()); max_items as usize]),
                                                    );

                                                    test_cases.push(create_test_case(
                                                        self.substitute_path_params(endpoint),
                                                        endpoint.method.clone(),
                                                        format!("Array {} at maxItems ({})", prop_name, max_items),
                                                        "functional-boundary".to_string(),
                                                        "maxItems".to_string(),
                                                        None,
                                                        None,
                                                        Some(Value::Object(body)),
                                                        200,
                                                        None,
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        test_cases
    }

    fn strategy_name(&self) -> &str {
        "boundary"
    }
}
