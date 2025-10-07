//! Negative Strategy: Generate invalid test cases expecting 4xx status codes

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{TestStrategy, create_test_case};
use crate::types::{EndpointInfo, TestCase};

pub struct NegativeStrategy;

impl NegativeStrategy {
    pub fn new() -> Self {
        Self
    }

    /// Generate invalid parameter values with violation types
    fn generate_invalid_param_values(&self, param: &Value) -> Vec<(Value, String)> {
        let schema = param.get("schema").unwrap_or(param);
        let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
        let mut invalid_values = Vec::new();

        match param_type {
            "integer" => {
                if let Some(minimum) = schema.get("minimum").and_then(|m| m.as_i64()) {
                    invalid_values.push((
                        Value::Number(serde_json::Number::from(minimum - 1)),
                        "out_of_range".to_string(),
                    ));
                }
                if let Some(maximum) = schema.get("maximum").and_then(|m| m.as_i64()) {
                    invalid_values.push((
                        Value::Number(serde_json::Number::from(maximum + 1)),
                        "out_of_range".to_string(),
                    ));
                }
                invalid_values.push((
                    Value::String("not_an_integer".to_string()),
                    "invalid_type".to_string(),
                ));
            }
            "string" => {
                let min_length = schema.get("minLength").and_then(|m| m.as_u64()).unwrap_or(0);
                let max_length = schema.get("maxLength").and_then(|m| m.as_u64());

                if min_length > 0 {
                    invalid_values.push((Value::String("".to_string()), "too_short".to_string()));
                    if min_length > 1 {
                        invalid_values.push((
                            Value::String("a".repeat((min_length - 1) as usize)),
                            "too_short".to_string(),
                        ));
                    }
                }

                if let Some(max_len) = max_length {
                    invalid_values.push((
                        Value::String("a".repeat((max_len + 1) as usize)),
                        "too_long".to_string(),
                    ));
                }
            }
            "boolean" => {
                invalid_values.push((
                    Value::String("not_a_boolean".to_string()),
                    "invalid_type".to_string(),
                ));
            }
            _ => {}
        }

        invalid_values
    }

    /// Generate body with invalid data types
    fn generate_invalid_body(&self, request_body: &Value, api_spec: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")?;
        let schema = json_content.get("schema")?;

        let resolved_schema = self.resolve_schema_ref(schema, api_spec);
        Some(self.generate_invalid_data(&resolved_schema))
    }

    /// Generate data with wrong types
    fn generate_invalid_data(&self, schema: &Value) -> Value {
        let schema_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        match schema_type {
            "string" => Value::Number(serde_json::Number::from(12345)), // Wrong type
            "integer" => Value::String("not_a_number".to_string()), // Wrong type
            "number" => Value::String("not_a_number".to_string()), // Wrong type
            "boolean" => Value::String("not_a_boolean".to_string()), // Wrong type
            "array" => Value::String("not_an_array".to_string()), // Wrong type
            "object" => {
                // Generate object with wrong property types
                let mut obj = serde_json::Map::new();
                if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                    for (prop_name, _) in properties {
                        obj.insert(prop_name.clone(), Value::String("wrong_type".to_string()));
                    }
                }
                Value::Object(obj)
            }
            _ => Value::Null,
        }
    }

    /// Generate body that violates constraints
    fn generate_constraint_violating_body(&self, request_body: &Value, api_spec: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")?;
        let schema = json_content.get("schema")?;

        let resolved_schema = self.resolve_schema_ref(schema, api_spec);

        if resolved_schema.get("type").and_then(|t| t.as_str()) != Some("object") {
            return None;
        }

        let properties = resolved_schema.get("properties")?.as_object()?;
        let mut violating_obj = serde_json::Map::new();

        for (prop_name, prop_schema) in properties {
            if prop_schema.get("type").and_then(|t| t.as_str()) == Some("string") {
                let max_length = prop_schema.get("maxLength").and_then(|m| m.as_u64()).unwrap_or(100);
                violating_obj.insert(
                    prop_name.clone(),
                    Value::String("a".repeat((max_length + 10) as usize)),
                );
            } else if prop_schema.get("type").and_then(|t| t.as_str()) == Some("integer") {
                let maximum = prop_schema.get("maximum").and_then(|m| m.as_i64()).unwrap_or(1000);
                violating_obj.insert(
                    prop_name.clone(),
                    Value::Number(serde_json::Number::from(maximum + 100)),
                );
            } else if prop_schema.get("type").and_then(|t| t.as_str()) == Some("number") {
                let minimum = prop_schema.get("minimum").and_then(|m| m.as_f64()).unwrap_or(0.0);
                violating_obj.insert(
                    prop_name.clone(),
                    Value::Number(serde_json::Number::from_f64(minimum - 100.0).unwrap_or(serde_json::Number::from(-100))),
                );
            } else {
                violating_obj.insert(prop_name.clone(), Value::String("valid_value".to_string()));
            }
        }

        if violating_obj.is_empty() {
            None
        } else {
            Some(Value::Object(violating_obj))
        }
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

    /// Substitute path parameters (excluding one optionally)
    fn substitute_path_params(&self, endpoint: &EndpointInfo, exclude: Option<&str>) -> String {
        let mut path = endpoint.path.clone();
        for param in &endpoint.parameters {
            if param.get("in").and_then(|i| i.as_str()) == Some("path") {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    if Some(name) != exclude {
                        let value = self.generate_valid_param_value(param);
                        path = path.replace(&format!("{{{}}}", name), &value);
                    }
                }
            }
        }
        path
    }

    /// Generate valid parameter value for substitution
    fn generate_valid_param_value(&self, param: &Value) -> String {
        let schema = param.get("schema").unwrap_or(param);
        let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        match param_type {
            "integer" => "123".to_string(),
            "string" => "test_id".to_string(),
            _ => "default".to_string(),
        }
    }
}

#[async_trait]
impl TestStrategy for NegativeStrategy {
    async fn generate_tests(
        &self,
        endpoints: &[EndpointInfo],
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for endpoint in endpoints {
            // Missing required parameters
            let required_params: Vec<_> = endpoint.parameters.iter()
                .filter(|p| p.get("required").and_then(|r| r.as_bool()).unwrap_or(false))
                .collect();

            for param in &required_params {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    let actual_path = if param.get("in").and_then(|i| i.as_str()) == Some("path") {
                        endpoint.path.replace(&format!("{{{}}}", name), "INVALID")
                    } else {
                        self.substitute_path_params(endpoint, None)
                    };

                    test_cases.push(create_test_case(
                        actual_path,
                        endpoint.method.clone(),
                        format!("Missing required parameter: {}", name),
                        "functional-negative".to_string(),
                        "missing_required".to_string(),
                        None,
                        None,
                        None,
                        400,
                        None,
                    ));
                }
            }

            // Invalid parameter types/values
            for param in &endpoint.parameters {
                let invalid_values = self.generate_invalid_param_values(param);

                for (value, violation_type) in invalid_values.iter().take(2) {
                    if param.get("in").and_then(|i| i.as_str()) == Some("query") {
                        if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                            let mut params = HashMap::new();
                            params.insert(name.to_string(), value.clone());

                            test_cases.push(create_test_case(
                                self.substitute_path_params(endpoint, None),
                                endpoint.method.clone(),
                                format!("Invalid {}: {}", name, violation_type),
                                "functional-negative".to_string(),
                                violation_type.clone(),
                                None,
                                Some(params),
                                None,
                                400,
                                None,
                            ));
                        }
                    }
                }
            }

            // Invalid body tests
            if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
                if let Some(request_body) = &endpoint.request_body {
                    let actual_path = self.substitute_path_params(endpoint, None);

                    // Missing required fields
                    test_cases.push(create_test_case(
                        actual_path.clone(),
                        endpoint.method.clone(),
                        "Missing required fields in body".to_string(),
                        "functional-negative".to_string(),
                        "missing_required".to_string(),
                        None,
                        None,
                        Some(Value::Object(serde_json::Map::new())),
                        400,
                        None,
                    ));

                    // Invalid data types
                    if let Some(invalid_body) = self.generate_invalid_body(request_body, api_spec) {
                        test_cases.push(create_test_case(
                            actual_path.clone(),
                            endpoint.method.clone(),
                            "Invalid data types in body".to_string(),
                            "functional-negative".to_string(),
                            "invalid_type".to_string(),
                            None,
                            None,
                            Some(invalid_body),
                            400,
                            None,
                        ));
                    }

                    // Constraint violations
                    if let Some(violating_body) = self.generate_constraint_violating_body(request_body, api_spec) {
                        test_cases.push(create_test_case(
                            actual_path,
                            endpoint.method.clone(),
                            "Constraint violations in body".to_string(),
                            "functional-negative".to_string(),
                            "out_of_range".to_string(),
                            None,
                            None,
                            Some(violating_body),
                            400,
                            None,
                        ));
                    }
                }
            }
        }

        test_cases
    }

    fn strategy_name(&self) -> &str {
        "negative"
    }
}
