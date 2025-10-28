//! Positive Strategy: Generate valid test cases expecting 2xx status codes

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{TestStrategy, create_test_case};
use crate::types::{EndpointInfo, TestCase};

pub struct PositiveStrategy;

impl PositiveStrategy {
    pub fn new() -> Self {
        Self
    }

    /// Generate a single valid parameter value
    fn generate_valid_param_value(&self, param: &Value) -> Value {
        let schema = param.get("schema").unwrap_or(param);
        let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
            return enum_values.first().unwrap_or(&Value::String("default".to_string())).clone();
        }

        match param_type {
            "integer" => {
                let minimum = schema.get("minimum").and_then(|m| m.as_i64()).unwrap_or(1);
                let maximum = schema.get("maximum").and_then(|m| m.as_i64()).unwrap_or(100);
                Value::Number(serde_json::Number::from((minimum + maximum) / 2))
            }
            "string" => Value::String("test_value".to_string()),
            "boolean" => Value::Bool(true),
            _ => Value::String("default".to_string()),
        }
    }

    /// Generate multiple valid parameter values
    fn generate_valid_param_values(&self, param: &Value) -> Vec<Value> {
        let schema = param.get("schema").unwrap_or(param);
        let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
            return enum_values.iter().take(3).cloned().collect();
        }

        match param_type {
            "integer" => {
                let minimum = schema.get("minimum").and_then(|m| m.as_i64()).unwrap_or(1);
                let maximum = schema.get("maximum").and_then(|m| m.as_i64()).unwrap_or(100);
                vec![
                    Value::Number(serde_json::Number::from(minimum)),
                    Value::Number(serde_json::Number::from((minimum + maximum) / 2)),
                    Value::Number(serde_json::Number::from(maximum)),
                ]
            }
            "string" => vec![
                Value::String("test".to_string()),
                Value::String("value".to_string()),
                Value::String("sample".to_string()),
            ],
            "boolean" => vec![Value::Bool(true), Value::Bool(false)],
            _ => vec![Value::String("default".to_string())],
        }
    }

    /// Generate valid request body
    fn generate_valid_body(&self, request_body: &Value, api_spec: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")?;
        let schema = json_content.get("schema")?;

        let resolved_schema = self.resolve_schema_ref(schema, api_spec);
        Some(self.generate_realistic_data(&resolved_schema))
    }

    /// Generate minimal body with only required fields
    fn generate_minimal_body(&self, request_body: &Value, api_spec: &Value) -> Option<Value> {
        let content = request_body.get("content")?;
        let json_content = content.get("application/json")?;
        let schema = json_content.get("schema")?;

        let resolved_schema = self.resolve_schema_ref(schema, api_spec);

        if resolved_schema.get("type").and_then(|t| t.as_str()) != Some("object") {
            return Some(self.generate_realistic_data(&resolved_schema));
        }

        let properties = resolved_schema.get("properties")?.as_object()?;
        let required = resolved_schema.get("required")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        let mut minimal_obj = serde_json::Map::new();
        for req_field in required {
            if let Some(prop_schema) = properties.get(req_field) {
                minimal_obj.insert(req_field.to_string(), self.generate_realistic_data(prop_schema));
            }
        }

        if minimal_obj.is_empty() {
            None
        } else {
            Some(Value::Object(minimal_obj))
        }
    }

    /// Generate realistic data from schema
    fn generate_realistic_data(&self, schema: &Value) -> Value {
        let schema_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

        if let Some(example) = schema.get("example") {
            return example.clone();
        }

        match schema_type {
            "string" => Value::String("test_data".to_string()),
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
                    Value::Array(vec![self.generate_realistic_data(items)])
                } else {
                    Value::Array(vec![])
                }
            }
            "object" => {
                let mut obj = serde_json::Map::new();
                if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                    for (prop_name, prop_schema) in properties {
                        obj.insert(prop_name.clone(), self.generate_realistic_data(prop_schema));
                    }
                }
                Value::Object(obj)
            }
            _ => Value::Null,
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

    /// Substitute path parameters
    fn substitute_path_params(&self, endpoint: &EndpointInfo) -> String {
        let mut path = endpoint.path.clone();
        for param in &endpoint.parameters {
            if param.get("in").and_then(|i| i.as_str()) == Some("path") {
                if let Some(name) = param.get("name").and_then(|n| n.as_str()) {
                    let value = self.generate_valid_param_value(param);
                    let value_str = match value {
                        Value::String(s) => s,
                        Value::Number(n) => n.to_string(),
                        _ => "test_id".to_string(),
                    };
                    path = path.replace(&format!("{{{}}}", name), &value_str);
                }
            }
        }
        path
    }

    /// Get expected success status
    fn get_success_status(&self, responses: &HashMap<String, Value>, method: &str) -> u16 {
        for (code, _) in responses {
            if code.starts_with('2') {
                return code.parse().unwrap_or(200);
            }
        }

        match method {
            "GET" => 200,
            "POST" => 201,
            "PUT" => 200,
            "PATCH" => 200,
            "DELETE" => 204,
            _ => 200,
        }
    }
}

#[async_trait]
impl TestStrategy for PositiveStrategy {
    async fn generate_tests(
        &self,
        endpoints: &[EndpointInfo],
        api_spec: &Value,
    ) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        for endpoint in endpoints {
            // Basic valid test
            let query_params = endpoint.parameters.iter()
                .filter(|p| p.get("in").and_then(|i| i.as_str()) == Some("query"))
                .map(|p| {
                    let name = p.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                    (name.to_string(), self.generate_valid_param_value(p))
                })
                .collect::<HashMap<_, _>>();

            let actual_path = self.substitute_path_params(endpoint);

            let body = if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
                endpoint.request_body.as_ref().and_then(|rb| self.generate_valid_body(rb, api_spec))
            } else {
                None
            };

            let expected_status = self.get_success_status(&endpoint.responses, &endpoint.method);

            test_cases.push(create_test_case(
                actual_path.clone(),
                endpoint.method.clone(),
                format!("Valid {} request to {}", endpoint.method, endpoint.path),
                "functional-positive".to_string(),
                "valid".to_string(),
                None,
                Some(query_params.clone()),
                body.clone(),
                expected_status,
                None,
            ));

            // Parameter variations for GET/DELETE
            if ["GET", "DELETE"].contains(&endpoint.method.as_str()) {
                for param in &endpoint.parameters {
                    if param.get("in").and_then(|i| i.as_str()) == Some("query") {
                        let name = param.get("name").and_then(|n| n.as_str()).unwrap_or("param");
                        let values = self.generate_valid_param_values(param);

                        for (i, value) in values.iter().take(3).enumerate() {
                            let mut params = HashMap::new();
                            params.insert(name.to_string(), value.clone());

                            test_cases.push(create_test_case(
                                actual_path.clone(),
                                endpoint.method.clone(),
                                format!("Test {}={:?}", name, value),
                                "functional-positive".to_string(),
                                "parameter_variation".to_string(),
                                None,
                                Some(params),
                                None,
                                200,
                                None,
                            ));
                        }
                    }
                }
            }

            // Body variations for POST/PUT/PATCH
            if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
                if let Some(request_body) = &endpoint.request_body {
                    // Minimal body
                    if let Some(minimal_body) = self.generate_minimal_body(request_body, api_spec) {
                        test_cases.push(create_test_case(
                            actual_path.clone(),
                            endpoint.method.clone(),
                            format!("Minimal valid {} body", endpoint.method),
                            "functional-positive".to_string(),
                            "minimal".to_string(),
                            None,
                            None,
                            Some(minimal_body.clone()),
                            self.get_success_status(&endpoint.responses, &endpoint.method),
                            None,
                        ));
                    }

                    // Complete body (if different from minimal)
                    if let Some(complete_body) = self.generate_valid_body(request_body, api_spec) {
                        test_cases.push(create_test_case(
                            actual_path.clone(),
                            endpoint.method.clone(),
                            format!("Complete valid {} body", endpoint.method),
                            "functional-positive".to_string(),
                            "complete".to_string(),
                            None,
                            None,
                            Some(complete_body),
                            self.get_success_status(&endpoint.responses, &endpoint.method),
                            None,
                        ));
                    }
                }
            }
        }

        test_cases
    }

    fn strategy_name(&self) -> &str {
        "positive"
    }
}
