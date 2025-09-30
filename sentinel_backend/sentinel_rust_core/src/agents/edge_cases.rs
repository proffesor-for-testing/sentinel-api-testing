//! Edge Cases Agent
//!
//! This agent specializes in generating test cases for edge conditions, unusual scenarios,
//! and corner cases that may reveal bugs in API implementations.

use async_trait::async_trait;
use rand::prelude::*;
use serde_json::{Value, Map};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};

use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo, Assertion};
use super::{Agent, BaseAgent};
use super::utils::*;

pub struct EdgeCasesAgent {
    base: BaseAgent,
}

impl EdgeCasesAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Edge-Cases-Agent".to_string()),
        }
    }

    /// Generate edge case tests for an endpoint
    async fn generate_edge_case_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Unicode and encoding edge cases
        test_cases.extend(self.generate_unicode_tests(endpoint, api_spec).await);

        // Extreme value tests
        test_cases.extend(self.generate_extreme_value_tests(endpoint, api_spec).await);

        // Timing-sensitive tests
        test_cases.extend(self.generate_timing_tests(endpoint, api_spec).await);

        // Boundary condition tests
        test_cases.extend(self.generate_boundary_tests(endpoint, api_spec).await);

        // Empty and null value tests
        test_cases.extend(self.generate_empty_value_tests(endpoint, api_spec).await);

        // Type confusion tests
        test_cases.extend(self.generate_type_confusion_tests(endpoint, api_spec).await);

        // Resource exhaustion tests
        test_cases.extend(self.generate_resource_exhaustion_tests(endpoint, api_spec).await);

        // Concurrency edge cases
        test_cases.extend(self.generate_concurrency_tests(endpoint, api_spec).await);

        // Protocol-specific edge cases
        test_cases.extend(self.generate_protocol_edge_tests(endpoint, api_spec).await);

        // Content-type confusion tests
        test_cases.extend(self.generate_content_type_tests(endpoint, api_spec).await);

        test_cases
    }

    /// Generate Unicode and encoding edge case tests
    async fn generate_unicode_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Unicode edge cases
        let unicode_test_cases = vec![
            ("Unicode BMP", "\u{1F600}\u{1F601}\u{1F602}"), // Emojis
            ("Unicode Astral", "\u{1D400}\u{1D401}\u{1D402}"), // Mathematical script characters
            ("RTL Override", "\u{202E}test\u{202C}"), // Right-to-left override
            ("Zero Width", "test\u{200B}value\u{FEFF}"), // Zero-width characters
            ("Combining Chars", "a\u{0300}e\u{0301}i\u{0302}"), // Combining diacriticals
            ("Normalization", "café vs café"), // Different normalizations
            ("High Unicode", "\u{10000}\u{10001}"), // Supplementary plane characters
            ("Private Use", "\u{E000}\u{F8FF}"), // Private use area
            ("Control Chars", "\u{0001}\u{0002}\u{0003}"), // Control characters
            ("BOM", "\u{FEFF}test"), // Byte order mark
        ];

        for (test_name, unicode_value) in unicode_test_cases {
            if let Some(body) = self.create_body_with_unicode(endpoint, api_spec, unicode_value) {
                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Edge Case: {} in request body", test_name),
                    None,
                    None,
                    Some(body),
                    400, // Expect failure for malformed unicode
                    Some(vec![
                        Assertion {
                            field: "status".to_string(),
                            operator: "in".to_string(),
                            expected: Value::Array(vec![
                                Value::Number(serde_json::Number::from(400)),
                                Value::Number(serde_json::Number::from(422)),
                                Value::Number(serde_json::Number::from(500)),
                            ]),
                        }
                    ]),
                );
                test_cases.push(test_case);
            }

            // Test unicode in query parameters
            if !endpoint.parameters.is_empty() {
                let mut query_params = HashMap::new();
                for param in endpoint.parameters.iter() {
                    if let Some(param_obj) = param.as_object() {
                        if let Some(name) = param_obj.get("name").and_then(|n| n.as_str()) {
                            if param_obj.get("in").and_then(|i| i.as_str()) == Some("query") {
                                query_params.insert(name.to_string(), Value::String(unicode_value.to_string()));
                                break;
                            }
                        }
                    }
                }

                if !query_params.is_empty() {
                    let test_case = self.base.create_test_case(
                        endpoint.path.clone(),
                        endpoint.method.clone(),
                        format!("Edge Case: {} in query parameter", test_name),
                        None,
                        Some(query_params),
                        None,
                        400,
                        None,
                    );
                    test_cases.push(test_case);
                }
            }
        }

        test_cases
    }

    /// Generate extreme value tests
    async fn generate_extreme_value_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        let extreme_values = vec![
            ("Max Integer", Value::Number(serde_json::Number::from(i64::MAX))),
            ("Min Integer", Value::Number(serde_json::Number::from(i64::MIN))),
            ("Zero", Value::Number(serde_json::Number::from(0))),
            ("Negative Zero", Value::Number(serde_json::Number::from_f64(-0.0).unwrap())),
            ("Infinity", Value::String("Infinity".to_string())),
            ("NaN", Value::String("NaN".to_string())),
            ("Very Large String", Value::String("x".repeat(1_000_000))),
            ("Empty String", Value::String("".to_string())),
            ("Null Byte", Value::String("\0".to_string())),
            ("Max Float", Value::Number(serde_json::Number::from_f64(f64::MAX).unwrap())),
            ("Min Float", Value::Number(serde_json::Number::from_f64(f64::MIN).unwrap())),
            ("Epsilon", Value::Number(serde_json::Number::from_f64(f64::EPSILON).unwrap())),
        ];

        for (test_name, extreme_value) in extreme_values {
            // Test in request body
            if let Some(body) = self.create_body_with_extreme_value(endpoint, api_spec, &extreme_value) {
                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Edge Case: {} in request body", test_name),
                    None,
                    None,
                    Some(body),
                    400,
                    Some(vec![
                        Assertion {
                            field: "status".to_string(),
                            operator: "in".to_string(),
                            expected: Value::Array(vec![
                                Value::Number(serde_json::Number::from(400)),
                                Value::Number(serde_json::Number::from(422)),
                                Value::Number(serde_json::Number::from(413)),
                            ]),
                        }
                    ]),
                );
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate timing-sensitive tests
    async fn generate_timing_tests(&self, endpoint: &EndpointInfo, _api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Timing attack test with delayed responses
        let test_case = self.base.create_test_case(
            endpoint.path.clone(),
            endpoint.method.clone(),
            "Edge Case: Response time analysis for timing attacks".to_string(),
            None,
            None,
            None,
            200,
            Some(vec![
                Assertion {
                    field: "response_time".to_string(),
                    operator: "lt".to_string(),
                    expected: Value::Number(serde_json::Number::from(5000)), // Less than 5 seconds
                }
            ]),
        );
        test_cases.push(test_case);

        // Rapid sequential requests
        for i in 0..5 {
            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                format!("Edge Case: Rapid request #{} for race condition detection", i + 1),
                None,
                None,
                None,
                200,
                Some(vec![
                    Assertion {
                        field: "status".to_string(),
                        operator: "in".to_string(),
                        expected: Value::Array(vec![
                            Value::Number(serde_json::Number::from(200)),
                            Value::Number(serde_json::Number::from(429)), // Rate limited
                        ]),
                    }
                ]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate boundary condition tests
    async fn generate_boundary_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Test array boundary conditions
        let array_sizes = vec![0, 1, 2, 100, 1000, 10000];

        for size in array_sizes {
            if let Some(body) = self.create_body_with_array_size(endpoint, api_spec, size) {
                let expected_status = if size == 0 || size > 1000 { 400 } else { 200 };

                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Edge Case: Array with {} elements", size),
                    None,
                    None,
                    Some(body),
                    expected_status,
                    None,
                );
                test_cases.push(test_case);
            }
        }

        // Test deeply nested objects
        for depth in vec![1, 10, 50, 100] {
            if let Some(body) = self.create_deeply_nested_object(depth) {
                let expected_status = if depth > 20 { 400 } else { 200 };

                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Edge Case: Object nested {} levels deep", depth),
                    None,
                    None,
                    Some(body),
                    expected_status,
                    None,
                );
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate empty and null value tests
    async fn generate_empty_value_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        let empty_values = vec![
            ("Empty Object", Value::Object(Map::new())),
            ("Empty Array", Value::Array(vec![])),
            ("Null", Value::Null),
            ("Empty String", Value::String("".to_string())),
            ("Whitespace Only", Value::String("   ".to_string())),
            ("Newlines Only", Value::String("\n\n\n".to_string())),
            ("Tabs Only", Value::String("\t\t\t".to_string())),
        ];

        for (test_name, empty_value) in empty_values {
            if endpoint.method.to_uppercase() != "GET" {
                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Edge Case: {} as request body", test_name),
                    None,
                    None,
                    Some(empty_value),
                    400,
                    None,
                );
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate type confusion tests
    async fn generate_type_confusion_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if let Some(body_schema) = self.get_request_body_schema(endpoint, api_spec) {
            if let Some(properties) = body_schema.get("properties").and_then(|p| p.as_object()) {
                for (prop_name, prop_schema) in properties {
                    let expected_type = prop_schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

                    // Test wrong types
                    let wrong_values = match expected_type {
                        "string" => vec![
                            ("Integer as String", Value::Number(serde_json::Number::from(123))),
                            ("Array as String", Value::Array(vec![Value::String("test".to_string())])),
                            ("Object as String", Value::Object(Map::new())),
                        ],
                        "integer" | "number" => vec![
                            ("String as Number", Value::String("not_a_number".to_string())),
                            ("Array as Number", Value::Array(vec![])),
                            ("Object as Number", Value::Object(Map::new())),
                        ],
                        "boolean" => vec![
                            ("String as Boolean", Value::String("true".to_string())),
                            ("Number as Boolean", Value::Number(serde_json::Number::from(1))),
                            ("Array as Boolean", Value::Array(vec![])),
                        ],
                        "array" => vec![
                            ("String as Array", Value::String("[]".to_string())),
                            ("Object as Array", Value::Object(Map::new())),
                            ("Number as Array", Value::Number(serde_json::Number::from(1))),
                        ],
                        "object" => vec![
                            ("String as Object", Value::String("{}".to_string())),
                            ("Array as Object", Value::Array(vec![])),
                            ("Number as Object", Value::Number(serde_json::Number::from(1))),
                        ],
                        _ => vec![],
                    };

                    for (test_name, wrong_value) in wrong_values {
                        let mut body = generate_schema_example(&body_schema);
                        if let Some(obj) = body.as_object_mut() {
                            obj.insert(prop_name.clone(), wrong_value);

                            let test_case = self.base.create_test_case(
                                endpoint.path.clone(),
                                endpoint.method.clone(),
                                format!("Edge Case: {} for property '{}'", test_name, prop_name),
                                None,
                                None,
                                Some(body),
                                400,
                                Some(vec![
                                    Assertion {
                                        field: "status".to_string(),
                                        operator: "in".to_string(),
                                        expected: Value::Array(vec![
                                            Value::Number(serde_json::Number::from(400)),
                                            Value::Number(serde_json::Number::from(422)),
                                        ]),
                                    }
                                ]),
                            );
                            test_cases.push(test_case);
                        }
                    }
                }
            }
        }

        test_cases
    }

    /// Generate resource exhaustion tests
    async fn generate_resource_exhaustion_tests(&self, endpoint: &EndpointInfo, _api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Large payload test
        let large_string = "x".repeat(10_000_000); // 10MB string
        let large_body = Value::Object({
            let mut map = Map::new();
            map.insert("large_field".to_string(), Value::String(large_string));
            map
        });

        let test_case = self.base.create_test_case(
            endpoint.path.clone(),
            endpoint.method.clone(),
            "Edge Case: Extremely large request payload (10MB)".to_string(),
            None,
            None,
            Some(large_body),
            413, // Payload too large
            Some(vec![
                Assertion {
                    field: "status".to_string(),
                    operator: "in".to_string(),
                    expected: Value::Array(vec![
                        Value::Number(serde_json::Number::from(413)),
                        Value::Number(serde_json::Number::from(400)),
                        Value::Number(serde_json::Number::from(500)),
                    ]),
                }
            ]),
        );
        test_cases.push(test_case);

        // Memory exhaustion through deep recursion
        let recursive_body = self.create_recursive_object(1000);
        let test_case = self.base.create_test_case(
            endpoint.path.clone(),
            endpoint.method.clone(),
            "Edge Case: Recursive object structure (memory exhaustion)".to_string(),
            None,
            None,
            Some(recursive_body),
            400,
            Some(vec![
                Assertion {
                    field: "status".to_string(),
                    operator: "in".to_string(),
                    expected: Value::Array(vec![
                        Value::Number(serde_json::Number::from(400)),
                        Value::Number(serde_json::Number::from(500)),
                    ]),
                }
            ]),
        );
        test_cases.push(test_case);

        test_cases
    }

    /// Generate concurrency edge case tests
    async fn generate_concurrency_tests(&self, endpoint: &EndpointInfo, _api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Test for race conditions by simulating concurrent requests
        for i in 0..10 {
            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                format!("Edge Case: Concurrent request #{} for race condition detection", i + 1),
                Some({
                    let mut headers = HashMap::new();
                    headers.insert("X-Request-ID".to_string(), format!("concurrent-{}", i));
                    headers
                }),
                None,
                None,
                200,
                Some(vec![
                    Assertion {
                        field: "status".to_string(),
                        operator: "in".to_string(),
                        expected: Value::Array(vec![
                            Value::Number(serde_json::Number::from(200)),
                            Value::Number(serde_json::Number::from(409)), // Conflict
                            Value::Number(serde_json::Number::from(429)), // Rate limited
                        ]),
                    }
                ]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate protocol-specific edge case tests
    async fn generate_protocol_edge_tests(&self, endpoint: &EndpointInfo, _api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // HTTP header edge cases
        let edge_headers = vec![
            ("Very Long Header", "X-Long-Header", "x".repeat(8192)),
            ("Binary Header", "X-Binary", "\x00\x01\x02\x03\x04"),
            ("Unicode Header", "X-Unicode", "🚀🔥💯"),
            ("Control Chars", "X-Control", "\r\n\t"),
            ("Empty Header", "X-Empty", ""),
        ];

        for (test_name, header_name, header_value) in edge_headers {
            let mut headers = HashMap::new();
            headers.insert(header_name.to_string(), header_value);

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                format!("Edge Case: {} in HTTP header", test_name),
                Some(headers),
                None,
                None,
                400,
                Some(vec![
                    Assertion {
                        field: "status".to_string(),
                        operator: "in".to_string(),
                        expected: Value::Array(vec![
                            Value::Number(serde_json::Number::from(200)),
                            Value::Number(serde_json::Number::from(400)),
                        ]),
                    }
                ]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate content-type confusion tests
    async fn generate_content_type_tests(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        if endpoint.method.to_uppercase() != "GET" {
            let json_body = generate_schema_example(&Value::Object({
                let mut obj = Map::new();
                obj.insert("type".to_string(), Value::String("object".to_string()));
                obj
            }));

            let content_types = vec![
                ("XML as JSON", "application/xml"),
                ("Form Data", "application/x-www-form-urlencoded"),
                ("Plain Text", "text/plain"),
                ("Binary", "application/octet-stream"),
                ("Multipart", "multipart/form-data"),
                ("Invalid Type", "invalid/content-type"),
                ("Empty Type", ""),
            ];

            for (test_name, content_type) in content_types {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), content_type.to_string());

                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Edge Case: {} content type with JSON body", test_name),
                    Some(headers),
                    None,
                    Some(json_body.clone()),
                    400,
                    Some(vec![
                        Assertion {
                            field: "status".to_string(),
                            operator: "in".to_string(),
                            expected: Value::Array(vec![
                                Value::Number(serde_json::Number::from(400)),
                                Value::Number(serde_json::Number::from(415)), // Unsupported media type
                            ]),
                        }
                    ]),
                );
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Helper: Create request body with unicode content
    fn create_body_with_unicode(&self, endpoint: &EndpointInfo, api_spec: &Value, unicode_value: &str) -> Option<Value> {
        if let Some(body_schema) = self.get_request_body_schema(endpoint, api_spec) {
            let mut body = generate_schema_example(&body_schema);

            // Insert unicode value into first string field found
            if let Some(obj) = body.as_object_mut() {
                if let Some(properties) = body_schema.get("properties").and_then(|p| p.as_object()) {
                    for (prop_name, prop_schema) in properties {
                        if prop_schema.get("type").and_then(|t| t.as_str()) == Some("string") {
                            obj.insert(prop_name.clone(), Value::String(unicode_value.to_string()));
                            break;
                        }
                    }
                }
            }

            Some(body)
        } else {
            None
        }
    }

    /// Helper: Create request body with extreme value
    fn create_body_with_extreme_value(&self, endpoint: &EndpointInfo, api_spec: &Value, extreme_value: &Value) -> Option<Value> {
        if let Some(body_schema) = self.get_request_body_schema(endpoint, api_spec) {
            let mut body = generate_schema_example(&body_schema);

            // Insert extreme value into appropriate field
            if let Some(obj) = body.as_object_mut() {
                if let Some(properties) = body_schema.get("properties").and_then(|p| p.as_object()) {
                    for (prop_name, _) in properties {
                        obj.insert(prop_name.clone(), extreme_value.clone());
                        break;
                    }
                }
            }

            Some(body)
        } else {
            None
        }
    }

    /// Helper: Create request body with specific array size
    fn create_body_with_array_size(&self, endpoint: &EndpointInfo, api_spec: &Value, size: usize) -> Option<Value> {
        if let Some(body_schema) = self.get_request_body_schema(endpoint, api_spec) {
            let mut body = generate_schema_example(&body_schema);

            // Find first array property and set its size
            if let Some(obj) = body.as_object_mut() {
                if let Some(properties) = body_schema.get("properties").and_then(|p| p.as_object()) {
                    for (prop_name, prop_schema) in properties {
                        if prop_schema.get("type").and_then(|t| t.as_str()) == Some("array") {
                            let array_items = vec![Value::String("test".to_string()); size];
                            obj.insert(prop_name.clone(), Value::Array(array_items));
                            break;
                        }
                    }
                }
            }

            Some(body)
        } else {
            None
        }
    }

    /// Helper: Create deeply nested object
    fn create_deeply_nested_object(&self, depth: usize) -> Option<Value> {
        if depth == 0 {
            return Some(Value::String("end".to_string()));
        }

        let mut obj = Map::new();
        obj.insert("nested".to_string(), self.create_deeply_nested_object(depth - 1)?);
        obj.insert("level".to_string(), Value::Number(serde_json::Number::from(depth)));

        Some(Value::Object(obj))
    }

    /// Helper: Create recursive object structure
    fn create_recursive_object(&self, depth: usize) -> Value {
        let mut obj = Map::new();
        obj.insert("id".to_string(), Value::Number(serde_json::Number::from(depth)));

        if depth > 0 {
            obj.insert("child".to_string(), self.create_recursive_object(depth - 1));
        }

        Value::Object(obj)
    }

    /// Helper: Get request body schema from endpoint
    fn get_request_body_schema(&self, endpoint: &EndpointInfo, api_spec: &Value) -> Option<Value> {
        endpoint.request_body
            .as_ref()
            .and_then(|rb| rb.get("content"))
            .and_then(|content| content.get("application/json"))
            .and_then(|json_content| json_content.get("schema"))
            .map(|schema| resolve_schema_ref(schema, api_spec))
    }
}

#[async_trait]
impl Agent for EdgeCasesAgent {
    fn agent_type(&self) -> &str {
        &self.base.agent_type
    }

    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        let start_time = std::time::Instant::now();
        let endpoints = self.base.extract_endpoints(&api_spec);
        let mut all_test_cases = Vec::new();
        let mut metadata = HashMap::new();

        // Generate edge case tests for each endpoint
        for endpoint in &endpoints {
            let edge_case_tests = self.generate_edge_case_tests(endpoint, &api_spec).await;
            all_test_cases.extend(edge_case_tests);
        }

        let processing_time = start_time.elapsed().as_millis();

        // Update metadata
        metadata.insert("total_endpoints".to_string(), Value::Number(serde_json::Number::from(endpoints.len())));
        metadata.insert("total_edge_case_tests".to_string(), Value::Number(serde_json::Number::from(all_test_cases.len())));
        metadata.insert("processing_time_ms".to_string(), Value::Number(serde_json::Number::from(processing_time)));
        metadata.insert("test_categories".to_string(), Value::Array(vec![
            Value::String("unicode_encoding".to_string()),
            Value::String("extreme_values".to_string()),
            Value::String("timing_attacks".to_string()),
            Value::String("boundary_conditions".to_string()),
            Value::String("empty_null_values".to_string()),
            Value::String("type_confusion".to_string()),
            Value::String("resource_exhaustion".to_string()),
            Value::String("concurrency_edge_cases".to_string()),
            Value::String("protocol_edge_cases".to_string()),
            Value::String("content_type_confusion".to_string()),
        ]));

        AgentResult {
            task_id: task.task_id,
            agent_type: self.agent_type().to_string(),
            status: "completed".to_string(),
            test_cases: all_test_cases,
            metadata,
            error_message: None,
        }
    }
}

impl Default for EdgeCasesAgent {
    fn default() -> Self {
        Self::new()
    }
}