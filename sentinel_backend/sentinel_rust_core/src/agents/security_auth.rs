//! Security Authentication Agent for Sentinel Platform
//!
//! This agent specializes in testing authentication and authorization vulnerabilities,
//! with a primary focus on Broken Object Level Authorization (BOLA) attacks.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use crate::agents::{Agent, BaseAgent};
use crate::agents::utils::*;
use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo, Assertion};

/// Agent specialized in testing authentication and authorization vulnerabilities.
pub struct SecurityAuthAgent {
    base: BaseAgent,
}

impl SecurityAuthAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Security-Auth-Agent".to_string()),
        }
    }

    /// Generate BOLA test cases.
    fn generate_bola_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let path_params = self.extract_path_parameters(endpoint);

        if path_params.is_empty() {
            return test_cases;
        }

        for param in &path_params {
            let param_name = param.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if !self.is_likely_object_id(param_name) {
                continue;
            }

            let bola_vectors = self.generate_bola_vectors(param);

            for vector in &bola_vectors {
                let auth_scenarios = self.get_auth_scenarios();
                for auth_scenario in &auth_scenarios {
                    let headers = self.get_auth_headers_variants(&auth_scenario.name);
                    let description = format!(
                        "BOLA Test: {} {} - {} with {}",
                        endpoint.method, endpoint.path, vector["description"].as_str().unwrap(), auth_scenario.name
                    );
                    let test_case = self.base.create_test_case(
                        endpoint.path.clone(),
                        endpoint.method.clone(),
                        description,
                        Some(headers),
                        None,
                        self.generate_request_body(&endpoint.operation),
                        auth_scenario.expected_status[0],
                        Some(vec![Assertion {
                            assertion_type: "status_code_in".to_string(),
                            expected: Value::Array(auth_scenario.expected_status.iter().map(|s| Value::from(*s)).collect()),
                            path: None,
                        }]),
                    );
                    test_cases.push(test_case);
                }
            }
        }
        test_cases
    }

    /// Generate function-level authorization test cases.
    fn generate_function_auth_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let sensitive_operations = self.identify_sensitive_operations(endpoint);

        if sensitive_operations.is_empty() {
            return test_cases;
        }

        let auth_scenarios = self.get_auth_scenarios();
        for scenario in &auth_scenarios {
            for operation_type in &sensitive_operations {
                let description = format!(
                    "Function Auth Test: {} {} - {} accessing {}",
                    endpoint.method, endpoint.path, scenario.name, operation_type
                );
                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    description,
                    Some(self.get_auth_headers_variants(&scenario.name)),
                    None,
                    self.generate_request_body(&endpoint.operation),
                    scenario.expected_status[0],
                    Some(vec![Assertion {
                        assertion_type: "status_code_in".to_string(),
                        expected: Value::Array(scenario.expected_status.iter().map(|s| Value::from(*s)).collect()),
                        path: None,
                    }]),
                );
                test_cases.push(test_case);
            }
        }
        test_cases
    }

    /// Generate authentication bypass test cases.
    fn generate_auth_bypass_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        if !self.requires_authentication(&endpoint.operation) {
            return test_cases;
        }

        let bypass_techniques = self.get_bypass_techniques();
        for technique in &bypass_techniques {
            let description = format!(
                "Auth Bypass Test: {} {} - {}",
                endpoint.method, endpoint.path, technique["description"].as_str().unwrap()
            );
            let headers = technique.get("headers").and_then(|h| h.as_object()).map(|h| {
                h.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect()
            }).unwrap_or_default();

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                description,
                Some(headers),
                None,
                self.generate_request_body(&endpoint.operation),
                401,
                Some(vec![Assertion {
                    assertion_type: "status_code_in".to_string(),
                    expected: Value::Array(vec![Value::from(401), Value::from(403)]),
                    path: None,
                }]),
            );
            test_cases.push(test_case);
        }
        test_cases
    }

    fn extract_path_parameters<'a>(&self, endpoint: &'a EndpointInfo) -> Vec<&'a Value> {
        endpoint.parameters.iter().filter(|p| p.get("in").and_then(|i| i.as_str()) == Some("path")).collect()
    }

    fn is_likely_object_id(&self, param_name: &str) -> bool {
        let id_patterns = ["id", "uuid", "key", "identifier", "ref"];
        let param_lower = param_name.to_lowercase();
        id_patterns.iter().any(|p| param_lower.contains(p))
    }

    fn generate_bola_vectors(&self, param: &Value) -> Vec<Value> {
        let param_type = param.get("schema").and_then(|s| s.get("type")).and_then(|t| t.as_str()).unwrap_or("string");
        if param_type == "integer" {
            vec![
                serde_json::json!({"value": 1, "description": "Access first resource"}),
                serde_json::json!({"value": 999999, "description": "Access high-numbered resource"}),
                serde_json::json!({"value": -1, "description": "Negative ID access"}),
                serde_json::json!({"value": 0, "description": "Zero ID access"}),
            ]
        } else {
            vec![
                serde_json::json!({"value": "admin", "description": "Admin user access"}),
                serde_json::json!({"value": "test", "description": "Test user access"}),
                serde_json::json!({"value": "00000000-0000-0000-0000-000000000001", "description": "First UUID access"}),
                serde_json::json!({"value": "../admin", "description": "Path traversal attempt"}),
            ]
        }
    }

    fn get_auth_headers_variants(&self, auth_scenario: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        match auth_scenario {
            "different_user" => {
                headers.insert("Authorization".to_string(), "Bearer different_user_token_12345".to_string());
            }
            "invalid_token" => {
                headers.insert("Authorization".to_string(), "Bearer invalid_token_67890".to_string());
            }
            _ => {}
        }
        headers
    }

    fn identify_sensitive_operations(&self, endpoint: &EndpointInfo) -> Vec<String> {
        let mut sensitive_ops = Vec::new();
        let sensitive_path_patterns = ["admin", "management", "config", "settings", "users", "accounts"];
        let path_lower = endpoint.path.to_lowercase();
        for pattern in &sensitive_path_patterns {
            if path_lower.contains(*pattern) {
                sensitive_ops.push(format!("{}_operation", pattern));
            }
        }
        if ["DELETE", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            sensitive_ops.push(format!("{}_operation", endpoint.method.to_lowercase()));
        }
        sensitive_ops.sort();
        sensitive_ops.dedup();
        sensitive_ops
    }

    fn requires_authentication(&self, operation_spec: &Value) -> bool {
        if let Some(security) = operation_spec.get("security").and_then(|s| s.as_array()) {
            if !security.is_empty() {
                return true;
            }
        }
        if let Some(responses) = operation_spec.get("responses").and_then(|r| r.as_object()) {
            return responses.contains_key("401") || responses.contains_key("403");
        }
        false
    }

    fn generate_request_body(&self, operation_spec: &Value) -> Option<Value> {
        operation_spec.get("requestBody").and_then(|body| {
            body.get("content").and_then(|content| {
                content.get("application/json").and_then(|json_content| {
                    json_content.get("schema").map(|schema| generate_schema_example(schema))
                })
            })
        })
    }

    fn get_bypass_techniques(&self) -> Vec<Value> {
        vec![
            serde_json::json!({
                "name": "header_manipulation",
                "headers": {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
                "description": "IP spoofing via proxy headers"
            }),
            serde_json::json!({
                "name": "method_override",
                "headers": {"X-HTTP-Method-Override": "GET"},
                "description": "HTTP method override bypass"
            }),
        ]
    }

    fn get_auth_scenarios(&self) -> Vec<AuthScenario> {
        vec![
            AuthScenario { name: "no_auth".to_string(), expected_status: vec![401, 403] },
            AuthScenario { name: "invalid_token".to_string(), expected_status: vec![401, 403] },
            AuthScenario { name: "different_user".to_string(), expected_status: vec![403, 404] },
        ]
    }
}

struct AuthScenario {
    name: String,
    expected_status: Vec<u16>,
}

#[async_trait]
impl Agent for SecurityAuthAgent {
    fn agent_type(&self) -> &str {
        &self.base.agent_type
    }

    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        let endpoints = self.base.extract_endpoints(&api_spec);
        let mut test_cases = Vec::new();

        for endpoint in &endpoints {
            test_cases.extend(self.generate_bola_tests(endpoint));
            test_cases.extend(self.generate_function_auth_tests(endpoint));
            test_cases.extend(self.generate_auth_bypass_tests(endpoint));
        }

        AgentResult {
            task_id: task.task_id,
            agent_type: self.agent_type().to_string(),
            status: "success".to_string(),
            test_cases,
            metadata: HashMap::new(),
            error_message: None,
        }
    }
}