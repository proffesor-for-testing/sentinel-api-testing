//! Security Authentication Agent for Sentinel Platform
//!
//! This agent specializes in testing authentication and authorization vulnerabilities,
//! covering OWASP Top 10 A01:2021 (Broken Access Control) and A07:2021 (Identification and Authentication Failures).
//! Tests include BOLA, BFLA, privilege escalation, session management, JWT attacks, and more.

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

    /// Generate Broken Function Level Authorization (BFLA) test cases
    fn generate_bfla_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let function_tests = self.get_function_level_tests(endpoint);

        for test_config in &function_tests {
            let auth_scenarios = self.get_enhanced_auth_scenarios();
            for scenario in &auth_scenarios {
                let description = format!(
                    "BFLA Test: {} {} - {} with role {}",
                    endpoint.method, endpoint.path, test_config["description"], scenario.role
                );
                let headers = self.get_role_based_headers(&scenario.role);
                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    description,
                    Some(headers),
                    None,
                    self.generate_request_body(&endpoint.operation),
                    scenario.expected_status[0],
                    Some(vec![Assertion {
                        assertion_type: "access_control_check".to_string(),
                        expected: Value::Object(serde_json::Map::from_iter([
                            ("type".to_string(), Value::String("bfla".to_string())),
                            ("role".to_string(), Value::String(scenario.role.clone())),
                            ("function".to_string(), test_config["function"].clone()),
                        ])),
                        path: None,
                    }]),
                );
                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate privilege escalation test cases
    fn generate_privilege_escalation_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let escalation_vectors = self.get_privilege_escalation_vectors();

        for vector in &escalation_vectors {
            let description = format!(
                "Privilege Escalation Test: {} {} - {}",
                endpoint.method, endpoint.path, vector["description"]
            );
            let headers = self.get_escalation_headers(vector);
            let body = self.get_escalation_body(vector, &endpoint.operation);

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                description,
                Some(headers),
                None,
                body,
                403,
                Some(vec![Assertion {
                    assertion_type: "privilege_escalation_check".to_string(),
                    expected: Value::Object(serde_json::Map::from_iter([
                        ("type".to_string(), Value::String("privilege_escalation".to_string())),
                        ("vector".to_string(), vector["vector"].clone()),
                        ("expected_behavior".to_string(), Value::String("Should deny privilege escalation attempts".to_string())),
                    ])),
                    path: None,
                }]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate JWT-specific attack test cases
    fn generate_jwt_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        if !self.uses_jwt_auth(endpoint) {
            return test_cases;
        }

        let jwt_attacks = self.get_jwt_attack_vectors();
        for attack in &jwt_attacks {
            let description = format!(
                "JWT Attack Test: {} {} - {}",
                endpoint.method, endpoint.path, attack["description"]
            );
            let headers = self.get_jwt_attack_headers(attack);

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                description,
                Some(headers),
                None,
                self.generate_request_body(&endpoint.operation),
                401,
                Some(vec![Assertion {
                    assertion_type: "jwt_security_check".to_string(),
                    expected: Value::Object(serde_json::Map::from_iter([
                        ("type".to_string(), Value::String("jwt_attack".to_string())),
                        ("attack_vector".to_string(), attack["vector"].clone()),
                        ("expected_behavior".to_string(), Value::String("Should reject invalid/malicious JWT tokens".to_string())),
                    ])),
                    path: None,
                }]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate session management test cases
    fn generate_session_management_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let session_attacks = self.get_session_attack_vectors();

        for attack in &session_attacks {
            let description = format!(
                "Session Management Test: {} {} - {}",
                endpoint.method, endpoint.path, attack["description"]
            );
            let headers = self.get_session_attack_headers(attack);

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                description,
                Some(headers),
                None,
                self.generate_request_body(&endpoint.operation),
                401,
                Some(vec![Assertion {
                    assertion_type: "session_security_check".to_string(),
                    expected: Value::Object(serde_json::Map::from_iter([
                        ("type".to_string(), Value::String("session_attack".to_string())),
                        ("attack_vector".to_string(), attack["vector"].clone()),
                        ("expected_behavior".to_string(), Value::String("Should properly validate session tokens".to_string())),
                    ])),
                    path: None,
                }]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate rate limiting and brute force test cases
    fn generate_rate_limiting_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        if !self.is_auth_endpoint(endpoint) {
            return test_cases;
        }

        let rate_limit_tests = self.get_rate_limiting_scenarios();
        for scenario in &rate_limit_tests {
            let description = format!(
                "Rate Limiting Test: {} {} - {}",
                endpoint.method, endpoint.path, scenario["description"]
            );
            let headers = self.get_standard_headers();

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                description,
                Some(headers),
                None,
                self.generate_rate_limit_body(scenario),
                429,
                Some(vec![Assertion {
                    assertion_type: "rate_limiting_check".to_string(),
                    expected: Value::Object(serde_json::Map::from_iter([
                        ("type".to_string(), Value::String("rate_limiting".to_string())),
                        ("scenario".to_string(), scenario["scenario"].clone()),
                        ("expected_behavior".to_string(), Value::String("Should enforce rate limiting and prevent brute force attacks".to_string())),
                    ])),
                    path: None,
                }]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate mass assignment test cases
    fn generate_mass_assignment_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        if !["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
            return test_cases;
        }

        let mass_assignment_vectors = self.get_mass_assignment_vectors();
        for vector in &mass_assignment_vectors {
            let description = format!(
                "Mass Assignment Test: {} {} - {}",
                endpoint.method, endpoint.path, vector["description"]
            );
            let headers = self.get_standard_headers();
            let body = self.get_mass_assignment_body(vector, &endpoint.operation);

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                description,
                Some(headers),
                None,
                body,
                400,
                Some(vec![Assertion {
                    assertion_type: "mass_assignment_check".to_string(),
                    expected: Value::Object(serde_json::Map::from_iter([
                        ("type".to_string(), Value::String("mass_assignment".to_string())),
                        ("vector".to_string(), vector["vector"].clone()),
                        ("expected_behavior".to_string(), Value::String("Should reject unauthorized field modifications".to_string())),
                    ])),
                    path: None,
                }]),
            );
            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate CORS misconfiguration test cases
    fn generate_cors_tests(&self, endpoint: &EndpointInfo) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let cors_vectors = self.get_cors_attack_vectors();

        for vector in &cors_vectors {
            let description = format!(
                "CORS Test: {} {} - {}",
                endpoint.method, endpoint.path, vector["description"]
            );
            let headers = self.get_cors_headers(vector);

            let test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                description,
                Some(headers),
                None,
                self.generate_request_body(&endpoint.operation),
                200,
                Some(vec![Assertion {
                    assertion_type: "cors_security_check".to_string(),
                    expected: Value::Object(serde_json::Map::from_iter([
                        ("type".to_string(), Value::String("cors_misconfiguration".to_string())),
                        ("vector".to_string(), vector["vector"].clone()),
                        ("expected_behavior".to_string(), Value::String("Should properly configure CORS headers".to_string())),
                    ])),
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
            AuthScenario { name: "no_auth".to_string(), role: "anonymous".to_string(), expected_status: vec![401, 403] },
            AuthScenario { name: "invalid_token".to_string(), role: "invalid".to_string(), expected_status: vec![401, 403] },
            AuthScenario { name: "different_user".to_string(), role: "user".to_string(), expected_status: vec![403, 404] },
        ]
    }

    /// Get enhanced authentication scenarios for comprehensive testing
    fn get_enhanced_auth_scenarios(&self) -> Vec<AuthScenario> {
        vec![
            AuthScenario { name: "anonymous_access".to_string(), role: "anonymous".to_string(), expected_status: vec![401, 403] },
            AuthScenario { name: "user_access".to_string(), role: "user".to_string(), expected_status: vec![200, 403] },
            AuthScenario { name: "admin_access".to_string(), role: "admin".to_string(), expected_status: vec![200] },
            AuthScenario { name: "moderator_access".to_string(), role: "moderator".to_string(), expected_status: vec![200, 403] },
            AuthScenario { name: "guest_access".to_string(), role: "guest".to_string(), expected_status: vec![403] },
            AuthScenario { name: "expired_token".to_string(), role: "expired".to_string(), expected_status: vec![401] },
            AuthScenario { name: "revoked_token".to_string(), role: "revoked".to_string(), expected_status: vec![401] },
        ]
    }

    /// Get function-level authorization test configurations
    fn get_function_level_tests(&self, endpoint: &EndpointInfo) -> Vec<Value> {
        let mut tests = Vec::new();

        // Test based on HTTP method
        match endpoint.method.as_str() {
            "DELETE" => tests.push(serde_json::json!({
                "function": "delete_resource",
                "description": "Attempting to delete resource with insufficient privileges",
                "required_role": "admin"
            })),
            "PUT" | "PATCH" => tests.push(serde_json::json!({
                "function": "modify_resource",
                "description": "Attempting to modify resource with insufficient privileges",
                "required_role": "user_or_admin"
            })),
            "POST" => tests.push(serde_json::json!({
                "function": "create_resource",
                "description": "Attempting to create resource with insufficient privileges",
                "required_role": "user_or_admin"
            })),
            _ => {}
        }

        // Test based on path patterns
        let path_lower = endpoint.path.to_lowercase();
        if path_lower.contains("admin") {
            tests.push(serde_json::json!({
                "function": "admin_function",
                "description": "Attempting to access admin function",
                "required_role": "admin"
            }));
        }
        if path_lower.contains("settings") || path_lower.contains("config") {
            tests.push(serde_json::json!({
                "function": "configuration_function",
                "description": "Attempting to access configuration function",
                "required_role": "admin"
            }));
        }

        if tests.is_empty() {
            tests.push(serde_json::json!({
                "function": "general_function",
                "description": "Attempting to access function with various privilege levels",
                "required_role": "authenticated"
            }));
        }

        tests
    }

    /// Get role-based authentication headers
    fn get_role_based_headers(&self, role: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        match role {
            "admin" => {
                headers.insert("Authorization".to_string(), "Bearer admin_token_with_full_privileges".to_string());
                headers.insert("X-User-Role".to_string(), "admin".to_string());
            }
            "user" => {
                headers.insert("Authorization".to_string(), "Bearer user_token_limited_privileges".to_string());
                headers.insert("X-User-Role".to_string(), "user".to_string());
            }
            "moderator" => {
                headers.insert("Authorization".to_string(), "Bearer moderator_token_moderate_privileges".to_string());
                headers.insert("X-User-Role".to_string(), "moderator".to_string());
            }
            "guest" => {
                headers.insert("Authorization".to_string(), "Bearer guest_token_minimal_privileges".to_string());
                headers.insert("X-User-Role".to_string(), "guest".to_string());
            }
            "expired" => {
                headers.insert("Authorization".to_string(), "Bearer expired_token_should_be_rejected".to_string());
            }
            "revoked" => {
                headers.insert("Authorization".to_string(), "Bearer revoked_token_should_be_invalid".to_string());
            }
            "invalid" => {
                headers.insert("Authorization".to_string(), "Bearer invalid_malformed_token_123".to_string());
            }
            _ => {} // anonymous - no auth headers
        }

        headers
    }

    /// Get privilege escalation attack vectors
    fn get_privilege_escalation_vectors(&self) -> Vec<Value> {
        vec![
            serde_json::json!({
                "vector": "role_manipulation",
                "description": "Attempting to escalate privileges by manipulating user role",
                "method": "header_injection"
            }),
            serde_json::json!({
                "vector": "token_manipulation",
                "description": "Attempting to modify JWT claims for privilege escalation",
                "method": "jwt_manipulation"
            }),
            serde_json::json!({
                "vector": "parameter_pollution",
                "description": "Attempting privilege escalation via HTTP parameter pollution",
                "method": "parameter_injection"
            }),
            serde_json::json!({
                "vector": "group_membership",
                "description": "Attempting to add user to privileged groups",
                "method": "body_manipulation"
            }),
        ]
    }

    /// Get headers for privilege escalation tests
    fn get_escalation_headers(&self, vector: &Value) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Authorization".to_string(), "Bearer user_token_attempting_escalation".to_string());

        match vector["method"].as_str().unwrap_or("") {
            "header_injection" => {
                headers.insert("X-User-Role".to_string(), "admin".to_string());
                headers.insert("X-Privilege-Level".to_string(), "superuser".to_string());
                headers.insert("X-Admin-Override".to_string(), "true".to_string());
            }
            "jwt_manipulation" => {
                // Malformed JWT with escalated claims
                headers.insert("Authorization".to_string(), "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4iLCJ1c2VyIjoidGVzdCIsImV4cCI6OTk5OTk5OTk5OX0.invalid_signature".to_string());
            }
            _ => {}
        }

        headers
    }

    /// Get body for privilege escalation tests
    fn get_escalation_body(&self, vector: &Value, operation_spec: &Value) -> Option<Value> {
        let base_body = self.generate_request_body(operation_spec);

        match vector["method"].as_str().unwrap_or("") {
            "body_manipulation" => {
                if let Some(Value::Object(mut body_map)) = base_body {
                    // Add privilege escalation fields
                    body_map.insert("role".to_string(), Value::String("admin".to_string()));
                    body_map.insert("permissions".to_string(), Value::Array(vec![
                        Value::String("read".to_string()),
                        Value::String("write".to_string()),
                        Value::String("delete".to_string()),
                        Value::String("admin".to_string()),
                    ]));
                    body_map.insert("is_admin".to_string(), Value::Bool(true));
                    body_map.insert("groups".to_string(), Value::Array(vec![
                        Value::String("administrators".to_string()),
                        Value::String("superusers".to_string()),
                    ]));
                    Some(Value::Object(body_map))
                } else {
                    Some(serde_json::json!({
                        "role": "admin",
                        "is_admin": true,
                        "permissions": ["read", "write", "delete", "admin"]
                    }))
                }
            }
            "parameter_pollution" => {
                if let Some(Value::Object(mut body_map)) = base_body {
                    // Add duplicate/conflicting parameters
                    body_map.insert("user_id".to_string(), Value::String("1".to_string()));
                    body_map.insert("user_id".to_string(), Value::String("admin".to_string()));
                    body_map.insert("role".to_string(), Value::String("user".to_string()));
                    body_map.insert("role".to_string(), Value::String("admin".to_string()));
                    Some(Value::Object(body_map))
                } else {
                    base_body
                }
            }
            _ => base_body
        }
    }

    /// Check if endpoint uses JWT authentication
    fn uses_jwt_auth(&self, endpoint: &EndpointInfo) -> bool {
        // Check if operation mentions JWT, Bearer tokens, or has JWT-related security schemes
        if let Some(security) = endpoint.operation.get("security").and_then(|s| s.as_array()) {
            for scheme in security {
                if let Some(scheme_obj) = scheme.as_object() {
                    for (name, _) in scheme_obj {
                        if name.to_lowercase().contains("jwt") || name.to_lowercase().contains("bearer") {
                            return true;
                        }
                    }
                }
            }
        }

        // Default assumption: most modern APIs use JWT
        self.requires_authentication(&endpoint.operation)
    }

    /// Get JWT attack vectors
    fn get_jwt_attack_vectors(&self) -> Vec<Value> {
        vec![
            serde_json::json!({
                "vector": "none_algorithm",
                "description": "JWT with 'none' algorithm to bypass signature verification",
                "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            }),
            serde_json::json!({
                "vector": "weak_secret",
                "description": "JWT signed with weak/common secret",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"
            }),
            serde_json::json!({
                "vector": "expired_token",
                "description": "Expired JWT token",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjN9.invalid_expired"
            }),
            serde_json::json!({
                "vector": "malformed_token",
                "description": "Malformed JWT structure",
                "token": "invalid.jwt.token.structure.here"
            }),
            serde_json::json!({
                "vector": "key_confusion",
                "description": "JWT key confusion attack (RS256 to HS256)",
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.key_confusion_attack"
            }),
        ]
    }

    /// Get JWT attack headers
    fn get_jwt_attack_headers(&self, attack: &Value) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        if let Some(token) = attack["token"].as_str() {
            headers.insert("Authorization".to_string(), format!("Bearer {}", token));
        }

        headers
    }

    /// Get session attack vectors
    fn get_session_attack_vectors(&self) -> Vec<Value> {
        vec![
            serde_json::json!({
                "vector": "session_fixation",
                "description": "Session fixation attack with predetermined session ID",
                "session_id": "FIXED_SESSION_ID_12345"
            }),
            serde_json::json!({
                "vector": "session_hijacking",
                "description": "Session hijacking with stolen session token",
                "session_id": "HIJACKED_SESSION_67890"
            }),
            serde_json::json!({
                "vector": "session_replay",
                "description": "Session replay attack with old session data",
                "session_id": "OLD_SESSION_ABCDEF"
            }),
            serde_json::json!({
                "vector": "concurrent_sessions",
                "description": "Multiple concurrent sessions for same user",
                "session_id": "CONCURRENT_SESSION_999"
            }),
        ]
    }

    /// Get session attack headers
    fn get_session_attack_headers(&self, attack: &Value) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        if let Some(session_id) = attack["session_id"].as_str() {
            headers.insert("Cookie".to_string(), format!("sessionid={}", session_id));
            headers.insert("X-Session-Token".to_string(), session_id.to_string());
        }

        headers
    }

    /// Check if endpoint is an authentication endpoint
    fn is_auth_endpoint(&self, endpoint: &EndpointInfo) -> bool {
        let auth_patterns = ["login", "signin", "auth", "token", "session", "password", "reset"];
        let path_lower = endpoint.path.to_lowercase();
        auth_patterns.iter().any(|pattern| path_lower.contains(pattern))
    }

    /// Get rate limiting test scenarios
    fn get_rate_limiting_scenarios(&self) -> Vec<Value> {
        vec![
            serde_json::json!({
                "scenario": "brute_force_login",
                "description": "Brute force login attempt",
                "request_count": 100,
                "credentials": {"username": "admin", "password": "wrong_password"}
            }),
            serde_json::json!({
                "scenario": "rapid_requests",
                "description": "Rapid successive requests to test rate limiting",
                "request_count": 50,
                "credentials": {"username": "test_user", "password": "test_pass"}
            }),
            serde_json::json!({
                "scenario": "distributed_attack",
                "description": "Distributed attack simulation",
                "request_count": 25,
                "credentials": {"username": "target", "password": "password123"}
            }),
        ]
    }

    /// Generate body for rate limiting tests
    fn generate_rate_limit_body(&self, scenario: &Value) -> Option<Value> {
        if let Some(credentials) = scenario["credentials"].as_object() {
            Some(Value::Object(credentials.clone()))
        } else {
            Some(serde_json::json!({
                "username": "test_user",
                "password": "brute_force_attempt"
            }))
        }
    }

    /// Get mass assignment attack vectors
    fn get_mass_assignment_vectors(&self) -> Vec<Value> {
        vec![
            serde_json::json!({
                "vector": "privilege_fields",
                "description": "Mass assignment of privilege-related fields",
                "fields": ["is_admin", "role", "permissions", "admin", "superuser"]
            }),
            serde_json::json!({
                "vector": "system_fields",
                "description": "Mass assignment of system/internal fields",
                "fields": ["id", "created_at", "updated_at", "internal_id", "system_flag"]
            }),
            serde_json::json!({
                "vector": "financial_fields",
                "description": "Mass assignment of financial/sensitive fields",
                "fields": ["balance", "credit_limit", "price", "discount", "cost"]
            }),
            serde_json::json!({
                "vector": "hidden_fields",
                "description": "Mass assignment of hidden/private fields",
                "fields": ["password", "secret", "token", "key", "private"]
            }),
        ]
    }

    /// Get mass assignment body
    fn get_mass_assignment_body(&self, vector: &Value, operation_spec: &Value) -> Option<Value> {
        let base_body = self.generate_request_body(operation_spec);

        if let Some(Value::Object(mut body_map)) = base_body {
            if let Some(fields) = vector["fields"].as_array() {
                for field in fields {
                    if let Some(field_name) = field.as_str() {
                        match field_name {
                            "is_admin" | "admin" | "superuser" => {
                                body_map.insert(field_name.to_string(), Value::Bool(true));
                            }
                            "role" => {
                                body_map.insert(field_name.to_string(), Value::String("admin".to_string()));
                            }
                            "permissions" => {
                                body_map.insert(field_name.to_string(), Value::Array(vec![
                                    Value::String("read".to_string()),
                                    Value::String("write".to_string()),
                                    Value::String("delete".to_string()),
                                ]));
                            }
                            "balance" | "credit_limit" | "price" => {
                                body_map.insert(field_name.to_string(), Value::Number(serde_json::Number::from(999999)));
                            }
                            "discount" => {
                                body_map.insert(field_name.to_string(), Value::Number(serde_json::Number::from(100)));
                            }
                            _ => {
                                body_map.insert(field_name.to_string(), Value::String("unauthorized_value".to_string()));
                            }
                        }
                    }
                }
            }
            Some(Value::Object(body_map))
        } else {
            Some(serde_json::json!({
                "is_admin": true,
                "role": "admin",
                "permissions": ["read", "write", "delete"],
                "balance": 999999
            }))
        }
    }

    /// Get CORS attack vectors
    fn get_cors_attack_vectors(&self) -> Vec<Value> {
        vec![
            serde_json::json!({
                "vector": "null_origin",
                "description": "CORS bypass with null origin",
                "origin": "null"
            }),
            serde_json::json!({
                "vector": "wildcard_subdomain",
                "description": "CORS bypass with wildcard subdomain",
                "origin": "https://evil.attacker.com"
            }),
            serde_json::json!({
                "vector": "localhost_bypass",
                "description": "CORS bypass using localhost variations",
                "origin": "http://localhost:8080"
            }),
            serde_json::json!({
                "vector": "arbitrary_port",
                "description": "CORS bypass with arbitrary port",
                "origin": "https://legitimate-site.com:1337"
            }),
        ]
    }

    /// Get CORS headers
    fn get_cors_headers(&self, vector: &Value) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        if let Some(origin) = vector["origin"].as_str() {
            headers.insert("Origin".to_string(), origin.to_string());
            headers.insert("Referer".to_string(), format!("{}/page", origin));
        }

        headers
    }

    /// Get standard headers
    fn get_standard_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());
        headers
    }
}

struct AuthScenario {
    name: String,
    role: String,
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
            test_cases.extend(self.generate_bfla_tests(endpoint));
            test_cases.extend(self.generate_privilege_escalation_tests(endpoint));
            test_cases.extend(self.generate_jwt_tests(endpoint));
            test_cases.extend(self.generate_session_management_tests(endpoint));
            test_cases.extend(self.generate_rate_limiting_tests(endpoint));
            test_cases.extend(self.generate_mass_assignment_tests(endpoint));
            test_cases.extend(self.generate_cors_tests(endpoint));
        }

        let mut metadata = HashMap::new();
        metadata.insert("total_tests".to_string(), Value::from(test_cases.len()));
        metadata.insert("auth_test_types".to_string(), Value::Array(vec![
            Value::String("BOLA (Broken Object Level Authorization)".to_string()),
            Value::String("BFLA (Broken Function Level Authorization)".to_string()),
            Value::String("Privilege Escalation".to_string()),
            Value::String("JWT Attacks".to_string()),
            Value::String("Session Management".to_string()),
            Value::String("Rate Limiting".to_string()),
            Value::String("Mass Assignment".to_string()),
            Value::String("CORS Misconfiguration".to_string()),
            Value::String("Authentication Bypass".to_string()),
        ]));
        metadata.insert("owasp_coverage".to_string(), Value::String("A01:2021 Broken Access Control + A07:2021 Identification and Authentication Failures".to_string()));
        metadata.insert("generation_strategy".to_string(), Value::String("comprehensive_auth_testing".to_string()));

        AgentResult {
            task_id: task.task_id,
            agent_type: self.agent_type().to_string(),
            status: "success".to_string(),
            test_cases,
            metadata,
            error_message: None,
        }
    }
}