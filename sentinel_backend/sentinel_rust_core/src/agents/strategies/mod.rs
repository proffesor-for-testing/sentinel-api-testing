//! Test generation strategies for the Functional Agent
//!
//! This module provides the strategy pattern implementation for generating different types of tests.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use crate::types::{EndpointInfo, TestCase, Assertion};
use crate::agents::BaseAgent;

pub mod positive;
pub mod negative;
pub mod boundary;
pub mod edge_case;

pub use positive::PositiveStrategy;
pub use negative::NegativeStrategy;
pub use boundary::BoundaryStrategy;
pub use edge_case::EdgeCaseStrategy;

/// Base trait for test generation strategies
#[async_trait]
pub trait TestStrategy: Send + Sync {
    /// Generate tests for given endpoints
    async fn generate_tests(
        &self,
        endpoints: &[EndpointInfo],
        api_spec: &Value,
    ) -> Vec<TestCase>;

    /// Get the strategy name
    fn strategy_name(&self) -> &str;
}

/// Create a standardized test case (utility function for strategies)
pub fn create_test_case(
    endpoint: String,
    method: String,
    description: String,
    test_type: String,
    test_subtype: String,
    headers: Option<HashMap<String, String>>,
    query_params: Option<HashMap<String, Value>>,
    body: Option<Value>,
    expected_status: u16,
    assertions: Option<Vec<Assertion>>,
) -> TestCase {
    let mut default_headers = HashMap::new();
    default_headers.insert("Content-Type".to_string(), "application/json".to_string());

    let headers = headers.unwrap_or(default_headers);
    let query_params = query_params.unwrap_or_default();
    let assertions = assertions.unwrap_or_default();

    let mut tags = vec!["functional".to_string(), test_type.split('-').last().unwrap_or("test").to_string()];
    tags.push(format!("{}-method", method.to_lowercase()));

    TestCase {
        test_name: description,
        test_type,
        method: method.to_uppercase(),
        path: endpoint,
        headers,
        query_params,
        body,
        timeout: 600,
        expected_status_codes: vec![expected_status],
        assertions,
        tags,
    }
}
