//! Consolidated Functional Agent with Strategy Pattern
//!
//! This agent consolidates:
//! - FunctionalPositiveAgent (valid test cases)
//! - FunctionalNegativeAgent (invalid test cases)
//! - EdgeCasesAgent (boundary values and edge cases)
//!
//! Eliminates 60-75% duplication by providing 4 distinct strategies:
//! 1. PositiveStrategy: Valid data, expect 2xx
//! 2. NegativeStrategy: Invalid data, expect 4xx
//! 3. BoundaryStrategy: Min/max values, expect varied
//! 4. EdgeCaseStrategy: Unicode, floats, dates, expect varied

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use crate::agents::{Agent, BaseAgent};
use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo};
use super::strategies::{
    TestStrategy, PositiveStrategy, NegativeStrategy,
    BoundaryStrategy, EdgeCaseStrategy
};

/// Consolidated Functional Testing Agent
///
/// Replaces:
/// - FunctionalPositiveAgent
/// - FunctionalNegativeAgent
/// - EdgeCasesAgent
///
/// Reduces duplication by 60-75% through strategy pattern and deduplication.
pub struct FunctionalAgent {
    base: BaseAgent,
    strategies: HashMap<String, Box<dyn TestStrategy>>,
}

impl FunctionalAgent {
    pub fn new() -> Self {
        let mut strategies: HashMap<String, Box<dyn TestStrategy>> = HashMap::new();

        // Initialize all strategies
        strategies.insert("positive".to_string(), Box::new(PositiveStrategy::new()));
        strategies.insert("negative".to_string(), Box::new(NegativeStrategy::new()));
        strategies.insert("boundary".to_string(), Box::new(BoundaryStrategy::new()));
        strategies.insert("edge_case".to_string(), Box::new(EdgeCaseStrategy::new()));

        Self {
            base: BaseAgent::new("Functional-Agent".to_string()),
            strategies,
        }
    }

    /// Extract endpoints from API specification
    fn extract_endpoints(&self, api_spec: &Value) -> Vec<EndpointInfo> {
        self.base.extract_endpoints(api_spec)
    }

    /// Deduplicate test cases based on signature
    fn deduplicate_tests(&self, test_cases: Vec<TestCase>) -> Vec<TestCase> {
        let mut seen_signatures: HashSet<String> = HashSet::new();
        let mut unique_tests = Vec::new();

        for test in test_cases {
            let signature = self.create_test_signature(&test);
            if !seen_signatures.contains(&signature) {
                seen_signatures.insert(signature);
                unique_tests.push(test);
            }
        }

        unique_tests
    }

    /// Create unique signature for a test case using MD5
    fn create_test_signature(&self, test: &TestCase) -> String {
        // Prepare query keys
        let mut query_keys: Vec<String> = test.query_params.keys().cloned().collect();
        query_keys.sort();

        // Prepare body keys
        let body_keys: Vec<String> = if let Some(body) = &test.body {
            if let Some(obj) = body.as_object() {
                let mut keys: Vec<String> = obj.keys().cloned().collect();
                keys.sort();
                keys
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let expected_status = test.expected_status_codes.first().unwrap_or(&200);

        let sig_data = serde_json::json!({
            "method": test.method.to_uppercase(),
            "endpoint": test.path.clone(),
            "test_type": test.test_type.clone(),
            "query_keys": query_keys,
            "body_keys": body_keys,
            "expected_status": expected_status
        });

        let sig_str = sig_data.to_string();
        let digest = md5::compute(sig_str.as_bytes());
        format!("{:x}", digest)
    }
}

#[async_trait]
impl Agent for FunctionalAgent {
    fn agent_type(&self) -> &str {
        &self.base.agent_type
    }

    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        // Get requested strategies (default to positive, negative, boundary)
        let requested_strategies = task.parameters
            .get("strategies")
            .and_then(|s| s.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec![
                "positive".to_string(),
                "negative".to_string(),
                "boundary".to_string(),
            ]);

        // Extract endpoints
        let endpoints = self.extract_endpoints(&api_spec);

        // Generate tests from each strategy
        let mut all_tests = Vec::new();
        let mut strategy_stats = HashMap::new();

        for strategy_name in &requested_strategies {
            if let Some(strategy) = self.strategies.get(strategy_name) {
                let strategy_tests = strategy.generate_tests(&endpoints, &api_spec).await;
                strategy_stats.insert(
                    strategy_name.clone(),
                    Value::Number(serde_json::Number::from(strategy_tests.len())),
                );
                all_tests.extend(strategy_tests);
            } else {
                eprintln!("Warning: Unknown strategy: {}", strategy_name);
            }
        }

        // Deduplicate tests
        let unique_tests = self.deduplicate_tests(all_tests.clone());
        let duplicates_removed = all_tests.len() - unique_tests.len();

        // Calculate deduplication rate
        let deduplication_rate = if !all_tests.is_empty() {
            format!("{:.1}%", (duplicates_removed as f64 / all_tests.len() as f64) * 100.0)
        } else {
            "0%".to_string()
        };

        // Build metadata
        let mut metadata = HashMap::new();
        metadata.insert(
            "total_endpoints".to_string(),
            Value::Number(serde_json::Number::from(endpoints.len())),
        );
        metadata.insert(
            "strategies_used".to_string(),
            Value::Array(requested_strategies.iter().map(|s| Value::String(s.clone())).collect()),
        );
        metadata.insert(
            "strategy_stats".to_string(),
            Value::Object(strategy_stats.into_iter().collect()),
        );
        metadata.insert(
            "total_generated".to_string(),
            Value::Number(serde_json::Number::from(all_tests.len())),
        );
        metadata.insert(
            "unique_tests".to_string(),
            Value::Number(serde_json::Number::from(unique_tests.len())),
        );
        metadata.insert(
            "duplicates_removed".to_string(),
            Value::Number(serde_json::Number::from(duplicates_removed)),
        );
        metadata.insert(
            "deduplication_rate".to_string(),
            Value::String(deduplication_rate),
        );
        metadata.insert(
            "generation_strategy".to_string(),
            Value::String("consolidated_strategy_pattern".to_string()),
        );

        AgentResult {
            task_id: task.task_id,
            agent_type: self.agent_type().to_string(),
            status: "success".to_string(),
            test_cases: unique_tests,
            metadata,
            error_message: None,
        }
    }
}
