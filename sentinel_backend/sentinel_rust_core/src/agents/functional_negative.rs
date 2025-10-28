//! DEPRECATED: Functional-Negative-Agent
//!
//! This agent is deprecated. Please use `FunctionalAgent` with `strategies: ["negative"]` instead.
//!
//! Migration:
//! ```rust
//! // Old way (DEPRECATED):
//! let agent = FunctionalNegativeAgent::new();
//!
//! // New way:
//! use crate::agents::functional_agent::FunctionalAgent;
//! let agent = FunctionalAgent::new();
//! // Use with task parameters: {"strategies": ["negative"]}
//! ```

use async_trait::async_trait;
use serde_json::Value;

use crate::agents::{Agent, functional_agent::FunctionalAgent};
use crate::types::{AgentTask, AgentResult};

/// DEPRECATED: Agent responsible for generating negative functional test cases
///
/// Use `FunctionalAgent` with `strategies: ["negative"]` instead.
#[deprecated(
    since = "2.0.0",
    note = "Use FunctionalAgent with strategies=['negative'] instead"
)]
pub struct FunctionalNegativeAgent {
    inner: FunctionalAgent,
}

impl FunctionalNegativeAgent {
    pub fn new() -> Self {
        eprintln!("⚠️  DEPRECATION WARNING: FunctionalNegativeAgent is deprecated.");
        eprintln!("   Please use FunctionalAgent with strategies=['negative'] instead.");
        eprintln!("   See docs/AGENT_MIGRATION_GUIDE.md for migration instructions.");

        Self {
            inner: FunctionalAgent::new(),
        }
    }
}

#[async_trait]
impl Agent for FunctionalNegativeAgent {
    fn agent_type(&self) -> &str {
        "Functional-Negative-Agent"
    }

    async fn execute(&self, mut task: AgentTask, api_spec: Value) -> AgentResult {
        // Force negative strategy only
        task.parameters.insert(
            "strategies".to_string(),
            serde_json::json!(["negative"])
        );

        // Delegate to consolidated FunctionalAgent
        self.inner.execute(task, api_spec).await
    }
}
