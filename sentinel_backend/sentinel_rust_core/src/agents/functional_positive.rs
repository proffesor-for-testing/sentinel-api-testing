//! DEPRECATED: Functional-Positive-Agent
//!
//! This agent is deprecated. Please use `FunctionalAgent` with `strategies: ["positive"]` instead.
//!
//! Migration:
//! ```rust
//! // Old way (DEPRECATED):
//! let agent = FunctionalPositiveAgent::new();
//!
//! // New way:
//! use crate::agents::functional_agent::FunctionalAgent;
//! let agent = FunctionalAgent::new();
//! // Use with task parameters: {"strategies": ["positive"]}
//! ```

use async_trait::async_trait;
use serde_json::Value;

use crate::agents::{Agent, functional_agent::FunctionalAgent};
use crate::types::{AgentTask, AgentResult};

/// DEPRECATED: Agent responsible for generating positive functional test cases
///
/// Use `FunctionalAgent` with `strategies: ["positive"]` instead.
#[deprecated(
    since = "2.0.0",
    note = "Use FunctionalAgent with strategies=['positive'] instead"
)]
pub struct FunctionalPositiveAgent {
    inner: FunctionalAgent,
}

impl FunctionalPositiveAgent {
    pub fn new() -> Self {
        eprintln!("⚠️  DEPRECATION WARNING: FunctionalPositiveAgent is deprecated.");
        eprintln!("   Please use FunctionalAgent with strategies=['positive'] instead.");
        eprintln!("   See docs/AGENT_MIGRATION_GUIDE.md for migration instructions.");

        Self {
            inner: FunctionalAgent::new(),
        }
    }
}

#[async_trait]
impl Agent for FunctionalPositiveAgent {
    fn agent_type(&self) -> &str {
        "Functional-Positive-Agent"
    }

    async fn execute(&self, mut task: AgentTask, api_spec: Value) -> AgentResult {
        // Force positive strategy only
        task.parameters.insert(
            "strategies".to_string(),
            serde_json::json!(["positive"])
        );

        // Delegate to consolidated FunctionalAgent
        self.inner.execute(task, api_spec).await
    }
}
