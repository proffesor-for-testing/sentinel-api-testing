//! DEPRECATED: Edge-Cases-Agent
//!
//! This agent is deprecated. Please use `FunctionalAgent` with `strategies: ["edge_case"]` instead.
//!
//! Migration:
//! ```rust
//! // Old way (DEPRECATED):
//! let agent = EdgeCasesAgent::new();
//!
//! // New way:
//! use crate::agents::functional_agent::FunctionalAgent;
//! let agent = FunctionalAgent::new();
//! // Use with task parameters: {"strategies": ["edge_case"]}
//! ```

use async_trait::async_trait;
use serde_json::Value;

use crate::agents::{Agent, functional_agent::FunctionalAgent};
use crate::types::{AgentTask, AgentResult};

/// DEPRECATED: Agent responsible for generating edge case test cases
///
/// Use `FunctionalAgent` with `strategies: ["edge_case"]` instead.
#[deprecated(
    since = "2.0.0",
    note = "Use FunctionalAgent with strategies=['edge_case'] instead"
)]
pub struct EdgeCasesAgent {
    inner: FunctionalAgent,
}

impl EdgeCasesAgent {
    pub fn new() -> Self {
        eprintln!("⚠️  DEPRECATION WARNING: EdgeCasesAgent is deprecated.");
        eprintln!("   Please use FunctionalAgent with strategies=['edge_case'] instead.");
        eprintln!("   See docs/AGENT_MIGRATION_GUIDE.md for migration instructions.");

        Self {
            inner: FunctionalAgent::new(),
        }
    }
}

#[async_trait]
impl Agent for EdgeCasesAgent {
    fn agent_type(&self) -> &str {
        "Edge-Cases-Agent"
    }

    async fn execute(&self, mut task: AgentTask, api_spec: Value) -> AgentResult {
        // Force edge_case strategy only
        task.parameters.insert(
            "strategies".to_string(),
            serde_json::json!(["edge_case"])
        );

        // Delegate to consolidated FunctionalAgent
        self.inner.execute(task, api_spec).await
    }
}
