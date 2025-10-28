//! Example: Using LLM with Rust agents
//!
//! This example demonstrates how to integrate LLM capabilities into Sentinel Rust agents.

use sentinel_rust_core::agents::{Agent, BaseAgent};
use sentinel_rust_core::llm::{LlmConfig, openai::OpenAiProvider};
use sentinel_rust_core::types::{AgentTask, AgentResult};
use serde_json::Value;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Create an OpenAI provider from environment variables
    println!("=== Example 1: Creating LLM Provider from Environment ===");
    let llm_provider = OpenAiProvider::from_env();

    if llm_provider.is_enabled() {
        println!("✓ LLM Provider enabled with model: {}", llm_provider.model_name());
    } else {
        println!("✗ LLM Provider not enabled (set OPENAI_API_KEY environment variable)");
    }

    // Example 2: Create a custom LLM configuration
    println!("\n=== Example 2: Custom LLM Configuration ===");
    let custom_config = LlmConfig {
        api_key: std::env::var("OPENAI_API_KEY").unwrap_or_else(|_| "not_set".to_string()),
        model: "gpt-4".to_string(),
        max_tokens: Some(2000),
        temperature: Some(0.7),
        api_endpoint: None,
    };

    let custom_provider = OpenAiProvider::new(custom_config);
    println!("Custom provider created with model: {}", custom_provider.model_name());

    // Example 3: Create a BaseAgent with LLM support
    println!("\n=== Example 3: BaseAgent with LLM ===");
    let base_agent = BaseAgent::new("Example-Agent".to_string())
        .with_llm(Box::new(OpenAiProvider::from_env()));

    if base_agent.has_llm() {
        println!("✓ Agent has LLM support enabled");

        // Example 4: Use LLM to enhance test generation
        println!("\n=== Example 4: Using LLM for Test Generation ===");
        let prompt = "Generate a creative test case description for testing user login endpoint with SQL injection vulnerabilities.";

        match base_agent.use_llm(prompt).await {
            Ok(response) => {
                println!("LLM Response:\n{}", response);
            }
            Err(e) => {
                println!("LLM Error: {}", e);
            }
        }
    } else {
        println!("✗ Agent does not have LLM support");
    }

    // Example 5: Agent orchestration with LLM-enhanced agents
    println!("\n=== Example 5: Creating LLM-Enhanced Agent ===");

    // You can create agents with LLM support like this:
    // let llm_enhanced_agent = FunctionalPositiveAgent::new()
    //     .with_llm(Box::new(OpenAiProvider::from_env()));

    println!("Agent can now use LLM to:");
    println!("  • Generate more creative test cases");
    println!("  • Understand complex API specifications");
    println!("  • Create realistic test data");
    println!("  • Suggest edge cases based on context");

    Ok(())
}

/// Example of integrating LLM into a custom agent
pub struct LlmEnhancedTestAgent {
    base: BaseAgent,
}

impl LlmEnhancedTestAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("LLM-Enhanced-Agent".to_string()),
        }
    }

    pub fn with_llm(mut self, llm: Box<dyn sentinel_rust_core::llm::Llm>) -> Self {
        self.base = self.base.with_llm(llm);
        self
    }

    /// Example: Use LLM to generate test case descriptions
    pub async fn generate_test_description(&self, endpoint_name: &str) -> Result<String, String> {
        if self.base.has_llm() {
            let prompt = format!(
                "Generate a comprehensive test case description for endpoint '{}'. \
                Include test purpose, expected behavior, and potential edge cases.",
                endpoint_name
            );

            self.base.use_llm(&prompt)
                .await
                .map_err(|e| e.to_string())
        } else {
            // Fallback to non-LLM approach
            Ok(format!("Standard test for endpoint: {}", endpoint_name))
        }
    }

    /// Example: Use LLM to suggest test data
    pub async fn suggest_test_data(&self, data_type: &str) -> Result<String, String> {
        if self.base.has_llm() {
            let prompt = format!(
                "Suggest realistic test data for type '{}'. \
                Provide 5 diverse examples that cover edge cases.",
                data_type
            );

            self.base.use_llm(&prompt)
                .await
                .map_err(|e| e.to_string())
        } else {
            Ok("default_test_value".to_string())
        }
    }
}

#[async_trait::async_trait]
impl Agent for LlmEnhancedTestAgent {
    fn agent_type(&self) -> &str {
        "LLM-Enhanced-Test-Agent"
    }

    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        // Example implementation that uses LLM when available
        let test_cases = vec![];
        let mut metadata = HashMap::new();

        metadata.insert(
            "llm_enabled".to_string(),
            Value::Bool(self.base.has_llm())
        );

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
