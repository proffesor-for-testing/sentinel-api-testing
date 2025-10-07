//! LLM (Large Language Model) integration for Rust agents
//!
//! This module provides a trait-based interface for integrating various LLM providers
//! into the Sentinel Rust agents to enhance test generation capabilities.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod openai;

/// Error types for LLM operations
#[derive(Error, Debug, Clone)]
pub enum LlmError {
    #[error("API request failed: {0}")]
    ApiError(String),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Invalid response format: {0}")]
    ParseError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitError(String),

    #[error("Model not available: {0}")]
    ModelNotAvailable(String),

    #[error("LLM is not enabled or configured")]
    NotEnabled,

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Configuration for LLM providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// API key for authentication
    pub api_key: String,

    /// Model name to use (e.g., "gpt-4", "gpt-3.5-turbo")
    pub model: String,

    /// Maximum tokens in response
    pub max_tokens: Option<u32>,

    /// Temperature for response randomness (0.0 to 2.0)
    pub temperature: Option<f32>,

    /// Custom API endpoint (optional)
    pub api_endpoint: Option<String>,
}

/// Response from LLM generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    /// Generated text content
    pub content: String,

    /// Model used for generation
    pub model: String,

    /// Number of tokens used
    pub tokens_used: Option<u32>,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Main trait for LLM providers
#[async_trait]
pub trait Llm: Send + Sync {
    /// Generate text based on a prompt
    ///
    /// # Arguments
    /// * `prompt` - The input prompt to send to the LLM
    ///
    /// # Returns
    /// * `Result<String, LlmError>` - Generated text or error
    async fn generate(&self, prompt: &str) -> Result<String, LlmError>;

    /// Generate with full response details
    ///
    /// # Arguments
    /// * `prompt` - The input prompt to send to the LLM
    ///
    /// # Returns
    /// * `Result<LlmResponse, LlmError>` - Full response with metadata or error
    async fn generate_with_details(&self, prompt: &str) -> Result<LlmResponse, LlmError>;

    /// Check if the LLM is enabled and properly configured
    ///
    /// # Returns
    /// * `bool` - True if LLM is ready to use, false otherwise
    fn is_enabled(&self) -> bool;

    /// Get the model name being used
    ///
    /// # Returns
    /// * `&str` - Model identifier
    fn model_name(&self) -> &str;

    /// Validate the configuration
    ///
    /// # Returns
    /// * `Result<(), LlmError>` - Ok if valid, error otherwise
    async fn validate_config(&self) -> Result<(), LlmError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_error_display() {
        let error = LlmError::ApiError("test error".to_string());
        assert_eq!(error.to_string(), "API request failed: test error");

        let not_enabled = LlmError::NotEnabled;
        assert_eq!(not_enabled.to_string(), "LLM is not enabled or configured");
    }

    #[test]
    fn test_llm_config_creation() {
        let config = LlmConfig {
            api_key: "test-key".to_string(),
            model: "gpt-4".to_string(),
            max_tokens: Some(1000),
            temperature: Some(0.7),
            api_endpoint: None,
        };

        assert_eq!(config.model, "gpt-4");
        assert_eq!(config.max_tokens, Some(1000));
    }

    #[test]
    fn test_llm_response_creation() {
        let response = LlmResponse {
            content: "Test response".to_string(),
            model: "gpt-4".to_string(),
            tokens_used: Some(50),
            metadata: None,
        };

        assert_eq!(response.content, "Test response");
        assert_eq!(response.tokens_used, Some(50));
    }
}
