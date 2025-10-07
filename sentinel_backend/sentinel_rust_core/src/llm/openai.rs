//! OpenAI LLM provider implementation
//!
//! This module provides integration with OpenAI's API for GPT-4 and GPT-3.5-turbo models.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::env;

use super::{Llm, LlmConfig, LlmError, LlmResponse};

/// OpenAI API client
pub struct OpenAiProvider {
    client: Client,
    config: LlmConfig,
    enabled: bool,
}

/// OpenAI API request structure
#[derive(Debug, Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
}

/// Message structure for chat completions
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Message {
    role: String,
    content: String,
}

/// OpenAI API response structure
#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    id: String,
    object: String,
    model: String,
    choices: Vec<Choice>,
    usage: Option<Usage>,
}

/// Choice in OpenAI response
#[derive(Debug, Deserialize)]
struct Choice {
    index: u32,
    message: Message,
    finish_reason: Option<String>,
}

/// Token usage information
#[derive(Debug, Deserialize)]
struct Usage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

/// Error response from OpenAI API
#[derive(Debug, Deserialize)]
struct OpenAiError {
    error: ErrorDetail,
}

#[derive(Debug, Deserialize)]
struct ErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    code: Option<String>,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider with configuration
    ///
    /// # Arguments
    /// * `config` - LLM configuration with API key and model settings
    ///
    /// # Returns
    /// * `Self` - Configured OpenAI provider instance
    pub fn new(config: LlmConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| Client::new());

        let enabled = !config.api_key.is_empty() && config.api_key != "not_set";

        Self {
            client,
            config,
            enabled,
        }
    }

    /// Create a new OpenAI provider from environment variables
    ///
    /// # Returns
    /// * `Self` - Provider instance configured from environment
    pub fn from_env() -> Self {
        let api_key = env::var("OPENAI_API_KEY").unwrap_or_else(|_| "not_set".to_string());
        let model = env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-3.5-turbo".to_string());
        let max_tokens = env::var("OPENAI_MAX_TOKENS")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        let temperature = env::var("OPENAI_TEMPERATURE")
            .ok()
            .and_then(|s| s.parse::<f32>().ok());

        let config = LlmConfig {
            api_key,
            model,
            max_tokens,
            temperature,
            api_endpoint: None,
        };

        Self::new(config)
    }

    /// Create a new OpenAI provider with specific model
    ///
    /// # Arguments
    /// * `api_key` - OpenAI API key
    /// * `model` - Model name (e.g., "gpt-4", "gpt-3.5-turbo")
    ///
    /// # Returns
    /// * `Self` - Configured provider instance
    pub fn with_model(api_key: String, model: String) -> Self {
        let config = LlmConfig {
            api_key,
            model,
            max_tokens: Some(2000),
            temperature: Some(0.7),
            api_endpoint: None,
        };

        Self::new(config)
    }

    /// Get the API endpoint URL
    fn api_endpoint(&self) -> String {
        self.config
            .api_endpoint
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1/chat/completions".to_string())
    }

    /// Build request for OpenAI API
    fn build_request(&self, prompt: &str) -> OpenAiRequest {
        OpenAiRequest {
            model: self.config.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
        }
    }

    /// Parse error response from API
    fn parse_error_response(&self, status: StatusCode, body: &str) -> LlmError {
        if let Ok(error_response) = serde_json::from_str::<OpenAiError>(body) {
            match status {
                StatusCode::UNAUTHORIZED => {
                    LlmError::AuthError(format!("Invalid API key: {}", error_response.error.message))
                }
                StatusCode::TOO_MANY_REQUESTS => {
                    LlmError::RateLimitError(error_response.error.message)
                }
                StatusCode::BAD_REQUEST if error_response.error.error_type == "invalid_request_error" => {
                    LlmError::ModelNotAvailable(error_response.error.message)
                }
                _ => LlmError::ApiError(format!(
                    "{}: {}",
                    error_response.error.error_type, error_response.error.message
                )),
            }
        } else {
            LlmError::ApiError(format!("HTTP {}: {}", status, body))
        }
    }
}

#[async_trait]
impl Llm for OpenAiProvider {
    async fn generate(&self, prompt: &str) -> Result<String, LlmError> {
        if !self.enabled {
            return Err(LlmError::NotEnabled);
        }

        let request_body = self.build_request(prompt);

        let response = self
            .client
            .post(&self.api_endpoint())
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| LlmError::NetworkError(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| LlmError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(self.parse_error_response(status, &body));
        }

        let api_response: OpenAiResponse = serde_json::from_str(&body)
            .map_err(|e| LlmError::ParseError(format!("Failed to parse response: {}", e)))?;

        api_response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| LlmError::ParseError("No choices in response".to_string()))
    }

    async fn generate_with_details(&self, prompt: &str) -> Result<LlmResponse, LlmError> {
        if !self.enabled {
            return Err(LlmError::NotEnabled);
        }

        let request_body = self.build_request(prompt);

        let response = self
            .client
            .post(&self.api_endpoint())
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| LlmError::NetworkError(e.to_string()))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| LlmError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(self.parse_error_response(status, &body));
        }

        let api_response: OpenAiResponse = serde_json::from_str(&body)
            .map_err(|e| LlmError::ParseError(format!("Failed to parse response: {}", e)))?;

        let choice = api_response
            .choices
            .first()
            .ok_or_else(|| LlmError::ParseError("No choices in response".to_string()))?;

        let tokens_used = api_response.usage.map(|u| u.total_tokens);

        let mut metadata = serde_json::Map::new();
        metadata.insert("finish_reason".to_string(), serde_json::json!(choice.finish_reason));
        metadata.insert("response_id".to_string(), serde_json::json!(api_response.id));

        Ok(LlmResponse {
            content: choice.message.content.clone(),
            model: api_response.model,
            tokens_used,
            metadata: Some(serde_json::Value::Object(metadata)),
        })
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn model_name(&self) -> &str {
        &self.config.model
    }

    async fn validate_config(&self) -> Result<(), LlmError> {
        if !self.enabled {
            return Err(LlmError::NotEnabled);
        }

        if self.config.api_key.is_empty() || self.config.api_key == "not_set" {
            return Err(LlmError::AuthError("API key not configured".to_string()));
        }

        // Validate by sending a minimal request
        let test_prompt = "Test connection";
        match self.generate(test_prompt).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_provider_creation() {
        let config = LlmConfig {
            api_key: "sk-test-key".to_string(),
            model: "gpt-4".to_string(),
            max_tokens: Some(1000),
            temperature: Some(0.7),
            api_endpoint: None,
        };

        let provider = OpenAiProvider::new(config);
        assert!(provider.is_enabled());
        assert_eq!(provider.model_name(), "gpt-4");
    }

    #[test]
    fn test_openai_provider_not_enabled() {
        let config = LlmConfig {
            api_key: "not_set".to_string(),
            model: "gpt-4".to_string(),
            max_tokens: None,
            temperature: None,
            api_endpoint: None,
        };

        let provider = OpenAiProvider::new(config);
        assert!(!provider.is_enabled());
    }

    #[test]
    fn test_build_request() {
        let config = LlmConfig {
            api_key: "sk-test".to_string(),
            model: "gpt-3.5-turbo".to_string(),
            max_tokens: Some(500),
            temperature: Some(0.5),
            api_endpoint: None,
        };

        let provider = OpenAiProvider::new(config);
        let request = provider.build_request("Test prompt");

        assert_eq!(request.model, "gpt-3.5-turbo");
        assert_eq!(request.max_tokens, Some(500));
        assert_eq!(request.temperature, Some(0.5));
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].content, "Test prompt");
    }

    #[test]
    fn test_from_env_not_set() {
        // When env vars are not set, should create disabled provider
        let provider = OpenAiProvider::from_env();
        // Provider might not be enabled if OPENAI_API_KEY is not set
        assert_eq!(provider.model_name(), "gpt-3.5-turbo");
    }
}
