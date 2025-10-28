# LLM Integration for Rust Agents

## Overview

The Sentinel Rust Core now supports LLM (Large Language Model) integration to enhance test generation capabilities. This allows agents to leverage AI for more intelligent and creative test case generation.

## Features

- **Trait-based design**: Easy to add new LLM providers
- **OpenAI provider**: Built-in support for GPT-4 and GPT-3.5-turbo
- **Async support**: Non-blocking LLM API calls
- **Error handling**: Comprehensive error types for LLM operations
- **Optional integration**: Agents work with or without LLM

## Architecture

### LLM Trait

```rust
#[async_trait]
pub trait Llm: Send + Sync {
    async fn generate(&self, prompt: &str) -> Result<String, LlmError>;
    async fn generate_with_details(&self, prompt: &str) -> Result<LlmResponse, LlmError>;
    fn is_enabled(&self) -> bool;
    fn model_name(&self) -> &str;
    async fn validate_config(&self) -> Result<(), LlmError>;
}
```

### Error Types

```rust
pub enum LlmError {
    ApiError(String),
    AuthError(String),
    ParseError(String),
    RateLimitError(String),
    ModelNotAvailable(String),
    NotEnabled,
    NetworkError(String),
}
```

## Usage

### 1. Environment Configuration

Set environment variables:

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4"  # Optional, defaults to gpt-3.5-turbo
export OPENAI_MAX_TOKENS="2000"  # Optional
export OPENAI_TEMPERATURE="0.7"  # Optional
```

### 2. Creating an LLM Provider

```rust
use sentinel_rust_core::llm::openai::OpenAiProvider;

// From environment variables
let llm = OpenAiProvider::from_env();

// With custom configuration
let config = LlmConfig {
    api_key: "sk-...".to_string(),
    model: "gpt-4".to_string(),
    max_tokens: Some(2000),
    temperature: Some(0.7),
    api_endpoint: None,
};
let llm = OpenAiProvider::new(config);
```

### 3. Adding LLM to BaseAgent

```rust
use sentinel_rust_core::agents::BaseAgent;
use sentinel_rust_core::llm::openai::OpenAiProvider;

let agent = BaseAgent::new("My-Agent".to_string())
    .with_llm(Box::new(OpenAiProvider::from_env()));

// Check if LLM is available
if agent.has_llm() {
    // Use LLM
    let response = agent.use_llm("Generate test data").await?;
}
```

### 4. Integrating into Existing Agents

Update agent constructors to accept optional LLM:

```rust
impl FunctionalPositiveAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Functional-Positive-Agent".to_string()),
        }
    }

    pub fn with_llm(mut self, llm: Box<dyn Llm>) -> Self {
        self.base = self.base.with_llm(llm);
        self
    }

    async fn generate_creative_test(&self, endpoint: &str) -> Result<TestCase, AgentError> {
        if self.base.has_llm() {
            let prompt = format!("Generate test case for {}", endpoint);
            let description = self.base.use_llm(&prompt).await?;
            // Use LLM-generated description
        } else {
            // Fallback to standard generation
        }
    }
}
```

## Supported Agents

The following agents now support LLM integration:

- **FunctionalPositiveAgent**: Enhanced test case descriptions and realistic data
- **FunctionalNegativeAgent**: Creative boundary and edge case generation
- **SecurityAuthAgent**: Advanced attack vector suggestions
- **SecurityInjectionAgent**: Context-aware injection payload generation

## API Reference

### OpenAiProvider

#### Methods

- `new(config: LlmConfig) -> Self`: Create provider with configuration
- `from_env() -> Self`: Create provider from environment variables
- `with_model(api_key: String, model: String) -> Self`: Create with specific model

### BaseAgent LLM Methods

- `with_llm(llm: Box<dyn Llm>) -> Self`: Add LLM to agent
- `has_llm() -> bool`: Check if LLM is configured
- `use_llm(prompt: &str) -> Result<String, AgentError>`: Generate text with LLM

## Error Handling

```rust
match agent.use_llm("prompt").await {
    Ok(response) => {
        // Use response
    }
    Err(AgentError::LlmError(e)) => {
        // Handle LLM-specific error
        eprintln!("LLM error: {}", e);
    }
    Err(e) => {
        // Handle other errors
        eprintln!("Error: {}", e);
    }
}
```

## Best Practices

1. **Graceful Degradation**: Always provide fallback behavior when LLM is not available
2. **Prompt Engineering**: Design clear, specific prompts for better results
3. **Rate Limiting**: Be aware of API rate limits, especially with gpt-4
4. **Error Handling**: Handle LLM errors gracefully without breaking agent execution
5. **Cost Management**: Monitor token usage, especially in production

## Performance Considerations

- LLM calls are async and non-blocking
- Consider caching LLM responses for identical prompts
- Use temperature=0 for deterministic outputs
- Batch similar requests when possible

## Future Enhancements

- [ ] Support for more LLM providers (Anthropic Claude, local models)
- [ ] Response caching layer
- [ ] Token usage tracking and reporting
- [ ] Prompt template system
- [ ] Fine-tuned models for specific test generation tasks

## Troubleshooting

### LLM Not Enabled

**Symptom**: `is_enabled()` returns false

**Solution**: Ensure OPENAI_API_KEY environment variable is set and not "not_set"

### Authentication Errors

**Symptom**: `AuthError("Invalid API key")`

**Solution**: Verify your OpenAI API key is valid and has not expired

### Rate Limit Errors

**Symptom**: `RateLimitError`

**Solution**: Implement retry logic with exponential backoff or reduce request frequency

### Network Errors

**Symptom**: `NetworkError`

**Solution**: Check internet connectivity and OpenAI API status

## Examples

See `examples/llm_agent_usage.rs` for complete examples of:
- Creating LLM providers
- Integrating LLM into agents
- Error handling
- Custom agent implementation with LLM support
