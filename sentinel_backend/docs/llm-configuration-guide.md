# LLM Configuration Guide

This guide provides practical examples for configuring and using different LLM providers with the Sentinel platform.

## Table of Contents
- [Quick Start](#quick-start)
- [Provider-Specific Setup](#provider-specific-setup)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)

## Quick Start

### 1. Default Setup (Anthropic Claude)

The platform uses Claude Sonnet 4 by default. This is the recommended configuration for most users.

```bash
# Set your API key
export SENTINEL_APP_ANTHROPIC_API_KEY="sk-ant-api03-..."

# Or use the configuration script
cd sentinel_backend/scripts
./switch_llm.sh claude

# Start the platform
cd .. && docker-compose up
```

### 2. Interactive Configuration

For a guided setup experience:

```bash
cd sentinel_backend/scripts
./switch_llm.sh

# Follow the prompts to:
# 1. Select a provider
# 2. Choose a model
# 3. Configure settings
# 4. Save configuration
```

## Provider-Specific Setup

### Anthropic Claude

#### Option 1: Claude Sonnet 4 (Balanced)
```bash
./switch_llm.sh claude
# Edit .env and add: SENTINEL_APP_ANTHROPIC_API_KEY=sk-ant-...
```

#### Option 2: Claude Opus 4.1 (Most Powerful)
```bash
# Interactive mode - select Anthropic, then Opus 4.1
./switch_llm.sh
```

### OpenAI

#### GPT-4 Turbo (Latest)
```bash
./switch_llm.sh openai
# Edit .env and add: SENTINEL_APP_OPENAI_API_KEY=sk-...
```

#### GPT-3.5 Turbo (Budget)
```bash
# Manual configuration
export SENTINEL_APP_LLM_PROVIDER=openai
export SENTINEL_APP_LLM_MODEL=gpt-3.5-turbo
export SENTINEL_APP_OPENAI_API_KEY=sk-...
```

### Google Gemini

#### Gemini 2.5 Flash (Fast)
```bash
./switch_llm.sh gemini
# Edit .env and add: SENTINEL_APP_GOOGLE_API_KEY=...
```

#### Gemini 2.5 Pro (2M Context)
```bash
# For Docker
./switch_llm_docker.sh gemini-pro
```

### Local Models (Ollama)

#### Setup Ollama
```bash
# Install Ollama (if not installed)
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# Pull a model
ollama pull mistral:7b
```

#### Configure Sentinel
```bash
./switch_llm.sh local
# No API key needed!
```

#### Available Local Models
- `mistral:7b` - Fast, general purpose
- `llama3.3:70b` - Powerful, rivals GPT-4
- `deepseek-r1:70b` - Excellent reasoning
- `qwen2.5-coder:32b` - Code-focused

### Disable LLM (Deterministic Only)

For testing without LLM or CI/CD environments:

```bash
./switch_llm.sh none
```

## Common Use Cases

### Development Environment

**Goal**: Fast iteration with low costs

```bash
# Option 1: Local Ollama (free)
./switch_llm.sh local
ollama pull mistral:7b

# Option 2: GPT-3.5 Turbo (cheap)
./switch_llm.sh
# Select OpenAI -> GPT-3.5 Turbo
```

### Production Environment

**Goal**: Best quality with fallback

```bash
# Primary: Claude Sonnet 4
./switch_llm.sh claude

# Configure fallback in .env
SENTINEL_APP_LLM_FALLBACK_ENABLED=true
SENTINEL_APP_LLM_FALLBACK_PROVIDERS=["anthropic", "openai", "google"]
```

### CI/CD Pipeline

**Goal**: Deterministic, reproducible tests

```bash
# Disable LLM for consistent results
./switch_llm.sh none
```

### High-Context Requirements

**Goal**: Process large API specifications

```bash
# Use Gemini 2.5 Pro (2M tokens)
./switch_llm_docker.sh gemini-pro
```

### Security Testing

**Goal**: Generate injection payloads without censorship

```bash
# Use local model to avoid API filters
./switch_llm.sh local
ollama pull deepseek-r1:70b
```

## Docker Configuration

### Quick Switch for Docker

```bash
cd sentinel_backend/scripts

# Switch to different providers
./switch_llm_docker.sh gpt4      # GPT-4 Turbo
./switch_llm_docker.sh gemini    # Gemini 2.5 Flash
./switch_llm_docker.sh claude    # Claude Sonnet 4
./switch_llm_docker.sh local     # Local Ollama

# Restart services
cd .. && docker-compose restart
```

### Environment Variables in Docker

Edit `sentinel_backend/config/docker.env`:

```env
# LLM Configuration
SENTINEL_APP_LLM_PROVIDER=anthropic
SENTINEL_APP_LLM_MODEL=claude-sonnet-4
SENTINEL_APP_ANTHROPIC_API_KEY=sk-ant-...

# Optional: Configure fallback
SENTINEL_APP_LLM_FALLBACK_ENABLED=true
```

## Advanced Configuration

### Cost Management

```bash
# Set budget limits
export SENTINEL_APP_LLM_COST_ALERT_THRESHOLD=10.0
export SENTINEL_APP_LLM_COST_TRACKING_ENABLED=true
```

### Response Caching

```bash
# Enable caching to reduce API calls
export SENTINEL_APP_LLM_CACHE_ENABLED=true
export SENTINEL_APP_LLM_CACHE_TTL=3600  # 1 hour
```

### Custom Temperature

```bash
# Adjust creativity (0.0 = deterministic, 1.0 = creative)
export SENTINEL_APP_LLM_TEMPERATURE=0.3  # More focused
export SENTINEL_APP_LLM_TEMPERATURE=0.9  # More creative
```

## Validation

### Test Your Configuration

```bash
cd sentinel_backend
python scripts/validate_llm_config.py
```

This will:
- ✓ Check environment variables
- ✓ Validate API keys
- ✓ Test provider connectivity
- ✓ Verify fallback chain
- ✓ Test agent integration

### Sample Output

```
========================================
    LLM Configuration Validator
========================================

Configuration Check:
  ✓ Primary Provider: anthropic
  ✓ Model: claude-sonnet-4
  ✓ API Key: Configured

Primary Provider Test:
  ✓ Anthropic (claude-sonnet-4): Success

Fallback Providers:
  ✓ OpenAI (gpt-3.5-turbo): Success
  ✓ Ollama (mistral:7b): Success

Agent Integration:
  ✓ Agent LLM Integration: Enabled
```

## Troubleshooting

### Provider Not Working

```bash
# Check configuration
python scripts/validate_llm_config.py

# View current settings
grep "SENTINEL_APP_LLM" .env
```

### API Key Issues

```bash
# Verify API key is set
echo $SENTINEL_APP_ANTHROPIC_API_KEY

# Test API key directly
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $SENTINEL_APP_ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01"
```

### Docker Can't Connect to Ollama

```bash
# Use host network mode
docker run --network host ...

# Or configure Ollama to listen on all interfaces
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

### Restore Previous Configuration

```bash
# Scripts create backups
mv .env.backup .env
```

## Examples

### Example 1: Team Development Setup

```bash
# Each developer uses their preferred provider
# Developer 1: Uses Claude
echo "SENTINEL_APP_LLM_PROVIDER=anthropic" > .env.local

# Developer 2: Uses local Ollama
echo "SENTINEL_APP_LLM_PROVIDER=ollama" > .env.local

# .env.local is gitignored
```

### Example 2: A/B Testing Providers

```bash
# Test Claude
./switch_llm.sh claude
python run_tests.py > results_claude.txt

# Test GPT-4
./switch_llm.sh openai
python run_tests.py > results_gpt4.txt

# Compare results
diff results_claude.txt results_gpt4.txt
```

### Example 3: Cost-Optimized Configuration

```bash
# Use cheap model with caching
export SENTINEL_APP_LLM_PROVIDER=openai
export SENTINEL_APP_LLM_MODEL=gpt-3.5-turbo
export SENTINEL_APP_LLM_CACHE_ENABLED=true
export SENTINEL_APP_LLM_CACHE_TTL=7200  # 2 hours
export SENTINEL_APP_LLM_TEMPERATURE=0.3  # Less variation
```

## Best Practices

1. **Always validate after configuration changes**
   ```bash
   python scripts/validate_llm_config.py
   ```

2. **Use .env.local for sensitive data**
   ```bash
   cp .env .env.local
   # Edit .env.local with API keys
   ```

3. **Configure fallback for production**
   ```bash
   SENTINEL_APP_LLM_FALLBACK_ENABLED=true
   ```

4. **Monitor costs in production**
   ```bash
   SENTINEL_APP_LLM_COST_TRACKING_ENABLED=true
   SENTINEL_APP_LLM_COST_ALERT_THRESHOLD=100.0
   ```

5. **Use local models for sensitive testing**
   ```bash
   # Security testing without API filters
   ./switch_llm.sh local
   ```

## Summary

The Sentinel platform provides flexible LLM configuration through:
- Interactive configuration scripts
- Quick preset commands
- Manual environment variables
- Docker-specific utilities

Choose the method that best fits your workflow and requirements.