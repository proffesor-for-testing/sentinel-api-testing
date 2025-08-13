# Sentinel LLM Configuration Scripts

This directory contains utility scripts for managing LLM provider configuration in the Sentinel platform.

## Scripts

### 1. `switch_llm.sh` - Interactive LLM Configuration

A comprehensive script for configuring LLM providers with interactive prompts.

#### Interactive Mode
```bash
./switch_llm.sh
```
This will guide you through:
- Selecting a provider (Anthropic, OpenAI, Google, Mistral, Ollama, vLLM, or None)
- Choosing a specific model
- Configuring temperature, max tokens, and other settings
- Saving configuration to `.env` file

#### Quick Setup Mode
```bash
# Use default models for each provider
./switch_llm.sh claude    # Anthropic Claude Sonnet 4
./switch_llm.sh openai    # OpenAI GPT-4 Turbo
./switch_llm.sh gemini    # Google Gemini 2.5 Flash
./switch_llm.sh local     # Ollama with Mistral 7B
./switch_llm.sh none      # Disable LLM
```

#### Custom Environment File
```bash
ENV_FILE=custom.env ./switch_llm.sh
```

### 2. `switch_llm_docker.sh` - Quick Docker Configuration

A simplified script for quickly switching LLM providers in Docker environments.

```bash
# Quick presets for Docker
./switch_llm_docker.sh claude      # Claude Sonnet 4
./switch_llm_docker.sh opus        # Claude Opus 4.1
./switch_llm_docker.sh gpt4        # GPT-4 Turbo
./switch_llm_docker.sh gpt3        # GPT-3.5 Turbo
./switch_llm_docker.sh gemini      # Gemini 2.5 Flash
./switch_llm_docker.sh gemini-pro  # Gemini 2.5 Pro
./switch_llm_docker.sh mistral     # Mistral Large
./switch_llm_docker.sh local       # Local Ollama
./switch_llm_docker.sh none        # Disable LLM
```

After switching, restart Docker services:
```bash
cd .. && docker-compose restart
```

### 3. `validate_llm_config.py` - Configuration Validator

Python script to validate your LLM configuration and test provider connectivity.

```bash
python validate_llm_config.py
```

This script will:
- Check environment configuration
- Validate API keys
- Test primary and fallback providers
- Verify agent LLM integration
- Provide recommendations for any issues

## Model Recommendations

### For Production Use
- **Default**: Anthropic Claude Sonnet 4 - Best balance of performance and cost
- **High Performance**: Anthropic Claude Opus 4.1 - Most capable but more expensive
- **Budget**: OpenAI GPT-3.5 Turbo or Google Gemini 2.5 Flash

### For Development/Testing
- **Local/Offline**: Ollama with Mistral 7B or Llama 3.3
- **No LLM**: Set provider to "none" for deterministic-only testing

### For Specific Use Cases
- **Large Context**: Google Gemini 2.5 Pro (2M tokens)
- **Code Generation**: Mistral Codestral or Qwen 2.5 Coder
- **Reasoning Tasks**: DeepSeek-R1 (via Ollama)

## API Key Configuration

After running the switch script, remember to set your API keys:

### Option 1: Edit .env file
```bash
# Edit the generated .env file
nano .env
# Replace 'your-api-key-here' with actual key
```

### Option 2: Export environment variables
```bash
export SENTINEL_APP_ANTHROPIC_API_KEY="sk-ant-..."
export SENTINEL_APP_OPENAI_API_KEY="sk-..."
export SENTINEL_APP_GOOGLE_API_KEY="..."
export SENTINEL_APP_MISTRAL_API_KEY="..."
```

### Option 3: Use .env.local (gitignored)
```bash
cp .env .env.local
# Edit .env.local with your keys
```

## Local Model Setup (Ollama)

If using Ollama for local models:

1. Install Ollama: https://ollama.ai
2. Start Ollama service: `ollama serve`
3. Pull desired model: `ollama pull mistral:7b`
4. Configure with script: `./switch_llm.sh local`

## Troubleshooting

### Provider not working?
```bash
# Run validation script
python validate_llm_config.py
```

### Docker can't connect to Ollama?
Use host network mode or configure Ollama to listen on all interfaces:
```bash
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

### Need to revert changes?
The script creates backups:
```bash
# Restore from backup
mv .env.backup .env
```

## Examples

### Development Setup (Free/Local)
```bash
# Use local Ollama with no API costs
./switch_llm.sh local
ollama pull mistral:7b
```

### Production Setup (Recommended)
```bash
# Use Claude with fallback to OpenAI
./switch_llm.sh claude
# Edit .env to add API keys and configure fallback
```

### CI/CD Setup (Minimal)
```bash
# Disable LLM for deterministic testing
./switch_llm.sh none
```

## Environment Variables

The scripts configure these environment variables:

- `SENTINEL_APP_LLM_PROVIDER` - Provider name (anthropic, openai, google, etc.)
- `SENTINEL_APP_LLM_MODEL` - Specific model to use
- `SENTINEL_APP_LLM_TEMPERATURE` - Generation temperature (0.0-1.0)
- `SENTINEL_APP_LLM_MAX_TOKENS` - Maximum tokens to generate
- `SENTINEL_APP_LLM_FALLBACK_ENABLED` - Enable automatic fallback
- `SENTINEL_APP_LLM_CACHE_ENABLED` - Enable response caching
- `SENTINEL_APP_*_API_KEY` - Provider-specific API keys
- `SENTINEL_APP_OLLAMA_BASE_URL` - Ollama server URL
- `SENTINEL_APP_VLLM_BASE_URL` - vLLM server URL

## Support

For more information about LLM configuration, see:
- [CLAUDE.md](../../CLAUDE.md#llm-integration)
- [LLM Provider Implementation Plan](../../LLM_PROVIDER_IMPLEMENTATION_PLAN.md)
- [Configuration Example](../config/llm_example.env)