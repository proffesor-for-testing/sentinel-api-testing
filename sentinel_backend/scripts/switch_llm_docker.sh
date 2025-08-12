#!/bin/bash

# Sentinel LLM Provider Switcher for Docker
# This script updates the Docker environment configuration

set -e

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Docker env file
DOCKER_ENV="../config/docker.env"

# Function to update Docker env
update_docker_env() {
    local provider=$1
    local model=$2
    
    echo -e "${YELLOW}Updating Docker configuration...${NC}"
    
    # Update provider and model in docker.env
    sed -i.bak "s/^SENTINEL_APP_LLM_PROVIDER=.*/SENTINEL_APP_LLM_PROVIDER=$provider/" "$DOCKER_ENV"
    sed -i.bak "s/^SENTINEL_APP_LLM_MODEL=.*/SENTINEL_APP_LLM_MODEL=$model/" "$DOCKER_ENV"
    
    echo -e "${GREEN}✓ Docker configuration updated${NC}"
    echo -e "${BLUE}  Provider: $provider${NC}"
    echo -e "${BLUE}  Model: $model${NC}"
}

# Quick presets
case "${1:-}" in
    claude)
        update_docker_env "anthropic" "claude-sonnet-4"
        echo -e "${YELLOW}Remember to set SENTINEL_APP_ANTHROPIC_API_KEY in docker.env${NC}"
        ;;
    opus)
        update_docker_env "anthropic" "claude-opus-4.1"
        echo -e "${YELLOW}Remember to set SENTINEL_APP_ANTHROPIC_API_KEY in docker.env${NC}"
        ;;
    gpt4)
        update_docker_env "openai" "gpt-4-turbo"
        echo -e "${YELLOW}Remember to set SENTINEL_APP_OPENAI_API_KEY in docker.env${NC}"
        ;;
    gpt3)
        update_docker_env "openai" "gpt-3.5-turbo"
        echo -e "${YELLOW}Remember to set SENTINEL_APP_OPENAI_API_KEY in docker.env${NC}"
        ;;
    gemini)
        update_docker_env "google" "gemini-2.5-flash"
        echo -e "${YELLOW}Remember to set SENTINEL_APP_GOOGLE_API_KEY in docker.env${NC}"
        ;;
    gemini-pro)
        update_docker_env "google" "gemini-2.5-pro"
        echo -e "${YELLOW}Remember to set SENTINEL_APP_GOOGLE_API_KEY in docker.env${NC}"
        ;;
    mistral)
        update_docker_env "mistral" "mistral-large"
        echo -e "${YELLOW}Remember to set SENTINEL_APP_MISTRAL_API_KEY in docker.env${NC}"
        ;;
    local)
        update_docker_env "ollama" "mistral:7b"
        echo -e "${YELLOW}Make sure Ollama is running and accessible from Docker${NC}"
        ;;
    none)
        update_docker_env "none" ""
        echo -e "${GREEN}LLM disabled - using deterministic algorithms only${NC}"
        ;;
    *)
        echo "Sentinel LLM Quick Switcher for Docker"
        echo ""
        echo "Usage: $0 <preset>"
        echo ""
        echo "Presets:"
        echo "  claude      - Anthropic Claude Sonnet 4 (default, balanced)"
        echo "  opus        - Anthropic Claude Opus 4.1 (most powerful)"
        echo "  gpt4        - OpenAI GPT-4 Turbo"
        echo "  gpt3        - OpenAI GPT-3.5 Turbo (fast & cheap)"
        echo "  gemini      - Google Gemini 2.5 Flash (fast)"
        echo "  gemini-pro  - Google Gemini 2.5 Pro (2M context)"
        echo "  mistral     - Mistral Large"
        echo "  local       - Ollama with Mistral 7B (no API costs)"
        echo "  none        - Disable LLM (deterministic only)"
        echo ""
        echo "After switching, restart Docker services:"
        echo "  cd .. && docker-compose restart"
        exit 0
        ;;
esac

echo ""
echo "To apply changes, restart Docker services:"
echo "  cd .. && docker-compose restart"