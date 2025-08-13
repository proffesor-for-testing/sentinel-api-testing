#!/bin/bash

# Sentinel LLM Provider Switcher
# This script helps you easily switch between different LLM providers and models

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration file
ENV_FILE="${ENV_FILE:-.env}"

# Function to print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

# Function to display header
show_header() {
    clear
    print_color "$BLUE" "========================================="
    print_color "$BLUE" "   Sentinel LLM Provider Configuration"
    print_color "$BLUE" "========================================="
    echo
}

# Function to show current configuration
show_current_config() {
    print_color "$YELLOW" "Current Configuration:"
    if [ -f "$ENV_FILE" ]; then
        local provider=$(grep "^SENTINEL_APP_LLM_PROVIDER=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "not set")
        local model=$(grep "^SENTINEL_APP_LLM_MODEL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "not set")
        print_color "$GREEN" "  Provider: $provider"
        print_color "$GREEN" "  Model: $model"
    else
        print_color "$RED" "  No configuration file found"
    fi
    echo
}

# Function to select provider
select_provider() {
    print_color "$YELLOW" "Select LLM Provider:"
    echo "  1) Anthropic Claude (Recommended)"
    echo "  2) OpenAI"
    echo "  3) Google Gemini"
    echo "  4) Mistral"
    echo "  5) Ollama (Local)"
    echo "  6) vLLM (Local)"
    echo "  7) None (Disable LLM)"
    echo
    read -p "Enter choice [1-7]: " provider_choice

    case $provider_choice in
        1) PROVIDER="anthropic";;
        2) PROVIDER="openai";;
        3) PROVIDER="google";;
        4) PROVIDER="mistral";;
        5) PROVIDER="ollama";;
        6) PROVIDER="vllm";;
        7) PROVIDER="none";;
        *) print_color "$RED" "Invalid choice"; exit 1;;
    esac
}

# Function to select model based on provider
select_model() {
    case $PROVIDER in
        anthropic)
            print_color "$YELLOW" "Select Anthropic Model:"
            echo "  1) Claude Sonnet 4 (Balanced - Default)"
            echo "  2) Claude Opus 4.1 (Most Powerful)"
            echo "  3) Claude Opus 4"
            echo "  4) Claude 3.5 Sonnet (Previous Gen)"
            echo "  5) Claude 3.5 Haiku (Fast & Cheap)"
            read -p "Enter choice [1-5]: " model_choice
            case $model_choice in
                1) MODEL="claude-sonnet-4";;
                2) MODEL="claude-opus-4.1";;
                3) MODEL="claude-opus-4";;
                4) MODEL="claude-3.5-sonnet";;
                5) MODEL="claude-3.5-haiku";;
                *) MODEL="claude-sonnet-4";;
            esac
            API_KEY_VAR="SENTINEL_APP_ANTHROPIC_API_KEY"
            ;;
        openai)
            print_color "$YELLOW" "Select OpenAI Model:"
            echo "  1) GPT-4 Turbo (Latest)"
            echo "  2) GPT-4"
            echo "  3) GPT-3.5 Turbo (Fast & Cheap)"
            read -p "Enter choice [1-3]: " model_choice
            case $model_choice in
                1) MODEL="gpt-4-turbo";;
                2) MODEL="gpt-4";;
                3) MODEL="gpt-3.5-turbo";;
                *) MODEL="gpt-4-turbo";;
            esac
            API_KEY_VAR="SENTINEL_APP_OPENAI_API_KEY"
            ;;
        google)
            print_color "$YELLOW" "Select Google Gemini Model:"
            echo "  1) Gemini 2.5 Pro (Latest, 2M context)"
            echo "  2) Gemini 2.5 Flash (Fast, 1M context)"
            echo "  3) Gemini 2.0 Flash (Multimodal)"
            echo "  4) Gemini 1.5 Pro (Legacy)"
            echo "  5) Gemini 1.5 Flash (Legacy)"
            read -p "Enter choice [1-5]: " model_choice
            case $model_choice in
                1) MODEL="gemini-2.5-pro";;
                2) MODEL="gemini-2.5-flash";;
                3) MODEL="gemini-2.0-flash";;
                4) MODEL="gemini-1.5-pro";;
                5) MODEL="gemini-1.5-flash";;
                *) MODEL="gemini-2.5-flash";;
            esac
            API_KEY_VAR="SENTINEL_APP_GOOGLE_API_KEY"
            ;;
        mistral)
            print_color "$YELLOW" "Select Mistral Model:"
            echo "  1) Mistral Large"
            echo "  2) Mistral Small 3"
            echo "  3) Codestral (Code-focused)"
            read -p "Enter choice [1-3]: " model_choice
            case $model_choice in
                1) MODEL="mistral-large";;
                2) MODEL="mistral-small-3";;
                3) MODEL="codestral";;
                *) MODEL="mistral-large";;
            esac
            API_KEY_VAR="SENTINEL_APP_MISTRAL_API_KEY"
            ;;
        ollama)
            print_color "$YELLOW" "Select Ollama Model:"
            echo "  1) DeepSeek-R1 671B (SOTA Reasoning)"
            echo "  2) DeepSeek-R1 70B"
            echo "  3) Llama 3.3 70B"
            echo "  4) Qwen 2.5 72B"
            echo "  5) Qwen 2.5 Coder 32B"
            echo "  6) Mistral 7B"
            echo "  7) Phi-3 14B"
            echo "  8) Custom (enter model name)"
            read -p "Enter choice [1-8]: " model_choice
            case $model_choice in
                1) MODEL="deepseek-r1:671b";;
                2) MODEL="deepseek-r1:70b";;
                3) MODEL="llama3.3:70b";;
                4) MODEL="qwen2.5:72b";;
                5) MODEL="qwen2.5-coder:32b";;
                6) MODEL="mistral:7b";;
                7) MODEL="phi3:14b";;
                8) read -p "Enter model name: " MODEL;;
                *) MODEL="mistral:7b";;
            esac
            BASE_URL_VAR="SENTINEL_APP_OLLAMA_BASE_URL"
            DEFAULT_BASE_URL="http://localhost:11434"
            ;;
        vllm)
            print_color "$YELLOW" "Enter vLLM model name:"
            read -p "Model: " MODEL
            BASE_URL_VAR="SENTINEL_APP_VLLM_BASE_URL"
            DEFAULT_BASE_URL="http://localhost:8000"
            ;;
        none)
            MODEL=""
            ;;
    esac
}

# Function to configure additional settings
configure_settings() {
    if [ "$PROVIDER" != "none" ]; then
        print_color "$YELLOW" "\nAdditional Settings (press Enter for defaults):"
        
        read -p "Temperature (0.0-1.0) [0.7]: " TEMPERATURE
        TEMPERATURE=${TEMPERATURE:-0.7}
        
        read -p "Max Tokens [2000]: " MAX_TOKENS
        MAX_TOKENS=${MAX_TOKENS:-2000}
        
        read -p "Enable Fallback? (true/false) [true]: " FALLBACK
        FALLBACK=${FALLBACK:-true}
        
        read -p "Enable Caching? (true/false) [true]: " CACHE
        CACHE=${CACHE:-true}
    fi
}

# Function to write configuration
write_config() {
    print_color "$YELLOW" "\nWriting configuration to $ENV_FILE..."
    
    # Backup existing file
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "${ENV_FILE}.backup"
        print_color "$GREEN" "Backed up existing config to ${ENV_FILE}.backup"
    fi
    
    # Remove existing LLM settings
    if [ -f "$ENV_FILE" ]; then
        grep -v "^SENTINEL_APP_LLM_" "$ENV_FILE" > "$ENV_FILE.tmp" || true
        grep -v "^SENTINEL_APP_OPENAI_API_KEY" "$ENV_FILE.tmp" > "$ENV_FILE.tmp2" || true
        grep -v "^SENTINEL_APP_ANTHROPIC_API_KEY" "$ENV_FILE.tmp2" > "$ENV_FILE.tmp" || true
        grep -v "^SENTINEL_APP_GOOGLE_API_KEY" "$ENV_FILE.tmp" > "$ENV_FILE.tmp2" || true
        grep -v "^SENTINEL_APP_MISTRAL_API_KEY" "$ENV_FILE.tmp2" > "$ENV_FILE.tmp" || true
        grep -v "^SENTINEL_APP_OLLAMA_BASE_URL" "$ENV_FILE.tmp" > "$ENV_FILE.tmp2" || true
        grep -v "^SENTINEL_APP_VLLM_BASE_URL" "$ENV_FILE.tmp2" > "$ENV_FILE.tmp" || true
        mv "$ENV_FILE.tmp" "$ENV_FILE"
        rm -f "$ENV_FILE.tmp2"
    fi
    
    # Write new settings
    {
        echo ""
        echo "# LLM Configuration (generated by switch_llm.sh)"
        echo "SENTINEL_APP_LLM_PROVIDER=$PROVIDER"
        
        if [ "$PROVIDER" != "none" ]; then
            echo "SENTINEL_APP_LLM_MODEL=$MODEL"
            echo "SENTINEL_APP_LLM_TEMPERATURE=$TEMPERATURE"
            echo "SENTINEL_APP_LLM_MAX_TOKENS=$MAX_TOKENS"
            echo "SENTINEL_APP_LLM_FALLBACK_ENABLED=$FALLBACK"
            echo "SENTINEL_APP_LLM_CACHE_ENABLED=$CACHE"
            
            # Add API key placeholder if needed
            if [ ! -z "$API_KEY_VAR" ]; then
                echo ""
                echo "# API Key (replace with your actual key)"
                echo "${API_KEY_VAR}=your-api-key-here"
            fi
            
            # Add base URL for local providers
            if [ ! -z "$BASE_URL_VAR" ]; then
                echo ""
                echo "# Base URL for local model"
                echo "${BASE_URL_VAR}=${DEFAULT_BASE_URL}"
            fi
        fi
    } >> "$ENV_FILE"
    
    print_color "$GREEN" "\n✓ Configuration saved successfully!"
}

# Function to validate configuration
validate_config() {
    print_color "$YELLOW" "\nValidating configuration..."
    
    if command -v python3 &> /dev/null; then
        cd "$(dirname "$0")/.." 2>/dev/null || cd sentinel_backend
        if [ -f "scripts/validate_llm_config.py" ]; then
            print_color "$BLUE" "Running validation script..."
            python3 scripts/validate_llm_config.py
        else
            print_color "$YELLOW" "Validation script not found, skipping validation"
        fi
    else
        print_color "$YELLOW" "Python not found, skipping validation"
    fi
}

# Function to show quick setup
quick_setup() {
    case $1 in
        claude|anthropic)
            PROVIDER="anthropic"
            MODEL="claude-sonnet-4"
            ;;
        openai|gpt)
            PROVIDER="openai"
            MODEL="gpt-4-turbo"
            ;;
        gemini|google)
            PROVIDER="google"
            MODEL="gemini-2.5-flash"
            ;;
        local|ollama)
            PROVIDER="ollama"
            MODEL="mistral:7b"
            ;;
        none|disable)
            PROVIDER="none"
            MODEL=""
            ;;
        *)
            print_color "$RED" "Unknown quick setup option: $1"
            echo "Valid options: claude, openai, gemini, local, none"
            exit 1
            ;;
    esac
    
    TEMPERATURE="0.7"
    MAX_TOKENS="2000"
    FALLBACK="true"
    CACHE="true"
    
    if [ "$PROVIDER" == "ollama" ]; then
        BASE_URL_VAR="SENTINEL_APP_OLLAMA_BASE_URL"
        DEFAULT_BASE_URL="http://localhost:11434"
    fi
    
    write_config
    print_color "$GREEN" "\nQuick setup complete: $PROVIDER with $MODEL"
}

# Main script
main() {
    # Check for quick setup argument
    if [ $# -eq 1 ]; then
        quick_setup $1
        exit 0
    fi
    
    # Interactive mode
    show_header
    show_current_config
    select_provider
    
    if [ "$PROVIDER" != "none" ]; then
        select_model
        configure_settings
    fi
    
    write_config
    
    # Ask if user wants to validate
    read -p "$(print_color "$YELLOW" "\nValidate configuration? (y/n) [y]: ")" validate
    validate=${validate:-y}
    if [ "$validate" == "y" ]; then
        validate_config
    fi
    
    print_color "$GREEN" "\n✓ LLM configuration complete!"
    
    # Show reminder about API keys
    if [ ! -z "$API_KEY_VAR" ]; then
        print_color "$YELLOW" "\n⚠️  Remember to set your API key:"
        print_color "$YELLOW" "   Edit $ENV_FILE and replace 'your-api-key-here' with your actual key"
    fi
    
    if [ "$PROVIDER" == "ollama" ]; then
        print_color "$YELLOW" "\n⚠️  Remember to start Ollama and pull the model:"
        print_color "$YELLOW" "   ollama pull $MODEL"
    fi
}

# Show help
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    print_color "$BLUE" "Sentinel LLM Provider Switcher"
    echo ""
    echo "Usage:"
    echo "  $0                    # Interactive mode"
    echo "  $0 <provider>         # Quick setup"
    echo ""
    echo "Quick setup options:"
    echo "  claude, anthropic     # Use Anthropic Claude Sonnet 4"
    echo "  openai, gpt          # Use OpenAI GPT-4 Turbo"
    echo "  gemini, google       # Use Google Gemini 2.5 Flash"
    echo "  local, ollama        # Use local Ollama with Mistral 7B"
    echo "  none, disable        # Disable LLM (deterministic only)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Interactive configuration"
    echo "  $0 claude            # Quick setup with Claude"
    echo "  $0 local             # Quick setup with local Ollama"
    echo ""
    echo "Environment:"
    echo "  ENV_FILE             # Config file to use (default: .env)"
    echo ""
    exit 0
fi

main "$@"