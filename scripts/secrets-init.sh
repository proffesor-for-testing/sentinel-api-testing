#!/bin/bash
#
# Sentinel Secrets Management - Initialization Script
# This script initializes HashiCorp Vault and configures secrets for the Sentinel platform
#
# Usage:
#   ./secrets-init.sh [environment]
#
# Environments: development, staging, production
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default environment
ENVIRONMENT="${1:-development}"
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

# Function to print colored messages
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to check if Vault is running
check_vault() {
    log_info "Checking Vault availability at ${VAULT_ADDR}..."

    if ! curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
        log_error "Vault is not accessible at ${VAULT_ADDR}"
        log_info "Starting Vault container..."

        # Check if docker-compose file exists for Vault
        if [ -f "${PROJECT_ROOT}/docker-compose.vault.yml" ]; then
            docker-compose -f "${PROJECT_ROOT}/docker-compose.vault.yml" up -d
            sleep 5
        else
            log_error "Vault docker-compose file not found. Please run setup first."
            exit 1
        fi
    fi

    log_success "Vault is accessible"
}

# Function to initialize Vault
init_vault() {
    log_info "Initializing Vault..."

    # Check if already initialized
    if vault status > /dev/null 2>&1; then
        log_warning "Vault already initialized"
        return 0
    fi

    # Initialize Vault
    INIT_OUTPUT=$(vault operator init -key-shares=5 -key-threshold=3 -format=json)

    # Save unseal keys and root token
    UNSEAL_KEYS_DIR="${PROJECT_ROOT}/.vault-keys"
    mkdir -p "${UNSEAL_KEYS_DIR}"
    chmod 700 "${UNSEAL_KEYS_DIR}"

    echo "${INIT_OUTPUT}" | jq -r '.unseal_keys_b64[]' > "${UNSEAL_KEYS_DIR}/unseal-keys.txt"
    echo "${INIT_OUTPUT}" | jq -r '.root_token' > "${UNSEAL_KEYS_DIR}/root-token.txt"

    chmod 600 "${UNSEAL_KEYS_DIR}"/*

    log_success "Vault initialized"
    log_warning "Unseal keys saved to: ${UNSEAL_KEYS_DIR}/unseal-keys.txt"
    log_warning "Root token saved to: ${UNSEAL_KEYS_DIR}/root-token.txt"
    log_warning "⚠️  IMPORTANT: Store these keys securely and remove from filesystem after backup!"
}

# Function to unseal Vault
unseal_vault() {
    log_info "Unsealing Vault..."

    UNSEAL_KEYS_FILE="${PROJECT_ROOT}/.vault-keys/unseal-keys.txt"

    if [ ! -f "${UNSEAL_KEYS_FILE}" ]; then
        log_error "Unseal keys file not found: ${UNSEAL_KEYS_FILE}"
        exit 1
    fi

    # Use first 3 keys to unseal
    head -n 3 "${UNSEAL_KEYS_FILE}" | while read -r key; do
        vault operator unseal "${key}" > /dev/null
    done

    log_success "Vault unsealed"
}

# Function to login to Vault
login_vault() {
    log_info "Logging in to Vault..."

    if [ -z "${VAULT_TOKEN}" ]; then
        ROOT_TOKEN_FILE="${PROJECT_ROOT}/.vault-keys/root-token.txt"

        if [ ! -f "${ROOT_TOKEN_FILE}" ]; then
            log_error "Root token file not found and VAULT_TOKEN not set"
            exit 1
        fi

        VAULT_TOKEN=$(cat "${ROOT_TOKEN_FILE}")
    fi

    export VAULT_TOKEN
    vault login token="${VAULT_TOKEN}" > /dev/null

    log_success "Logged in to Vault"
}

# Function to enable secrets engines
enable_secrets_engines() {
    log_info "Enabling secrets engines..."

    # Enable KV v2 secrets engine
    if ! vault secrets list | grep -q "^secret/"; then
        vault secrets enable -version=2 -path=secret kv
        log_success "Enabled KV v2 secrets engine at 'secret/'"
    else
        log_warning "KV v2 secrets engine already enabled"
    fi

    # Enable database secrets engine for dynamic credentials
    if ! vault secrets list | grep -q "^database/"; then
        vault secrets enable database
        log_success "Enabled database secrets engine"
    else
        log_warning "Database secrets engine already enabled"
    fi
}

# Function to enable auth methods
enable_auth_methods() {
    log_info "Enabling authentication methods..."

    # Enable AppRole for service authentication
    if ! vault auth list | grep -q "^approle/"; then
        vault auth enable approle
        log_success "Enabled AppRole authentication"
    else
        log_warning "AppRole authentication already enabled"
    fi

    # Enable userpass for human users
    if ! vault auth list | grep -q "^userpass/"; then
        vault auth enable userpass
        log_success "Enabled userpass authentication"
    else
        log_warning "Userpass authentication already enabled"
    fi
}

# Function to create policies
create_policies() {
    log_info "Creating Vault policies..."

    POLICIES_DIR="${PROJECT_ROOT}/config/vault/policies"

    if [ ! -d "${POLICIES_DIR}" ]; then
        log_error "Policies directory not found: ${POLICIES_DIR}"
        return 1
    fi

    for policy_file in "${POLICIES_DIR}"/*.hcl; do
        if [ -f "${policy_file}" ]; then
            policy_name=$(basename "${policy_file}" .hcl)
            vault policy write "${policy_name}" "${policy_file}"
            log_success "Created policy: ${policy_name}"
        fi
    done
}

# Function to create AppRoles for services
create_approles() {
    log_info "Creating AppRoles for services..."

    local services=(
        "api-gateway:sentinel-api-gateway"
        "auth-service:sentinel-auth"
        "spec-service:sentinel-spec"
        "orchestration-service:sentinel-orchestration"
        "execution-service:sentinel-execution"
        "data-service:sentinel-data"
        "rust-core:sentinel-rust-core"
    )

    for service in "${services[@]}"; do
        IFS=':' read -r role_name policy <<< "${service}"

        # Create AppRole
        vault write "auth/approle/role/${role_name}" \
            token_policies="${policy}" \
            token_ttl=1h \
            token_max_ttl=24h \
            secret_id_ttl=0 \
            bind_secret_id=true

        log_success "Created AppRole: ${role_name}"
    done
}

# Function to generate and store secrets
generate_secrets() {
    log_info "Generating and storing secrets for ${ENVIRONMENT}..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"

    # Generate secure random values
    JWT_SECRET=$(openssl rand -base64 48)
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)
    RABBITMQ_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)

    # Database secrets
    vault kv put "${BASE_PATH}/database" \
        username="sentinel_${ENVIRONMENT}" \
        password="${DB_PASSWORD}" \
        host="postgres_db" \
        port="5432" \
        database="sentinel_${ENVIRONMENT}_db" \
        url="postgresql+asyncpg://sentinel_${ENVIRONMENT}:${DB_PASSWORD}@postgres_db:5432/sentinel_${ENVIRONMENT}_db"

    log_success "Stored database secrets"

    # Authentication secrets
    vault kv put "${BASE_PATH}/auth" \
        jwt_secret_key="${JWT_SECRET}" \
        jwt_algorithm="HS256" \
        jwt_expiration_hours="24" \
        admin_email="admin@sentinel.com" \
        admin_password="${ADMIN_PASSWORD}"

    log_success "Stored authentication secrets"

    # Message broker secrets
    vault kv put "${BASE_PATH}/broker" \
        username="sentinel" \
        password="${RABBITMQ_PASSWORD}" \
        host="message_broker" \
        port="5672" \
        url="amqp://sentinel:${RABBITMQ_PASSWORD}@message_broker:5672/"

    log_success "Stored message broker secrets"

    # LLM API keys (prompt for actual keys)
    log_warning "LLM API keys must be set manually:"
    echo ""
    echo "  vault kv put ${BASE_PATH}/llm \\"
    echo "    anthropic_api_key=\"sk-ant-...\" \\"
    echo "    openai_api_key=\"sk-...\" \\"
    echo "    google_api_key=\"AIza...\" \\"
    echo "    mistral_api_key=\"...\""
    echo ""

    # Create placeholder
    vault kv put "${BASE_PATH}/llm" \
        anthropic_api_key="REPLACE_WITH_ACTUAL_KEY" \
        openai_api_key="REPLACE_WITH_ACTUAL_KEY" \
        google_api_key="REPLACE_WITH_ACTUAL_KEY" \
        mistral_api_key="REPLACE_WITH_ACTUAL_KEY"

    log_success "Created LLM secrets placeholder"
}

# Function to export secrets for initial setup
export_secrets_for_setup() {
    log_info "Exporting secrets for initial setup..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"
    EXPORT_FILE="${PROJECT_ROOT}/.env.vault.${ENVIRONMENT}"

    # Get secrets from Vault
    DB_SECRETS=$(vault kv get -format=json "${BASE_PATH}/database" | jq -r '.data.data')
    AUTH_SECRETS=$(vault kv get -format=json "${BASE_PATH}/auth" | jq -r '.data.data')
    BROKER_SECRETS=$(vault kv get -format=json "${BASE_PATH}/broker" | jq -r '.data.data')

    # Create .env file
    cat > "${EXPORT_FILE}" <<EOF
# Sentinel Vault-Generated Secrets for ${ENVIRONMENT}
# Generated: $(date)
# WARNING: This file contains sensitive credentials. Do not commit to version control.

# Database Configuration
SENTINEL_DB_URL=$(echo "${DB_SECRETS}" | jq -r '.url')
POSTGRES_USER=$(echo "${DB_SECRETS}" | jq -r '.username')
POSTGRES_PASSWORD=$(echo "${DB_SECRETS}" | jq -r '.password')
POSTGRES_DB=$(echo "${DB_SECRETS}" | jq -r '.database')

# Authentication Configuration
SENTINEL_SECURITY_JWT_SECRET_KEY=$(echo "${AUTH_SECRETS}" | jq -r '.jwt_secret_key')
SENTINEL_SECURITY_DEFAULT_ADMIN_EMAIL=$(echo "${AUTH_SECRETS}" | jq -r '.admin_email')
SENTINEL_SECURITY_DEFAULT_ADMIN_PASSWORD=$(echo "${AUTH_SECRETS}" | jq -r '.admin_password')

# Message Broker Configuration
SENTINEL_BROKER_URL=$(echo "${BROKER_SECRETS}" | jq -r '.url')
RABBITMQ_DEFAULT_USER=$(echo "${BROKER_SECRETS}" | jq -r '.username')
RABBITMQ_DEFAULT_PASS=$(echo "${BROKER_SECRETS}" | jq -r '.password')

# Environment
SENTINEL_ENVIRONMENT=${ENVIRONMENT}
EOF

    chmod 600 "${EXPORT_FILE}"

    log_success "Secrets exported to: ${EXPORT_FILE}"
    log_warning "⚠️  This file should be used for initial setup only"
    log_warning "⚠️  Services should read secrets directly from Vault in production"
}

# Function to display AppRole credentials
display_approle_credentials() {
    log_info "Retrieving AppRole credentials..."

    CREDENTIALS_FILE="${PROJECT_ROOT}/.vault-keys/approle-credentials.${ENVIRONMENT}.txt"

    cat > "${CREDENTIALS_FILE}" <<EOF
# AppRole Credentials for ${ENVIRONMENT}
# Generated: $(date)
# These credentials allow services to authenticate with Vault

EOF

    local services=("api-gateway" "auth-service" "spec-service" "orchestration-service" "execution-service" "data-service" "rust-core")

    for service in "${services[@]}"; do
        ROLE_ID=$(vault read -field=role_id "auth/approle/role/${service}/role-id")
        SECRET_ID=$(vault write -field=secret_id -f "auth/approle/role/${service}/secret-id")

        echo "Service: ${service}" >> "${CREDENTIALS_FILE}"
        echo "  VAULT_ROLE_ID=${ROLE_ID}" >> "${CREDENTIALS_FILE}"
        echo "  VAULT_SECRET_ID=${SECRET_ID}" >> "${CREDENTIALS_FILE}"
        echo "" >> "${CREDENTIALS_FILE}"
    done

    chmod 600 "${CREDENTIALS_FILE}"

    log_success "AppRole credentials saved to: ${CREDENTIALS_FILE}"
}

# Main execution
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Sentinel Secrets Management - Initialization          ║"
    echo "║  Environment: ${ENVIRONMENT}                            "
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""

    # Validate environment
    if [[ ! "${ENVIRONMENT}" =~ ^(development|staging|production)$ ]]; then
        log_error "Invalid environment: ${ENVIRONMENT}"
        echo "Valid environments: development, staging, production"
        exit 1
    fi

    # Check dependencies
    command -v vault >/dev/null 2>&1 || { log_error "vault CLI not found. Please install HashiCorp Vault."; exit 1; }
    command -v jq >/dev/null 2>&1 || { log_error "jq not found. Please install jq."; exit 1; }
    command -v openssl >/dev/null 2>&1 || { log_error "openssl not found. Please install OpenSSL."; exit 1; }

    # Set Vault address
    export VAULT_ADDR

    # Execute initialization steps
    check_vault
    init_vault
    unseal_vault
    login_vault
    enable_secrets_engines
    enable_auth_methods
    create_policies
    create_approles
    generate_secrets
    export_secrets_for_setup
    display_approle_credentials

    echo ""
    log_success "✅ Secrets initialization complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Review and update LLM API keys in Vault"
    echo "  2. Configure services to use Vault (see docs/secrets-management-guide.md)"
    echo "  3. Test service connectivity with Vault"
    echo "  4. Securely backup unseal keys and destroy local copies"
    echo ""
    log_warning "⚠️  IMPORTANT: Store unseal keys and root token in a secure location!"
    echo ""
}

# Run main function
main
