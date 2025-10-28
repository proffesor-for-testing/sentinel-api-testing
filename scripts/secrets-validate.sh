#!/bin/bash
#
# Sentinel Secrets Management - Validation Script
# This script validates secrets configuration and connectivity
#
# Usage:
#   ./secrets-validate.sh [environment]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ENVIRONMENT="${1:-development}"
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

ERRORS=0
WARNINGS=0
CHECKS_PASSED=0
TOTAL_CHECKS=0

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; CHECKS_PASSED=$((CHECKS_PASSED + 1)); }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
log_error() { echo -e "${RED}✗${NC} $1"; ERRORS=$((ERRORS + 1)); }

run_check() {
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    "$@"
}

# Check Vault availability
check_vault_availability() {
    log_info "Checking Vault availability..."

    if curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; then
        log_success "Vault is accessible at ${VAULT_ADDR}"
        return 0
    else
        log_error "Vault is not accessible at ${VAULT_ADDR}"
        return 1
    fi
}

# Check Vault seal status
check_vault_seal_status() {
    log_info "Checking Vault seal status..."

    SEAL_STATUS=$(vault status -format=json 2>/dev/null | jq -r '.sealed')

    if [ "${SEAL_STATUS}" = "false" ]; then
        log_success "Vault is unsealed"
        return 0
    else
        log_error "Vault is sealed"
        return 1
    fi
}

# Check authentication
check_authentication() {
    log_info "Checking Vault authentication..."

    if vault token lookup > /dev/null 2>&1; then
        log_success "Successfully authenticated to Vault"
        return 0
    else
        log_error "Vault authentication failed"
        return 1
    fi
}

# Check secrets engines
check_secrets_engines() {
    log_info "Checking secrets engines..."

    if vault secrets list | grep -q "^secret/"; then
        log_success "KV v2 secrets engine enabled"
    else
        log_error "KV v2 secrets engine not enabled"
        return 1
    fi

    if vault secrets list | grep -q "^database/"; then
        log_success "Database secrets engine enabled"
    else
        log_warning "Database secrets engine not enabled"
    fi
}

# Check auth methods
check_auth_methods() {
    log_info "Checking auth methods..."

    if vault auth list | grep -q "^approle/"; then
        log_success "AppRole authentication enabled"
    else
        log_error "AppRole authentication not enabled"
        return 1
    fi

    if vault auth list | grep -q "^userpass/"; then
        log_success "Userpass authentication enabled"
    else
        log_warning "Userpass authentication not enabled"
    fi
}

# Check database secrets
check_database_secrets() {
    log_info "Checking database secrets..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}/database"

    if ! vault kv get "${BASE_PATH}" > /dev/null 2>&1; then
        log_error "Database secrets not found at ${BASE_PATH}"
        return 1
    fi

    # Validate required fields
    SECRETS=$(vault kv get -format=json "${BASE_PATH}" | jq -r '.data.data')

    for field in username password host port database url; do
        VALUE=$(echo "${SECRETS}" | jq -r ".${field}")
        if [ "${VALUE}" = "null" ] || [ -z "${VALUE}" ]; then
            log_error "Database secret missing field: ${field}"
        else
            log_success "Database secret has valid ${field}"
        fi
    done

    # Validate password strength
    PASSWORD=$(echo "${SECRETS}" | jq -r '.password')
    if [ ${#PASSWORD} -lt 16 ]; then
        log_warning "Database password is shorter than 16 characters"
    else
        log_success "Database password meets minimum length requirement"
    fi
}

# Check auth secrets
check_auth_secrets() {
    log_info "Checking authentication secrets..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}/auth"

    if ! vault kv get "${BASE_PATH}" > /dev/null 2>&1; then
        log_error "Auth secrets not found at ${BASE_PATH}"
        return 1
    fi

    SECRETS=$(vault kv get -format=json "${BASE_PATH}" | jq -r '.data.data')

    for field in jwt_secret_key jwt_algorithm jwt_expiration_hours admin_email admin_password; do
        VALUE=$(echo "${SECRETS}" | jq -r ".${field}")
        if [ "${VALUE}" = "null" ] || [ -z "${VALUE}" ]; then
            log_error "Auth secret missing field: ${field}"
        else
            log_success "Auth secret has valid ${field}"
        fi
    done

    # Validate JWT secret strength
    JWT_SECRET=$(echo "${SECRETS}" | jq -r '.jwt_secret_key')
    if [ ${#JWT_SECRET} -lt 32 ]; then
        log_error "JWT secret is shorter than 32 characters"
    else
        log_success "JWT secret meets minimum length requirement (${#JWT_SECRET} chars)"
    fi

    # Check for default secrets
    if [[ "${JWT_SECRET}" == *"sentinel-dev-secret"* ]]; then
        log_error "JWT secret is still using default value"
    fi

    if [ "$(echo "${SECRETS}" | jq -r '.admin_password')" = "admin123" ]; then
        log_error "Admin password is still using default value"
    fi
}

# Check broker secrets
check_broker_secrets() {
    log_info "Checking message broker secrets..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}/broker"

    if ! vault kv get "${BASE_PATH}" > /dev/null 2>&1; then
        log_error "Broker secrets not found at ${BASE_PATH}"
        return 1
    fi

    SECRETS=$(vault kv get -format=json "${BASE_PATH}" | jq -r '.data.data')

    for field in username password host port url; do
        VALUE=$(echo "${SECRETS}" | jq -r ".${field}")
        if [ "${VALUE}" = "null" ] || [ -z "${VALUE}" ]; then
            log_error "Broker secret missing field: ${field}"
        else
            log_success "Broker secret has valid ${field}"
        fi
    done

    # Check for default credentials
    if [ "$(echo "${SECRETS}" | jq -r '.username')" = "guest" ] && [ "$(echo "${SECRETS}" | jq -r '.password')" = "guest" ]; then
        log_error "RabbitMQ is using default guest/guest credentials"
    fi
}

# Check LLM secrets
check_llm_secrets() {
    log_info "Checking LLM API secrets..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}/llm"

    if ! vault kv get "${BASE_PATH}" > /dev/null 2>&1; then
        log_warning "LLM secrets not found at ${BASE_PATH}"
        return 0
    fi

    SECRETS=$(vault kv get -format=json "${BASE_PATH}" | jq -r '.data.data')

    for provider in anthropic openai google mistral; do
        KEY=$(echo "${SECRETS}" | jq -r ".${provider}_api_key")
        if [ "${KEY}" = "null" ] || [ -z "${KEY}" ]; then
            log_warning "LLM secret missing: ${provider}_api_key"
        elif [ "${KEY}" = "REPLACE_WITH_ACTUAL_KEY" ]; then
            log_warning "${provider} API key is placeholder - needs real value"
        else
            # Validate key format
            case "${provider}" in
                anthropic)
                    if [[ "${KEY}" == sk-ant-* ]]; then
                        log_success "${provider} API key format valid"
                    else
                        log_warning "${provider} API key format may be invalid"
                    fi
                    ;;
                openai)
                    if [[ "${KEY}" == sk-* ]]; then
                        log_success "${provider} API key format valid"
                    else
                        log_warning "${provider} API key format may be invalid"
                    fi
                    ;;
                google)
                    if [[ "${KEY}" == AIza* ]]; then
                        log_success "${provider} API key format valid"
                    else
                        log_warning "${provider} API key format may be invalid"
                    fi
                    ;;
                *)
                    log_success "${provider} API key present"
                    ;;
            esac
        fi
    done
}

# Check policies
check_policies() {
    log_info "Checking Vault policies..."

    local required_policies=("sentinel-api-gateway" "sentinel-auth" "sentinel-spec" "sentinel-orchestration" "sentinel-execution" "sentinel-data" "sentinel-rust-core")

    for policy in "${required_policies[@]}"; do
        if vault policy read "${policy}" > /dev/null 2>&1; then
            log_success "Policy exists: ${policy}"
        else
            log_warning "Policy not found: ${policy}"
        fi
    done
}

# Check AppRoles
check_approles() {
    log_info "Checking AppRoles..."

    local required_roles=("api-gateway" "auth-service" "spec-service" "orchestration-service" "execution-service" "data-service" "rust-core")

    for role in "${required_roles[@]}"; do
        if vault read "auth/approle/role/${role}" > /dev/null 2>&1; then
            log_success "AppRole exists: ${role}"
        else
            log_error "AppRole not found: ${role}"
        fi
    done
}

# Check database connectivity
check_database_connectivity() {
    log_info "Checking database connectivity..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}/database"
    SECRETS=$(vault kv get -format=json "${BASE_PATH}" | jq -r '.data.data')

    HOST=$(echo "${SECRETS}" | jq -r '.host')
    PORT=$(echo "${SECRETS}" | jq -r '.port')
    USERNAME=$(echo "${SECRETS}" | jq -r '.username')
    PASSWORD=$(echo "${SECRETS}" | jq -r '.password')
    DATABASE=$(echo "${SECRETS}" | jq -r '.database')

    export PGPASSWORD="${PASSWORD}"
    if psql -h "${HOST}" -p "${PORT}" -U "${USERNAME}" -d "${DATABASE}" -c "SELECT 1" > /dev/null 2>&1; then
        log_success "Database connection successful"
    else
        log_error "Database connection failed"
        log_info "Make sure PostgreSQL is running and credentials are correct"
    fi
}

# Check broker connectivity
check_broker_connectivity() {
    log_info "Checking message broker connectivity..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}/broker"
    SECRETS=$(vault kv get -format=json "${BASE_PATH}" | jq -r '.data.data')

    URL=$(echo "${SECRETS}" | jq -r '.url')

    # Simple connectivity check using curl
    HOST=$(echo "${SECRETS}" | jq -r '.host')
    PORT=$(echo "${SECRETS}" | jq -r '.port')

    if nc -z "${HOST}" "${PORT}" 2>/dev/null; then
        log_success "Message broker is accessible"
    else
        log_error "Message broker connection failed"
        log_info "Make sure RabbitMQ is running at ${HOST}:${PORT}"
    fi
}

# Check for secrets in version control
check_git_secrets() {
    log_info "Checking for secrets in version control..."

    cd "${PROJECT_ROOT}"

    # Check if .env files are in .gitignore
    if grep -q "^\.env$" .gitignore 2>/dev/null; then
        log_success ".env files are in .gitignore"
    else
        log_error ".env files are NOT in .gitignore"
    fi

    # Check for committed secrets
    if git ls-files | grep -q "\.env$"; then
        log_error "Found .env files tracked in git"
    else
        log_success "No .env files found in git"
    fi

    # Check for API keys in committed files
    if git grep -i "api.key.*=.*sk-" > /dev/null 2>&1; then
        log_error "Found potential API keys in committed files"
    else
        log_success "No obvious API keys found in committed files"
    fi
}

# Check audit logging
check_audit_logging() {
    log_info "Checking Vault audit logging..."

    if vault audit list | grep -q "file"; then
        log_success "Audit logging is enabled"
    else
        log_warning "Audit logging is not enabled"
        log_info "Consider enabling with: vault audit enable file file_path=/vault/logs/audit.log"
    fi
}

# Check secrets rotation age
check_secrets_age() {
    log_info "Checking secrets rotation age..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"

    for secret_type in database auth broker; do
        METADATA=$(vault kv metadata get -format=json "${BASE_PATH}/${secret_type}" 2>/dev/null)

        if [ $? -eq 0 ]; then
            CREATED=$(echo "${METADATA}" | jq -r '.data.created_time')
            UPDATED=$(echo "${METADATA}" | jq -r '.data.updated_time')

            CREATED_EPOCH=$(date -d "${CREATED}" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "${CREATED%.*}" +%s 2>/dev/null)
            CURRENT_EPOCH=$(date +%s)
            AGE_DAYS=$(( (CURRENT_EPOCH - CREATED_EPOCH) / 86400 ))

            if [ ${AGE_DAYS} -gt 90 ]; then
                log_warning "${secret_type} secrets are ${AGE_DAYS} days old (recommend rotation every 90 days)"
            else
                log_success "${secret_type} secrets age: ${AGE_DAYS} days"
            fi
        fi
    done
}

# Generate validation report
generate_report() {
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Validation Report                                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Total Checks: ${TOTAL_CHECKS}"
    echo "Passed: ${CHECKS_PASSED}"
    echo "Warnings: ${WARNINGS}"
    echo "Errors: ${ERRORS}"
    echo ""

    if [ ${ERRORS} -eq 0 ]; then
        log_success "✅ All critical checks passed!"
        if [ ${WARNINGS} -gt 0 ]; then
            log_warning "⚠️  ${WARNINGS} warning(s) found - review recommended"
        fi
        return 0
    else
        log_error "❌ ${ERRORS} error(s) found - action required"
        return 1
    fi
}

# Main execution
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Sentinel Secrets Management - Validation              ║"
    echo "║  Environment: ${ENVIRONMENT}                            "
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""

    # Check dependencies
    command -v vault >/dev/null 2>&1 || { log_error "vault CLI not found"; exit 1; }
    command -v jq >/dev/null 2>&1 || { log_error "jq not found"; exit 1; }

    # Set Vault address
    export VAULT_ADDR

    # Login if token not set
    if [ -z "${VAULT_TOKEN}" ]; then
        ROOT_TOKEN_FILE="${PROJECT_ROOT}/.vault-keys/root-token.txt"
        if [ -f "${ROOT_TOKEN_FILE}" ]; then
            VAULT_TOKEN=$(cat "${ROOT_TOKEN_FILE}")
            export VAULT_TOKEN
        fi
    fi

    # Run all checks
    run_check check_vault_availability
    run_check check_vault_seal_status
    run_check check_authentication
    run_check check_secrets_engines
    run_check check_auth_methods
    run_check check_database_secrets
    run_check check_auth_secrets
    run_check check_broker_secrets
    run_check check_llm_secrets
    run_check check_policies
    run_check check_approles
    run_check check_git_secrets
    run_check check_audit_logging
    run_check check_secrets_age

    # Optional connectivity checks
    if command -v psql >/dev/null 2>&1; then
        run_check check_database_connectivity
    else
        log_warning "Skipping database connectivity check (psql not found)"
    fi

    if command -v nc >/dev/null 2>&1; then
        run_check check_broker_connectivity
    else
        log_warning "Skipping broker connectivity check (nc not found)"
    fi

    # Generate report
    generate_report
}

main
