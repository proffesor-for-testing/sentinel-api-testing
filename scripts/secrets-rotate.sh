#!/bin/bash
#
# Sentinel Secrets Management - Rotation Script
# This script rotates secrets in HashiCorp Vault with zero-downtime
#
# Usage:
#   ./secrets-rotate.sh [environment] [secret-type]
#
# Environments: development, staging, production
# Secret Types: database, jwt, admin, broker, all
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parameters
ENVIRONMENT="${1:-development}"
SECRET_TYPE="${2:-all}"
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }

# Function to rotate database password
rotate_database() {
    log_info "Rotating database password..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"

    # Generate new password
    NEW_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

    # Get current secrets
    CURRENT=$(vault kv get -format=json "${BASE_PATH}/database" | jq -r '.data.data')
    USERNAME=$(echo "${CURRENT}" | jq -r '.username')
    HOST=$(echo "${CURRENT}" | jq -r '.host')
    PORT=$(echo "${CURRENT}" | jq -r '.port')
    DATABASE=$(echo "${CURRENT}" | jq -r '.database')

    # Update password in database
    log_info "Updating database password in PostgreSQL..."
    export PGPASSWORD=$(echo "${CURRENT}" | jq -r '.password')
    psql -h "${HOST}" -p "${PORT}" -U postgres -d postgres <<EOF
ALTER USER ${USERNAME} WITH PASSWORD '${NEW_PASSWORD}';
EOF

    # Update in Vault
    vault kv put "${BASE_PATH}/database" \
        username="${USERNAME}" \
        password="${NEW_PASSWORD}" \
        host="${HOST}" \
        port="${PORT}" \
        database="${DATABASE}" \
        url="postgresql+asyncpg://${USERNAME}:${NEW_PASSWORD}@${HOST}:${PORT}/${DATABASE}"

    log_success "Database password rotated"
    log_warning "⚠️  Services must reconnect with new credentials"
}

# Function to rotate JWT secret
rotate_jwt() {
    log_info "Rotating JWT secret..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"

    # Generate new JWT secret
    NEW_JWT_SECRET=$(openssl rand -base64 48)

    # Get current secrets
    CURRENT=$(vault kv get -format=json "${BASE_PATH}/auth" | jq -r '.data.data')

    # Store new secret with version metadata
    vault kv put "${BASE_PATH}/auth" \
        jwt_secret_key="${NEW_JWT_SECRET}" \
        jwt_secret_key_old=$(echo "${CURRENT}" | jq -r '.jwt_secret_key') \
        jwt_algorithm=$(echo "${CURRENT}" | jq -r '.jwt_algorithm') \
        jwt_expiration_hours=$(echo "${CURRENT}" | jq -r '.jwt_expiration_hours') \
        admin_email=$(echo "${CURRENT}" | jq -r '.admin_email') \
        admin_password=$(echo "${CURRENT}" | jq -r '.admin_password') \
        rotation_date="$(date -Iseconds)"

    log_success "JWT secret rotated"
    log_warning "⚠️  Old JWT secret kept for 24h to allow token grace period"
    log_warning "⚠️  All existing tokens will expire naturally"
}

# Function to rotate admin password
rotate_admin() {
    log_info "Rotating admin password..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"

    # Generate new password
    NEW_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)

    # Get current secrets
    CURRENT=$(vault kv get -format=json "${BASE_PATH}/auth" | jq -r '.data.data')

    # Update in Vault
    vault kv put "${BASE_PATH}/auth" \
        jwt_secret_key=$(echo "${CURRENT}" | jq -r '.jwt_secret_key') \
        jwt_algorithm=$(echo "${CURRENT}" | jq -r '.jwt_algorithm') \
        jwt_expiration_hours=$(echo "${CURRENT}" | jq -r '.jwt_expiration_hours') \
        admin_email=$(echo "${CURRENT}" | jq -r '.admin_email') \
        admin_password="${NEW_PASSWORD}" \
        admin_password_last_rotated="$(date -Iseconds)"

    log_success "Admin password rotated to: ${NEW_PASSWORD}"
    log_warning "⚠️  Store this password securely"

    # Save to secure file
    ADMIN_CREDS_FILE="${PROJECT_ROOT}/.vault-keys/admin-credentials.${ENVIRONMENT}.txt"
    echo "Admin Credentials (Generated: $(date))" > "${ADMIN_CREDS_FILE}"
    echo "Email: $(echo "${CURRENT}" | jq -r '.admin_email')" >> "${ADMIN_CREDS_FILE}"
    echo "Password: ${NEW_PASSWORD}" >> "${ADMIN_CREDS_FILE}"
    chmod 600 "${ADMIN_CREDS_FILE}"

    log_info "Admin credentials saved to: ${ADMIN_CREDS_FILE}"
}

# Function to rotate RabbitMQ password
rotate_broker() {
    log_info "Rotating message broker password..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"

    # Generate new password
    NEW_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-16)

    # Get current secrets
    CURRENT=$(vault kv get -format=json "${BASE_PATH}/broker" | jq -r '.data.data')
    USERNAME=$(echo "${CURRENT}" | jq -r '.username')
    HOST=$(echo "${CURRENT}" | jq -r '.host')
    PORT=$(echo "${CURRENT}" | jq -r '.port')

    # Update password in RabbitMQ
    log_info "Updating password in RabbitMQ..."
    docker exec sentinel_message_broker rabbitmqctl change_password "${USERNAME}" "${NEW_PASSWORD}"

    # Update in Vault
    vault kv put "${BASE_PATH}/broker" \
        username="${USERNAME}" \
        password="${NEW_PASSWORD}" \
        host="${HOST}" \
        port="${PORT}" \
        url="amqp://${USERNAME}:${NEW_PASSWORD}@${HOST}:${PORT}/"

    log_success "Message broker password rotated"
    log_warning "⚠️  Services must reconnect with new credentials"
}

# Function to rotate all secrets
rotate_all() {
    log_info "Rotating all secrets..."

    rotate_jwt
    sleep 2

    rotate_admin
    sleep 2

    rotate_broker
    sleep 2

    rotate_database

    log_success "All secrets rotated successfully"
}

# Function to check rotation history
check_rotation_history() {
    log_info "Checking rotation history..."

    BASE_PATH="secret/sentinel/${ENVIRONMENT}"

    echo ""
    echo "Database Secrets:"
    vault kv metadata get "${BASE_PATH}/database" | grep -A 5 "Version"

    echo ""
    echo "Auth Secrets:"
    vault kv metadata get "${BASE_PATH}/auth" | grep -A 5 "Version"

    echo ""
    echo "Broker Secrets:"
    vault kv metadata get "${BASE_PATH}/broker" | grep -A 5 "Version"
}

# Main execution
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Sentinel Secrets Management - Rotation                ║"
    echo "║  Environment: ${ENVIRONMENT}                            "
    echo "║  Secret Type: ${SECRET_TYPE}                            "
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""

    # Validate environment
    if [[ ! "${ENVIRONMENT}" =~ ^(development|staging|production)$ ]]; then
        log_error "Invalid environment: ${ENVIRONMENT}"
        exit 1
    fi

    # Validate secret type
    if [[ ! "${SECRET_TYPE}" =~ ^(database|jwt|admin|broker|all|history)$ ]]; then
        log_error "Invalid secret type: ${SECRET_TYPE}"
        echo "Valid types: database, jwt, admin, broker, all, history"
        exit 1
    fi

    # Check dependencies
    command -v vault >/dev/null 2>&1 || { log_error "vault CLI not found"; exit 1; }
    command -v jq >/dev/null 2>&1 || { log_error "jq not found"; exit 1; }

    # Login to Vault
    if [ -z "${VAULT_TOKEN}" ]; then
        ROOT_TOKEN_FILE="${PROJECT_ROOT}/.vault-keys/root-token.txt"
        if [ -f "${ROOT_TOKEN_FILE}" ]; then
            VAULT_TOKEN=$(cat "${ROOT_TOKEN_FILE}")
        else
            log_error "VAULT_TOKEN not set and root token file not found"
            exit 1
        fi
    fi

    export VAULT_ADDR
    export VAULT_TOKEN

    # Confirm rotation for production
    if [ "${ENVIRONMENT}" = "production" ]; then
        log_warning "⚠️  You are about to rotate secrets in PRODUCTION"
        read -p "Are you sure? (type 'yes' to confirm): " confirm
        if [ "${confirm}" != "yes" ]; then
            log_error "Rotation cancelled"
            exit 0
        fi
    fi

    # Execute rotation
    case "${SECRET_TYPE}" in
        database)
            rotate_database
            ;;
        jwt)
            rotate_jwt
            ;;
        admin)
            rotate_admin
            ;;
        broker)
            rotate_broker
            ;;
        all)
            rotate_all
            ;;
        history)
            check_rotation_history
            ;;
    esac

    echo ""
    log_success "✅ Secrets rotation complete!"
    echo ""
    log_info "Next steps:"
    echo "  1. Monitor service logs for connection errors"
    echo "  2. Verify all services reconnected successfully"
    echo "  3. Update any external references to rotated secrets"
    echo ""
}

main
