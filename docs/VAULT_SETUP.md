# HashiCorp Vault Setup for Sentinel

This document provides instructions for setting up HashiCorp Vault for secure secrets management in the Sentinel platform.

## Overview

Sentinel uses HashiCorp Vault for:
- Secure storage of credentials and API keys
- Dynamic secrets generation
- Secret rotation with zero downtime
- Access control via AppRole authentication
- Audit logging of all secret access

## Quick Start

### 1. Start Vault Service

```bash
# Start Vault in development mode
docker-compose -f docker-compose.vault.yml up -d

# Wait for Vault to be ready
docker logs -f sentinel_vault
```

### 2. Initialize Secrets

```bash
# Run initialization script
./scripts/secrets-init.sh
```

This will:
- Enable KV v2 secrets engine
- Create Vault policies for each service
- Generate secure random secrets
- Create AppRole credentials
- Save credentials to `.vault-keys/` directory

### 3. Validate Configuration

```bash
# Run validation script
./scripts/secrets-validate.sh
```

## Architecture

### Service-Specific Policies

Each service has its own Vault policy limiting access to only required secrets:

- **api-gateway-policy**: API Gateway, database, shared secrets
- **auth-service-policy**: Auth, JWT, database secrets
- **spec-service-policy**: Spec service, LLM API keys, database
- **orchestration-service-policy**: Orchestration, RabbitMQ, database
- **execution-service-policy**: Execution, RabbitMQ, database
- **data-service-policy**: Data service, external APIs, database
- **rust-core-policy**: Rust core, swarm configuration, database

### AppRole Authentication

Services authenticate to Vault using AppRole:

1. Each service has a unique `role-id` (public)
2. Each service has a unique `secret-id` (private)
3. Credentials are stored in `.vault-keys/{service}.env`
4. Services use these credentials to obtain a Vault token
5. Tokens have limited TTL (1 hour) and auto-renew

### Secret Organization

Secrets are organized by environment and category:

```
secret/
  └── sentinel/
      └── {environment}/
          ├── shared/           # Shared encryption keys
          ├── database/         # PostgreSQL credentials
          ├── jwt/              # JWT signing keys
          ├── auth/             # Auth service secrets
          ├── api-gateway/      # API Gateway secrets
          ├── spec/             # Spec service secrets
          ├── llm/              # LLM provider API keys
          ├── orchestration/    # Orchestration service secrets
          ├── rabbitmq/         # RabbitMQ credentials
          ├── execution/        # Execution service secrets
          ├── data/             # Data service secrets
          ├── external-api/     # External API keys
          ├── rust-core/        # Rust core secrets
          └── swarm/            # Swarm coordination keys
```

## Secret Rotation

### Manual Rotation

```bash
# Run rotation script
./scripts/secrets-rotate.sh

# Select rotation type:
# 1. All secrets (full rotation)
# 2. Database password (zero downtime)
# 3. JWT secret (with grace period)
# 4. API keys and service secrets
# 5. AppRole credentials
```

### Automated Rotation

For production, set up automated secret rotation:

```bash
# Add cron job for weekly rotation
0 2 * * 0 /path/to/sentinel/scripts/secrets-rotate.sh <<< "4"
```

### Zero-Downtime Database Rotation

The database password rotation uses a multi-step process:

1. Generate new password
2. Create new database user/update password
3. Update Vault with new password
4. Wait for services to reload (30s grace period)
5. Revoke old password from database

### JWT Secret Rotation with Grace Period

JWT secret rotation maintains both old and new secrets for 1 hour:

1. Generate new JWT secret
2. Store both `secret_key` (new) and `secret_key_old` in Vault
3. Services accept tokens signed with either key for 1 hour
4. After grace period, remove `secret_key_old`

## Service Integration

### Environment Variables

Each service loads Vault credentials from environment variables:

```bash
VAULT_ADDR=http://localhost:8200
VAULT_ROLE_ID={service-specific-role-id}
VAULT_SECRET_ID={service-specific-secret-id}
ENVIRONMENT=development
```

### Authentication Flow

```python
import hvac

# Load credentials from environment
vault_addr = os.getenv('VAULT_ADDR')
role_id = os.getenv('VAULT_ROLE_ID')
secret_id = os.getenv('VAULT_SECRET_ID')
environment = os.getenv('ENVIRONMENT')

# Authenticate with AppRole
client = hvac.Client(url=vault_addr)
client.auth.approle.login(
    role_id=role_id,
    secret_id=secret_id
)

# Read secrets
database_secrets = client.secrets.kv.v2.read_secret_version(
    path=f'sentinel/{environment}/database'
)

db_password = database_secrets['data']['data']['password']
```

### Token Renewal

Services should automatically renew Vault tokens:

```python
import hvac
import threading
import time

def renew_token(client):
    while True:
        try:
            client.auth.token.renew_self()
            time.sleep(1800)  # Renew every 30 minutes
        except Exception as e:
            print(f"Token renewal failed: {e}")
            # Re-authenticate with AppRole
            client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id
            )

# Start renewal thread
renewal_thread = threading.Thread(target=renew_token, args=(client,))
renewal_thread.daemon = True
renewal_thread.start()
```

## Security Best Practices

### Development Environment

- Use `dev` mode for local development
- Root token is saved to `.vault-keys/root-token.txt`
- Data is stored in memory (not persisted)
- TLS is disabled

### Production Environment

1. **Use Production Mode**:
   ```bash
   # Update docker-compose.vault.yml
   command: server -config=/vault/config/vault.hcl
   ```

2. **Enable TLS**:
   - Generate TLS certificates
   - Configure Vault with HTTPS
   - Update `VAULT_ADDR` to use https://

3. **Seal Configuration**:
   - Use auto-unseal with cloud KMS
   - Never store unseal keys with encrypted data

4. **Backup Strategy**:
   - Regular snapshots using `vault operator raft snapshot save`
   - Store backups in separate secure location
   - Test restore procedures regularly

5. **Audit Logging**:
   ```bash
   vault audit enable file file_path=/vault/logs/audit.log
   ```

6. **Secret TTL**:
   - Reduce token TTL in production
   - Enable secret versioning
   - Implement automated rotation

## Troubleshooting

### Vault Not Accessible

```bash
# Check Vault status
docker logs sentinel_vault

# Verify network
docker network inspect sentinel_network

# Test connectivity
curl http://localhost:8200/v1/sys/health
```

### Authentication Failures

```bash
# Verify AppRole configuration
vault read auth/approle/role/api-gateway-service/role-id

# Check policy assignment
vault token lookup -format=json

# Test login manually
vault write auth/approle/login \
  role_id=$VAULT_ROLE_ID \
  secret_id=$VAULT_SECRET_ID
```

### Missing Secrets

```bash
# List all secrets
vault kv list secret/sentinel/development/

# Check secret metadata
vault kv metadata get secret/sentinel/development/database

# Recreate secrets
./scripts/secrets-init.sh
```

### Permission Denied

```bash
# View effective policy
vault token capabilities secret/sentinel/development/database

# Check policy rules
vault policy read api-gateway-policy

# Update policy if needed
vault policy write api-gateway-policy \
  config/vault/policies/api-gateway-policy.hcl
```

## Monitoring

### Health Check

```bash
# Vault health status
curl http://localhost:8200/v1/sys/health

# Response codes:
# 200: Unsealed and active
# 429: Unsealed and standby
# 473: Performance standby
# 501: Not initialized
# 503: Sealed
```

### Metrics

Vault exposes Prometheus metrics at:
- `/v1/sys/metrics?format=prometheus`

Add to Prometheus configuration:
```yaml
scrape_configs:
  - job_name: 'vault'
    static_configs:
      - targets: ['localhost:8200']
    metrics_path: /v1/sys/metrics
    params:
      format: ['prometheus']
```

## API Reference

### Read Secret

```bash
vault kv get secret/sentinel/development/database
vault kv get -field=password secret/sentinel/development/database
```

### Write Secret

```bash
vault kv put secret/sentinel/development/custom \
  key1=value1 \
  key2=value2
```

### Delete Secret

```bash
vault kv delete secret/sentinel/development/custom
```

### List Secrets

```bash
vault kv list secret/sentinel/development/
```

## Support

For issues or questions:
- Check Vault documentation: https://www.vaultproject.io/docs
- Review Vault logs: `docker logs sentinel_vault`
- Run validation script: `./scripts/secrets-validate.sh`
