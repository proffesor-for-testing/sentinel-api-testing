# Sentinel Secrets Management Guide

## Overview

This guide provides comprehensive documentation for managing secrets in the Sentinel platform using HashiCorp Vault. The implementation follows security best practices and enables zero-trust security architecture.

## Table of Contents

1. [Architecture](#architecture)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Integration](#service-integration)
6. [Secrets Rotation](#secrets-rotation)
7. [Monitoring & Auditing](#monitoring--auditing)
8. [Troubleshooting](#troubleshooting)
9. [Production Deployment](#production-deployment)
10. [Security Best Practices](#security-best-practices)

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Secrets Management Flow                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Service Startup                                          │
│     ├── Load VAULT_ADDR from environment                    │
│     ├── Authenticate using AppRole (role-id + secret-id)    │
│     └── Receive time-limited Vault token                    │
│                                                              │
│  2. Secrets Retrieval                                        │
│     ├── Request secrets from Vault using token              │
│     ├── Vault validates token + policy permissions          │
│     ├── Secrets returned if authorized                      │
│     └── Service caches secrets (configurable TTL)           │
│                                                              │
│  3. Runtime                                                  │
│     ├── Use cached secrets for operations                   │
│     ├── Renew Vault token before expiration                 │
│     └── Re-fetch secrets on cache expiration                │
│                                                              │
│  4. Secrets Rotation                                         │
│     ├── Admin triggers rotation (manual/automated)          │
│     ├── New secrets generated and stored in Vault           │
│     ├── Services detect change and refresh cache            │
│     └── Old secrets deprecated after grace period           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Security Model

- **Zero-Trust Architecture**: No hardcoded secrets, all access authenticated and authorized
- **Least Privilege**: Services only access secrets they need
- **Audit Trail**: All secret access logged to audit log
- **Automatic Rotation**: Secrets rotated on schedule (90 days default)
- **Encryption**: Secrets encrypted at rest and in transit

## Quick Start

### Development Environment

```bash
# 1. Start Vault container
docker-compose -f docker-compose.vault.yml up -d

# 2. Initialize Vault and generate secrets
./scripts/secrets-init.sh development

# 3. Validate configuration
./scripts/secrets-validate.sh development

# 4. Start Sentinel services
make start
```

### First-Time Setup

```bash
# Install Vault CLI
brew install vault  # macOS
# or
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault

# Verify installation
vault version
```

## Installation

### Local Development (Docker)

1. **Deploy Vault Container:**

```bash
docker-compose -f docker-compose.vault.yml up -d
```

This starts:
- Vault server (port 8200)
- Vault UI (port 8000) - Development only

2. **Initialize Vault:**

```bash
./scripts/secrets-init.sh development
```

This will:
- Initialize Vault cluster
- Generate unseal keys and root token
- Create secrets hierarchy
- Configure authentication backends
- Generate development secrets

3. **Save Critical Files:**

The initialization creates:
- `.vault-keys/unseal-keys.txt` - Unseal keys (required to unseal Vault)
- `.vault-keys/root-token.txt` - Root access token
- `.vault-keys/approle-credentials.development.txt` - Service authentication credentials

⚠️ **CRITICAL**: Back up these files to a secure location and remove from the filesystem.

### Production Deployment

For production, use a managed Vault service or deploy a high-availability cluster:

**Managed Services:**
- AWS: HashiCorp Cloud Platform (HCP) Vault
- Azure: HashiCorp Vault on Azure Kubernetes Service
- GCP: Vault on Google Cloud

**Self-Hosted HA Cluster:**

```yaml
# vault-config.hcl
storage "consul" {
  address = "consul:8500"
  path    = "vault/"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/vault/config/tls/cert.pem"
  tls_key_file  = "/vault/config/tls/key.pem"
}

api_addr = "https://vault.example.com:8200"
cluster_addr = "https://vault.example.com:8201"
ui = true
```

## Configuration

### Secrets Hierarchy

```
secret/sentinel/
├── development/
│   ├── database/
│   │   ├── username
│   │   ├── password
│   │   ├── host
│   │   ├── port
│   │   └── url
│   ├── auth/
│   │   ├── jwt_secret_key
│   │   ├── jwt_algorithm
│   │   ├── jwt_expiration_hours
│   │   ├── admin_email
│   │   └── admin_password
│   ├── broker/
│   │   ├── username
│   │   ├── password
│   │   ├── host
│   │   ├── port
│   │   └── url
│   └── llm/
│       ├── anthropic_api_key
│       ├── openai_api_key
│       ├── google_api_key
│       └── mistral_api_key
├── staging/
│   └── [same structure]
└── production/
    └── [same structure]
```

### Access Policies

Each service has a dedicated policy defining what secrets it can access:

| Service | Policy | Secrets Access |
|---------|--------|----------------|
| API Gateway | `sentinel-api-gateway` | auth (read) |
| Auth Service | `sentinel-auth` | auth (read), database (read) |
| Spec Service | `sentinel-spec` | database (read), llm (read) |
| Orchestration | `sentinel-orchestration` | broker (read), llm (read), database (read) |
| Execution | `sentinel-execution` | database (read), broker (read) |
| Data Service | `sentinel-data` | database (read) |
| Rust Core | `sentinel-rust-core` | broker (read) |

### Environment Variables

Services need these environment variables:

```bash
# Vault Configuration
VAULT_ADDR=http://localhost:8200
VAULT_ROLE_ID=<from secrets-init.sh>
VAULT_SECRET_ID=<from secrets-init.sh>

# Application Configuration
SENTINEL_ENVIRONMENT=development
VAULT_SECRETS_PATH=secret/sentinel/development
VAULT_TOKEN_RENEW_THRESHOLD=300  # Renew token 5 min before expiry
VAULT_CACHE_TTL=3600  # Cache secrets for 1 hour
```

## Service Integration

### Python Services (FastAPI)

**1. Install Vault Client:**

```bash
pip install hvac
```

**2. Create Vault Client Module:**

```python
# sentinel_backend/utils/vault_client.py
import os
import hvac
from functools import lru_cache
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class VaultClient:
    """HashiCorp Vault client for secrets management."""

    def __init__(self):
        self.vault_addr = os.getenv("VAULT_ADDR", "http://localhost:8200")
        self.role_id = os.getenv("VAULT_ROLE_ID")
        self.secret_id = os.getenv("VAULT_SECRET_ID")
        self.environment = os.getenv("SENTINEL_ENVIRONMENT", "development")
        self.base_path = f"secret/sentinel/{self.environment}"

        self.client = hvac.Client(url=self.vault_addr)
        self._authenticate()

    def _authenticate(self):
        """Authenticate to Vault using AppRole."""
        if not self.role_id or not self.secret_id:
            raise ValueError("VAULT_ROLE_ID and VAULT_SECRET_ID must be set")

        response = self.client.auth.approle.login(
            role_id=self.role_id,
            secret_id=self.secret_id
        )

        self.client.token = response["auth"]["client_token"]
        logger.info("Successfully authenticated to Vault")

    def get_secret(self, path: str) -> Dict[str, Any]:
        """
        Retrieve a secret from Vault.

        Args:
            path: Secret path relative to base_path (e.g., "database")

        Returns:
            Dictionary containing secret data
        """
        full_path = f"{self.base_path}/{path}"

        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=full_path
            )
            return response["data"]["data"]
        except Exception as e:
            logger.error(f"Failed to read secret {full_path}: {e}")
            raise

    def renew_token(self):
        """Renew Vault token."""
        self.client.auth.token.renew_self()
        logger.info("Vault token renewed")

@lru_cache()
def get_vault_client() -> VaultClient:
    """Get cached Vault client instance."""
    return VaultClient()
```

**3. Update Settings to Use Vault:**

```python
# sentinel_backend/config/settings.py
from utils.vault_client import get_vault_client

class DatabaseSettings(BaseSettings):
    """Database configuration from Vault."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Load from Vault if available
        if os.getenv("VAULT_ADDR"):
            vault = get_vault_client()
            db_secrets = vault.get_secret("database")

            self.url = db_secrets["url"]
            # Override other settings from Vault as needed

class SecuritySettings(BaseSettings):
    """Security configuration from Vault."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        if os.getenv("VAULT_ADDR"):
            vault = get_vault_client()
            auth_secrets = vault.get_secret("auth")

            self.jwt_secret_key = auth_secrets["jwt_secret_key"]
            self.default_admin_email = auth_secrets["admin_email"]
            self.default_admin_password = auth_secrets["admin_password"]
```

**4. Add Token Renewal Task:**

```python
# sentinel_backend/tasks/vault_renewal.py
from apscheduler.schedulers.background import BackgroundScheduler
from utils.vault_client import get_vault_client
import logging

logger = logging.getLogger(__name__)

def renew_vault_token():
    """Background task to renew Vault token."""
    try:
        vault = get_vault_client()
        vault.renew_token()
        logger.info("Vault token renewed successfully")
    except Exception as e:
        logger.error(f"Failed to renew Vault token: {e}")

def start_vault_renewal_task():
    """Start background task for token renewal."""
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        renew_vault_token,
        'interval',
        minutes=15,  # Renew every 15 minutes
        id='vault_token_renewal'
    )
    scheduler.start()
    logger.info("Vault token renewal task started")
```

### Rust Services

**1. Add Vault Dependency:**

```toml
# Cargo.toml
[dependencies]
vaultrs = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

**2. Create Vault Client:**

```rust
// src/vault.rs
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize)]
pub struct BrokerSecrets {
    pub username: String,
    pub password: String,
    pub url: String,
}

pub struct VaultManager {
    client: VaultClient,
    base_path: String,
}

impl VaultManager {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let vault_addr = env::var("VAULT_ADDR")
            .unwrap_or_else(|_| "http://localhost:8200".to_string());
        let role_id = env::var("VAULT_ROLE_ID")?;
        let secret_id = env::var("VAULT_SECRET_ID")?;
        let environment = env::var("SENTINEL_ENVIRONMENT")
            .unwrap_or_else(|_| "development".to_string());

        let base_path = format!("secret/data/sentinel/{}", environment);

        // Create client
        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(&vault_addr)
                .build()?
        )?;

        // Authenticate with AppRole
        let auth_response = vaultrs::auth::approle::login(
            &client,
            "approle",
            &role_id,
            &secret_id,
        ).await?;

        client.set_token(&auth_response.client_token);

        Ok(Self { client, base_path })
    }

    pub async fn get_broker_secrets(&self) -> Result<BrokerSecrets, Box<dyn std::error::Error>> {
        let path = format!("{}/broker", self.base_path);
        let secret: BrokerSecrets = kv2::read(&self.client, "secret", &path).await?;
        Ok(secret)
    }
}
```

## Secrets Rotation

### Manual Rotation

```bash
# Rotate specific secret type
./scripts/secrets-rotate.sh development database
./scripts/secrets-rotate.sh development jwt
./scripts/secrets-rotate.sh development admin
./scripts/secrets-rotate.sh development broker

# Rotate all secrets
./scripts/secrets-rotate.sh development all
```

### Automated Rotation

**1. Create Cron Job:**

```bash
# Add to crontab (runs every 90 days at 2 AM)
0 2 */90 * * /path/to/scripts/secrets-rotate.sh production all >> /var/log/sentinel/rotation.log 2>&1
```

**2. Vault Dynamic Secrets (Recommended for Production):**

Configure Vault to automatically rotate database credentials:

```bash
# Configure PostgreSQL secrets engine
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    allowed_roles="sentinel-db" \
    connection_url="postgresql://{{username}}:{{password}}@localhost:5432/sentinel_db" \
    username="vault" \
    password="vault-password"

# Create role with automatic rotation
vault write database/roles/sentinel-db \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"
```

### Rotation Best Practices

1. **Grace Period**: Keep old secrets valid for 24 hours during rotation
2. **Monitoring**: Alert on rotation failures
3. **Testing**: Test rotation in staging before production
4. **Documentation**: Log all rotations with timestamps
5. **Rollback Plan**: Keep previous version accessible for emergency rollback

## Monitoring & Auditing

### Enable Audit Logging

```bash
# Enable file-based audit logging
vault audit enable file file_path=/vault/logs/audit.log

# Enable syslog audit logging
vault audit enable syslog tag="vault" facility="LOCAL7"
```

### Audit Log Format

```json
{
  "time": "2025-10-27T12:34:56.789Z",
  "type": "response",
  "auth": {
    "client_token": "hmac-sha256:...",
    "accessor": "hmac-sha256:...",
    "display_name": "approle",
    "policies": ["sentinel-auth"],
    "token_policies": ["sentinel-auth"]
  },
  "request": {
    "id": "abc-123-def",
    "operation": "read",
    "client_token": "hmac-sha256:...",
    "path": "secret/data/sentinel/production/database"
  },
  "response": {
    "data": {
      "data": null,
      "metadata": null
    }
  }
}
```

### Monitoring Metrics

Track these key metrics:

- **Secret Access Frequency**: Monitor unusual access patterns
- **Authentication Failures**: Alert on repeated failures
- **Token Expiration**: Track tokens nearing expiration
- **Seal Status**: Alert if Vault becomes sealed
- **Audit Log Growth**: Monitor disk usage
- **Policy Violations**: Track denied access attempts

### Integration with Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'vault'
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
    bearer_token: 'vault-token'
    static_configs:
      - targets: ['vault:8200']
```

## Troubleshooting

### Common Issues

**1. Vault is Sealed**

```bash
# Check status
vault status

# Unseal with keys
vault operator unseal <key-1>
vault operator unseal <key-2>
vault operator unseal <key-3>
```

**2. Authentication Failed**

```bash
# Verify AppRole exists
vault read auth/approle/role/api-gateway

# Generate new secret-id
vault write -f auth/approle/role/api-gateway/secret-id

# Test authentication
vault write auth/approle/login role_id="..." secret_id="..."
```

**3. Permission Denied**

```bash
# Check token capabilities
vault token capabilities secret/sentinel/development/database

# Verify policy
vault policy read sentinel-api-gateway

# Check token info
vault token lookup
```

**4. Secret Not Found**

```bash
# List secrets
vault kv list secret/sentinel/development

# Read secret
vault kv get secret/sentinel/development/database

# Check metadata
vault kv metadata get secret/sentinel/development/database
```

**5. Service Can't Connect to Vault**

```bash
# Test connectivity
curl http://localhost:8200/v1/sys/health

# Check network
docker network inspect sentinel_network

# Verify environment variables
env | grep VAULT
```

### Debug Mode

Enable debug logging for Vault client:

```python
# Python
import logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("hvac").setLevel(logging.DEBUG)
```

```rust
// Rust
env::set_var("RUST_LOG", "vaultrs=debug");
env_logger::init();
```

## Production Deployment

### Pre-Deployment Checklist

- [ ] Vault cluster deployed with HA configuration
- [ ] TLS certificates configured for Vault API
- [ ] Unseal keys securely distributed (Shamir's Secret Sharing)
- [ ] Root token securely stored and access restricted
- [ ] Audit logging enabled and monitored
- [ ] Backup strategy implemented for Vault data
- [ ] Monitoring and alerting configured
- [ ] Secrets rotation schedule configured
- [ ] All services tested with Vault integration
- [ ] Disaster recovery plan documented

### Deployment Steps

**1. Deploy Vault Cluster:**

```bash
# Use Terraform, Helm, or cloud provider
terraform apply -var="environment=production"
```

**2. Initialize Production Secrets:**

```bash
./scripts/secrets-init.sh production
```

**3. Configure Service Authentication:**

```bash
# For each service, set environment variables:
export VAULT_ADDR=https://vault.example.com
export VAULT_ROLE_ID=<production-role-id>
export VAULT_SECRET_ID=<production-secret-id>
export SENTINEL_ENVIRONMENT=production
```

**4. Deploy Services:**

```bash
# Deploy with updated environment variables
kubectl apply -f k8s/production/
```

**5. Validate:**

```bash
./scripts/secrets-validate.sh production
```

### High Availability Configuration

```hcl
# vault-ha.hcl
storage "raft" {
  path = "/vault/data"
  node_id = "vault-node-1"

  retry_join {
    leader_api_addr = "https://vault-node-2:8200"
  }

  retry_join {
    leader_api_addr = "https://vault-node-3:8200"
  }
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/cert.pem"
  tls_key_file  = "/vault/tls/key.pem"
}

api_addr = "https://vault-node-1.example.com:8200"
cluster_addr = "https://vault-node-1.example.com:8201"
ui = true

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
```

## Security Best Practices

### 1. Principle of Least Privilege

- Grant services only the secrets they need
- Use dedicated policies per service
- Regularly audit access patterns

### 2. Secret Rotation

- Rotate secrets every 90 days (minimum)
- Use dynamic secrets when possible
- Automate rotation process

### 3. Audit Everything

- Enable comprehensive audit logging
- Monitor for suspicious access patterns
- Alert on policy violations

### 4. Network Security

- Use TLS for all Vault communication
- Restrict Vault access to service network
- Use mTLS for service authentication (production)

### 5. Key Management

- Use HSM for encryption keys (production)
- Distribute unseal keys using Shamir's Secret Sharing
- Store root token in secure vault (not on filesystem)

### 6. Backup & Recovery

- Regular automated backups of Vault data
- Test recovery procedures quarterly
- Maintain offline backup of unseal keys

### 7. Access Control

- Use AppRole for service authentication
- Require MFA for human access
- Implement IP allowlisting

### 8. Monitoring

- Monitor Vault health continuously
- Alert on seal status changes
- Track secret access patterns

## Additional Resources

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Vault Best Practices](https://learn.hashicorp.com/tutorials/vault/production-hardening)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Sentinel Project Repository](https://github.com/sentinel/api-testing-agents)

## Support

For issues or questions:
- GitHub Issues: https://github.com/sentinel/api-testing-agents/issues
- Security Issues: security@sentinel.com
- Documentation: https://docs.sentinel.com

---

**Last Updated:** 2025-10-27
**Version:** 1.0.0
**Maintained by:** Security Infrastructure Team
