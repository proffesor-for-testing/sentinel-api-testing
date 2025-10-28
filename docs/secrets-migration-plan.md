# Secrets Migration Plan - Phase 1.3

## Overview

This document outlines the step-by-step plan to migrate Sentinel from hardcoded secrets to production-grade secrets management using HashiCorp Vault.

## Migration Status

**Current Phase:** Implementation
**Target Completion:** End of Week 1
**Risk Level:** Medium (requires coordination with services)

## Pre-Migration Checklist

### Immediate Actions (CRITICAL - Do First)

- [ ] **Revoke exposed API keys**
  - [ ] Regenerate Anthropic API key (currently exposed: `sk-ant-api03-7q2mHDkEy...`)
  - [ ] Regenerate Google API key (currently exposed: `AIzaSyAhMtzX...`)
  - [ ] Update services with new keys temporarily
  - [ ] Rotate database password (currently: `sentinel_password`)
  - [ ] Change JWT secret (currently using default)
  - [ ] Update default admin password (currently: `admin123`)

- [ ] **Backup current configuration**
  - [ ] Export current .env files to secure location
  - [ ] Document all service configurations
  - [ ] Test current system functionality

### Infrastructure Setup

- [ ] **Deploy Vault Infrastructure**
  - [ ] Start Vault container: `docker-compose -f docker-compose.vault.yml up -d`
  - [ ] Verify Vault accessibility
  - [ ] Initialize Vault cluster
  - [ ] Securely store unseal keys
  - [ ] Securely store root token

- [ ] **Configure Vault**
  - [ ] Enable secrets engines (KV v2, Database)
  - [ ] Enable authentication methods (AppRole, Userpass)
  - [ ] Create policies for each service
  - [ ] Create AppRoles for services
  - [ ] Set up audit logging

- [ ] **Generate New Secrets**
  - [ ] Generate strong database passwords
  - [ ] Generate cryptographically secure JWT secrets (64+ chars)
  - [ ] Generate strong admin passwords
  - [ ] Generate RabbitMQ credentials
  - [ ] Obtain new LLM API keys

## Migration Phases

### Phase 1: Infrastructure & Setup (Days 1-2)

**Goal:** Deploy Vault and configure basic infrastructure

#### Day 1: Vault Deployment

1. **Deploy Vault container:**
```bash
cd /workspaces/api-testing-agents
docker-compose -f docker-compose.vault.yml up -d
```

2. **Initialize Vault:**
```bash
./scripts/secrets-init.sh development
```

3. **Verify deployment:**
```bash
./scripts/secrets-validate.sh development
```

4. **Backup critical files:**
```bash
# Backup to secure location (NOT in repo)
cp .vault-keys/* /secure/backup/location/
```

#### Day 2: Secrets Configuration

1. **Update LLM API keys in Vault:**
```bash
vault kv put secret/sentinel/development/llm \
  anthropic_api_key="<NEW-KEY>" \
  openai_api_key="<KEY>" \
  google_api_key="<NEW-KEY>" \
  mistral_api_key="<KEY>"
```

2. **Verify secrets storage:**
```bash
vault kv get secret/sentinel/development/database
vault kv get secret/sentinel/development/auth
vault kv get secret/sentinel/development/broker
vault kv get secret/sentinel/development/llm
```

3. **Test AppRole authentication:**
```bash
# Get role credentials
vault read auth/approle/role/api-gateway/role-id
vault write -f auth/approle/role/api-gateway/secret-id

# Test login
vault write auth/approle/login \
  role_id="..." \
  secret_id="..."
```

### Phase 2: Service Integration (Days 3-5)

**Goal:** Update services to use Vault for secrets

#### Services Migration Order

1. **Data Service** (Lowest risk - only database)
2. **Execution Service** (Database + Broker)
3. **Spec Service** (Database + LLM)
4. **Auth Service** (Critical - Database + JWT)
5. **Orchestration Service** (Complex - All secrets)
6. **API Gateway** (Final - JWT validation)
7. **Rust Core** (Broker only)

#### Per-Service Migration Steps

For each service:

1. **Add Vault client dependency:**

   **Python:**
   ```bash
   pip install hvac
   echo "hvac>=1.2.1" >> requirements.txt
   ```

   **Rust:**
   ```toml
   # Cargo.toml
   [dependencies]
   vaultrs = "0.7"
   ```

2. **Create Vault client module:**
   - Copy implementation from docs/secrets-management-guide.md
   - Adapt for service-specific needs

3. **Update settings to use Vault:**
   - Modify config/settings.py to fetch from Vault
   - Implement caching for performance
   - Add fallback for development without Vault

4. **Set environment variables:**
   ```bash
   export VAULT_ADDR=http://localhost:8200
   export VAULT_ROLE_ID=<from-init-output>
   export VAULT_SECRET_ID=<from-init-output>
   ```

5. **Test service startup:**
   ```bash
   # Test that service can authenticate and fetch secrets
   python -m sentinel_backend.<service>.main
   ```

6. **Validate functionality:**
   ```bash
   # Run service-specific tests
   pytest sentinel_backend/tests/unit/test_<service>.py
   ```

7. **Monitor logs for issues:**
   ```bash
   docker logs -f sentinel_<service>
   ```

#### Day 3: Low-Risk Services

- [ ] Migrate Data Service
  - [ ] Add Vault client
  - [ ] Update database configuration
  - [ ] Test database connectivity
  - [ ] Run integration tests

- [ ] Migrate Execution Service
  - [ ] Add Vault client
  - [ ] Update database + broker configuration
  - [ ] Test service functionality
  - [ ] Verify task execution

#### Day 4: Medium-Risk Services

- [ ] Migrate Spec Service
  - [ ] Add Vault client
  - [ ] Update database + LLM configuration
  - [ ] Test specification parsing
  - [ ] Verify LLM integration

- [ ] Migrate Rust Core
  - [ ] Add Vault client (vaultrs)
  - [ ] Update broker configuration
  - [ ] Test message processing
  - [ ] Verify agent integration

#### Day 5: High-Risk Services

- [ ] Migrate Auth Service
  - [ ] Add Vault client
  - [ ] Update JWT configuration
  - [ ] Test authentication flow
  - [ ] Verify user creation/login
  - [ ] Test RBAC functionality

- [ ] Migrate Orchestration Service
  - [ ] Add Vault client
  - [ ] Update all secret configurations
  - [ ] Test task orchestration
  - [ ] Verify agent spawning

- [ ] Migrate API Gateway
  - [ ] Add Vault client
  - [ ] Update JWT validation
  - [ ] Test routing functionality
  - [ ] Run end-to-end tests

### Phase 3: Cleanup & Documentation (Days 6-7)

**Goal:** Remove hardcoded secrets and finalize documentation

#### Day 6: Secrets Removal

1. **Remove secrets from .env files:**
```bash
# Backup current .env
cp .env .env.backup

# Replace with template
cp .env.template .env

# Update with Vault configuration only
vim .env  # Set VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID
```

2. **Update .env files for all services:**
```bash
for dir in sentinel_backend/*/; do
  if [ -f "${dir}.env" ]; then
    cp .env.template "${dir}.env"
  fi
done
```

3. **Verify no secrets in version control:**
```bash
# Check for hardcoded secrets
./scripts/secrets-validate.sh development

# Scan git history
git log --all --full-history --source --pretty=format:'%h %s' -- '*.env'

# Remove from history if found
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all
```

4. **Update docker-compose.yml:**
```yaml
services:
  auth_service:
    environment:
      - VAULT_ADDR=http://vault:8200
      - VAULT_ROLE_ID=${VAULT_ROLE_ID}
      - VAULT_SECRET_ID=${VAULT_SECRET_ID}
      - SENTINEL_ENVIRONMENT=development
    # Remove env_file with secrets
```

#### Day 7: Documentation & Testing

1. **Update documentation:**
   - [ ] Update README.md with Vault setup instructions
   - [ ] Create SECRETS.md with quick reference
   - [ ] Update deployment documentation
   - [ ] Create runbook for operations team

2. **Create developer onboarding guide:**
```markdown
# Developer Setup with Vault

## Quick Start

1. Clone repository
2. Start Vault: `docker-compose -f docker-compose.vault.yml up -d`
3. Initialize: `./scripts/secrets-init.sh development`
4. Configure services: Copy `.vault-keys/approle-credentials.development.txt`
5. Start services: `make start`
```

3. **Run comprehensive tests:**
```bash
# Unit tests
cd sentinel_backend && pytest

# Integration tests
./run_tests.sh -d

# E2E tests
cd sentinel_frontend && npm run test:e2e
```

4. **Load testing:**
```bash
# Verify performance with Vault
k6 run scripts/load-test.js
```

### Phase 4: Production Preparation (Week 2)

**Goal:** Prepare for production deployment

#### Staging Environment

1. **Deploy Vault to staging:**
   - Use managed Vault service or HA cluster
   - Configure TLS certificates
   - Set up auto-unseal (AWS KMS/Azure Key Vault)

2. **Initialize staging secrets:**
```bash
./scripts/secrets-init.sh staging
```

3. **Deploy services to staging:**
```bash
# Update CI/CD pipeline with Vault configuration
kubectl apply -f k8s/staging/
```

4. **Run staging validation:**
```bash
./scripts/secrets-validate.sh staging
```

#### Production Planning

1. **Security review:**
   - [ ] Audit all policies
   - [ ] Review access controls
   - [ ] Validate encryption settings
   - [ ] Test disaster recovery procedures

2. **Create production runbook:**
   - [ ] Deployment procedures
   - [ ] Rollback procedures
   - [ ] Secrets rotation schedule
   - [ ] Incident response procedures

3. **Set up monitoring:**
   - [ ] Vault health checks
   - [ ] Secret access monitoring
   - [ ] Audit log analysis
   - [ ] Alerting for anomalies

## Rollback Plan

### If Migration Fails

1. **Immediate rollback:**
```bash
# Restore .env files from backup
cp .env.backup .env

# Restart services with old configuration
docker-compose restart
```

2. **Identify issue:**
   - Check Vault connectivity
   - Verify AppRole credentials
   - Review service logs
   - Test secrets retrieval

3. **Fix and retry:**
   - Address root cause
   - Test fix in isolation
   - Retry migration for affected service

### If Production Issues Occur

1. **Emergency access:**
   - Use break-glass admin credentials
   - Restore from backup if needed

2. **Gradual rollback:**
   - Rollback one service at a time
   - Monitor for stability
   - Keep Vault running for services that work

## Success Criteria

### Technical Metrics

- [ ] Zero secrets in version control
- [ ] All services authenticate to Vault
- [ ] 100% of secrets loaded from Vault
- [ ] Secrets rotation working
- [ ] Audit logging enabled
- [ ] All tests passing

### Operational Metrics

- [ ] Service uptime > 99.9%
- [ ] Mean time to secrets retrieval < 100ms
- [ ] Zero security incidents
- [ ] Developer onboarding time < 30 minutes

### Security Metrics

- [ ] No hardcoded credentials
- [ ] All secrets encrypted at rest
- [ ] All secrets encrypted in transit
- [ ] Complete audit trail
- [ ] Regular rotation schedule active

## Risk Mitigation

### High-Risk Scenarios

1. **Vault becomes unavailable:**
   - **Mitigation:** Use caching with reasonable TTL
   - **Fallback:** Emergency .env file (break-glass)
   - **Prevention:** Deploy HA Vault cluster

2. **Token expiration during operation:**
   - **Mitigation:** Automatic token renewal
   - **Fallback:** Re-authenticate on failure
   - **Prevention:** Long TTL + renewal alerts

3. **Secrets rotation causes outage:**
   - **Mitigation:** Grace period for old secrets
   - **Fallback:** Rollback rotation
   - **Prevention:** Test in staging first

4. **Lost unseal keys:**
   - **Mitigation:** Shamir secret sharing (5 keys, 3 required)
   - **Fallback:** Recovery keys stored securely offline
   - **Prevention:** Multiple key holders + documentation

## Post-Migration Tasks

### Week 2-4

- [ ] Monitor system stability
- [ ] Collect performance metrics
- [ ] Train operations team
- [ ] Schedule first secrets rotation
- [ ] Conduct security audit
- [ ] Update disaster recovery procedures

### Ongoing

- [ ] Monthly security reviews
- [ ] Quarterly secrets rotation
- [ ] Annual penetration testing
- [ ] Continuous monitoring and improvement

## Support & Escalation

### Issues & Questions

- **Technical Issues:** Create GitHub issue
- **Security Incidents:** Email security@sentinel.com
- **Operations Support:** Contact DevOps team

### Escalation Path

1. Service Owner
2. Tech Lead
3. Security Team
4. CTO/CISO

## Appendix

### Useful Commands

```bash
# Check Vault status
vault status

# Unseal Vault
vault operator unseal

# List secrets
vault kv list secret/sentinel/development

# Get secret
vault kv get secret/sentinel/development/database

# Rotate secret
./scripts/secrets-rotate.sh development jwt

# Validate configuration
./scripts/secrets-validate.sh development

# View audit log
docker exec sentinel_vault cat /vault/logs/audit.log | tail -n 100
```

### Reference Documentation

- [Secrets Management Guide](./secrets-management-guide.md)
- [Vault Policies](../config/vault/policies/)
- [Secrets Audit Report](./secrets-audit-report.md)

---

**Document Version:** 1.0
**Last Updated:** 2025-10-27
**Next Review:** 2025-11-03
