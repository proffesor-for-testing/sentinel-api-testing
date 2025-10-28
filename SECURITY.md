# Security Policy

## 🔒 Security at Sentinel

Sentinel takes security seriously. We are committed to ensuring the security of our platform and protecting our users' data. This document outlines our security policy, including supported versions, how to report vulnerabilities, and our security practices.

---

## 📋 Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Security Best Practices](#security-best-practices)
- [Known Security Considerations](#known-security-considerations)
- [Security Features](#security-features)
- [Disclosure Policy](#disclosure-policy)
- [Security Updates](#security-updates)
- [Contact](#contact)

---

## 📌 Supported Versions

We actively support the following versions of Sentinel with security updates:

| Version | Supported          | End of Life |
| ------- | ------------------ | ----------- |
| 1.0.x   | :white_check_mark: | TBD         |
| < 1.0   | :x:                | 2025-10-28  |

**Note**: Only the latest minor version of each major release receives security updates. We recommend always running the latest version.

---

## 🚨 Reporting a Vulnerability

We take all security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### ⚠️ **DO NOT** Report Security Vulnerabilities Through Public GitHub Issues

### ✅ **DO** Report via Private Security Advisory

#### Option 1: GitHub Security Advisory (Preferred)

1. Go to the [Security tab](https://github.com/proffesor-for-testing/sentinel-api-testing/security/advisories)
2. Click "Report a vulnerability"
3. Fill out the form with detailed information
4. Submit the advisory

#### Option 2: Direct Contact

If you prefer not to use GitHub's advisory system, you can report vulnerabilities via:

- **Email**: security@sentinel-testing.io *(if available)*
- **Subject Line**: `[SECURITY] Brief description of the issue`

### 📝 What to Include in Your Report

To help us triage and fix the issue quickly, please include:

1. **Type of vulnerability** (e.g., SQL injection, XSS, authentication bypass)
2. **Affected component(s)** (e.g., API Gateway, Auth Service, Frontend)
3. **Affected version(s)** or commit hash
4. **Step-by-step instructions to reproduce** the vulnerability
5. **Proof of concept** or exploit code (if applicable)
6. **Potential impact** of the vulnerability
7. **Suggested fix** (if you have one)
8. **Your contact information** for follow-up questions

### 🕐 Response Timeline

| Stage | Timeline |
|-------|----------|
| **Initial Response** | Within 24-48 hours |
| **Triage & Assessment** | Within 3-5 business days |
| **Fix Development** | Depends on severity (1-30 days) |
| **Security Advisory** | Published with fix release |
| **Public Disclosure** | 90 days after fix or by mutual agreement |

### 🏆 Recognition

We appreciate responsible disclosure and will:

- Acknowledge your contribution in our security advisories (if desired)
- Credit you in release notes (if desired)
- Work with you on disclosure timing
- Consider security bug bounty programs in the future

---

## 🛡️ Security Best Practices

### For Deployment

#### 1. **Environment Variables & Secrets**

**❌ Never commit secrets to version control:**
- API keys (Anthropic, OpenAI, Google, etc.)
- Database passwords
- JWT secret keys
- Service credentials

**✅ Use secure secret management:**
```bash
# Use environment variables
export SENTINEL_APP_ANTHROPIC_API_KEY="your-key"
export SENTINEL_SECURITY_JWT_SECRET_KEY="$(openssl rand -base64 64)"

# Or use secrets management tools
# - HashiCorp Vault
# - AWS Secrets Manager
# - Azure Key Vault
# - Kubernetes Secrets
```

#### 2. **Database Security**

**✅ Production database configuration:**
```bash
# Use strong passwords (minimum 32 characters)
export SENTINEL_DB_PASSWORD="$(openssl rand -base64 32)"

# Enable SSL/TLS for database connections
export SENTINEL_DB_SSL_MODE="require"

# Restrict network access
# Only allow connections from backend services
```

#### 3. **Authentication & Authorization**

**✅ JWT Configuration:**
```bash
# Use strong secret key (minimum 64 characters)
export SENTINEL_SECURITY_JWT_SECRET_KEY="$(openssl rand -base64 64)"

# Set appropriate token expiration
export SENTINEL_SECURITY_JWT_EXPIRATION_HOURS=24

# Use secure algorithm (HS256 or RS256)
export SENTINEL_SECURITY_JWT_ALGORITHM="HS256"
```

#### 4. **CORS Configuration**

**✅ Restrict CORS origins in production:**
```python
# In sentinel_backend/config/settings.py
ALLOWED_ORIGINS = [
    "https://your-production-domain.com",
    "https://app.your-domain.com"
]
# Do NOT use ["*"] in production
```

#### 5. **Network Security**

**✅ Use HTTPS/TLS:**
- Enable HTTPS for all external-facing services
- Use valid SSL/TLS certificates (Let's Encrypt)
- Enforce HTTPS redirects
- Enable HSTS (HTTP Strict Transport Security)

**✅ Network segmentation:**
- Keep database and message broker on private networks
- Use firewalls to restrict access
- Implement network policies in Kubernetes

#### 6. **Docker Security**

**✅ Container security:**
```yaml
# Run containers as non-root user
user: "1000:1000"

# Use read-only root filesystem where possible
read_only: true

# Drop unnecessary capabilities
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE

# Use security options
security_opt:
  - no-new-privileges:true
```

### For Development

#### 1. **Dependency Management**

**✅ Keep dependencies updated:**
```bash
# Backend (Python)
cd sentinel_backend
poetry update
poetry audit  # Check for known vulnerabilities

# Frontend (Node.js)
cd sentinel_frontend
npm audit fix
npm outdated
```

#### 2. **Code Security**

**✅ Input validation:**
- Validate all user inputs
- Sanitize data before database queries
- Use parameterized queries (avoid SQL injection)
- Validate API specification uploads
- Implement rate limiting

**✅ Output encoding:**
- Encode data before rendering in UI
- Prevent XSS attacks
- Use Content Security Policy (CSP)

#### 3. **Testing**

**✅ Security testing:**
```bash
# Run security tests
pytest tests/security/ -v

# Run vulnerability scanning
bandit -r sentinel_backend/
safety check

# Frontend security audit
npm audit
```

---

## ⚠️ Known Security Considerations

### Current Security Posture

#### ✅ Implemented Protections

1. **Authentication**
   - JWT-based authentication
   - Password hashing with bcrypt
   - Token expiration
   - Secure session management

2. **Authorization**
   - Role-based access control (RBAC)
   - Resource-level permissions
   - API endpoint protection

3. **Data Protection**
   - SQL injection prevention (SQLAlchemy ORM)
   - Input validation
   - Output encoding
   - CORS configuration

4. **Infrastructure**
   - Docker containerization
   - Service isolation
   - Health checks
   - Structured logging

#### ⚠️ Areas for Enhancement

The following areas are under active development for enhanced security:

1. **Secrets Management**
   - Currently using environment variables
   - **Recommendation**: Implement HashiCorp Vault or cloud-based secret management
   - **Tracking**: See `docs/secrets-audit-report.md`

2. **TLS/HTTPS**
   - Development uses HTTP
   - **Recommendation**: Enable HTTPS for production deployments
   - **Status**: Configuration documented, implementation required

3. **API Rate Limiting**
   - Basic rate limiting implemented
   - **Recommendation**: Implement per-user and per-endpoint rate limits
   - **Status**: Planned for v1.1.0

4. **Audit Logging**
   - Application logging implemented
   - **Recommendation**: Centralized security audit trail
   - **Status**: Planned for v1.1.0

5. **Multi-Factor Authentication (MFA)**
   - Not currently implemented
   - **Recommendation**: Add TOTP-based MFA
   - **Status**: Planned for v1.2.0

### Security Testing Notes

#### AI Agent Security

- **LLM Prompt Injection**: Agents test for this vulnerability
- **Generated Test Data**: Validated before execution
- **API Requests**: Rate-limited and sanitized

#### Test Execution Security

- **Isolated Execution**: Tests run in containerized environments
- **Network Boundaries**: Test traffic isolated from production
- **Data Sanitization**: Test data sanitized before storage

---

## 🔐 Security Features

### Current Security Features

#### 1. Authentication & Authorization
- JWT-based authentication with secure tokens
- Role-based access control (Admin, Manager, Tester, Viewer)
- Password hashing with bcrypt
- Session management with token expiration

#### 2. API Security
- Input validation on all endpoints
- SQL injection prevention (SQLAlchemy ORM)
- CORS configuration
- Request size limits
- Rate limiting (basic implementation)

#### 3. Data Security
- Encrypted database connections (asyncpg with SSL)
- Sensitive data redacted from logs
- Secure session storage
- Environment-based configuration

#### 4. Infrastructure Security
- Docker containerization
- Service isolation
- Health monitoring
- Structured logging with correlation IDs
- Non-root container users (recommended)

#### 5. Security Testing
- Security testing agents (Auth, Injection)
- 272+ security-related tests
- Automated vulnerability scanning in CI/CD
- Regular dependency audits

### Planned Security Features (Roadmap)

#### v1.1.0
- [ ] Enhanced rate limiting per user/endpoint
- [ ] Centralized security audit logging
- [ ] Automated vulnerability scanning integration
- [ ] Content Security Policy (CSP) headers

#### v1.2.0
- [ ] Multi-factor authentication (TOTP)
- [ ] IP allowlisting/blocklisting
- [ ] Advanced threat detection
- [ ] Security dashboard

#### v1.3.0
- [ ] Secrets rotation automation
- [ ] Certificate management
- [ ] Security compliance reports (SOC 2, ISO 27001)
- [ ] Penetration testing integration

---

## 📢 Disclosure Policy

### Responsible Disclosure

We follow a **coordinated disclosure** process:

1. **Private Notification**: You report the vulnerability privately
2. **Acknowledgment**: We acknowledge receipt within 24-48 hours
3. **Investigation**: We investigate and develop a fix
4. **Fix Development**: We create and test the security patch
5. **Release**: We release the patched version
6. **Advisory**: We publish a security advisory
7. **Public Disclosure**: Details disclosed 90 days after fix or by agreement

### Public Disclosure Timeline

- **Critical vulnerabilities**: Immediate patch, 7-day disclosure
- **High severity**: 14-30 day patch, 30-day disclosure
- **Medium severity**: 30-60 day patch, 60-day disclosure
- **Low severity**: 60-90 day patch, 90-day disclosure

We may request extended disclosure timelines for complex issues, which we'll negotiate in good faith.

---

## 🔄 Security Updates

### How We Communicate Security Updates

1. **GitHub Security Advisories**: Primary channel for security announcements
2. **Release Notes**: Security fixes highlighted in release notes
3. **CVE Database**: Critical vulnerabilities assigned CVE identifiers
4. **Mailing List**: Security-focused mailing list (planned)

### Subscribing to Security Updates

- **Watch Repository**: Click "Watch" → "Custom" → "Security alerts"
- **GitHub Advisories**: Follow [Security Advisories](https://github.com/proffesor-for-testing/sentinel-api-testing/security/advisories)
- **Release Notes**: Check [Releases](https://github.com/proffesor-for-testing/sentinel-api-testing/releases) for security sections

### Applying Security Updates

```bash
# Check current version
git describe --tags

# Update to latest secure version
git fetch --tags
git checkout v1.0.x  # Latest patch version

# Rebuild and redeploy
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Verify update
make status
```

---

## 📞 Contact

### Security Team

- **GitHub Security Advisories**: [Report a Vulnerability](https://github.com/proffesor-for-testing/sentinel-api-testing/security/advisories/new)
- **Email**: security@sentinel-testing.io *(if available)*
- **GitHub Issues**: For non-security bugs only

### General Questions

For general security questions or best practices:
- **GitHub Discussions**: [Security Category](https://github.com/proffesor-for-testing/sentinel-api-testing/discussions/categories/security)
- **Documentation**: [Security Guide](docs/deployment/security-hardening.md)

---

## 🏅 Hall of Fame

We recognize and thank the following security researchers who have responsibly disclosed vulnerabilities:

<!-- Hall of Fame will be updated as researchers contribute -->

*No vulnerabilities reported yet. Be the first to help secure Sentinel!*

---

## 📚 Additional Resources

### Security Documentation

- [Deployment Security Guide](docs/deployment/security-hardening.md) *(planned)*
- [Secrets Management Guide](docs/secrets-audit-report.md)
- [OWASP Top 10 Mitigation](docs/security/owasp-mitigation.md) *(planned)*
- [Compliance Documentation](docs/security/compliance.md) *(planned)*

### External Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)

---

## 📜 License

This security policy is part of the Sentinel project and is licensed under the same [MIT License](LICENSE).

---

## 🙏 Thank You

Thank you for helping keep Sentinel and our users safe!

Your responsible disclosure of security vulnerabilities helps us maintain a secure platform for the entire community.

---

**Last Updated**: 2025-10-28
**Version**: 1.0
**Status**: Active

🛡️ Sentinel Security Team
