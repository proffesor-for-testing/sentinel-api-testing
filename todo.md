# Configuration Modularization TODO

This document tracks the progress of moving hardcoded values to configuration files to make the Sentinel project more modular and maintainable.

## Overview

The goal is to create a centralized configuration system that supports:
- Environment-specific configurations (development, testing, production)
- Environment variable overrides
- Secure handling of sensitive data
- Easy deployment and maintenance

## Configuration Framework Setup

### ✅ Core Configuration Infrastructure
- [x] Create `sentinel_backend/config/` directory structure
- [x] Implement `sentinel_backend/config/settings.py` with Pydantic BaseSettings
- [x] Create environment-specific configuration files:
  - [x] `config/development.env`
  - [x] `config/production.env` 
  - [x] `config/testing.env`
  - [x] `config/docker.env`
- [x] Add configuration validation and error handling
- [x] Create configuration loading utilities

**Implementation Notes:**
- Created comprehensive Pydantic BaseSettings configuration system with type safety
- Implemented environment-specific configuration files with appropriate defaults
- Added configuration validation with custom validators for security settings
- Created modular configuration sections: Database, Services, Security, Network, Application
- Implemented caching with @lru_cache for performance
- Added environment detection and automatic config file loading

## Database Configuration

### ✅ Database Settings Centralization
- [x] **data_service/main.py**: Move `DATABASE_URL` to config
  - Current: `postgresql+asyncpg://user:password@localhost/sentinel_db`
- [x] **spec_service/main.py**: Move `DATABASE_URL` to config
  - Current: `postgresql+asyncpg://user:password@localhost/sentinel_db`
- [ ] **execution_service/main.py**: Move database configuration to config
- [ ] **docker-compose.yml**: Move database credentials to environment files
  - Current: `POSTGRES_PASSWORD=supersecretpassword`
  - Current: `POSTGRES_USER=sentinel`
  - Current: `POSTGRES_DB=sentinel_db`
- [x] Add database pool configuration (min/max connections, timeouts)
- [x] Add database migration settings

**Implementation Notes:**
- Updated data_service and spec_service to use centralized configuration
- Added comprehensive database pool settings (pool_size, max_overflow, pool_timeout, pool_recycle)
- Integrated database migration settings in configuration
- Added python-dotenv and pydantic dependencies to pyproject.toml
- Services now use get_database_settings() for type-safe configuration access

## Service URLs & Inter-Service Communication

### ✅ Service Discovery Configuration
- [x] **api_gateway/main.py**: Move all service URLs to config
  - Current: `AUTH_SERVICE_URL = "http://auth_service:8005"`
  - Current: `SPEC_SERVICE_URL = "http://spec_service:8000"`
  - Current: `ORCHESTRATION_SERVICE_URL = "http://orchestration_service:8000"`
  - Current: `DATA_SERVICE_URL = "http://data_service:8000"`
  - Current: `EXECUTION_SERVICE_URL = "http://execution_service:8000"`
- [x] **orchestration_service/main.py**: Move service URLs to config
  - ✅ Updated to use `service_settings.spec_service_url`, `service_settings.data_service_url`, `service_settings.execution_service_url`
  - ✅ Added proper timeout configuration using `service_settings.service_timeout`
  - ✅ Updated logging configuration from `app_settings`
- [x] **execution_service/main.py**: Move service URLs to config
  - ✅ Updated to use `service_settings.data_service_url`
  - ✅ Added proper timeout configuration using `service_settings.service_timeout` and `app_settings.test_execution_timeout`
  - ✅ Updated logging configuration from `app_settings`
- [x] **auth_service/auth_middleware.py**: Move service URLs to config
  - ✅ Updated to use `service_settings.auth_service_url`
  - ✅ Added proper timeout configuration using `service_settings.service_timeout`

**Implementation Notes:**
- Updated API Gateway to use service_settings.auth_service_url, service_settings.spec_service_url, etc.
- Replaced all hardcoded service URLs with configuration-based references
- Added proper timeout configuration using service_settings.service_timeout
- Integrated logging configuration from app_settings
- All HTTP clients now use centralized timeout settings

## Security Configuration

### ✅ Security Settings Centralization
- [ ] **auth_service/main.py**: Move security settings to config
  - Current: `JWT_SECRET_KEY = "sentinel-secret-key-change-in-production"`
  - Current: `JWT_ALGORITHM = "HS256"`
  - Current: `JWT_EXPIRATION_HOURS = 24`
  - Current: Admin password `"admin123"`
- [ ] Add password policy configuration
- [ ] Add session timeout settings
- [ ] Add CORS configuration
- [ ] Add rate limiting settings
- [ ] Create secure secret management for production

## Network & Infrastructure Configuration

### ✅ Network Settings
- [ ] **docker-compose.yml**: Move all port mappings to config
  - Current: API Gateway `"8000:8000"`
  - Current: Auth Service `"8005:8000"`
  - Current: Spec Service `"8001:8001"`
  - Current: Orchestration Service `"8002:8002"`
  - Current: Execution Service `"8003:8003"`
  - Current: Data Service `"8004:8004"`
  - Current: Database `"5432:5432"`
- [ ] **All services**: Move host binding to config
  - Current: `host="0.0.0.0"` in various services
- [ ] **All services**: Move timeout configurations to config
  - Current: `timeout=30000` in frontend
  - Current: `timeout=5.0` in various HTTP clients
  - Current: `timeout=300` in CLI

## Frontend Configuration

### ✅ Frontend Settings
- [ ] **sentinel_frontend/src/services/api.js**: Move API configuration
  - Current: `API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080'`
  - Current: `timeout: 30000`
- [ ] Create environment-specific frontend configs
- [ ] Add build-time configuration injection
- [ ] Move CORS settings to backend config

## CLI Configuration

### ✅ CLI Settings
- [ ] **cli/main.py**: Move default configurations
  - Current: `base_url: str = "http://localhost:8000"`
  - Current: `timeout: int = 300`
- [ ] Add CLI configuration file support
- [ ] Add profile-based configurations (dev, staging, prod)

## Application Settings

### ✅ Application-Level Configuration
- [ ] **auth_service/main.py**: Move user role and permission settings
- [ ] **data_service/main.py**: Move pagination and query limits
- [ ] **All services**: Move logging configuration
- [ ] **orchestration_service/agents/**: Move agent-specific settings
  - Mock data generation parameters
  - Test case generation limits
  - LLM API configurations
- [ ] Add feature flags configuration
- [ ] Add monitoring and metrics settings

## Agent Configuration

### ✅ Agent-Specific Settings
- [ ] **orchestration_service/agents/data_mocking_agent.py**: Move generation settings
  - Mock data strategies and counts
  - Faker locale settings
- [ ] **orchestration_service/agents/security_*.py**: Move security test parameters
  - Payload configurations
  - Test case limits
- [ ] **orchestration_service/agents/functional_*.py**: Move functional test settings
  - Example URLs (currently `https://example.com/test`)
  - Test data generation parameters
- [ ] **orchestration_service/agents/performance_planner_agent.py**: Move performance settings
  - Load test configurations
  - Performance thresholds

## Docker & Deployment Configuration

### ✅ Container Configuration
- [ ] Update all Dockerfiles to use configuration
- [ ] **docker-compose.yml**: Use environment file references
- [ ] Create Docker Compose overrides for different environments
- [ ] Add health check configurations
- [ ] Add resource limit configurations

## Testing Configuration

### ✅ Test Environment Settings
- [ ] Create test-specific configuration
- [ ] Move test database settings
- [ ] Add test data generation settings
- [ ] Configure test service URLs
- [ ] Add integration test configurations

## Documentation Updates

### ✅ Configuration Documentation
- [ ] Update README.md with configuration instructions
- [ ] Create configuration reference documentation
- [ ] Add environment setup guides
- [ ] Document security best practices
- [ ] Create deployment configuration examples

## Validation & Error Handling

### ✅ Configuration Validation
- [ ] Add configuration schema validation
- [ ] Implement startup configuration checks
- [ ] Add configuration error reporting
- [ ] Create configuration migration tools
- [ ] Add configuration backup/restore utilities

## Security Hardening

### ✅ Production Security
- [ ] Implement secure secret storage
- [ ] Add configuration encryption for sensitive data
- [ ] Create secure configuration deployment process
- [ ] Add configuration audit logging
- [ ] Implement configuration access controls

## Implementation Priority

### Phase 1: Core Infrastructure (High Priority)
1. Configuration framework setup
2. Database configuration
3. Service URLs
4. Security settings

### Phase 2: Application Settings (Medium Priority)
1. Network configuration
2. Frontend settings
3. CLI configuration
4. Agent settings

### Phase 3: Advanced Features (Low Priority)
1. Feature flags
2. Monitoring configuration
3. Advanced security hardening
4. Configuration management tools

## Notes

- All configuration changes should maintain backward compatibility during transition
- Environment variables should take precedence over file-based configuration
- Sensitive data (passwords, API keys, secrets) must never be committed to version control
- Configuration validation should fail fast with clear error messages
- Default values should be suitable for development environments
- Production configurations should be documented with security considerations

## Progress Tracking

- **Total Tasks**: 60+
- **Completed**: 0
- **In Progress**: 0
- **Remaining**: 60+

---

*This document will be updated as tasks are completed. Each completed task should be marked with ✅ and include implementation notes.*
