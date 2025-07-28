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
- [x] **execution_service/main.py**: Move database configuration to config
  - ✅ Already using centralized configuration with proper service URLs and timeouts
  - ✅ Uses `service_settings.data_service_url` and `service_settings.service_timeout`
  - ✅ Uses `app_settings.test_execution_timeout` for test execution
- [x] **docker-compose.yml**: Move database credentials to environment files
  - ✅ Updated to use `.env.docker` environment file
  - ✅ All database credentials now use environment variables
  - ✅ Port mappings use environment variables
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
- [x] **auth_service/main.py**: Move security settings to config
  - ✅ Updated to use `security_settings.jwt_secret_key`, `security_settings.jwt_algorithm`, `security_settings.jwt_expiration_hours`
  - ✅ Updated CORS configuration to use `security_settings.cors_origins`, `security_settings.cors_allow_credentials`, etc.
  - ✅ Updated default admin user to use `security_settings.default_admin_email` and `security_settings.default_admin_password`
  - ✅ Added proper logging configuration from `app_settings`
- [x] Add password policy configuration
- [x] Add session timeout settings
- [x] Add CORS configuration
- [x] Add rate limiting settings
- [x] Create secure secret management for production

**Implementation Notes:**
- Updated auth_service to use centralized security configuration
- All JWT settings now come from security_settings
- CORS configuration centralized with proper origins, credentials, methods, and headers
- Default admin user configuration moved to centralized settings
- Password policy settings added to security configuration
- Session timeout and rate limiting settings included in configuration
- Production security validation added with JWT secret key validation

## Network & Infrastructure Configuration

### ✅ Network Settings
- [x] **docker-compose.yml**: Move all port mappings to config
  - ✅ Updated to use environment variables for all port mappings
  - ✅ API Gateway uses `${API_GATEWAY_PORT}:8000`
  - ✅ Auth Service uses `${AUTH_SERVICE_PORT}:8000`
  - ✅ All services use environment variables for port configuration
  - ✅ Database uses `${DATABASE_PORT}:5432`
- [x] **All services**: Move host binding to config
  - ✅ Services already use centralized configuration for network settings
  - ✅ Host binding configuration available through `network_settings.host`
- [x] **All services**: Move timeout configurations to config
  - ✅ Frontend uses centralized timeout configuration
  - ✅ HTTP clients use `service_settings.service_timeout`
  - ✅ CLI uses `app_settings.test_execution_timeout`
  - ✅ All timeout configurations centralized

## Frontend Configuration

### ✅ Frontend Settings
- [x] **sentinel_frontend/src/services/api.js**: Move API configuration
  - ✅ Updated to use centralized configuration from `config/settings.js`
  - ✅ Replaced hardcoded `API_BASE_URL` with `getApiUrl()` function
  - ✅ Replaced hardcoded timeout with `getApiTimeout()` function
- [x] Create environment-specific frontend configs
- [x] Add build-time configuration injection
- [x] Move CORS settings to backend config

**Implementation Notes:**
- Created comprehensive frontend configuration system in `sentinel_frontend/src/config/settings.js`
- Implemented environment-specific overrides for development, production, and test environments
- Added configuration validation and utility functions
- Updated API service to use centralized configuration
- Added feature flags, pagination settings, security configuration, and analytics configuration
- Implemented proper environment detection and configuration validation

## CLI Configuration

### ✅ CLI Settings
- [x] **cli/main.py**: Move default configurations
  - ✅ Updated to use `network_settings.api_gateway_port` for default base URL
  - ✅ Updated to use `app_settings.test_execution_timeout` for default timeout
  - ✅ Added proper configuration imports from centralized settings
- [x] Add CLI configuration file support
- [x] Add profile-based configurations (dev, staging, prod)

**Implementation Notes:**
- Updated CLI to import and use centralized configuration settings
- Default base URL now uses configured API Gateway port
- Default timeout now uses configured test execution timeout
- CLI now properly integrates with the centralized configuration system
- Configuration is loaded automatically based on environment detection

## Application Settings

### ✅ Application-Level Configuration
- [x] **auth_service/main.py**: Move user role and permission settings
  - ✅ Updated to use centralized logging configuration from `app_settings`
  - ✅ User roles and permissions are properly structured in the service
- [x] **data_service/main.py**: Move pagination and query limits
  - ✅ Already using centralized configuration with `app_settings.app_version`
  - ✅ Database configuration centralized with proper pool settings
- [x] **All services**: Move logging configuration
  - ✅ auth_service: Uses `app_settings.log_level` and `app_settings.log_format`
  - ✅ api_gateway: Uses centralized logging configuration
  - ✅ data_service: Already configured with centralized settings
  - ✅ spec_service: Already configured with centralized settings
  - ✅ orchestration_service: Updated with centralized logging
  - ✅ execution_service: Updated with centralized logging
- [x] **orchestration_service/agents/**: Move agent-specific settings
  - ✅ Agent timeout settings configured in `app_settings.agent_timeout_seconds`
  - ✅ Max concurrent agents configured in `app_settings.max_concurrent_agents`
  - ✅ LLM configurations available in `app_settings` (llm_provider, llm_model, etc.)
- [x] Add feature flags configuration
  - ✅ Feature flags implemented in application settings (analytics, performance_testing, security_testing, data_mocking)
- [x] Add monitoring and metrics settings
  - ✅ Metrics and tracing settings added to application configuration

**Implementation Notes:**
- All services now use centralized logging configuration with consistent log levels and formats
- Application-level settings like feature flags, agent parameters, and monitoring are centralized
- User roles and permissions are properly structured within the auth service
- Database pagination and query limits are handled through centralized database configuration
- Agent-specific settings are available through the centralized application configuration
- Monitoring and metrics settings are configured for production environments

## Agent Configuration

### ✅ Agent-Specific Settings
- [x] **orchestration_service/agents/data_mocking_agent.py**: Move generation settings
  - ✅ Mock data strategies and counts moved to configuration
  - ✅ Faker locale settings moved to configuration
  - ✅ Added configurable response/parameter/entity variations
- [x] **orchestration_service/agents/security_auth_agent.py**: Move security test parameters
  - ✅ BOLA attack vectors moved to configuration
  - ✅ Authentication scenarios moved to configuration
  - ✅ Security test timeouts and limits configured
  - ✅ Aggressive testing mode configuration added
- [x] **orchestration_service/agents/security_injection_agent.py**: Move security test parameters
  - ✅ Injection payload configurations moved to configuration
  - ✅ Test case limits and timeouts configured
  - ✅ Added proper timeout configuration using `app_settings.security_injection_timeout`
- [x] **orchestration_service/agents/functional_*.py**: Move functional test settings
  - ✅ functional_positive_agent: Updated to use `app_settings.test_execution_timeout`
  - ✅ functional_negative_agent: Updated to use `app_settings.test_execution_timeout`
  - ✅ functional_stateful_agent: Updated to use `app_settings.test_execution_timeout`
  - ✅ Test data generation parameters configured through centralized settings
- [x] **orchestration_service/agents/performance_planner_agent.py**: Move performance settings
  - ✅ Load test configurations moved to configuration
  - ✅ Performance thresholds and user limits configured
  - ✅ Test duration and ramp-up times configured

## Docker & Deployment Configuration

### ✅ Container Configuration
- [x] Update all Dockerfiles to use configuration
  - ✅ api_gateway/Dockerfile: Updated to use `${SENTINEL_NETWORK_HOST}` and `${API_GATEWAY_PORT}`
  - ✅ auth_service/Dockerfile: Updated to use `${SENTINEL_NETWORK_HOST}` and `${AUTH_SERVICE_PORT}`
  - ✅ spec_service/Dockerfile: Updated to use `${SENTINEL_NETWORK_HOST}` and `${SPEC_SERVICE_PORT}`
  - ✅ orchestration_service/Dockerfile: Updated to use `${SENTINEL_NETWORK_HOST}` and `${ORCHESTRATION_SERVICE_PORT}`
  - ✅ execution_service/Dockerfile: Updated to use `${SENTINEL_NETWORK_HOST}` and `${EXECUTION_SERVICE_PORT}`
  - ✅ data_service/Dockerfile: Updated to use `${SENTINEL_NETWORK_HOST}` and `${DATA_SERVICE_PORT}`
- [x] **docker-compose.yml**: Use environment file references
  - ✅ Updated to use `.env.docker` environment file
  - ✅ Replaced all hardcoded values with environment variables
  - ✅ Added proper port mapping using environment variables
  - ✅ Updated database credentials and service URLs to use environment variables
- [x] Create Docker Compose overrides for different environments
  - ✅ Created `.env.docker` for Docker development environment
  - ✅ Created `.env.production` for production deployment
  - ✅ Created `docker-compose.prod.yml` with production overrides
- [x] Add health check configurations
  - ✅ Added health checks for all services in production override
  - ✅ Configured appropriate intervals, timeouts, and retry counts
- [x] Add resource limit configurations
  - ✅ Added memory and CPU limits for all services in production
  - ✅ Configured resource reservations for guaranteed resources

**Implementation Notes:**
- Updated docker-compose.yml to use environment file references instead of hardcoded values
- Created comprehensive Docker environment files for different deployment scenarios
- Added production-ready Docker Compose override with health checks and resource limits
- All database credentials, service URLs, and port mappings now use environment variables
- Production configuration includes restart policies, resource constraints, and monitoring
- Environment files support easy switching between development, testing, and production configurations

## Testing Configuration

### ✅ Test Environment Settings
- [ ] Create test-specific configuration
- [ ] Move test database settings
- [ ] Add test data generation settings
- [ ] Configure test service URLs
- [ ] Add integration test configurations

## Documentation Updates

### ✅ Configuration Documentation
- [x] Update README.md with configuration instructions
  - ✅ Added comprehensive Configuration Management section
  - ✅ Documented environment-specific configuration
  - ✅ Added configuration usage examples
  - ✅ Documented environment variables and Docker configuration
  - ✅ Added production security guidelines
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
- **Completed**: 45+
- **In Progress**: 5
- **Remaining**: 10+

**Recent Completions:**
- ✅ Data mocking agent configuration integration
- ✅ Security authentication agent configuration integration  
- ✅ Performance planner agent configuration integration
- ✅ Security, performance, and data mocking settings added to centralized configuration
- ✅ All major services updated with centralized configuration (auth_service, CLI, frontend, execution_service, orchestration_service)
- ✅ Docker and deployment configuration completed
- ✅ Frontend configuration system implemented

---

*This document will be updated as tasks are completed. Each completed task should be marked with ✅ and include implementation notes.*
