# Security Agent Authentication Detection

## Overview

The Sentinel Platform security agents have been enhanced with intelligent authentication detection to prevent generating unnecessary authentication tests for APIs that don't have authentication mechanisms. This addresses the issue where 30% of tests were being wasted on APIs like Petstore that have no authentication requirements.

## Problem Solved

**Before**: Security agents would generate authentication tests for all APIs, including those without any authentication mechanisms (like the Petstore API), resulting in:
- 30% of tests being irrelevant
- Wasted computational resources
- Longer test execution times
- Cluttered test results with meaningless auth tests

**After**: Security agents now intelligently detect authentication and only generate relevant tests, resulting in:
- Focused testing on actual security vulnerabilities
- 30% reduction in unnecessary test cases
- Faster test execution
- More accurate security assessment

## Implementation Details

### Files Modified

1. **`/sentinel_backend/orchestration_service/agents/security_auth_agent.py`**
   - Added `_has_authentication()` method
   - Added `_get_auth_type()` method
   - Added `_count_endpoints_with_auth()` method
   - Modified `execute()` method to skip auth tests when no authentication is detected
   - Enhanced metadata with authentication detection information

2. **`/sentinel_backend/orchestration_service/agents/security_injection_agent.py`**
   - Added `_has_authentication()` method
   - Added `_get_auth_type()` method  
   - Added `_is_auth_related_param()` method
   - Modified SQL and NoSQL injection payload generation to exclude auth-specific payloads
   - Enhanced injection test methods to skip auth-related tests when appropriate

### Authentication Detection Logic

The agents check for authentication in the following order:

1. **Global Security Schemes** (`components.securitySchemes`)
   ```yaml
   components:
     securitySchemes:
       bearerAuth:
         type: http
         scheme: bearer
   ```

2. **Global Security Requirements** (`security`)
   ```yaml
   security:
     - bearerAuth: []
   ```

3. **Endpoint-Level Security Requirements**
   ```yaml
   paths:
     /users:
       get:
         security:
           - bearerAuth: []
   ```

4. **Authentication Status Codes in Responses**
   ```yaml
   responses:
     '401':
       description: Unauthorized
     '403':
       description: Forbidden
   ```

### Supported Authentication Types

- **HTTP Authentication** (`http`)
  - Basic authentication
  - Bearer token authentication
  - Digest authentication
- **API Key Authentication** (`apiKey`)
  - Header-based API keys
  - Query parameter API keys
  - Cookie-based API keys
- **OAuth2 Authentication** (`oauth2`)
  - Authorization code flow
  - Client credentials flow
  - Implicit flow
- **OpenID Connect** (`openIdConnect`)

## Behavioral Changes

### SecurityAuthAgent

**With Authentication Detected:**
```python
# Generates comprehensive auth vulnerability tests
test_cases = [
    # BOLA (Broken Object Level Authorization) tests
    # Function-level authorization tests  
    # Authentication bypass tests
]
metadata = {
    "total_tests": 24,
    "auth_type": "http",
    "focus_areas": ["BOLA", "Function-level auth", "Auth bypass"]
}
```

**Without Authentication Detected:**
```python
# Skips all auth tests
test_cases = []
metadata = {
    "total_tests": 0,
    "skipped_reason": "No authentication mechanisms detected",
    "auth_detection": {
        "has_security_schemes": False,
        "has_global_security": False,
        "endpoints_with_auth": 0
    }
}
```

### SecurityInjectionAgent

**With Authentication:**
- Includes auth-related SQL injection payloads:
  ```sql
  ' UNION SELECT username, password FROM users --
  ' OR user_role='admin' --
  ```
- Includes auth-related NoSQL injection payloads:
  ```javascript
  {"$or": [{"username": {"$exists": true}}, {"password": {"$exists": true}}]}
  ```

**Without Authentication:**
- Skips auth-related parameters (`username`, `password`, `token`, etc.)
- Excludes user/credential targeting injection tests
- Focuses on general vulnerability testing

## Usage Examples

### API Without Authentication (Petstore)

```python
# API spec with no security schemes
petstore_spec = {
    "openapi": "3.0.0",
    "paths": {
        "/pets": {
            "get": {
                "responses": {"200": {"description": "List pets"}}
            }
        }
    }
}

# SecurityAuthAgent result
result = await auth_agent.execute(task, petstore_spec)
# result.test_cases = []  # No auth tests generated
# result.metadata["skipped_reason"] = "No authentication mechanisms detected"
```

### API With Authentication (Secure API)

```python
# API spec with JWT authentication
secure_spec = {
    "openapi": "3.0.0",
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"}
        }
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/users": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {"description": "Users"},
                    "401": {"description": "Unauthorized"}
                }
            }
        }
    }
}

# SecurityAuthAgent result  
result = await auth_agent.execute(task, secure_spec)
# result.test_cases = [... 24 comprehensive auth tests ...]
# result.metadata["auth_type"] = "http"
```

## Benefits

1. **Resource Efficiency**: 30% reduction in unnecessary test generation
2. **Focused Testing**: Security tests target actual vulnerabilities
3. **Faster Execution**: Reduced test suite size improves performance
4. **Better Insights**: Clear metadata about authentication detection
5. **Cost Reduction**: Less computational overhead for test generation

## Configuration

No additional configuration is required. The authentication detection is automatic and uses the OpenAPI specification to determine authentication requirements.

## Logging

The agents now provide detailed logging about authentication detection:

```
INFO: Found security schemes: ['bearerAuth']
INFO: Detected authentication type: http (scheme: bearerAuth)
INFO: Security Auth Agent skipping auth tests - no authentication detected
DEBUG: Skipping auth-related SQL injection test for parameter 'username' - no authentication detected
```

## Testing

A demonstration script is available at `/src/auth_detection_demo.py` that shows:
- Authentication detection logic in action
- Comparison between authenticated and non-authenticated APIs
- Simulated agent behavior for both scenarios

Run the demo:
```bash
python3 src/auth_detection_demo.py
```

## Future Enhancements

Potential future improvements include:
- Support for custom authentication schemes
- Authentication strength assessment
- Dynamic authentication discovery during runtime
- Integration with API documentation standards beyond OpenAPI