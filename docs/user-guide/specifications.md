# Managing API Specifications

API specifications are the foundation of testing in Sentinel. This guide covers everything you need to know about uploading, managing, and optimizing your OpenAPI/Swagger specifications.

## Supported Formats

Sentinel supports:
- **OpenAPI 3.0.x** (Recommended)
- **OpenAPI 3.1.x**
- **Swagger 2.0**
- **JSON and YAML formats**

## Uploading Specifications

### Via Web Interface

1. Navigate to **Specifications** in the main menu
2. Click **"Upload New Specification"**
3. Choose your upload method:
   - **File Upload**: Select a `.json` or `.yaml` file
   - **URL Import**: Provide a URL to your specification
   - **Direct Input**: Paste specification content directly

4. Provide metadata:
   - **Name**: A descriptive name for your API
   - **Version**: Version identifier (e.g., "1.0.0", "v2")
   - **Description**: Optional description
   - **Tags**: Optional tags for organization

5. Click **"Upload"** to process the specification

### Via API

```bash
# Upload from file
curl -X POST "http://localhost:8000/specifications" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d @specification.json

# Upload with metadata
curl -X POST "http://localhost:8000/specifications" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "User Management API",
    "version": "2.1.0",
    "description": "API for user management operations",
    "tags": ["users", "authentication"],
    "spec_data": { ... }
  }'
```

### Via CLI

```bash
# Upload a local file
sentinel spec upload ./api-spec.yaml --name "My API" --version "1.0.0"

# Upload from URL
sentinel spec upload https://api.example.com/openapi.json

# Upload with tags
sentinel spec upload ./spec.yaml --tags "production,critical"
```

## Specification Validation

Sentinel automatically validates specifications upon upload:

### Validation Checks

1. **Syntax Validation**
   - Valid JSON/YAML structure
   - Correct OpenAPI schema

2. **Semantic Validation**
   - Required fields present
   - Valid data types
   - Reference resolution

3. **Best Practices**
   - Descriptive operation IDs
   - Complete response schemas
   - Security definitions

### Validation Results

After upload, you'll receive a validation report:

```json
{
  "status": "valid_with_warnings",
  "errors": [],
  "warnings": [
    {
      "path": "/paths/users/get",
      "message": "Missing operationId"
    },
    {
      "path": "/components/schemas/User",
      "message": "No example provided"
    }
  ],
  "info": {
    "endpoints": 15,
    "schemas": 8,
    "security_schemes": 2
  }
}
```

## Optimizing Specifications for Testing

### 1. Provide Complete Schemas

**Good:**
```yaml
components:
  schemas:
    User:
      type: object
      required:
        - id
        - email
        - name
      properties:
        id:
          type: integer
          minimum: 1
          description: Unique user identifier
        email:
          type: string
          format: email
          maxLength: 255
          description: User email address
        name:
          type: string
          minLength: 1
          maxLength: 100
          description: User full name
        age:
          type: integer
          minimum: 0
          maximum: 150
          description: User age in years
```

**Why it helps:**
- Enables accurate data generation
- Improves boundary value testing
- Supports better validation

### 2. Include Examples

```yaml
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/User'
            examples:
              valid_user:
                value:
                  email: "john.doe@example.com"
                  name: "John Doe"
                  age: 30
              minimal_user:
                value:
                  email: "jane@example.com"
                  name: "Jane"
```

### 3. Define Security Schemes

```yaml
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    apiKey:
      type: apiKey
      in: header
      name: X-API-Key
    
security:
  - bearerAuth: []
  - apiKey: []
```

### 4. Document Error Responses

```yaml
paths:
  /users/{id}:
    get:
      responses:
        200:
          description: Success
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        404:
          description: User not found
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        401:
          description: Unauthorized
        500:
          description: Internal server error
```

## Managing Multiple Versions

### Version Strategy

1. **Semantic Versioning**: Use versions like "1.0.0", "1.1.0", "2.0.0"
2. **Date-based**: Use versions like "2024-01-15", "2024-02-01"
3. **Custom**: Any string that makes sense for your team

### Comparing Versions

View differences between specification versions:

```bash
# Via CLI
sentinel spec diff --spec1 1 --spec2 2

# Via API
curl -X GET "http://localhost:8000/specifications/compare?spec1=1&spec2=2" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Version Management Best Practices

1. **Keep History**: Don't delete old versions, mark them as deprecated
2. **Document Changes**: Include change notes with each version
3. **Test Compatibility**: Run tests against multiple versions
4. **Use Tags**: Tag versions as "stable", "beta", "deprecated"

## Specification Organization

### Using Tags

Organize specifications with tags:

```bash
# Add tags
sentinel spec tag --id 1 --tags "production,customer-facing"

# Filter by tags
sentinel spec list --tags "production"
```

### Creating Collections

Group related specifications:

```json
{
  "name": "E-commerce Platform",
  "specifications": [
    {"id": 1, "name": "User API"},
    {"id": 2, "name": "Product API"},
    {"id": 3, "name": "Order API"}
  ]
}
```

## Advanced Features

### Specification Preprocessing

Apply transformations before testing:

```python
# Custom preprocessor example
def preprocess_spec(spec_data):
    # Add default security to all endpoints
    for path in spec_data.get('paths', {}).values():
        for operation in path.values():
            if 'security' not in operation:
                operation['security'] = [{'bearerAuth': []}]
    return spec_data
```

### Environment Variables

Use environment-specific configurations:

```yaml
servers:
  - url: ${API_BASE_URL}
    description: API server
    variables:
      protocol:
        default: https
        enum: [http, https]
      environment:
        default: production
        enum: [development, staging, production]
```

### External References

Include external schema definitions:

```yaml
components:
  schemas:
    User:
      $ref: 'https://schemas.example.com/user.yaml#/User'
    Address:
      $ref: './schemas/address.yaml#/Address'
```

## Troubleshooting

### Common Issues

1. **Invalid JSON/YAML**
   - Use a validator: https://jsonlint.com or http://www.yamllint.com
   - Check for syntax errors in your editor

2. **Missing Required Fields**
   - Ensure `openapi` or `swagger` version is specified
   - Include `info` object with `title` and `version`

3. **Unresolved References**
   - Check all `$ref` paths are correct
   - Ensure referenced schemas exist

4. **Large Specifications**
   - Split into multiple files using `$ref`
   - Use specification collections
   - Consider API versioning

### Specification Linting

Use the built-in linter to improve specification quality:

```bash
# Lint a specification
sentinel spec lint ./api-spec.yaml

# Auto-fix common issues
sentinel spec lint ./api-spec.yaml --fix
```

## Best Practices

1. **Keep Specifications Updated**: Sync with your API implementation
2. **Use Descriptive Names**: Clear operation IDs and schema names
3. **Document Everything**: Include descriptions for all elements
4. **Provide Examples**: Add request/response examples
5. **Define Constraints**: Specify min/max values, patterns, enums
6. **Version Control**: Store specifications in Git
7. **Automate Updates**: Generate specs from code when possible
8. **Review Regularly**: Audit specifications for completeness

## Next Steps

- Learn about [different test types](./test-types.md)
- Configure [test execution](./first-test.md)
- Set up [CI/CD integration](./cicd-integration.md)

---

← [Back to User Guide](./index.md) | [Next: Running Your First Test](./first-test.md) →