# End-to-End Testing Guide - Sentinel Platform

## Overview

The Sentinel platform employs comprehensive E2E testing across both frontend and backend to ensure complete workflow validation. Our E2E tests simulate real user scenarios and validate the entire system from API specification upload through test execution and results analysis.

## Test Architecture

### Frontend E2E Tests (Playwright)
- **Location**: `sentinel_frontend/e2e/`
- **Framework**: Playwright Test
- **Browsers**: Chrome, Firefox, Safari, Mobile
- **Test Suites**: 9 comprehensive suites with 45+ test scenarios

### Backend E2E Tests (Python/Pytest)
- **Location**: `sentinel_backend/tests/e2e/`
- **Framework**: Pytest with asyncio
- **Test Suites**: 4 comprehensive suites with 30+ test scenarios

## Frontend E2E Test Suites

### 1. Authentication Tests (`auth.spec.ts`)
- Login with valid/invalid credentials
- Role-based access control (RBAC)
- Session persistence
- Concurrent login sessions
- Logout functionality

### 2. Specifications Management (`specifications.spec.ts`)
- Upload API specifications (JSON/file)
- OpenAPI format validation
- Search and filter specifications
- View specification details
- Delete specifications
- Handle large specifications

### 3. Test Generation Workflow (`test-generation.spec.ts`)
- Create test runs with AI agents
- Monitor generation progress
- Display generated test cases
- Filter test cases by agent type
- Execute generated tests
- Error handling

### 4. Test Execution (`test-execution.spec.ts`)
- Complete workflow from spec to results
- Partial test execution
- Test re-execution
- Execution interruption handling
- Export test results
- Display execution metrics
- Filter results by status
- Show error details for failed tests

### 5. Results Visualization (`results-visualization.spec.ts`)
- Test results dashboard
- Execution trends chart
- Coverage by endpoint
- Agent performance comparison
- Date range filtering
- Failure analysis
- Export analytics reports
- Real-time status monitoring
- Cross-run comparison
- Execution heatmap

### 6. Multi-Agent Coordination (`multi-agent.spec.ts`)
- Coordinate multiple agents
- Handle agent failures
- Display collaboration insights
- Optimize agent selection
- Manage priorities and sequencing
- Aggregate results
- Visualize coordination flow
- Handle concurrency limits

### 7. RBAC Testing (`rbac.spec.ts`)
- Admin full access validation
- Manager limited access
- Tester operational access
- Viewer read-only access
- Field-level permissions
- Dynamic permission changes
- Audit logging
- API key permissions
- Data visibility based on role

### 8. API Import Workflows (`api-import.spec.ts`)
- OpenAPI 3.0 import
- Swagger 2.0 import
- Import from URL
- Validation and error fixing
- Postman collection import
- GraphQL schema import
- Bulk import
- Metadata preservation
- API versioning

## Backend E2E Test Suites

### 1. Spec to Execution (`test_spec_to_execution.py`)
**Tests the complete workflow:**
- Upload API specification
- Create test run with AI agents
- Monitor test generation
- Retrieve generated test cases
- Execute test cases
- Monitor execution progress
- Retrieve execution results
- Save results to data service
- Spec validation workflow
- Agent failure handling
- Concurrent test execution
- Data persistence

### 2. Multi-Agent Coordination (`test_multi_agent_coordination.py`)
**Tests agent orchestration:**
- Agent collaboration workflow
- Dependency resolution
- Parallel agent execution
- Failure recovery
- Resource optimization
- Inter-agent communication
- Distributed execution
- Shared context management
- Message passing protocols
- Load balancing

### 3. Performance Pipeline (`test_performance_pipeline.py`)
**Tests performance testing capabilities:**
- Load test generation (k6/JMeter scripts)
- Stress testing to find breaking points
- Spike test scenarios
- Endurance testing
- Scalability testing
- Performance baseline establishment
- Metrics collection
- Resource monitoring
- Bottleneck detection

### 4. Security Pipeline (`test_security_pipeline.py`)
**Tests security testing capabilities:**
- Authentication security tests
- BOLA (Broken Object Level Authorization)
- SQL/NoSQL/Command injection detection
- Rate limiting and DoS protection
- Security headers validation
- Cryptographic weakness detection
- JWT vulnerability testing
- CORS testing
- Comprehensive security scanning
- OWASP Top 10 coverage

## Running E2E Tests

### Frontend Playwright Tests

```bash
# Install Playwright
cd sentinel_frontend
npm install --save-dev @playwright/test
npx playwright install

# Run all E2E tests
npm run test:e2e

# Run tests in UI mode (interactive)
npm run test:e2e:ui

# Run tests in headed mode (see browser)
npm run test:e2e:headed

# Debug tests
npm run test:e2e:debug

# Run specific test file
npx playwright test e2e/tests/auth.spec.ts

# Run specific test by name
npx playwright test -g "should login successfully"

# Run tests in specific browser
npx playwright test --project=chromium
npx playwright test --project=firefox

# Generate HTML report
npm run test:e2e:report

# View last test report
npx playwright show-report
```

### Backend E2E Tests

```bash
cd sentinel_backend

# Run all E2E tests
pytest tests/e2e/ -v

# Run specific test file
pytest tests/e2e/test_security_pipeline.py -v

# Run tests matching pattern
pytest tests/e2e/ -k "security"

# Run with coverage
pytest tests/e2e/ --cov=. --cov-report=html

# Run with specific markers
pytest tests/e2e/ -m "slow"

# Stop on first failure
pytest tests/e2e/ --maxfail=1

# Run in parallel
pytest tests/e2e/ -n auto

# Verbose output with print statements
pytest tests/e2e/ -v -s
```

### Docker Testing

```bash
# Run E2E tests in Docker
docker-compose -f docker-compose.test.yml up --build

# Frontend E2E in Docker
docker run --rm -v $(pwd):/app -w /app/sentinel_frontend \
  mcr.microsoft.com/playwright:v1.40.0-focal \
  npm run test:e2e

# Backend E2E in Docker
docker-compose run --rm test_runner pytest tests/e2e/ -v
```

## Test Configuration

### Playwright Configuration (`playwright.config.ts`)

```typescript
export default defineConfig({
  testDir: './e2e/tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 1,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
```

### Pytest Configuration (`pytest.ini`)

```ini
[pytest]
testpaths = tests/e2e
python_files = test_*.py
python_classes = Test*
python_functions = test_*
asyncio_mode = auto
markers =
    slow: marks tests as slow
    security: security-related tests
    performance: performance-related tests
    integration: integration tests
```

## Test Data Management

### Frontend Test Data (`fixtures/test-data.ts`)

```typescript
export const testUsers = {
  admin: { email: 'admin@sentinel.com', password: 'admin123' },
  manager: { email: 'manager@sentinel.com', password: 'manager123' },
  tester: { email: 'tester@sentinel.com', password: 'tester123' },
  viewer: { email: 'viewer@sentinel.com', password: 'viewer123' }
};

export const sampleAPISpec = {
  name: 'Test API',
  description: 'API for testing',
  content: { /* OpenAPI spec */ }
};
```

### Backend Test Fixtures

```python
@pytest.fixture
async def auth_headers():
    """Get authentication headers for API calls."""
    # Login and return auth headers
    return {"Authorization": "Bearer token"}

@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI specification."""
    return { /* spec data */ }
```

## Best Practices

### Test Organization
1. Use Page Object Model for frontend tests
2. Group related tests in describe blocks
3. Use fixtures for common setup/teardown
4. Keep tests independent and atomic
5. Use descriptive test names

### Test Data
1. Use test fixtures for reusable data
2. Clean up test data after each test
3. Use unique identifiers for test data
4. Mock external dependencies

### Assertions
1. Use explicit assertions
2. Test both positive and negative cases
3. Verify error messages and codes
4. Check response structure and data

### Performance
1. Run tests in parallel when possible
2. Use test hooks for setup/teardown
3. Minimize waits and use proper selectors
4. Cache test data where appropriate

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: E2E Tests

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  frontend-e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - name: Install dependencies
        run: |
          cd sentinel_frontend
          npm ci
          npx playwright install --with-deps
      - name: Run E2E tests
        run: |
          cd sentinel_frontend
          npm run test:e2e
      - uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-report
          path: sentinel_frontend/playwright-report/

  backend-e2e:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
      rabbitmq:
        image: rabbitmq:3-management
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          cd sentinel_backend
          pip install poetry
          poetry install
      - name: Run E2E tests
        run: |
          cd sentinel_backend
          poetry run pytest tests/e2e/ -v --junit-xml=test-results.xml
      - uses: actions/upload-artifact@v3
        if: always()
        with:
          name: test-results
          path: sentinel_backend/test-results.xml
```

## Debugging E2E Tests

### Frontend Debugging

1. **Use Playwright Inspector**:
   ```bash
   PWDEBUG=1 npx playwright test
   ```

2. **VS Code Extension**: Install Playwright Test for VS Code

3. **Trace Viewer**:
   ```bash
   npx playwright show-trace trace.zip
   ```

4. **Screenshots and Videos**: Check `test-results/` folder

### Backend Debugging

1. **Use pytest debugger**:
   ```python
   import pdb; pdb.set_trace()
   ```

2. **Verbose logging**:
   ```bash
   pytest tests/e2e/ -v -s --log-cli-level=DEBUG
   ```

3. **VS Code debugging**: Configure launch.json for pytest

## Monitoring & Metrics

### Key Metrics to Track
- Test execution time
- Pass/fail rates
- Flaky test detection
- Coverage metrics
- Performance benchmarks

### Test Reports
- HTML reports for visual inspection
- JUnit XML for CI integration
- Coverage reports with detailed metrics
- Performance trend analysis

## Troubleshooting

### Common Issues

1. **Timeout Errors**:
   - Increase timeout in test config
   - Check service availability
   - Verify network connectivity

2. **Flaky Tests**:
   - Add proper waits
   - Ensure test isolation
   - Check for race conditions

3. **Authentication Issues**:
   - Verify test user credentials
   - Check token expiration
   - Ensure proper session handling

4. **Database State**:
   - Use transactions for isolation
   - Clean up test data
   - Reset database between tests

## Future Enhancements

1. **Visual Regression Testing**: Add screenshot comparison
2. **API Contract Testing**: Validate API contracts
3. **Load Testing Integration**: Combine with performance tests
4. **Mobile Testing**: Expand mobile browser coverage
5. **Accessibility Testing**: Add a11y checks
6. **Cross-browser Testing**: Add BrowserStack/Sauce Labs
7. **Test Data Generation**: AI-powered test data
8. **Mutation Testing**: Validate test effectiveness

## Resources

- [Playwright Documentation](https://playwright.dev)
- [Pytest Documentation](https://docs.pytest.org)
- [Testing Best Practices](https://testingjavascript.com)
- [E2E Testing Patterns](https://martinfowler.com/articles/practical-test-pyramid.html)