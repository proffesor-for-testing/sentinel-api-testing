# Playwright E2E Tests

Real browser-based end-to-end tests for the Sentinel API Testing Platform using Playwright.

## 📋 Test Coverage

### Authentication Tests (`auth.spec.ts`)
- ✅ Login with valid credentials
- ✅ Error handling for invalid credentials
- ✅ Role-based access control (RBAC)
- ✅ Logout functionality
- ✅ Session persistence
- ✅ Concurrent login sessions

### Specifications Management (`specifications.spec.ts`)
- ✅ Upload API specification via JSON
- ✅ Upload API specification via file
- ✅ OpenAPI format validation
- ✅ Search and filter specifications
- ✅ View specification details
- ✅ Delete specifications
- ✅ Handle large specifications

### Test Generation Workflow (`test-generation.spec.ts`)
- ✅ Create test run with AI agents
- ✅ Monitor generation progress
- ✅ Display generated test cases
- ✅ Filter test cases by agent type
- ✅ Execute generated tests
- ✅ Error handling

## 🚀 Setup

### Install Playwright
```bash
cd sentinel_frontend
npm install --save-dev @playwright/test
npx playwright install
```

### Install browsers (if needed)
```bash
npx playwright install chromium
npx playwright install firefox
npx playwright install webkit
```

## 🧪 Running Tests

### Run all E2E tests
```bash
npm run test:e2e
```

### Run tests in UI mode (interactive)
```bash
npm run test:e2e:ui
```

### Run tests in headed mode (see browser)
```bash
npm run test:e2e:headed
```

### Debug tests
```bash
npm run test:e2e:debug
```

### Run specific test file
```bash
npx playwright test e2e/tests/auth.spec.ts
```

### Run specific test
```bash
npx playwright test -g "should login successfully"
```

### Run tests in specific browser
```bash
npx playwright test --project=chromium
npx playwright test --project=firefox
npx playwright test --project=webkit
```

## 📊 Test Reports

### Generate HTML report
```bash
npm run test:e2e:report
```

### View last test report
```bash
npx playwright show-report
```

## 🐳 Docker Testing

### Run E2E tests in Docker
```bash
docker run --rm -v $(pwd):/app -w /app/sentinel_frontend \
  mcr.microsoft.com/playwright:v1.40.0-focal \
  npm run test:e2e
```

### Docker Compose setup
```yaml
# docker-compose.e2e.yml
version: '3.8'
services:
  e2e-tests:
    image: mcr.microsoft.com/playwright:v1.40.0-focal
    volumes:
      - ./sentinel_frontend:/app
    working_dir: /app
    command: npm run test:e2e
    network_mode: host
```

## 🏗️ Test Architecture

### Page Object Model
Tests use the Page Object Model pattern for maintainability:

```
e2e/
├── pages/           # Page objects
│   ├── login.page.ts
│   ├── dashboard.page.ts
│   └── specifications.page.ts
├── fixtures/        # Test data
│   └── test-data.ts
└── tests/          # Test specifications
    ├── auth.spec.ts
    ├── specifications.spec.ts
    └── test-generation.spec.ts
```

### Page Objects
- Encapsulate page interactions
- Provide reusable methods
- Abstract locator strategies
- Handle waiting and timeouts

### Fixtures
- Centralized test data
- User credentials
- Sample API specifications
- Configuration values

## 🔧 Configuration

### Environment Variables
```bash
# .env.test
BASE_URL=http://localhost:3000
API_URL=http://localhost:8000
TEST_TIMEOUT=30000
```

### Playwright Config
See `playwright.config.ts` for:
- Browser configurations
- Timeout settings
- Report options
- Screenshot/video settings
- Parallel execution

## 📱 Cross-Browser Testing

Tests run on:
- **Desktop**: Chrome, Firefox, Safari
- **Mobile**: iPhone 13, Pixel 5

## 🎥 Screenshots & Videos

- Screenshots on failure: `test-results/screenshots/`
- Videos on failure: `test-results/videos/`
- Traces: `test-results/traces/`

## 💡 Best Practices

1. **Use Page Objects**: Keep tests clean and maintainable
2. **Data-driven tests**: Use fixtures for test data
3. **Explicit waits**: Use Playwright's built-in waiting
4. **Parallel execution**: Tests run in parallel by default
5. **Isolation**: Each test is independent
6. **Retry logic**: Failed tests retry automatically

## 🐛 Debugging

### VS Code Extension
Install the Playwright VS Code extension for:
- Running tests from editor
- Debugging with breakpoints
- Generating locators

### Debug mode
```bash
PWDEBUG=1 npx playwright test
```

### Trace viewer
```bash
npx playwright show-trace trace.zip
```

## 📈 CI/CD Integration

### GitHub Actions
```yaml
- name: Install Playwright
  run: npx playwright install --with-deps

- name: Run E2E tests
  run: npm run test:e2e

- name: Upload test results
  if: always()
  uses: actions/upload-artifact@v3
  with:
    name: playwright-results
    path: test-results/
```

## 🔍 Common Issues

### Browser not installed
```bash
npx playwright install
```

### Timeout errors
Increase timeout in `playwright.config.ts`:
```typescript
use: {
  actionTimeout: 20000,
  navigationTimeout: 30000,
}
```

### Flaky tests
Add retries:
```typescript
retries: process.env.CI ? 2 : 1
```

## 📚 Resources

- [Playwright Documentation](https://playwright.dev)
- [Best Practices](https://playwright.dev/docs/best-practices)
- [API Reference](https://playwright.dev/docs/api/class-test)