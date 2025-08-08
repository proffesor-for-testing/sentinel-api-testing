# CI/CD Integration Guide

Integrate Sentinel into your continuous integration and deployment pipelines to automatically test your APIs with every code change.

## Overview

Sentinel provides multiple integration methods:
- **CLI Tool**: Command-line interface for scripting
- **REST API**: Direct API calls from any CI/CD tool
- **Docker**: Containerized testing environments
- **Pre-built Templates**: GitHub Actions, GitLab CI, Jenkins

## Quick Start Templates

### GitHub Actions

Create `.github/workflows/api-testing.yml`:

```yaml
name: API Testing with Sentinel

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  api-test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.10'
    
    - name: Install Sentinel CLI
      run: |
        pip install sentinel-cli
        
    - name: Configure Sentinel
      env:
        SENTINEL_API_URL: ${{ secrets.SENTINEL_API_URL }}
        SENTINEL_API_KEY: ${{ secrets.SENTINEL_API_KEY }}
      run: |
        sentinel config set api_url $SENTINEL_API_URL
        sentinel config set api_key $SENTINEL_API_KEY
        
    - name: Upload API Specification
      run: |
        sentinel spec upload ./openapi.yaml --name "My API" --version "${{ github.sha }}"
        
    - name: Run Functional Tests
      run: |
        sentinel test run \
          --spec-name "My API" \
          --types functional \
          --wait \
          --fail-on-errors
          
    - name: Run Security Tests
      if: github.event_name == 'pull_request'
      run: |
        sentinel test run \
          --spec-name "My API" \
          --types security \
          --wait \
          --fail-on-errors
          
    - name: Generate Test Report
      if: always()
      run: |
        sentinel report generate \
          --format html \
          --output ./test-report.html
          
    - name: Upload Test Results
      if: always()
      uses: actions/upload-artifact@v2
      with:
        name: test-results
        path: ./test-report.html
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security
  - performance

variables:
  SENTINEL_API_URL: "https://sentinel.example.com"
  SPEC_FILE: "./api/openapi.yaml"

before_script:
  - pip install sentinel-cli
  - sentinel config set api_url $SENTINEL_API_URL
  - sentinel auth login --token $SENTINEL_API_TOKEN

functional_tests:
  stage: test
  script:
    - sentinel spec upload $SPEC_FILE --version $CI_COMMIT_SHA
    - |
      TEST_RUN_ID=$(sentinel test run \
        --spec-version $CI_COMMIT_SHA \
        --types functional \
        --output-format json | jq -r '.test_run_id')
    - sentinel test wait --run-id $TEST_RUN_ID --timeout 600
    - sentinel test results --run-id $TEST_RUN_ID --format junit > test-results.xml
  artifacts:
    reports:
      junit: test-results.xml
    expire_in: 1 week

security_scan:
  stage: security
  only:
    - main
    - develop
  script:
    - |
      sentinel test run \
        --spec-version $CI_COMMIT_SHA \
        --types security \
        --wait \
        --fail-on-critical
  allow_failure: false

performance_baseline:
  stage: performance
  only:
    - main
  script:
    - |
      sentinel test run \
        --spec-version $CI_COMMIT_SHA \
        --types performance \
        --performance-users 100 \
        --performance-duration 10m \
        --wait
    - sentinel analytics compare --baseline previous --current $CI_COMMIT_SHA
```

### Jenkins

Create `Jenkinsfile`:

```groovy
pipeline {
    agent any
    
    environment {
        SENTINEL_URL = credentials('sentinel-url')
        SENTINEL_TOKEN = credentials('sentinel-token')
        SPEC_FILE = 'openapi.yaml'
    }
    
    stages {
        stage('Setup') {
            steps {
                sh 'pip install sentinel-cli'
                sh 'sentinel config set api_url $SENTINEL_URL'
                sh 'sentinel auth login --token $SENTINEL_TOKEN'
            }
        }
        
        stage('Upload Specification') {
            steps {
                sh "sentinel spec upload ${SPEC_FILE} --version ${BUILD_NUMBER}"
            }
        }
        
        stage('Functional Tests') {
            steps {
                script {
                    def testRun = sh(
                        script: "sentinel test run --spec-version ${BUILD_NUMBER} --types functional --wait",
                        returnStdout: true
                    ).trim()
                    
                    def results = sh(
                        script: "sentinel test results --run-id ${testRun} --format json",
                        returnStdout: true
                    )
                    
                    def json = readJSON text: results
                    if (json.failed_tests > 0) {
                        error("Functional tests failed: ${json.failed_tests} failures")
                    }
                }
            }
        }
        
        stage('Security Tests') {
            when {
                branch 'main'
            }
            steps {
                sh 'sentinel test run --spec-version ${BUILD_NUMBER} --types security --wait'
            }
        }
        
        stage('Performance Tests') {
            when {
                branch 'main'
            }
            steps {
                sh '''
                    sentinel test run \
                        --spec-version ${BUILD_NUMBER} \
                        --types performance \
                        --performance-profile standard \
                        --wait
                '''
            }
        }
    }
    
    post {
        always {
            sh 'sentinel report generate --format html --output report.html'
            publishHTML([
                reportDir: '.',
                reportFiles: 'report.html',
                reportName: 'Sentinel Test Report'
            ])
        }
        failure {
            emailext(
                subject: "API Tests Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "API tests failed. Check the report: ${env.BUILD_URL}",
                to: 'team@example.com'
            )
        }
    }
}
```

## CLI Installation and Configuration

### Installation

```bash
# Via pip
pip install sentinel-cli

# Via Docker
docker pull sentinel/cli:latest
alias sentinel='docker run -it --rm sentinel/cli:latest'

# From source
git clone https://github.com/proffesor-for-testing/sentinel-api-testing.git
cd sentinel-api-testing/cli
pip install -e .
```

### Configuration

```bash
# Set API endpoint
sentinel config set api_url https://sentinel.example.com

# Configure authentication
sentinel auth login --email user@example.com --password yourpassword

# Or use API token
sentinel config set api_token YOUR_API_TOKEN

# Verify configuration
sentinel config show
```

### Environment Variables

```bash
export SENTINEL_API_URL=https://sentinel.example.com
export SENTINEL_API_TOKEN=your-token-here
export SENTINEL_DEFAULT_TIMEOUT=300
export SENTINEL_OUTPUT_FORMAT=json
```

## Integration Patterns

### 1. Pull Request Testing

Run tests on every pull request:

```yaml
# GitHub Actions example
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  api-tests:
    runs-on: ubuntu-latest
    steps:
      - name: Run API Tests
        run: |
          sentinel test run \
            --spec-file ${{ github.event.pull_request.head.sha }}/openapi.yaml \
            --types functional,security \
            --comment-on-pr \
            --fail-on-errors
```

### 2. Nightly Regression Testing

Schedule comprehensive tests:

```yaml
# GitLab CI example
nightly_regression:
  stage: test
  only:
    - schedules
  script:
    - sentinel test run --spec-name "Production API" --types all --comprehensive
    - sentinel report email --recipients team@example.com
```

### 3. Deployment Validation

Test before and after deployment:

```bash
#!/bin/bash
# Pre-deployment validation
sentinel test run --env staging --types smoke --fail-fast

# Deploy application
./deploy.sh

# Post-deployment validation
sentinel test run --env production --types smoke,functional --wait

# Compare with baseline
sentinel analytics compare --env production --baseline yesterday
```

### 4. Performance Regression Detection

```python
# Python script for performance regression
import subprocess
import json

def check_performance_regression():
    # Run performance test
    result = subprocess.run([
        'sentinel', 'test', 'run',
        '--types', 'performance',
        '--output-format', 'json'
    ], capture_output=True, text=True)
    
    test_data = json.loads(result.stdout)
    
    # Get baseline metrics
    baseline = subprocess.run([
        'sentinel', 'analytics', 'baseline',
        '--metric', 'p95_latency',
        '--format', 'json'
    ], capture_output=True, text=True)
    
    baseline_data = json.loads(baseline.stdout)
    
    # Compare
    current_p95 = test_data['metrics']['p95_latency']
    baseline_p95 = baseline_data['p95_latency']
    
    if current_p95 > baseline_p95 * 1.1:  # 10% regression threshold
        print(f"Performance regression detected: {current_p95}ms vs {baseline_p95}ms")
        return 1
    
    return 0
```

## Advanced Configuration

### Custom Test Profiles

Create reusable test configurations:

```yaml
# .sentinel/profiles.yaml
profiles:
  quick:
    types: [functional-positive]
    timeout: 60
    fail_fast: true
    
  standard:
    types: [functional, security-auth]
    timeout: 300
    parallel: true
    
  comprehensive:
    types: [functional, security, performance]
    timeout: 1800
    performance:
      users: 500
      duration: 15m
    security:
      aggressiveness: high
```

Use profiles in CI/CD:

```bash
sentinel test run --profile comprehensive
```

### Conditional Testing

Run different tests based on conditions:

```bash
#!/bin/bash
# Determine test scope based on changes
if git diff --name-only HEAD~1 | grep -q "auth"; then
    TEST_TYPES="functional,security"
else
    TEST_TYPES="functional"
fi

if [ "$BRANCH" == "main" ]; then
    TEST_TYPES="$TEST_TYPES,performance"
fi

sentinel test run --types $TEST_TYPES
```

### Parallel Execution

Speed up testing with parallel execution:

```yaml
# GitHub Actions matrix strategy
strategy:
  matrix:
    test-type: [functional, security, performance]
    
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run ${{ matrix.test-type }} tests
        run: |
          sentinel test run --types ${{ matrix.test-type }} --wait
```

## Reporting and Notifications

### Test Result Formats

```bash
# JUnit XML (for CI/CD tools)
sentinel test results --format junit > results.xml

# HTML Report
sentinel report generate --format html --output report.html

# JSON (for custom processing)
sentinel test results --format json | jq '.summary'

# Markdown (for PR comments)
sentinel report generate --format markdown
```

### Slack Notifications

```bash
# Send results to Slack
sentinel test run --types all --wait
sentinel notify slack \
  --webhook-url $SLACK_WEBHOOK \
  --channel "#api-testing" \
  --mention-on-failure "@team"
```

### Email Reports

```bash
# Email test results
sentinel report email \
  --recipients "team@example.com,manager@example.com" \
  --subject "API Test Results - Build #$BUILD_NUMBER" \
  --attach-html
```

## Best Practices

### 1. Fail Fast Strategy

```bash
# Stop on first failure for quick feedback
sentinel test run --types functional --fail-fast
```

### 2. Incremental Testing

```yaml
stages:
  - quick_tests    # 2 minutes
  - standard_tests # 10 minutes  
  - full_tests     # 30 minutes

quick_tests:
  stage: quick_tests
  script:
    - sentinel test run --profile quick
    
standard_tests:
  stage: standard_tests
  when: on_success
  script:
    - sentinel test run --profile standard
```

### 3. Test Data Management

```bash
# Create test data before tests
sentinel data generate --spec-id 1 --count 100

# Run tests
sentinel test run --use-generated-data

# Clean up after tests
sentinel data cleanup --older-than 1d
```

### 4. Environment-Specific Testing

```bash
# Development environment
sentinel test run --env dev --types functional

# Staging environment  
sentinel test run --env staging --types all

# Production smoke tests
sentinel test run --env prod --types smoke --read-only
```

## Troubleshooting CI/CD Integration

### Common Issues

1. **Authentication Failures**
   - Verify API token is valid
   - Check token permissions
   - Ensure token is properly escaped in CI/CD variables

2. **Timeout Issues**
   ```bash
   # Increase timeout
   sentinel test run --timeout 1800
   ```

3. **Network Connectivity**
   ```bash
   # Test connectivity
   sentinel health check
   ```

4. **Specification Not Found**
   ```bash
   # List available specifications
   sentinel spec list
   ```

## Next Steps

- Configure [role-based access](./rbac.md) for CI/CD users
- Set up [advanced features](./advanced-features.md)
- Monitor with [analytics dashboards](./test-results.md)

---

← [Back to User Guide](./index.md) | [Next: Role-Based Access Control](./rbac.md) →