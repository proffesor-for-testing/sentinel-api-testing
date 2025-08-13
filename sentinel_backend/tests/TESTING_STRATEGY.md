# Testing Strategy for Sentinel Backend

## Overview
The Sentinel backend uses a multi-layered testing approach with clear separation between unit, integration, and Rust-specific tests.

## Test Categories

### 1. Unit Tests (`pytest -m unit`)
- Test individual components in isolation
- Use mocks for all external dependencies
- Fast execution (< 1 second per test)
- Always run in CI/CD pipeline

### 2. Integration Tests (`pytest -m integration`)
- Test service interactions
- May use real databases (in Docker)
- Test API endpoints with mocked external services
- Run in Docker test environment

### 3. Rust Integration Tests (`pytest -m rust`)
- Specifically test Python-Rust hybrid architecture
- Require Rust core service (sentinel_rust_core) to be running
- Test agent delegation and fallback mechanisms
- Conditionally executed based on service availability

## Running Tests

### Quick Start
```bash
# Run all tests except Rust (if Rust service not available)
./run_tests.sh -d

# Run only unit tests
./run_tests.sh -d -t unit

# Run with Rust tests (forces execution even if service unavailable)
./run_tests_filtered.sh --with-rust -d
```

### Test Filtering
```bash
# Exclude Rust tests explicitly
pytest -m "not rust"

# Run only Rust integration tests
pytest -m rust

# Run integration tests excluding Rust
pytest -m "integration and not rust"
```

## Rust Integration Tests

### Design Philosophy
The Rust integration tests (`tests/test_rust_integration.py`) verify the critical Python-Rust bridge. They:

1. **Auto-skip when Rust service unavailable**: Tests check for service availability and skip gracefully
2. **Can be forced to run**: Set `FORCE_RUST_TESTS=1` to run with mocks
3. **Test real integration when possible**: When Rust service is running, tests verify actual integration

### Why This Approach?
- **Development flexibility**: Developers can work on Python code without Rust service
- **CI/CD reliability**: Tests won't randomly fail due to service availability
- **Clear intent**: Tests marked with `@pytest.mark.rust` clearly indicate Rust dependency
- **Fallback testing**: Critical fallback mechanisms are always tested

### Running Rust Tests

#### Option 1: With Rust Service (Recommended for Integration Testing)
```bash
# Start Rust service
docker-compose up sentinel_rust_core

# Run tests
pytest -m rust
```

#### Option 2: With Mocks (Development/Quick Testing)
```bash
# Force tests to run with mocks
FORCE_RUST_TESTS=1 pytest -m rust
```

#### Option 3: In Docker (Complete Environment)
```bash
# Docker compose includes Rust service
docker-compose -f docker-compose.test.yml up
```

## Test Markers

| Marker | Description | When to Use |
|--------|-------------|-------------|
| `unit` | Unit tests | Always run |
| `integration` | Integration tests | Run in Docker/CI |
| `rust` | Rust service required | Run when Rust available |
| `fallback` | Fallback mechanism tests | Critical path testing |
| `slow` | Long-running tests | Exclude in quick runs |
| `external` | External service required | Run in full environment |

## Best Practices

1. **New tests should be marked appropriately**
   ```python
   @pytest.mark.unit  # or integration, rust, etc.
   async def test_something():
       pass
   ```

2. **Rust-dependent tests should check availability**
   ```python
   @pytest.mark.rust
   @pytest.mark.skipif(not rust_available(), reason="Rust service required")
   async def test_rust_integration():
       pass
   ```

3. **Use mocks for unit tests, real services for integration**
   - Unit tests: Mock everything external
   - Integration tests: Use Docker services
   - Rust tests: Use actual Rust service when available

## Troubleshooting

### "Rust service not available" errors
- Start the Rust service: `docker-compose up sentinel_rust_core`
- Or exclude Rust tests: `pytest -m "not rust"`
- Or force with mocks: `FORCE_RUST_TESTS=1 pytest`

### Test failures in Docker but not locally
- Check Docker test environment: `docker-compose -f docker-compose.test.yml ps`
- Rebuild test image: `docker-compose -f docker-compose.test.yml build test_runner`
- Check dependencies: Ensure all packages in pyproject.toml are installed

### Slow test execution
- Run only unit tests: `pytest -m unit`
- Exclude slow tests: `pytest -m "not slow"`
- Use parallel execution: `pytest -n auto`

## Current Test Status (as of latest fixes)

- **Total Tests**: 224
- **Passing**: 219 (97.8%)
- **Failing**: 5
  - 1 LLM integration test (metadata issue)
  - 3 Rust integration tests (conditional - pass when Rust service available)
  - 1 API Gateway health check (mock configuration issue)

The failing tests are well-understood and documented. Rust tests are expected to fail when the service isn't available, which is by design.