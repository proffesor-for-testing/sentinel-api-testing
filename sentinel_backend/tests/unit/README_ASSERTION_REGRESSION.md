# 🔴 CRITICAL: Assertion Semantics Regression Tests (PR #30)

## Executive Summary

**Risk Score: 42/100 (MEDIUM-HIGH)**
**Priority: P1 - MUST PASS BEFORE PRODUCTION**

PR #30 changed the Assertion struct from `field+operator` pattern to `assertion_type` pattern across **47 instances** in `edge_cases.rs` and `performance_planner.rs`.

These regression tests validate that assertion semantics remain **IDENTICAL** after the structural changes.

## Files

- **Test Suite**: `/workspaces/api-testing-agents/sentinel_backend/tests/unit/test_assertion_semantics_regression.py`
- **Test Runner**: `/workspaces/api-testing-agents/sentinel_backend/tests/unit/run_assertion_regression_tests.py`
- **Analysis**: `/workspaces/api-testing-agents/docs/REGRESSION_RISK_ANALYSIS_PR30.md`

## What Changed in PR #30

### Old Pattern (INCORRECT - Compilation Failures)
```rust
Assertion {
    field: "status".to_string(),
    operator: "in".to_string(),
    expected: Value::Array([...]),
}
```

### New Pattern (CORRECT - Fixed in PR #30)
```rust
Assertion {
    assertion_type: "status_code_in".to_string(),
    expected: Value::Array([...]),
    path: None,
}
```

## Critical Risks

### 1. Security Vulnerabilities (HIGH)
- **Edge case tests** (unicode malformation, payload size limits, rate limiting)
- If `status_code_in` semantics differ, malicious input could bypass validation
- **Impact**: Injection attacks, DoS vulnerabilities reaching production

### 2. Performance Degradation (CRITICAL)
- **SLO thresholds** (P95, P99 response times)
- If percentile assertions fail silently, performance violations won't be caught
- **Impact**: Production outages, capacity planning errors

### 3. Production Instability (CRITICAL)
- **Memory leak detection** in 2h/8h/72h endurance tests
- If boolean assertions change semantics, leaks could reach production
- **Impact**: OOM crashes, service instability

### 4. Data Integrity (HIGH)
- **Throughput validation**, performance degradation tracking
- If numeric/string comparisons change, capacity issues may go undetected
- **Impact**: Under-provisioned infrastructure, gradual degradation

## Test Coverage

The test suite validates **ALL** assertion types used in PR #30:

### Priority 1: CRITICAL (9 tests)
- ✅ `status_code_in` - Status code validation
- ✅ `response_time_p{N}_lt` - Response time percentiles (P50, P75, P90, P95, P99, P99.9)
- ✅ `memory_leak_detection_eq` - Boolean memory leak detection
- ✅ `performance_degradation_lt` - String percentage comparison
- ✅ `throughput_gt` - Throughput validation
- ✅ `user_experience_score_gt` - UX score validation
- ✅ Edge case scenarios (unicode, payload size, rate limiting)

### Priority 2: HIGH (2 tests)
- ✅ Assertion type name mapping correctness
- ✅ Dynamic percentile assertion name generation

### Priority 3: MEDIUM (4 tests)
- ✅ Backward compatibility validation
- ✅ Old vs new pattern detection
- ✅ Comprehensive assertion type coverage (25+ types)
- ✅ Security assertion types

## Running the Tests

### Option 1: Quick Validation (Recommended for CI)
```bash
# Run inline critical tests (no dependencies)
./sentinel_backend/venv/bin/python3 << 'EOF'
import sys
sys.path.insert(0, 'sentinel_backend')
exec(open('sentinel_backend/tests/unit/run_assertion_regression_tests.py').read())
EOF
```

### Option 2: Full pytest Suite (After fixing conftest)
```bash
# Run all tests with pytest
./sentinel_backend/venv/bin/pytest \
  sentinel_backend/tests/unit/test_assertion_semantics_regression.py \
  -v --tb=short --no-cov

# Run only critical tests
./sentinel_backend/venv/bin/pytest \
  sentinel_backend/tests/unit/test_assertion_semantics_regression.py \
  -v -m critical --no-cov
```

### Option 3: Docker Environment
```bash
# Run in Docker container (recommended for full environment)
cd sentinel_backend && ./run_tests.sh -d -t test_assertion_semantics_regression.py
```

## Expected Results

### ✅ Success (Safe for Production)
```
================================================================================
🔴 CRITICAL REGRESSION TESTS: PR #30 Assertion Semantics
================================================================================

Test 1: status_code_in assertion
  ✓ PASSED
Test 2: response_time_p99_lt assertion
  ✓ PASSED
Test 3: memory_leak_detection_eq assertion
  ✓ PASSED
Test 4: performance_degradation_lt assertion (string percentage)
  ✓ PASSED
Test 5: throughput_gt assertion
  ✓ PASSED

================================================================================
✅ ALL CRITICAL TESTS PASSED
✅ Assertion semantics validated for PR #30
✅ SAFE for production deployment
================================================================================
```

### ❌ Failure (BLOCK PRODUCTION)
```
================================================================================
❌ TESTS FAILED
❌ Assertion semantics have changed - REGRESSION DETECTED
❌ DO NOT DEPLOY to production until fixed
================================================================================
```

## Fixing Test Failures

If tests fail:

1. **Check assertion evaluator implementation**
   ```bash
   # Find the actual evaluator
   grep -r "def.*evaluate_assertion" sentinel_backend/
   ```

2. **Compare expected vs actual behavior**
   - Old pattern: `field + operator`
   - New pattern: `assertion_type` string parsing
   - Must produce IDENTICAL results

3. **Update evaluator if needed**
   - Ensure `assertion_type` parsing extracts correct operator
   - Verify comparison logic matches old behavior
   - Test ALL operator types: `in`, `eq`, `lt`, `gt`, `ne`, `lte`, `gte`

4. **Re-run tests until all pass**

## Integration with CI/CD

### Pre-Production Checklist
- [ ] All 15 regression tests pass
- [ ] No assertion evaluator changes between PR #30 and deployment
- [ ] Edge case agent tested end-to-end
- [ ] Performance planner agent tested end-to-end
- [ ] Production monitoring configured for assertion failures

### Continuous Monitoring
After deployment, monitor for:
- ❌ Assertion evaluation errors in logs
- ❌ Unexpected test pass/fail rate changes
- ❌ Security vulnerabilities from edge case failures
- ❌ Performance degradation not caught by tests

## References

- **Risk Analysis**: `docs/REGRESSION_RISK_ANALYSIS_PR30.md`
- **PR #30**: Assertion struct fixes (merged 2025-10-02)
- **PR #32**: Massive infrastructure changes (context)
- **Rust Types**: `sentinel_backend/sentinel_rust_core/src/types.rs`
- **Edge Cases**: `sentinel_backend/sentinel_rust_core/src/agents/edge_cases.rs`
- **Performance**: `sentinel_backend/sentinel_rust_core/src/agents/performance_planner.rs`

## Contact

For questions about these tests:
- Review the full risk analysis: `docs/REGRESSION_RISK_ANALYSIS_PR30.md`
- Check test implementation: `tests/unit/test_assertion_semantics_regression.py`
- Examine Rust changes: `git show <PR30-commit>`

## Timeline

- **Now**: Run regression tests
- **Before Production**: All tests must pass
- **After Deployment**: Monitor for assertion-related failures
- **1 Week**: Review production metrics
- **1 Month**: Full regression suite validation

---

**Last Updated**: 2025-10-29
**Test Suite Version**: 1.0
**Status**: ✅ Ready for Production Validation
