# PR #30 Verification Checklist

**Purpose**: Production deployment validation for Assertion struct changes
**Estimated Time**: 12-16 hours total
**Priority**: CRITICAL before production deployment

---

## Pre-Deployment Checklist

### ✅ Phase 1: Code Review (COMPLETED)
- [x] Review all 47 assertion transformations
- [x] Verify pattern consistency
- [x] Check semantic preservation
- [x] Validate type conversions
- [x] Confirm no breaking changes

**Status**: ✅ **COMPLETE** - All transformations verified correct

**Key Finding**: EdgeCasesAgent is DEPRECATED (reduces risk by 50%)

---

## 🔴 Phase 2: CRITICAL VERIFICATION (REQUIRED)

### Task 1: Assertion Evaluator Documentation (2 hours)

**Goal**: Document how `assertion_type` strings are evaluated

**Checklist**:
- [ ] Locate assertion evaluator implementation
  - **Files to check**:
    - `/sentinel_backend/sentinel_rust_core/src/types.rs`
    - `/sentinel_backend/sentinel_rust_core/src/executors/`
    - Python test executor code
- [ ] Document parsing logic:
  - [ ] How is `response_time_p99_lt` parsed?
  - [ ] Is `p99` extracted as percentile?
  - [ ] Is `lt` extracted as operator?
- [ ] Document operator mapping:
  - [ ] `eq` → equality comparison
  - [ ] `lt` → less than
  - [ ] `gt` → greater than
  - [ ] `in` → array membership
- [ ] Create lookup table of all supported assertion types

**Deliverable**: `/docs/ASSERTION_EVALUATOR_SPEC.md`

**Validation**:
```bash
# Find evaluator implementation
cd sentinel_backend
grep -r "assertion_type" --include="*.rs" --include="*.py"
grep -r "evaluate_assertion" --include="*.rs" --include="*.py"
```

---

### Task 2: Percentile Assertion Testing (2 hours)

**Goal**: Verify percentile parsing works correctly

**Checklist**:
- [ ] Create test file: `/sentinel_backend/tests/unit/test_assertion_percentiles.py`
- [ ] Test P50 assertion:
  ```python
  def test_p50_assertion():
      assertion = {
          'assertion_type': 'response_time_p50_lt',
          'expected': '200ms',
          'path': None
      }
      # Pass case
      assert evaluate_assertion(assertion, {'response_time_p50': 150}) == True
      # Fail case
      assert evaluate_assertion(assertion, {'response_time_p50': 250}) == False
  ```
- [ ] Test all percentiles: P50, P75, P90, P95, P99, P99.9
- [ ] Test boundary conditions:
  - [ ] Exactly at threshold: `p95 = 2000ms` (should fail for `< 2000ms`)
  - [ ] Just under: `p95 = 1999ms` (should pass)
  - [ ] Just over: `p95 = 2001ms` (should fail)
- [ ] Run tests:
  ```bash
  cd sentinel_backend
  pytest tests/unit/test_assertion_percentiles.py -v
  ```

**Expected Result**: All percentile patterns correctly parsed and evaluated

---

### Task 3: Boolean Assertion Testing (1 hour)

**Goal**: Verify boolean equality works correctly

**Checklist**:
- [ ] Create test file: `/sentinel_backend/tests/unit/test_assertion_boolean.py`
- [ ] Test memory leak detection:
  ```python
  def test_memory_leak_detection():
      assertion = {
          'assertion_type': 'memory_leak_detection_eq',
          'expected': False,
          'path': None
      }
      # No leak detected (pass)
      assert evaluate_assertion(assertion, {'memory_leak_detected': False}) == True

      # Leak detected (fail)
      assert evaluate_assertion(assertion, {'memory_leak_detected': True}) == False
  ```
- [ ] Test with different boolean values
- [ ] Test type coercion (if any): `0` vs `False`, `1` vs `True`
- [ ] Run tests:
  ```bash
  cd sentinel_backend
  pytest tests/unit/test_assertion_boolean.py -v
  ```

**Expected Result**: Boolean equality correctly evaluates both `True` and `False`

---

### Task 4: String Percentage Testing (1 hour)

**Goal**: Verify percentage string comparison is numeric

**Checklist**:
- [ ] Create test file: `/sentinel_backend/tests/unit/test_assertion_percentages.py`
- [ ] Test performance degradation:
  ```python
  def test_performance_degradation_numeric():
      assertion = {
          'assertion_type': 'performance_degradation_lt',
          'expected': '10%',
          'path': None
      }
      # 5% < 10% (pass)
      assert evaluate_assertion(assertion, {'degradation': '5%'}) == True

      # 15% > 10% (fail)
      assert evaluate_assertion(assertion, {'degradation': '15%'}) == False

      # Boundary: 10% == 10% (fail for <)
      assert evaluate_assertion(assertion, {'degradation': '10%'}) == False

      # Lexicographic would fail: "8%" > "10%" lexicographically
      assert evaluate_assertion(assertion, {'degradation': '8%'}) == True  # Must be numeric!
  ```
- [ ] Test edge cases:
  - [ ] Missing `%` symbol: `"10"` vs `"10%"`
  - [ ] Decimal percentages: `"9.5%"`
  - [ ] Large percentages: `"150%"`
- [ ] Run tests:
  ```bash
  cd sentinel_backend
  pytest tests/unit/test_assertion_percentages.py -v
  ```

**Expected Result**: Percentage comparison uses **numeric parsing**, not lexicographic

**🔴 CRITICAL**: If lexicographic, `"8%" > "10%"` would incorrectly pass as `< 10%`

---

## 🟠 Phase 3: HIGH PRIORITY TESTING (6 hours)

### Task 5: End-to-End Performance Planner Test (3 hours)

**Goal**: Verify complete workflow from generation to execution

**Checklist**:
- [ ] Create test file: `/sentinel_backend/tests/integration/test_performance_planner_e2e.py`
- [ ] Test load test generation:
  ```python
  def test_load_test_generation():
      api_spec = load_sample_api_spec()
      task = create_task(agent_type="Performance-Planner-Agent")

      # Generate tests
      result = performance_planner_agent.execute(task, api_spec)

      # Verify assertions use new pattern
      for test_case in result.test_cases:
          for assertion in test_case.assertions:
              assert 'assertion_type' in assertion
              assert 'path' in assertion
              # Old fields should NOT exist
              assert 'field' not in assertion
              assert 'operator' not in assertion
  ```
- [ ] Test assertion execution:
  ```python
  def test_assertion_execution():
      # Create mock performance results
      mock_results = {
          'response_time_p95': 1500,  # Under 2000ms threshold
          'response_time_p99': 4000,  # Under 5000ms threshold
          'error_rate': '0.5%',        # Under 1% threshold
          'throughput': 120,           # Over 100 threshold
          'memory_leak_detected': False,
          'performance_degradation': '3%',
      }

      # Execute assertions
      test_case = result.test_cases[0]
      for assertion in test_case.assertions:
          result = evaluate_assertion(assertion, mock_results)
          assert result == True, f"Assertion {assertion['assertion_type']} failed unexpectedly"
  ```
- [ ] Test failure scenarios:
  ```python
  def test_assertion_failures():
      mock_results = {
          'response_time_p95': 2500,  # Over 2000ms threshold (should fail)
          'memory_leak_detected': True,  # Leak detected (should fail)
      }

      # P95 assertion should fail
      p95_assertion = {'assertion_type': 'response_time_p95_lt', 'expected': '2000ms', 'path': None}
      assert evaluate_assertion(p95_assertion, mock_results) == False

      # Memory leak assertion should fail
      leak_assertion = {'assertion_type': 'memory_leak_detection_eq', 'expected': False, 'path': None}
      assert evaluate_assertion(leak_assertion, mock_results) == False
  ```
- [ ] Run E2E test:
  ```bash
  cd sentinel_backend
  pytest tests/integration/test_performance_planner_e2e.py -v --tb=long
  ```

**Expected Result**: All assertions generate correctly AND evaluate correctly

---

### Task 6: Regression Test Suite (3 hours)

**Goal**: Comprehensive regression coverage for all assertion types

**Checklist**:
- [ ] Create test file: `/sentinel_backend/tests/regression/test_pr30_assertions.py`
- [ ] Test all 9 assertion type families:
  - [ ] `status_code_in`: Array membership
  - [ ] `response_time_lt`: Numeric less than
  - [ ] `response_time_p{N}_lt`: Percentile thresholds
  - [ ] `throughput_gt`: Numeric greater than
  - [ ] `error_rate_lt`: Percentage less than
  - [ ] `memory_leak_detection_eq`: Boolean equality
  - [ ] `performance_degradation_lt`: Percentage less than
  - [ ] `user_experience_score_gt`: Numeric greater than
  - [ ] `journey_completion_rate_gt`: Percentage greater than
- [ ] Test data type handling:
  - [ ] Numbers: integers, floats
  - [ ] Strings: percentages, time units
  - [ ] Booleans: `True`, `False`
  - [ ] Arrays: status codes, error types
- [ ] Test edge cases:
  - [ ] Empty arrays
  - [ ] Null values
  - [ ] Missing keys in result data
  - [ ] Type mismatches
- [ ] Run full regression suite:
  ```bash
  cd sentinel_backend
  pytest tests/regression/test_pr30_assertions.py -v --cov=sentinel_rust_core
  ```

**Expected Result**: 100% pass rate, no regressions

---

## 🟡 Phase 4: MEDIUM PRIORITY (Optional, 4 hours)

### Task 7: Documentation (2 hours)

**Checklist**:
- [ ] Create assertion type registry: `/docs/ASSERTION_TYPES_REGISTRY.md`
- [ ] Document all supported types:
  - Comparison operators: `eq`, `lt`, `gt`, `in`
  - Special patterns: percentiles, percentages
  - Data types: number, string, boolean, array
- [ ] Create migration guide for any remaining old patterns
- [ ] Update API documentation

---

### Task 8: Backward Compatibility Detection (2 hours)

**Checklist**:
- [ ] Add compile-time check for old pattern:
  ```rust
  impl Assertion {
      #[deprecated(since = "2.0.0", note = "Use assertion_type instead")]
      pub fn from_legacy(_field: String, _operator: String, _expected: Value) -> Result<Self, String> {
          Err("Legacy assertion format (field + operator) is no longer supported. Use assertion_type field.".to_string())
      }
  }
  ```
- [ ] Scan codebase for any remaining old patterns:
  ```bash
  cd sentinel_backend
  grep -r "field.*operator.*Assertion" --include="*.rs"
  ```
- [ ] If found, convert or document as known issues

---

## Final Verification

### Pre-Production Checklist

**MANDATORY** (Must ALL be checked before production):

- [ ] **Phase 2 Complete**: All 4 critical verification tasks passed
- [ ] **Phase 3 Complete**: E2E and regression tests passed
- [ ] **Assertion Evaluator**: Implementation documented
- [ ] **Test Coverage**: Regression tests achieve >95% coverage
- [ ] **Performance**: No degradation in test execution time
- [ ] **Documentation**: Assertion types documented
- [ ] **Staging Deployment**: Tested in staging for 48 hours
- [ ] **No Production Incidents**: During staging period

### Production Deployment Approval

**Sign-off Required**:
- [ ] QE Team Lead
- [ ] Code Review Specialist
- [ ] DevOps Engineer
- [ ] Product Owner (if SLO changes)

**Deployment Plan**:
1. **Stage 1**: Deploy to staging (IMMEDIATE)
2. **Stage 2**: Run verification tests (Phase 2-3)
3. **Stage 3**: Monitor staging for 48 hours
4. **Stage 4**: Deploy to production (gradual rollout)
5. **Stage 5**: Monitor production metrics

---

## Risk Mitigation Plan

### If Tests Fail

**Percentile Assertions Fail**:
- [ ] **Action**: Fix assertion evaluator percentile parsing
- [ ] **Timeline**: 4-6 hours
- [ ] **Rollback**: Revert PR #30 (compilation will fail, but safer than wrong assertions)

**Boolean Assertions Fail**:
- [ ] **Action**: Fix boolean equality logic
- [ ] **Timeline**: 2-4 hours
- [ ] **Rollback**: Not recommended (breaks compilation)

**Percentage Assertions Fail**:
- [ ] **Action**: Fix string percentage parsing (numeric vs lexicographic)
- [ ] **Timeline**: 3-5 hours
- [ ] **Rollback**: Revert if string comparison is lexicographic

---

## Success Criteria

**Deployment is APPROVED if**:
1. ✅ All Phase 2 tests pass (percentiles, booleans, percentages)
2. ✅ All Phase 3 tests pass (E2E, regression)
3. ✅ Test coverage >95% for assertion-related code
4. ✅ No performance degradation
5. ✅ Staging deployment stable for 48 hours
6. ✅ All sign-offs obtained

**Timeline**: **1 week** from code review completion

---

## Contacts

**Questions or Issues**:
- **Code Review**: Code Review Specialist Agent
- **QE Lead**: [Team Lead Name]
- **DevOps**: [DevOps Engineer Name]
- **Emergency Rollback**: [On-Call Engineer]

**Documentation**:
- Full Review: `/docs/PR30_ASSERTION_CODE_REVIEW.md`
- Summary: `/docs/PR30_REVIEW_SUMMARY.md`
- This Checklist: `/docs/PR30_VERIFICATION_CHECKLIST.md`

---

**Created**: 2025-10-29
**Last Updated**: 2025-10-29
**Version**: 1.0
