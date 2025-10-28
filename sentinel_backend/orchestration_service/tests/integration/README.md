# Integration Test Suite - Agent Consolidation

## Overview

This directory contains comprehensive integration tests for validating the agent consolidation effort. The goal is to reduce test duplication from 60-75% to < 10% while maintaining test coverage.

## Files

### 1. test_agent_consolidation.py
Comprehensive pytest test suite for agent validation.

**Test Classes:**
- `TestAgentDuplication` - Validates duplication rate across all agents
- `TestCaseQuality` - Ensures test case structure and quality
- `TestAgentSpecialization` - Verifies no overlap between specialized agents
- `TestPerformanceMetrics` - Validates test generation efficiency

**Key Features:**
- TestSignatureGenerator - Creates unique signatures for duplicate detection
- DuplicationAnalyzer - Measures and reports duplication across agents
- Automated validation against < 10% threshold

### 2. run_duplication_analysis.py
Standalone script for baseline duplication measurement.

**Usage:**
```bash
cd /workspaces/api-testing-agents/sentinel_backend
PYTHONPATH=$(pwd) python orchestration_service/tests/integration/run_duplication_analysis.py
```

**Outputs:**
- Console report with duplication statistics
- JSON report saved to `duplication_report.json`
- Exit code 0 if duplication < 10%, exit code 1 otherwise

### 3. VALIDATION_REPORT.md
Comprehensive assessment report documenting:
- Current implementation status
- Agent-by-agent analysis
- Duplication evidence
- Integration test results
- Recommendations and action items

## Running Tests

### Prerequisites
```bash
# Ensure virtual environment is activated
source /workspaces/api-testing-agents/sentinel_backend/venv/bin/activate

# Install dependencies (if needed)
pip install pytest pytest-asyncio
```

### Run All Integration Tests
```bash
cd /workspaces/api-testing-agents/sentinel_backend
pytest orchestration_service/tests/integration/test_agent_consolidation.py -v
```

### Run Specific Test Classes
```bash
# Test duplication only
pytest orchestration_service/tests/integration/test_agent_consolidation.py::TestAgentDuplication -v

# Test quality only
pytest orchestration_service/tests/integration/test_agent_consolidation.py::TestCaseQuality -v
```

### Run Duplication Analysis
```bash
python orchestration_service/tests/integration/run_duplication_analysis.py
```

## Test Signature Algorithm

The deduplication system uses MD5 hashes of test characteristics:

```python
signature = {
    'method': 'GET',
    'path': '/users',
    'query_params': ['limit', 'offset'],  # Keys only, sorted
    'body_structure': {'name': 'str', 'email': 'str'},  # Structure only
    'expected_status': 200
}
# MD5 hash -> unique signature
```

This ensures:
- Same endpoint + method + params = duplicate
- Different parameter values = same signature (expected)
- Different body values with same structure = same signature

## Success Criteria

### Phase 1: Baseline Measurement ✅
- [x] Integration test suite created
- [x] Deduplication analyzer implemented
- [x] Test signature generation working
- [x] Validation report generated

### Phase 2: Consolidation (Pending)
- [ ] Agent count reduced to 4
- [ ] Duplication rate < 10%
- [ ] All integration tests pass
- [ ] No test coverage regression

### Phase 3: Validation (Pending)
- [ ] Run full test suite
- [ ] Measure performance improvement
- [ ] Document final metrics
- [ ] Generate compliance report

## Known Issues

### Import Path Issues
The standalone analysis script currently has Python module path issues due to the sentinel_backend package structure. This will be resolved when:

1. Agents are properly consolidated
2. Module structure is cleaned up
3. PYTHONPATH is correctly configured

**Workaround**: Use the pytest-based tests instead of the standalone script.

### Current Limitations

1. **Cannot measure actual duplication yet** - Agents not consolidated
2. **Integration tests prepared but not executable** - Python path issues
3. **DataGenerationService partially integrated** - Only 2 of 9 agents updated

## Next Steps

1. **Complete Agent Consolidation**
   - Merge Functional-Positive + Functional-Negative
   - Delete Edge-Cases-Agent
   - Merge Security agents

2. **Run Validation Tests**
   - Execute test_agent_consolidation.py
   - Verify duplication < 10%
   - Confirm test quality

3. **Generate Final Report**
   - Actual duplication measurements
   - Performance improvements
   - Code reduction metrics

## Contact

For questions about these tests, see:
- `/sentinel_backend/docs/implementation-roadmap.md` - Consolidation plan
- `/sentinel_backend/docs/agent-value-assessment.md` - Agent analysis
- `/orchestration_service/tests/integration/VALIDATION_REPORT.md` - Current status

---

**Last Updated**: 2025-10-03
**Status**: Baseline assessment complete, consolidation pending
