# Functional Agent Consolidation Plan

## Status: Waiting for TDD Tests

**Current State:** Ready to implement once test file is created
**Test File Required:** `/workspaces/api-testing-agents/sentinel_backend/orchestration_service/tests/agents/test_functional_agent.py`

## Analysis Complete

### Source Agents (4,812 LOC Total)
1. **functional_positive_agent.py** (29,421 bytes)
   - Happy path tests
   - Valid data generation
   - Parameter/body variations
   - LLM enhancement support

2. **functional_negative_agent.py** (133,672 bytes) ⚠️ LARGEST
   - Invalid data tests
   - **Boundary Value Analysis** (DUPLICATE)
   - Type mismatches
   - Required field tests
   - Constraint violations
   - 8+ test generation stages

3. **edge_cases_agent.py** (34,058 bytes)
   - **Boundary Value Analysis** (DUPLICATE)
   - Unicode edge cases
   - Float precision tests
   - DateTime edge cases
   - Collection size tests
   - Case sensitivity tests

### Key Duplication Found
**70% overlap confirmed:**
- Both Negative and Edge agents implement BVA independently
- Both test minimum/maximum boundaries
- Both test boundary violations (min-1, max+1)
- Same test patterns, different names

## Consolidation Strategy

### New Architecture: FunctionalAgent (~1,500 LOC target)

```python
class FunctionalAgent(BaseAgent):
    strategy: Literal["positive", "negative", "boundary", "edge_case"]

    strategies = {
        "positive": PositiveStrategy(),
        "negative": NegativeStrategy(),
        "boundary": BoundaryStrategy(),  # SINGLE SOURCE OF TRUTH
        "edge_case": EdgeCaseStrategy()
    }
```

### Strategy Responsibilities

#### 1. PositiveStrategy
**Source:** functional_positive_agent.py
**Responsibility:** Valid/happy path tests
- Basic positive tests
- Valid parameter combinations
- Valid request bodies
- Expected success (200/201)

#### 2. NegativeStrategy
**Source:** functional_negative_agent.py (minus BVA)
**Responsibility:** Invalid data tests
- Missing required fields
- Wrong data types
- Invalid enum values
- Constraint violations (non-boundary)
- Format violations

#### 3. BoundaryStrategy ⭐ KEY CONSOLIDATION
**Source:** Extract from BOTH negative + edge agents
**Responsibility:** ALL boundary testing in ONE place
- Numeric boundaries (min, max, min-1, max+1)
- String length boundaries
- Array size boundaries
- Exclusive/inclusive boundaries
- **Eliminates all BVA duplication**

#### 4. EdgeCaseStrategy
**Source:** edge_cases_agent.py (minus BVA)
**Responsibility:** Special value edge cases
- Unicode/emoji tests
- Float precision (NaN, Inf, -0.0)
- DateTime edge cases
- Collection edge cases (empty, single item)
- Whitespace variations
- Case sensitivity

## Implementation Checklist

- [ ] Wait for test_functional_agent.py from TDD specialist
- [ ] Review test requirements
- [ ] Create FunctionalAgent base with strategy enum
- [ ] Implement PositiveStrategy (extract from positive agent)
- [ ] Implement NegativeStrategy (extract from negative agent, REMOVE BVA)
- [ ] Implement BoundaryStrategy (consolidate BVA from both agents)
- [ ] Implement EdgeCaseStrategy (extract from edge agent, REMOVE BVA)
- [ ] Add deduplication logic (test signatures)
- [ ] Run tests and iterate
- [ ] Verify no duplication with other agents
- [ ] Validate ~1,500 LOC target achieved

## Expected Results

### Code Reduction
- **Before:** 4,812 LOC across 3 agents
- **After:** ~1,500 LOC in 1 agent
- **Reduction:** 68% fewer lines

### Test Quality
- Single source of truth for boundaries
- Consistent test naming
- No duplicate test generation
- Faster execution
- Easier maintenance

## Next Step
**Waiting for:** TDD specialist to create test_functional_agent.py
**Then:** Implement based on test requirements
