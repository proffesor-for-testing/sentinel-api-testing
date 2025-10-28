# Implementation Roadmap: Agent Consolidation

## Overview

This roadmap provides a step-by-step plan to consolidate from 9 agents to 4 core agents, eliminating 60-75% duplication and reducing codebase by 54%.

**Timeline**: 1 week (40 hours)
**Team Size**: 1-2 developers
**Risk Level**: MEDIUM (requires careful migration and testing)

---

## Phase 1: Preparation & Foundation (Day 1 - 8 hours)

### Milestone 1.1: Create Data Generation Service (4 hours)

**Objective**: Extract data generation logic into reusable service

**Steps**:
1. Create new file: `/workspaces/api-testing-agents/sentinel_backend/orchestration_service/services/data_generation_service.py`
2. Move data generation logic from Data-Mocking-Agent:
   - `_generate_from_schema()` → `generate_from_schema()`
   - `_generate_realistic_object()` → `_generate_realistic()`
   - Field pattern mappings
   - Faker integration
3. Add strategy support: realistic, edge_case, boundary, invalid
4. Create singleton instance with `get_data_service()`

**Validation**:
```python
# Test the service independently
from services.data_generation_service import get_data_service

service = get_data_service()
schema = {"type": "object", "properties": {"name": {"type": "string"}}}
data = service.generate_from_schema(schema, strategy="realistic")
assert isinstance(data, dict)
assert "name" in data
```

**Deliverables**:
- `/sentinel_backend/orchestration_service/services/data_generation_service.py` (400 LOC)
- Unit tests for data service (100 LOC)

---

### Milestone 1.2: Create Test Deduplication Utility (2 hours)

**Objective**: Build utility to detect and remove duplicate tests

**Steps**:
1. Create `/workspaces/api-testing-agents/sentinel_backend/orchestration_service/utils/test_deduplication.py`
2. Implement test signature generation:
   ```python
   def create_test_signature(test: Dict) -> str:
       """Create unique signature for test case."""
       return json.dumps({
           'method': test.get('method'),
           'path': test.get('path'),
           'test_type': test.get('test_type'),
           'key_params': sorted(test.get('query_params', {}).keys()),
           'body_keys': sorted(test.get('body', {}).keys()) if test.get('body') else []
       }, sort_keys=True)

   def deduplicate_tests(test_cases: List[Dict]) -> List[Dict]:
       """Remove duplicate tests."""
       seen = set()
       unique = []
       for test in test_cases:
           sig = create_test_signature(test)
           if sig not in seen:
               seen.add(sig)
               unique.append(test)
       return unique
   ```

**Validation**:
```python
# Test deduplication
tests = [
    {'method': 'GET', 'path': '/users', 'test_type': 'positive'},
    {'method': 'GET', 'path': '/users', 'test_type': 'positive'},  # Duplicate
    {'method': 'GET', 'path': '/users', 'test_type': 'negative'},  # Different type
]
unique = deduplicate_tests(tests)
assert len(unique) == 2
```

**Deliverables**:
- `/sentinel_backend/orchestration_service/utils/test_deduplication.py` (80 LOC)
- Unit tests (50 LOC)

---

### Milestone 1.3: Setup Test Framework (2 hours)

**Objective**: Prepare comprehensive testing infrastructure

**Steps**:
1. Create test fixtures for sample OpenAPI specs
2. Setup pytest configuration
3. Create baseline metrics for current agents:
   ```python
   # baseline_metrics.py
   def measure_agent_performance():
       """Measure current agent test generation."""
       results = {}
       for agent in [Positive, Negative, EdgeCases]:
           tests = agent.execute(sample_spec)
           results[agent.name] = {
               'test_count': len(tests),
               'execution_time': measure_time(),
               'unique_tests': count_unique(tests)
           }
       return results
   ```

**Deliverables**:
- Test fixtures (3 sample OpenAPI specs)
- Baseline metrics report
- Pytest configuration

---

## Phase 2: Core Agent Consolidation (Days 2-3 - 16 hours)

### Milestone 2.1: Create Unified Functional-Agent (8 hours)

**Objective**: Merge Functional-Positive, Functional-Negative, Edge-Cases into one agent

**Steps**:

**Hour 1-2: Create base structure**
```bash
cd /workspaces/api-testing-agents/sentinel_backend/orchestration_service/agents/
touch functional_agent.py
```

Create strategy classes:
- `PositiveStrategy`
- `NegativeStrategy`
- `BoundaryStrategy`
- `EdgeCaseStrategy`

**Hour 3-4: Migrate Positive tests**
- Copy logic from `functional_positive_agent.py`
- Refactor into `PositiveStrategy.generate_tests()`
- Update to use data service
- Add unit tests

**Hour 5-6: Migrate Negative tests**
- Copy logic from `functional_negative_agent.py`
- Extract only unique tests (remove BVA - that goes to BoundaryStrategy)
- Focus on: wrong types, missing required, constraint violations
- Add unit tests

**Hour 7: Migrate Boundary tests**
- Consolidate BVA from all three agents
- Single source of truth for boundary testing
- Test: min, max, min-1, max+1 for all parameters
- Add unit tests

**Hour 8: Migrate Edge case tests**
- Extract ONLY unique tests from Edge-Cases-Agent:
  - Unicode edge cases
  - Float precision tests
  - DateTime edge cases
- Add to `EdgeCaseStrategy`
- Add unit tests

**Integration**:
```python
class FunctionalAgent(BaseAgent):
    def __init__(self):
        super().__init__("Functional-Agent")
        self.strategies = {
            'positive': PositiveStrategy(self),
            'negative': NegativeStrategy(self),
            'boundary': BoundaryStrategy(self),
            'edge_case': EdgeCaseStrategy(self)
        }
        self.data_service = get_data_service()

    async def execute(self, task: AgentTask, api_spec: Dict) -> AgentResult:
        requested_strategies = task.parameters.get('strategies', ['positive', 'negative', 'boundary'])

        all_tests = []
        for strategy_name in requested_strategies:
            strategy = self.strategies[strategy_name]
            tests = await strategy.generate_tests(endpoints, api_spec)
            all_tests.extend(tests)

        # Deduplicate
        unique_tests = deduplicate_tests(all_tests)

        return AgentResult(
            test_cases=unique_tests,
            metadata={
                'total_generated': len(all_tests),
                'unique_tests': len(unique_tests),
                'duplicates_removed': len(all_tests) - len(unique_tests)
            }
        )
```

**Validation**:
```python
# Test all strategies
agent = FunctionalAgent()
result = await agent.execute(task, sample_openapi_spec)

# Should have tests from all strategies
assert any(t['test_type'] == 'functional-positive' for t in result.test_cases)
assert any(t['test_type'] == 'functional-negative' for t in result.test_cases)
assert any(t['test_type'] == 'functional-boundary' for t in result.test_cases)

# Should NOT have duplicates
signatures = [create_test_signature(t) for t in result.test_cases]
assert len(signatures) == len(set(signatures))  # All unique
```

**Deliverables**:
- `/sentinel_backend/orchestration_service/agents/functional_agent.py` (~1,500 LOC)
- Comprehensive unit tests (500 LOC)
- Integration tests (200 LOC)
- Migration documentation

---

### Milestone 2.2: Merge Security Agents (4 hours)

**Objective**: Consolidate Security-Auth and Security-Injection

**Steps**:

**Hour 1: Create SecurityAgent structure**
```python
class SecurityAgent(BaseAgent):
    def __init__(self):
        super().__init__("Security-Agent")
        self.test_types = {
            'authentication': AuthenticationTests(self),
            'authorization': AuthorizationTests(self),
            'injection': InjectionTests(self)
        }
```

**Hour 2: Migrate Auth tests**
- BOLA tests from Security-Auth-Agent
- Auth bypass tests
- Function-level authorization tests

**Hour 3: Migrate Injection tests**
- SQL injection from Security-Injection-Agent
- NoSQL injection
- Command injection
- Prompt injection (for LLM APIs)

**Hour 4: Testing and integration**
- Unit tests for each test type
- Integration tests
- Validate all security scenarios covered

**Deliverables**:
- `/sentinel_backend/orchestration_service/agents/security_agent.py` (~900 LOC)
- Unit tests (300 LOC)

---

### Milestone 2.3: Refactor Data-Mocking-Agent (4 hours)

**Objective**: Convert from test-generating agent to data utility

**Steps**:

**Hour 1-2: Remove test generation**
- Delete `_generate_data_test_cases()` (lines 442-572)
- Delete `_generate_endpoint_data_cases()` (lines 477-572)
- Keep only data generation methods

**Hour 3: Reorganize as utility**
- Move remaining logic to data_generation_service.py
- Deprecate agent
- Update imports in other agents

**Hour 4: Update other agents**
- Update Functional-Agent to use data service
- Update Security-Agent to use data service
- Remove data generation duplication

**Deliverables**:
- Deprecated Data-Mocking-Agent (or removed)
- Enhanced data_generation_service.py (600 LOC total)
- Updated imports across all agents

---

## Phase 3: Testing & Validation (Day 4 - 8 hours)

### Milestone 3.1: Comprehensive Testing (4 hours)

**Test Coverage Requirements**:
- Unit tests: 90%+ coverage
- Integration tests: All agent interactions
- E2E tests: Full workflow with real OpenAPI specs

**Test Scenarios**:

1. **Functional-Agent Tests**:
   ```python
   def test_functional_agent_positive_strategy():
       agent = FunctionalAgent()
       task = AgentTask(parameters={'strategies': ['positive']})
       result = await agent.execute(task, petstore_spec)

       assert result.status == "success"
       assert len(result.test_cases) > 0
       assert all(t['test_type'] == 'functional-positive' for t in result.test_cases)

   def test_functional_agent_no_duplicates():
       agent = FunctionalAgent()
       task = AgentTask(parameters={'strategies': ['positive', 'negative', 'boundary']})
       result = await agent.execute(task, petstore_spec)

       # Check for duplicates
       signatures = [create_test_signature(t) for t in result.test_cases]
       assert len(signatures) == len(set(signatures))

   def test_functional_agent_uses_data_service():
       agent = FunctionalAgent()
       assert agent.data_service is not None

       # Verify it uses service for body generation
       with mock.patch.object(agent.data_service, 'generate_from_schema') as mock_gen:
           mock_gen.return_value = {'name': 'test'}
           await agent.execute(task, petstore_spec)
           assert mock_gen.called
   ```

2. **Security-Agent Tests**:
   ```python
   def test_security_agent_bola_tests():
       agent = SecurityAgent()
       result = await agent.execute(task, api_spec)

       bola_tests = [t for t in result.test_cases if t['test_subtype'] == 'bola']
       assert len(bola_tests) > 0

   def test_security_agent_injection_tests():
       agent = SecurityAgent()
       result = await agent.execute(task, api_spec)

       injection_tests = [t for t in result.test_cases
                         if 'injection' in t['test_type']]
       assert len(injection_tests) > 0
   ```

3. **Data Service Tests**:
   ```python
   def test_data_service_realistic_strategy():
       service = get_data_service()
       schema = {
           "type": "object",
           "properties": {
               "email": {"type": "string", "format": "email"},
               "age": {"type": "integer", "minimum": 18, "maximum": 100}
           }
       }

       data = service.generate_from_schema(schema, strategy="realistic")
       assert '@' in data['email']
       assert 18 <= data['age'] <= 100

   def test_data_service_boundary_strategy():
       service = get_data_service()
       schema = {"type": "integer", "minimum": 10, "maximum": 100}

       value = service.generate_from_schema(schema, strategy="boundary")
       assert value in [10, 100]  # Should be min or max
   ```

**Deliverables**:
- 90%+ test coverage
- Test report with metrics
- Regression test suite

---

### Milestone 3.2: Performance & Metrics Validation (2 hours)

**Benchmark Tests**:

```python
def benchmark_old_vs_new():
    """Compare old architecture vs new."""

    # Old architecture (3 agents)
    old_agents = [FunctionalPositive(), FunctionalNegative(), EdgeCases()]
    old_start = time.time()
    old_tests = []
    for agent in old_agents:
        result = agent.execute(task, sample_spec)
        old_tests.extend(result.test_cases)
    old_time = time.time() - old_start
    old_unique = deduplicate_tests(old_tests)

    # New architecture (1 agent)
    new_agent = FunctionalAgent()
    new_start = time.time()
    new_result = new_agent.execute(task, sample_spec)
    new_time = time.time() - new_start

    # Metrics
    print(f"Old: {len(old_tests)} tests, {len(old_unique)} unique, {old_time:.2f}s")
    print(f"New: {len(new_result.test_cases)} tests (all unique), {new_time:.2f}s")
    print(f"Duplication reduced: {((len(old_tests) - len(old_unique)) / len(old_tests) * 100):.1f}%")
    print(f"Speed improvement: {((old_time - new_time) / old_time * 100):.1f}%")

    assert len(new_result.test_cases) <= len(old_unique)  # Should have fewer or equal tests
    assert new_time < old_time  # Should be faster
```

**Expected Results**:
- 60-75% reduction in duplicate tests
- 40-50% faster execution
- Same or better test coverage

**Deliverables**:
- Performance benchmark report
- Metrics comparison (old vs new)

---

### Milestone 3.3: Integration Testing (2 hours)

**Test Full Orchestration**:

```python
async def test_full_orchestration():
    """Test all agents working together."""

    # Initialize agents
    functional = FunctionalAgent()
    security = SecurityAgent()
    stateful = StatefulAgent()
    performance = PerformanceAgent()

    # Execute all agents
    tasks = [
        AgentTask(agent_type="functional", parameters={'strategies': ['positive', 'negative']}),
        AgentTask(agent_type="security", parameters={'security_types': ['authentication', 'injection']}),
        AgentTask(agent_type="stateful"),
        AgentTask(agent_type="performance")
    ]

    all_tests = []
    for task, agent in zip(tasks, [functional, security, stateful, performance]):
        result = await agent.execute(task, sample_spec)
        assert result.status == "success"
        all_tests.extend(result.test_cases)

    # Verify no cross-agent duplicates
    signatures = [create_test_signature(t) for t in all_tests]
    assert len(signatures) == len(set(signatures))

    # Verify coverage
    test_types = {t['test_type'] for t in all_tests}
    assert 'functional-positive' in test_types
    assert 'functional-negative' in test_types
    assert 'security-auth' in test_types
    assert 'stateful-workflow' in test_types
```

**Deliverables**:
- Integration test suite (200 LOC)
- Cross-agent validation tests
- E2E workflow tests

---

## Phase 4: Rust Implementation Sync (Day 5 - 8 hours)

### Milestone 4.1: Add LLM Support to Rust Agents (4 hours)

**Objective**: Bring Rust agents to parity with Python

**Steps**:

**Hour 1: Add LLM trait**
```rust
// src/agents/llm.rs
use async_trait::async_trait;
use serde_json::Value;

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn generate(
        &self,
        messages: Vec<Message>,
        temperature: f32
    ) -> Result<String, String>;
}

pub struct Message {
    pub role: String,
    pub content: String,
}

pub struct OpenAIProvider {
    api_key: String,
    model: String,
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn generate(&self, messages: Vec<Message>, temperature: f32) -> Result<String, String> {
        // Implementation using reqwest
        todo!()
    }
}
```

**Hour 2-3: Update BaseAgent**
```rust
// src/agents/base_agent.rs
pub struct BaseAgent {
    pub agent_type: String,
    pub llm_provider: Option<Box<dyn LLMProvider>>,
    pub llm_enabled: bool,
}

impl BaseAgent {
    pub fn new(agent_type: String) -> Self {
        let llm_provider = Self::initialize_llm();
        let llm_enabled = llm_provider.is_some();

        Self {
            agent_type,
            llm_provider,
            llm_enabled,
        }
    }

    pub async fn enhance_with_llm(&self, test_case: &TestCase, prompt: &str) -> Option<TestCase> {
        if !self.llm_enabled {
            return None;
        }

        // Use LLM to enhance test case
        todo!()
    }
}
```

**Hour 4: Testing**
- Unit tests for LLM integration
- Mock LLM provider for testing
- Integration tests

---

### Milestone 4.2: Port Consolidated Agents to Rust (4 hours)

**Steps**:
- Port FunctionalAgent strategy pattern to Rust
- Port SecurityAgent to Rust
- Ensure feature parity with Python
- Add tests

---

## Phase 5: Migration & Cleanup (Days 6-7 - 8 hours)

### Milestone 5.1: Update Orchestration Layer (2 hours)

**Update agent registry**:
```python
# orchestration_service/agent_registry.py
AVAILABLE_AGENTS = {
    'functional': FunctionalAgent,      # NEW
    'security': SecurityAgent,          # NEW
    'stateful': StatefulAgent,          # Unchanged
    'performance': PerformanceAgent,    # Unchanged

    # Deprecated agents (kept for backward compatibility)
    'functional-positive': FunctionalAgent,  # Maps to new agent
    'functional-negative': FunctionalAgent,  # Maps to new agent
    'edge-cases': FunctionalAgent,           # Maps to new agent
}
```

---

### Milestone 5.2: Update API & Documentation (2 hours)

**Update OpenAPI endpoints**:
```yaml
/api/v1/tests/generate:
  post:
    parameters:
      - name: agents
        schema:
          type: array
          items:
            enum: [functional, security, stateful, performance]
      - name: strategies  # For functional agent
        schema:
          type: array
          items:
            enum: [positive, negative, boundary, edge_case]
```

**Update documentation**:
- API documentation
- Agent usage guide
- Migration guide for users

---

### Milestone 5.3: Deprecation & Cleanup (4 hours)

**Steps**:

1. **Mark old agents as deprecated**:
   ```python
   # functional_positive_agent.py
   import warnings

   class FunctionalPositiveAgent(BaseAgent):
       def __init__(self):
           warnings.warn(
               "FunctionalPositiveAgent is deprecated. Use FunctionalAgent with strategy='positive'",
               DeprecationWarning,
               stacklevel=2
           )
           super().__init__("functional-positive")
   ```

2. **Create migration guide**:
   ```markdown
   # Migration Guide: Old Agents → New Architecture

   ## Functional Agents

   OLD:
   ```python
   positive_agent = FunctionalPositiveAgent()
   negative_agent = FunctionalNegativeAgent()
   edge_agent = EdgeCasesAgent()
   ```

   NEW:
   ```python
   functional_agent = FunctionalAgent()

   # Equivalent to old Positive agent
   result = await functional_agent.execute(
       task=AgentTask(parameters={'strategies': ['positive']})
   )

   # Equivalent to old Negative agent
   result = await functional_agent.execute(
       task=AgentTask(parameters={'strategies': ['negative']})
   )

   # Get all strategies
   result = await functional_agent.execute(
       task=AgentTask(parameters={'strategies': ['positive', 'negative', 'boundary']})
   )
   ```
   ```

3. **Remove after deprecation period** (3 months):
   - Delete old agent files
   - Remove from registry
   - Update all references

---

## Risk Management

### Risk Matrix

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking existing tests | MEDIUM | HIGH | Maintain backward compatibility, gradual deprecation |
| Performance regression | LOW | MEDIUM | Comprehensive benchmarking, rollback plan |
| Missing edge cases | MEDIUM | HIGH | Thorough test coverage, side-by-side comparison |
| Integration issues | MEDIUM | MEDIUM | Extensive integration testing, staging deployment |

### Rollback Plan

If critical issues arise:

1. **Immediate**: Revert to old agents (keep old code for 3 months)
2. **Short-term**: Fix issues in new agents while old agents run
3. **Long-term**: Address root causes, re-deploy with fixes

---

## Success Metrics

### Quantitative Metrics

| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| Test duplication rate | 60-75% | <10% | Signature comparison |
| Lines of code | ~10,000 | ~4,600 | CLOC analysis |
| Test generation time | 100% | <60% | Benchmark suite |
| Agent count | 9 | 4 | Direct count |
| Test coverage | 85% | >90% | pytest-cov |

### Qualitative Metrics

- Code maintainability (subjective assessment)
- Ease of adding new test types
- Developer onboarding time
- System comprehensibility

---

## Timeline Summary

| Phase | Duration | Key Deliverables |
|-------|----------|-----------------|
| 1. Preparation | 1 day (8h) | Data service, deduplication utility, test framework |
| 2. Consolidation | 2 days (16h) | Functional-Agent, Security-Agent, refactored Data-Mocking |
| 3. Testing | 1 day (8h) | Unit tests, integration tests, performance benchmarks |
| 4. Rust Sync | 1 day (8h) | LLM support in Rust, ported agents |
| 5. Migration | 2 days (8h) | Updated docs, deprecation, cleanup |

**Total: 6-7 days (48 hours)**

---

## Next Steps

1. **Get stakeholder approval** for this roadmap
2. **Allocate resources**: 1-2 senior developers for 1-2 weeks
3. **Setup staging environment** for testing
4. **Begin Phase 1** immediately upon approval
5. **Daily standups** to track progress and address blockers

This roadmap provides a concrete, step-by-step plan to transform the agent architecture with minimal risk and maximum benefit.
