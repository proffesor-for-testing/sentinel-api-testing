# Performance Benchmarking & Bottleneck Analysis

This directory contains comprehensive performance benchmarking tools for analyzing and optimizing the Sentinel agent architecture.

## 📁 Files

### `benchmark_agents.py`
Comprehensive benchmark suite for measuring agent performance, duplication rates, and optimization opportunities.

**Key Features:**
- Execution time measurement
- Memory usage profiling
- Test case duplication analysis
- Concurrent execution benchmarks
- Before/after comparison metrics

### `bottleneck_analyzer.py`
Advanced bottleneck detection and analysis tool for identifying performance issues.

**Key Features:**
- Function-level profiling
- Memory hotspot detection
- Call graph analysis
- Optimization recommendations
- Multi-agent comparison

## 🚀 Quick Start

### Running Benchmarks

```bash
# Run all performance benchmarks
cd /workspaces/api-testing-agents/sentinel_backend
python -m pytest tests/performance/benchmark_agents.py -v -s

# Run specific benchmark
python -m pytest tests/performance/benchmark_agents.py::TestAgentPerformanceBenchmarks::test_performance_comparison_and_improvement -v -s

# Run with detailed output
python -m pytest tests/performance/benchmark_agents.py -v -s --tb=short
```

### Running Bottleneck Analysis

```python
import asyncio
from tests.performance.bottleneck_analyzer import analyze_agent_bottlenecks, compare_agent_performance
from orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from orchestration_service.agents.base_agent import AgentTask

# Analyze single agent
async def analyze_single_agent():
    agent = FunctionalPositiveAgent()
    task = AgentTask(task_id="1", spec_id=1, agent_type="functional-positive")
    api_spec = {...}  # Your OpenAPI spec

    report = await analyze_agent_bottlenecks(agent, task, api_spec)
    return report

# Compare multiple agents
async def analyze_all_agents():
    from orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
    from orchestration_service.agents.edge_cases_agent import EdgeCasesAgent

    agents = [
        FunctionalPositiveAgent(),
        FunctionalNegativeAgent(),
        EdgeCasesAgent()
    ]

    reports = {}
    for agent in agents:
        task = AgentTask(task_id=f"task_{agent.agent_type}", spec_id=1, agent_type=agent.agent_type)
        reports[agent.agent_type] = await analyze_agent_bottlenecks(agent, task, api_spec)

    compare_agent_performance(reports)

# Run analysis
asyncio.run(analyze_all_agents())
```

## 📊 Benchmark Results

### Expected Metrics

| Benchmark | Current (3 Agents) | Target (1 Agent) | Improvement |
|-----------|-------------------|------------------|-------------|
| **Execution Time** | ~2500ms | ~900ms | 64% faster |
| **Memory Usage** | ~150MB | ~65MB | 57% reduction |
| **Test Duplication** | 43.5% | 7.7% | 82% reduction |
| **Lines of Code** | 18,954 | ~13,000 | 31% reduction |

### Key Test Cases

#### 1. `test_baseline_old_architecture_performance`
Measures current architecture with 3 separate agents.

**Metrics Collected:**
- Individual agent execution times
- Memory usage per agent
- Test case generation count
- Duplication analysis

**Expected Output:**
```
=== OLD ARCHITECTURE BENCHMARK ===
Total execution time: 2500.00ms
Average per agent: 833.33ms
Peak memory: 150.00MB
Total tests generated: 85
Unique tests: 48
Duplication rate: 43.5%
```

#### 2. `test_new_consolidated_architecture_performance`
Simulates consolidated agent performance.

**Expected Output:**
```
=== NEW CONSOLIDATED ARCHITECTURE BENCHMARK ===
Total execution time: 900.00ms
Peak memory: 65.00MB
Total tests generated: 52
Unique tests: 48
Duplication rate: 7.7%
```

#### 3. `test_performance_comparison_and_improvement`
Compares old vs new and validates improvement targets.

**Expected Output:**
```
=== PERFORMANCE IMPROVEMENT ANALYSIS ===
⏱️  Execution Time Improvement: 64.0%
💾 Memory Usage Improvement: 57.0%
🔄 Duplication Rate Reduction: 35.8%
📊 Agent Count Reduction: 3 → 1 (67% reduction)
```

#### 4. `test_concurrent_execution_performance`
Measures parallel execution capabilities.

**Expected Output:**
```
=== CONCURRENCY PERFORMANCE ===
Sequential time: 2500.00ms
Concurrent time: 1100.00ms
Speedup: 2.3x
```

#### 5. `test_duplication_rate_measurement`
Detailed duplication analysis across agents.

**Expected Output:**
```
=== DUPLICATION ANALYSIS ===
Total tests across all agents: 85
Unique tests: 48
Duplicate tests: 37
Duplication rate: 43.5%
  Functional-Positive-Agent: 28 tests
  Functional-Negative-Agent: 35 tests
  Edge-Cases-Agent: 22 tests
```

## 🔍 Bottleneck Analysis

### Running Bottleneck Analyzer

```bash
# Standalone analysis
python tests/performance/bottleneck_analyzer.py
```

### Expected Bottleneck Report

```
============================================================
BOTTLENECK ANALYSIS: Functional-Positive-Agent
============================================================

📊 Total Execution Time: 850.00ms

🐌 Top Bottlenecks:
  1. 🟡 _generate_endpoint_tests
     Time: 320.00ms (37.6%)
     Calls: 5
  2. 🟡 _generate_request_body
     Time: 180.00ms (21.2%)
     Calls: 15
  3. 🟠 _resolve_schema_ref
     Time: 95.00ms (11.2%)
     Calls: 42
  4. 🟠 _generate_parameter_variation_tests
     Time: 78.00ms (9.2%)
     Calls: 8
  5. 🟢 _create_test_case
     Time: 45.00ms (5.3%)
     Calls: 28

💾 Memory Hotspots:
  1. functional_positive_agent.py:440
     Allocated: 12.50MB (2500 objects)
  2. functional_positive_agent.py:165
     Allocated: 8.20MB (1800 objects)
  3. base_agent.py:95
     Allocated: 3.10MB (850 objects)

💡 Recommendations:
  • 🟡 HIGH: '_generate_endpoint_tests' takes 320ms (37.6% of total). Review for optimization opportunities.
  • 🟡 HIGH: '_generate_request_body' takes 180ms (21.2% of total). Review for optimization opportunities.
  • 💾 MEMORY: 1 locations allocating >5MB. Consider streaming, chunking, or object pooling.
  • ⚡ OPTIMIZATION: Enable parallelization for independent operations. Use asyncio.gather() for concurrent execution.

============================================================
```

### Multi-Agent Comparison

```
============================================================
MULTI-AGENT PERFORMANCE COMPARISON
============================================================

📊 Execution Time Comparison:
  • Functional-Negative-Agent: 920.00ms
  • Functional-Positive-Agent: 850.00ms
  • Edge-Cases-Agent: 730.00ms

🔄 Shared Bottlenecks (Duplication Opportunities):
  • '_extract_endpoints'
    Total time: 285.00ms across 3 agents
    Agents: Functional-Positive-Agent, Functional-Negative-Agent, Edge-Cases-Agent
    💡 Consolidation could save ~285ms
  • '_resolve_schema_ref'
    Total time: 240.00ms across 3 agents
    Agents: Functional-Positive-Agent, Functional-Negative-Agent, Edge-Cases-Agent
    💡 Consolidation could save ~240ms
  • '_generate_request_body'
    Total time: 420.00ms across 2 agents
    Agents: Functional-Positive-Agent, Functional-Negative-Agent
    💡 Consolidation could save ~420ms

⚡ Consolidation Impact:
  Current total: 2500.00ms
  Estimated consolidated: 900.00ms
  Expected savings: 1600.00ms (64%)

============================================================
```

## 📈 Interpreting Results

### Severity Classifications

- **🔴 Critical** (>30% of execution time): Immediate optimization required
- **🟡 High** (15-30%): Should optimize in near term
- **🟠 Medium** (5-15%): Optimize if time permits
- **🟢 Low** (<5%): Monitor but not urgent

### Common Bottlenecks

1. **Schema Resolution** - Often called repeatedly with same schemas
   - **Solution:** Implement LRU cache for schema references

2. **Endpoint Extraction** - Duplicated across agents
   - **Solution:** Extract once in orchestrator, pass to agents

3. **Request Body Generation** - Complex object generation
   - **Solution:** Use data generation service with caching

4. **Test Case Duplication** - Same tests generated by multiple agents
   - **Solution:** Consolidated agent with intelligent categorization

## 🎯 Performance Targets

### Must-Have (Go/No-Go Criteria)
- ✅ Execution time ≤ 900ms (64% improvement)
- ✅ Duplication rate ≤ 10% (77% reduction minimum)
- ✅ Memory usage ≤ 70MB (53% reduction minimum)
- ✅ Zero regression in test coverage

### Should-Have (Performance Goals)
- 🎯 Execution time ≤ 850ms (66% improvement)
- 🎯 Duplication rate ≤ 5% (89% reduction)
- 🎯 LOC reduction ≥ 30%
- 🎯 Code complexity reduction ≥ 20%

## 🔧 Optimization Techniques

### 1. Caching
```python
from functools import lru_cache

@lru_cache(maxsize=128)
def resolve_schema_ref(ref: str, spec_hash: str):
    # Cached schema resolution
    return _resolve_ref_impl(ref, spec_hash)
```

### 2. Parallelization
```python
# Generate test categories in parallel
categories = await asyncio.gather(
    generate_positive(spec),
    generate_negative(spec),
    generate_edge_cases(spec)
)
```

### 3. Deduplication
```python
def deduplicate_tests(all_tests):
    seen_signatures = set()
    unique_tests = []

    for test in all_tests:
        sig = create_test_signature(test)
        if sig not in seen_signatures:
            seen_signatures.add(sig)
            unique_tests.append(test)

    return unique_tests
```

## 📝 Adding New Benchmarks

### Template for New Benchmark

```python
@pytest.mark.asyncio
async def test_my_new_benchmark(self, mock_llm_provider, sample_openapi_spec):
    """Description of what this benchmark measures."""
    metrics = PerformanceMetrics()

    # Setup
    agent = MyAgent()

    # Measure
    start = time.perf_counter()
    result = await agent.execute(task, sample_openapi_spec)
    elapsed = time.perf_counter() - start

    metrics.add_execution_time(agent.agent_type, elapsed)

    # Assert
    assert elapsed < threshold, f"Expected <{threshold}s, got {elapsed}s"

    # Log results
    print(f"\n=== MY BENCHMARK ===")
    print(f"Execution time: {elapsed*1000:.2f}ms")

    return metrics.calculate_summary()
```

## 🐛 Troubleshooting

### Issue: Benchmarks Fail with TimeoutError
**Solution:** Increase test timeout or reduce test spec complexity

### Issue: Memory measurements inconsistent
**Solution:** Run benchmarks in isolation, clear caches between runs

### Issue: Duplication rate higher than expected
**Solution:** Check test signature algorithm, may need refinement

## 📚 References

- [Performance Report](../../docs/performance-results.md) - Full analysis report
- [Agent Architecture](../../docs/agent-architecture.md) - System design
- [Optimization Guide](../../docs/optimization-guide.md) - Best practices

## 🤝 Contributing

When adding new performance tests:

1. Follow the naming convention: `test_<metric>_<scenario>`
2. Include clear assertions for expected performance
3. Add detailed logging for benchmark results
4. Update this README with new benchmarks
5. Ensure benchmarks are repeatable and deterministic

---

**Last Updated:** 2025-10-03
**Maintained By:** Performance Analysis Team
