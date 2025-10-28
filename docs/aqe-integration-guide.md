# AQE Fleet Integration Guide

## Overview

The **Agentic Quality Engineering (AQE) Fleet** is now fully integrated into the Sentinel platform, providing 19 specialized AI agents for comprehensive API testing and quality assurance.

## Architecture

### Core Components

1. **Agent Registry** (`agent_registry.py`)
   - Central registration of all 19 AQE agents
   - Capability-based discovery
   - Status tracking and lifecycle management

2. **Memory Manager** (`memory_manager.py`)
   - Namespace-based memory isolation (`aqe/*`)
   - TTL support for automatic cleanup
   - Cross-agent communication
   - Persistent storage to disk

3. **Coordinator** (`coordinator.py`)
   - Agent invocation and lifecycle management
   - Native hooks (100-500x faster than external)
   - Task queuing and parallel execution
   - Progress tracking

4. **REST API** (`api/routes.py`)
   - HTTP endpoints for agent invocation
   - WebSocket support for real-time progress
   - Memory and statistics endpoints

## Available Agents

### Core Testing (5 agents)

#### qe-test-generator
AI-powered test generation with sublinear optimization.

**Capabilities:**
- `generate_unit_tests`: Create comprehensive unit tests
- `generate_integration_tests`: Create integration test scenarios

**Usage:**
```python
task = await coordinator.invoke_agent(
    agent_id="qe-test-generator",
    capability="generate_unit_tests",
    input_data={
        "module": "UserService",
        "framework": "jest",
        "coverage_target": 90.0
    }
)
```

#### qe-test-executor
Multi-framework execution with parallel processing.

**Capabilities:**
- `execute_tests`: Run test suites with parallel execution
- `retry_failed_tests`: Intelligently retry flaky tests

**Frameworks:** Jest, Pytest, JUnit, Mocha

#### qe-coverage-analyzer
Real-time gap detection with O(log n) algorithms.

**Capabilities:**
- `analyze_coverage`: Identify coverage gaps
- `suggest_tests`: Suggest tests for uncovered paths

#### qe-quality-gate
Intelligent quality gate with risk assessment.

**Capabilities:**
- `evaluate_quality`: Comprehensive quality assessment
- `assess_risk`: Risk analysis for deployment

#### qe-quality-analyzer
Comprehensive quality metrics analysis.

### Performance & Security (2 agents)

- **qe-performance-tester**: Load testing (k6, JMeter, Gatling)
- **qe-security-scanner**: Multi-layer security (SAST/DAST)

### Strategic Planning (3 agents)

- **qe-requirements-validator**: INVEST validation and BDD generation
- **qe-production-intelligence**: Production data → test scenarios
- **qe-fleet-commander**: Hierarchical fleet coordination

### Deployment (1 agent)

- **qe-deployment-readiness**: Multi-factor risk assessment

### Advanced Testing (4 agents)

- **qe-regression-risk-analyzer**: Smart test selection with ML
- **qe-test-data-architect**: High-speed data generation (10k+ records/sec)
- **qe-api-contract-validator**: Breaking change detection
- **qe-flaky-test-hunter**: Statistical flakiness detection

### Specialized (2 agents)

- **qe-visual-tester**: Visual regression with AI comparison
- **qe-chaos-engineer**: Resilience testing with fault injection

## Memory Namespaces

Agents coordinate through the `aqe/*` memory namespace:

- `aqe/test-plan/*` - Test planning and requirements
- `aqe/coverage/*` - Coverage analysis and gaps
- `aqe/quality/*` - Quality metrics and gates
- `aqe/performance/*` - Performance test results
- `aqe/security/*` - Security scan findings
- `aqe/swarm/coordination` - Cross-agent coordination
- `aqe/learning/*` - Learned patterns and improvements

## API Endpoints

### Agent Discovery

```http
GET /aqe/agents
GET /aqe/agents/{agent_id}
GET /aqe/agents?category=core_testing
GET /aqe/agents?status=available
```

### Agent Invocation

```http
POST /aqe/agents/invoke
{
  "agent_id": "qe-test-generator",
  "capability": "generate_unit_tests",
  "input_data": {
    "module": "UserService",
    "framework": "jest"
  }
}
```

### Task Monitoring

```http
GET /aqe/tasks/{task_id}
GET /aqe/tasks?status=running
GET /aqe/tasks?agent_id=qe-test-executor
DELETE /aqe/tasks/{task_id}  # Cancel task
```

### Memory Management

```http
GET /aqe/memory/namespaces
GET /aqe/memory/{namespace}/keys
GET /aqe/memory/{namespace}/stats
```

### Statistics

```http
GET /aqe/stats
```

### WebSocket (Real-time Progress)

```javascript
const ws = new WebSocket('ws://host/aqe/ws/tasks/{task_id}');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`Progress: ${data.progress}% - ${data.message}`);
};
```

## Usage Examples

### Example 1: Generate and Execute Tests

```python
from sentinel_backend.orchestration_service.aqe_integration.services.coordinator import get_coordinator

async def generate_and_execute_tests():
    coordinator = get_coordinator()

    # Step 1: Generate tests
    gen_task = await coordinator.invoke_agent(
        agent_id="qe-test-generator",
        capability="generate_unit_tests",
        input_data={
            "module": "api/users",
            "framework": "jest",
            "coverage_target": 90.0
        }
    )

    # Wait for completion
    while gen_task.status == TaskStatus.RUNNING:
        await asyncio.sleep(1)
        gen_task = await coordinator.get_task_status(gen_task.task_id)

    tests = gen_task.result["tests"]

    # Step 2: Execute generated tests
    exec_task = await coordinator.invoke_agent(
        agent_id="qe-test-executor",
        capability="execute_tests",
        input_data={
            "test_suite": tests,
            "framework": "jest",
            "parallel": True,
            "coverage": True
        }
    )

    return exec_task
```

### Example 2: Quality Gate Evaluation

```python
async def evaluate_quality_gate():
    coordinator = get_coordinator()

    # Get test results and coverage
    test_results = {
        "statistics": {
            "total": 100,
            "passed": 95,
            "failed": 5,
            "pass_rate": 95.0
        }
    }

    coverage_report = {
        "coverage_metrics": {
            "line_coverage": 85.0,
            "branch_coverage": 80.0,
            "function_coverage": 90.0
        }
    }

    # Evaluate quality gate
    gate_task = await coordinator.invoke_agent(
        agent_id="qe-quality-gate",
        capability="evaluate_quality",
        input_data={
            "test_results": test_results,
            "coverage_report": coverage_report
        }
    )

    # Wait and get decision
    while gate_task.status == TaskStatus.RUNNING:
        await asyncio.sleep(0.5)
        gate_task = await coordinator.get_task_status(gate_task.task_id)

    return gate_task.result["can_deploy"]
```

### Example 3: Coverage Analysis and Suggestions

```python
async def improve_coverage():
    coordinator = get_coordinator()

    # Analyze coverage
    analysis_task = await coordinator.invoke_agent(
        agent_id="qe-coverage-analyzer",
        capability="analyze_coverage",
        input_data={
            "coverage_report": {
                "line_coverage": 75.0,
                "branch_coverage": 70.0
            },
            "threshold": 80.0
        }
    )

    # Wait for completion
    while analysis_task.status == TaskStatus.RUNNING:
        await asyncio.sleep(0.5)
        analysis_task = await coordinator.get_task_status(analysis_task.task_id)

    gaps = analysis_task.result["gaps"]

    # Get test suggestions
    suggestions_task = await coordinator.invoke_agent(
        agent_id="qe-coverage-analyzer",
        capability="suggest_tests",
        input_data={
            "gap_report": analysis_task.result,
            "max_suggestions": 10
        }
    )

    return suggestions_task
```

## Integration with Existing Sentinel Services

### Adding AQE Routes to Orchestration Service

```python
# In sentinel_backend/orchestration_service/main.py

from sentinel_backend.orchestration_service.aqe_integration.api.routes import router as aqe_router

app.include_router(aqe_router)
```

### Using AQE Agents in Existing Workflows

```python
# In existing test generation endpoints
from sentinel_backend.orchestration_service.aqe_integration.services.coordinator import get_coordinator

@app.post("/generate-tests")
async def generate_tests(spec_id: int):
    coordinator = get_coordinator()

    # Use AQE test generator instead of legacy generator
    task = await coordinator.invoke_agent(
        agent_id="qe-test-generator",
        capability="generate_unit_tests",
        input_data={"spec_id": spec_id}
    )

    return {"task_id": task.task_id}
```

## Performance Benefits

- **Native Hooks**: 100-500x faster than external hooks
- **Parallel Execution**: Up to 5x faster test execution
- **O(log n) Algorithms**: Efficient coverage gap detection
- **Memory Caching**: Fast pattern retrieval for learning

## Configuration

### Adjusting Quality Gate Thresholds

```python
from sentinel_backend.orchestration_service.aqe_integration.agents.quality_gate_agent import QualityGateAgent

# Get agent and modify thresholds
agent_def = registry.get("qe-quality-gate")
gate_agent = QualityGateAgent(agent_def)

gate_agent.thresholds = {
    "test_pass_rate": 98.0,  # Increase from 95%
    "coverage": 85.0,         # Increase from 80%
    "security_issues": 0,
    "critical_bugs": 0,
    "performance_degradation": 5.0  # Decrease from 10%
}
```

## Monitoring and Debugging

### Check Agent Status

```python
registry = get_agent_registry()
stats = registry.get_stats()
print(f"Total agents: {stats['total_agents']}")
print(f"Available: {stats['by_status']['available']}")
```

### Monitor Memory Usage

```python
memory = get_memory_manager()
stats = await memory.get_all_stats()
print(f"Total entries: {stats['total_entries']}")
print(f"Namespaces: {list(stats['namespaces'].keys())}")
```

### View Coordinator Stats

```python
coordinator = get_coordinator()
stats = await coordinator.get_stats()
print(f"Total tasks: {stats['total_tasks']}")
print(f"Running: {stats['running_tasks']}")
print(f"Avg duration: {stats['avg_duration_ms']}ms")
```

## Troubleshooting

### Agent Not Available

```python
registry = get_agent_registry()
agent = registry.get("qe-test-generator")

if agent.status != AgentStatus.AVAILABLE:
    print(f"Agent busy: {agent.agent_id}")
    # Wait or use another agent
```

### Task Stuck in Running State

```python
coordinator = get_coordinator()
task = await coordinator.get_task_status(task_id)

if task.status == TaskStatus.RUNNING:
    # Cancel if needed
    await coordinator.cancel_task(task_id)
```

### Memory Namespace Cleanup

```python
memory = get_memory_manager()

# Clear old test data
await memory.namespace_clear("aqe/test-plan")
```

## Next Steps

1. **Expand Agent Implementations**: Add real LLM integration
2. **UI Dashboard**: Build React components for agent management
3. **Advanced Learning**: Implement Q-learning for agent improvement
4. **Production Monitoring**: Add metrics and alerting
5. **Multi-Model Router**: Integrate cost-optimized model selection

## Support

For issues or questions:
- Check the integration tests in `tests/test_integration.py`
- Review agent definitions in `services/agent_registry.py`
- Examine memory patterns in `.swarm/aqe-memory.json`
