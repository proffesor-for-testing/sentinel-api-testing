# Agent Learning System

## Overview

The Agent Learning System enables Sentinel's 8 API testing agents to learn from experience through trajectory tracking and feedback loops integrated with ReasoningBank.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Execution                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Functional   │  │  Security    │  │ Performance  │      │
│  │   Agents     │  │   Agents     │  │    Agent     │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
│                            │                                 │
│                            ▼                                 │
│                 ┌──────────────────────┐                    │
│                 │ BaseLearningAgent     │                    │
│                 │   - start_trajectory  │                    │
│                 │   - log_action        │                    │
│                 │   - complete_trajectory│                   │
│                 └──────────┬────────────┘                    │
└────────────────────────────┼─────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     ReasoningBank                            │
│  ┌───────────────────────────────────────────────────────┐  │
│  │             TrajectoryService                          │  │
│  │  - create_trajectory()                                 │  │
│  │  - add_action()                                        │  │
│  │  - complete_trajectory()                               │  │
│  │  - get_unjudged_trajectories()                         │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │         TaskTrajectory (Database Model)               │  │
│  │  - trajectory_id, task_type, agent_type               │  │
│  │  - context_data, actions[], final_output              │  │
│  │  - outcome, confidence, reasoning                      │  │
│  │  - extracted_pattern_ids[]                             │  │
│  └───────────────────────┬───────────────────────────────┘  │
└────────────────────────────┼─────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                 Learning Orchestrator                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  1. Process learning queue                            │  │
│  │  2. Judge trajectories (JudgmentService)              │  │
│  │  3. Extract patterns from success                     │  │
│  │  4. Update agent behavior                             │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. BaseLearningAgent (Mixin)

**Purpose:** Adds trajectory tracking to any agent

**Key Methods:**
- `start_trajectory(task_type, description, context, db_session)`
- `log_action(description, metadata)`
- `complete_trajectory(output, metrics)`
- `abort_trajectory(error)`

**Usage Example:**
```python
class MyAgent(BaseAgent, BaseLearningAgent):
    def __init__(self):
        BaseAgent.__init__(self, "my-agent")
        BaseLearningAgent.__init__(self)

    async def execute(self, task, api_spec, db_session=None):
        # Start tracking
        trajectory = await self.start_trajectory(
            task_type="test_generation",
            task_description="Generate tests",
            context_data={"spec_id": task.spec_id},
            db_session=db_session
        )

        # Log actions
        await self.log_action("Step 1: Analyze spec")
        # ... do work ...
        await self.log_action("Step 2: Generate tests")

        # Complete
        await self.complete_trajectory(
            final_output={"test_count": 10},
            test_success_rate=0.95
        )

        return result
```

### 2. LearningOrchestrator

**Purpose:** Coordinates the learning loop

**Key Methods:**
- `process_learning_queue()` - Batch process unjudged trajectories
- `get_agent_learning_stats()` - Get metrics
- `get_learning_recommendations()` - Get improvement suggestions
- `feedback_to_learning_loop()` - Process user feedback

**Usage Example:**
```python
orchestrator = LearningOrchestrator(
    db_session=session,
    judgment_service=judgment_service
)

# Process pending judgments
result = await orchestrator.process_learning_queue(
    batch_size=10,
    max_iterations=100
)

print(f"Processed: {result['processed_count']}")
print(f"Judgments: {result['metrics']['judgments_made']}")

# Get stats
stats = await orchestrator.get_agent_learning_stats(
    agent_type="Functional-Positive-Agent"
)
```

### 3. TrajectoryService (ReasoningBank)

**Purpose:** Persist and query trajectories

**Key Methods:**
- `create_trajectory()` - Start new trajectory
- `add_action()` - Log action step
- `complete_trajectory()` - Finalize with results
- `get_unjudged_trajectories()` - Get pending judgments
- `update_judgment()` - Store verdict
- `mark_distilled()` - Mark pattern extraction done

### 4. JudgmentService (ReasoningBank)

**Purpose:** LLM-as-judge evaluation

**Model:** Claude Sonnet 4.5 at temperature=0

**Returns:**
- Verdict: SUCCESS, FAILURE, or PARTIAL
- Confidence: 0.0-1.0
- Reasoning: Brief explanation
- Quality score and issues

## Agent Integration Pattern

All agents should follow this pattern:

```python
async def execute(self, task, api_spec, db_session=None):
    """Execute agent with trajectory tracking."""

    # 1. Start trajectory (optional if db_session provided)
    trajectory = None
    if db_session:
        try:
            trajectory = await self.start_trajectory(
                task_type="test_generation",
                task_description=f"Generate {self.agent_type} tests",
                context_data={
                    "task_id": task.task_id,
                    "spec_id": task.spec_id,
                    "parameters": task.parameters
                },
                db_session=db_session
            )
        except Exception as e:
            self.logger.warning(f"Could not start trajectory: {e}")

    try:
        # 2. Log major actions during execution
        if trajectory:
            await self.log_action("Extracting endpoints")

        endpoints = self._extract_endpoints(api_spec)

        if trajectory:
            await self.log_action(
                f"Generating tests for {len(endpoints)} endpoints",
                action_metadata={"endpoint_count": len(endpoints)}
            )

        test_cases = []
        # ... generate tests ...

        # 3. Complete trajectory with results
        if trajectory:
            await self.complete_trajectory(
                final_output={
                    "test_case_count": len(test_cases),
                    "endpoint_count": len(endpoints)
                },
                test_success_rate=1.0 if test_cases else 0.0
            )

        # 4. Return result with trajectory_id
        return AgentResult(
            task_id=task.task_id,
            agent_type=self.agent_type,
            status="success",
            test_cases=test_cases,
            metadata={
                "total_tests": len(test_cases),
                "trajectory_id": self.get_current_trajectory_id()
            }
        )

    except Exception as e:
        # 5. Abort trajectory on error
        if trajectory:
            await self.abort_trajectory(str(e))

        return AgentResult(
            task_id=task.task_id,
            agent_type=self.agent_type,
            status="failed",
            error_message=str(e)
        )
```

## Actions to Log

Each agent should log domain-specific actions:

### Functional Positive Agent
- "Extracting endpoints from API specification"
- "Generating test cases for X endpoints"
- "Enhancing test cases with LLM variants"

### Functional Negative Agent
- "Extracting endpoints from API specification"
- "Generating negative test cases using BVA"
- "Generating LLM-enhanced negative tests"

### Functional Stateful Agent
- "Building Semantic Operation Dependency Graph (SODG)"
- "Detecting operation dependencies"
- "Generating stateful test scenarios"

### Security Auth Agent
- "Analyzing authentication requirements"
- "Generating BOLA test vectors"
- "Generating authorization bypass tests"

### Security Injection Agent
- "Analyzing input parameters for injection points"
- "Generating SQL injection test cases"
- "Generating NoSQL injection test cases"
- "Generating command injection test cases"

### Performance Planner Agent
- "Analyzing endpoints for performance testing"
- "Generating load test scripts"
- "Generating stress test scenarios"

## Database Schema

### task_trajectories Table

```sql
CREATE TABLE task_trajectories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trajectory_id VARCHAR(100) UNIQUE NOT NULL,
    task_type VARCHAR(50) NOT NULL,
    task_description TEXT NOT NULL,
    context_data JSON,
    agent_type VARCHAR(50),

    -- Process trace
    actions JSON NOT NULL,
    intermediate_outputs JSON,

    -- Output
    final_output JSON NOT NULL,
    execution_time_ms INTEGER,
    token_count INTEGER,

    -- Judgment
    outcome VARCHAR(20) DEFAULT 'unknown',
    outcome_confidence FLOAT DEFAULT 0.0,
    judgment_reasoning TEXT,

    -- Patterns
    extracted_pattern_ids JSON,
    distillation_performed INTEGER DEFAULT 0,

    -- Metrics
    test_success_rate FLOAT,
    coverage_score FLOAT,

    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    judged_at DATETIME,
    distilled_at DATETIME,

    -- Multi-tenancy
    tenant_id VARCHAR(100),

    INDEX idx_trajectory_task_type (task_type),
    INDEX idx_trajectory_outcome (outcome),
    INDEX idx_trajectory_created (created_at),
    INDEX idx_trajectory_distilled (distillation_performed)
);
```

## Learning Loop Flow

1. **Agent Execution**
   ```python
   agent = FunctionalPositiveAgent()
   result = await agent.execute(task, api_spec, db_session=session)
   # Trajectory created and stored
   ```

2. **Queue Processing**
   ```python
   orchestrator = LearningOrchestrator(session)
   await orchestrator.process_learning_queue()
   # Trajectories judged by Claude Sonnet 4.5
   ```

3. **Pattern Distillation**
   ```python
   # Automatic during queue processing
   # Successful trajectories → extracted patterns
   ```

4. **Agent Improvement**
   ```python
   recommendations = await orchestrator.get_learning_recommendations(
       agent_type="Functional-Positive-Agent"
   )
   # Use patterns to improve future executions
   ```

## Testing

### Unit Tests
```bash
pytest sentinel_backend/tests/unit/agents/test_base_learning_agent.py -v
```

### Integration Tests
```bash
pytest sentinel_backend/tests/integration/agents/test_agent_learning.py -v
```

### Test Individual Agent
```python
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

async def test_agent():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with AsyncSession(engine) as session:
        agent = FunctionalPositiveAgent()
        task = AgentTask(task_id="test", spec_id=1, agent_type="agent")
        result = await agent.execute(task, api_spec, db_session=session)
        print(f"Trajectory: {result.metadata['trajectory_id']}")

asyncio.run(test_agent())
```

## Configuration

### Enable/Disable Learning

In agent execution:
```python
# With learning
result = await agent.execute(task, api_spec, db_session=session)

# Without learning (faster)
result = await agent.execute(task, api_spec, db_session=None)
```

### Orchestrator Settings

```python
orchestrator = LearningOrchestrator(
    db_session=session,
    judgment_service=judgment_service,
    anthropic_api_key="sk-..."  # Optional if env var set
)

# Process queue
await orchestrator.process_learning_queue(
    batch_size=10,      # Trajectories per batch
    max_iterations=100  # Max batches to process
)
```

## Metrics and Monitoring

### Agent Metrics
```python
# Get current trajectory ID
trajectory_id = agent.get_current_trajectory_id()

# Check if tracking
is_tracking = agent.is_tracking_trajectory()
```

### Orchestrator Metrics
```python
metrics = orchestrator.get_metrics()
print(f"Total processed: {metrics['total_processed']}")
print(f"Judgments made: {metrics['judgments_made']}")
print(f"Patterns distilled: {metrics['patterns_distilled']}")
print(f"Errors: {metrics['errors']}")
```

### Trajectory Statistics
```python
stats = await trajectory_service.get_trajectory_statistics(
    task_type="test_generation"
)
print(f"Success rate: {stats['success_rate']:.1%}")
print(f"Avg execution time: {stats['avg_execution_time_ms']}ms")
```

## Troubleshooting

### Trajectory Not Created
- Check if `db_session` is passed to `execute()`
- Verify database connection
- Check logs for initialization errors

### Actions Not Logged
- Verify `start_trajectory()` was called
- Check if trajectory creation succeeded
- Look for exceptions in logs

### Judgments Not Processing
- Verify JudgmentService has API key
- Check orchestrator logs
- Ensure trajectories are completed

### No Patterns Extracted
- Verify trajectories are marked as SUCCESS
- Check distillation logic
- Review pattern extraction criteria

## Future Enhancements

### Phase 3 (Planned)
- Sophisticated pattern extraction using LLM
- Dynamic agent behavior updates from patterns
- Real-time feedback processing
- Pattern-based test generation
- Cross-agent pattern sharing
- Automated A/B testing of patterns

## References

- [IMPLEMENTATION_CHECKLIST.md](../../../docs/IMPLEMENTATION_CHECKLIST.md) - Full roadmap
- [phase2_agent_learning_implementation_summary.md](../../../docs/phase2_agent_learning_implementation_summary.md) - Implementation guide
- [ReasoningBank Documentation](../../reasoningbank/README.md) - Core learning system
- [Learning Loop Architecture](../../../docs/learning_loop_architecture.md) - Detailed design

---

**Status:** Phase 2 Implementation In Progress
**Next:** Complete remaining agent modifications and run integration tests
