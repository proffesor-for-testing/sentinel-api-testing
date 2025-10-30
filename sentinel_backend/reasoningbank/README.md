# ReasoningBank Service - Complete Documentation

## Overview

**ReasoningBankService** is the main orchestrator for Sentinel's self-improving memory system. It implements a closed-loop learning architecture that enables AI agents to learn from their execution experiences and continuously improve test generation quality.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ReasoningBankService                      │
│                  (Main Orchestrator)                         │
└──────────────────┬──────────────────────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    │              │              │
    ▼              ▼              ▼
┌─────────┐  ┌──────────┐  ┌──────────────┐
│Trajectory│  │ Judgment │  │  Retrieval   │
│ Service  │  │ Service  │  │  Service     │
└─────────┘  └──────────┘  └──────────────┘
                   │              │
    ┌──────────────┼──────────────┼────────────┐
    │              │              │            │
    ▼              ▼              ▼            ▼
┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│Distilla-│  │Consolida-│  │ Pattern  │  │   Task   │
│tion     │  │tion      │  │Embeddings│  │Trajecto- │
│Service  │  │Service   │  │  (DB)    │  │ries (DB) │
└─────────┘  └──────────┘  └──────────┘  └──────────┘
```

## Learning Loop Flow

```
1. Trajectory Capture
   Agent executes task → Actions logged → Output stored

2. Judgment Phase
   LLM evaluates outcome → SUCCESS/FAILURE/PARTIAL

3. Pattern Distillation (planned)
   Extract strategic patterns → Store as embeddings

4. Memory Consolidation (planned)
   Deduplicate → Detect contradictions → Age patterns

5. Retrieval & Application
   Semantic search → Inject patterns into prompts
```

## Core Components

### 1. ReasoningBankService

Main orchestrator that coordinates all learning operations.

**Key Methods:**
- `process_trajectory_for_learning()` - Full learning loop
- `batch_process_trajectories()` - Bulk processing
- `retrieve_relevant_knowledge()` - Pattern retrieval
- `get_learning_statistics()` - System metrics
- `run_consolidation_cycle()` - Memory optimization

### 2. TrajectoryService

Captures complete execution paths:
- Input (task description, context)
- Actions (step-by-step trace)
- Output (test cases generated)
- Metrics (execution time, coverage)

### 3. JudgmentService

LLM-as-judge evaluation using Claude Sonnet 4.5:
- Deterministic judgments (temperature=0)
- Structured verdicts (SUCCESS/FAILURE/PARTIAL)
- Confidence scores (0.0-1.0)
- Quality assessment

### 4. RetrievalService (implementation pending)

Semantic search for relevant patterns:
- Vector similarity search
- MMR (Maximal Marginal Relevance)
- Domain-aware filtering
- Recency and reliability scoring

### 5. DistillationService (implementation pending)

Pattern extraction from trajectories:
- Strategic principle extraction
- 3-8 step procedures
- Domain tagging
- Confidence initialization

### 6. ConsolidationService (implementation pending)

Memory maintenance and optimization:
- Deduplication (merge similar patterns)
- Contradiction detection
- Confidence aging
- Low-value pattern pruning

## Usage Examples

### Basic Usage

```python
from reasoningbank.services.reasoningbank_service import ReasoningBankService
from reasoningbank.services.judgment_service import JudgmentService
from anthropic import AsyncAnthropic

# Initialize services
anthropic_client = AsyncAnthropic(api_key="your-key")
judgment_service = JudgmentService(anthropic_client=anthropic_client)

rb = ReasoningBankService(
    db_session=db_session,
    judgment_service=judgment_service,
    enable_background_consolidation=True,
    consolidation_interval_hours=24
)

# Process a completed trajectory
result = await rb.process_trajectory_for_learning(
    trajectory_id="traj_abc123",
    force_judgment=False,
    auto_distill=True
)

print(f"Outcome: {result['outcome']}")
print(f"Confidence: {result['confidence']}")
print(f"Patterns extracted: {result['patterns_extracted']}")
```

### Agent Integration

```python
from orchestration_service.agents.base_learning_agent import BaseLearningAgent

class MyTestGeneratorAgent(BaseAgent, BaseLearningAgent):
    def __init__(self):
        BaseAgent.__init__(self, "my-agent")
        BaseLearningAgent.__init__(self)

    async def execute(self, task, api_spec, db_session):
        # 1. Start trajectory tracking
        trajectory = await self.start_trajectory(
            task_type="test_generation",
            task_description=f"Generate tests for {task.task_id}",
            context_data={
                "api_spec": api_spec.dict(),
                "task": task.dict()
            },
            db_session=db_session
        )

        # 2. Execute task with action logging
        await self.log_action(
            "Analyzing API specification",
            metadata={"endpoint_count": len(endpoints)}
        )

        # Generate tests...
        test_cases = await self._generate_tests(api_spec)

        await self.log_action(
            f"Generated {len(test_cases)} test cases",
            metadata={"coverage": 0.92}
        )

        # 3. Complete trajectory
        await self.complete_trajectory(
            final_output={
                "test_cases": [tc.dict() for tc in test_cases]
            },
            execution_time_ms=execution_time,
            test_success_rate=0.95,
            coverage_score=0.92
        )

        return test_cases
```

### Batch Processing

```python
# Process all unjudged trajectories
result = await rb.batch_process_trajectories(
    task_type="test_generation",
    limit=50,
    tenant_id="tenant_123"
)

print(f"Processed: {result['total_processed']}")
print(f"Success rate: {result['success_count'] / result['total_processed']:.1%}")
print(f"Patterns extracted: {result['patterns_extracted']}")
```

### Knowledge Retrieval

```python
# Get relevant patterns for new task
patterns = await rb.retrieve_relevant_knowledge(
    task_description="Generate security tests for authentication API",
    task_type="test_generation",
    domain_tags=["security", "authentication"],
    limit=5,
    min_confidence=0.7
)

# Format patterns for prompt injection
pattern_text = "\n\n".join([
    p["content"] for p in patterns
])

# Use in agent prompt
prompt = f"""
Generate security tests using these learned patterns:

{pattern_text}

Task: {task_description}
"""
```

### Statistics & Monitoring

```python
# Get comprehensive statistics
stats = await rb.get_learning_statistics(
    task_type="test_generation",
    tenant_id="tenant_123"
)

print(f"Total trajectories: {stats['trajectories']['total_trajectories']}")
print(f"Success rate: {stats['trajectories']['success_rate']:.1%}")
print(f"Pattern library size: {stats['patterns']['total_patterns']}")
print(f"System health: {stats['learning_metrics']['system_health_score']:.2f}")

# Get recent activity
activity = await rb.get_recent_learning_activity(hours=24)
print(f"Last 24h: {activity['trajectories_created']} new trajectories")
print(f"Patterns learned: {activity['patterns_learned']}")
```

### Health Check

```python
# Check system health
health = await rb.health_check()

print(f"Status: {health['status']}")
print(f"Database: {health['database']}")
print(f"Judgment service: {health['judgment_service']}")
print(f"Recent activity: {health['recent_activity_1h']} trajectories")
```

## Database Schema

### TaskTrajectory Table

```sql
CREATE TABLE task_trajectories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trajectory_id VARCHAR(100) UNIQUE NOT NULL,
    task_type VARCHAR(50) NOT NULL,
    task_description TEXT NOT NULL,
    context_data JSON,
    agent_type VARCHAR(50),
    actions JSON NOT NULL,
    final_output JSON NOT NULL,
    outcome VARCHAR(20) NOT NULL,
    outcome_confidence FLOAT NOT NULL,
    judgment_reasoning TEXT,
    extracted_pattern_ids JSON,
    distillation_performed INTEGER DEFAULT 0,
    execution_time_ms INTEGER,
    token_count INTEGER,
    test_success_rate FLOAT,
    coverage_score FLOAT,
    created_at DATETIME NOT NULL,
    judged_at DATETIME,
    distilled_at DATETIME,
    tenant_id VARCHAR(100),
    INDEX idx_trajectory_task_type (task_type),
    INDEX idx_trajectory_outcome (outcome),
    INDEX idx_trajectory_created (created_at)
);
```

### PatternEmbedding Table

```sql
CREATE TABLE pattern_embeddings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding VECTOR(1536) NOT NULL,
    confidence FLOAT DEFAULT 0.75,
    usage_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    domain_tags JSON,
    source_trajectory_id VARCHAR(100),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    last_used_at DATETIME,
    tenant_id VARCHAR(100),
    INDEX idx_pattern_confidence (confidence),
    INDEX idx_pattern_usage (usage_count),
    INDEX idx_pattern_created (created_at)
);
```

## Configuration

### Environment Variables

```bash
# Anthropic API for judgment
ANTHROPIC_API_KEY=sk-ant-...

# Database configuration
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/sentinel

# OpenAI for embeddings (future)
OPENAI_API_KEY=sk-...
```

### Service Configuration

```python
rb = ReasoningBankService(
    db_session=db_session,
    judgment_service=judgment_service,

    # Background consolidation
    enable_background_consolidation=True,
    consolidation_interval_hours=24,
)
```

## API Reference

### ReasoningBankService

#### `__init__(db_session, judgment_service, enable_background_consolidation, consolidation_interval_hours)`

Initialize the orchestrator.

**Parameters:**
- `db_session` (AsyncSession): Database session
- `judgment_service` (Optional[JudgmentService]): Judgment service instance
- `enable_background_consolidation` (bool): Enable periodic consolidation
- `consolidation_interval_hours` (int): Hours between consolidation runs

#### `process_trajectory_for_learning(trajectory_id, force_judgment, auto_distill)`

Process trajectory through complete learning loop.

**Parameters:**
- `trajectory_id` (str): Trajectory identifier
- `force_judgment` (bool): Force re-judgment if already judged
- `auto_distill` (bool): Automatically distill patterns

**Returns:**
```python
{
    "trajectory_id": str,
    "judgment_performed": bool,
    "outcome": str,  # "success", "failure", "partial"
    "confidence": float,
    "patterns_extracted": int,
    "processing_time_ms": int
}
```

#### `batch_process_trajectories(trajectory_ids, task_type, limit, tenant_id)`

Process multiple trajectories in batch.

**Parameters:**
- `trajectory_ids` (Optional[List[str]]): Specific trajectories (if None, auto-discovers unjudged)
- `task_type` (Optional[str]): Filter by task type
- `limit` (int): Maximum trajectories to process
- `tenant_id` (Optional[str]): Tenant filter

**Returns:**
```python
{
    "total_processed": int,
    "judgments_performed": int,
    "distillations_performed": int,
    "patterns_extracted": int,
    "success_count": int,
    "failure_count": int,
    "partial_count": int,
    "errors": List[Dict],
    "processing_time_ms": int
}
```

#### `retrieve_relevant_knowledge(task_description, task_type, domain_tags, limit, min_confidence, tenant_id)`

Retrieve relevant patterns for new task.

**Parameters:**
- `task_description` (str): Task description for semantic search
- `task_type` (Optional[str]): Filter by task type
- `domain_tags` (Optional[List[str]]): Filter by domain tags
- `limit` (int): Maximum patterns to return
- `min_confidence` (float): Minimum confidence threshold
- `tenant_id` (Optional[str]): Tenant filter

**Returns:** List of pattern dictionaries

#### `get_learning_statistics(task_type, tenant_id, use_cache)`

Get comprehensive learning statistics.

**Parameters:**
- `task_type` (Optional[str]): Filter by task type
- `tenant_id` (Optional[str]): Filter by tenant
- `use_cache` (bool): Use cached statistics

**Returns:**
```python
{
    "trajectories": {
        "total_trajectories": int,
        "success_count": int,
        "failure_count": int,
        "success_rate": float,
        ...
    },
    "patterns": {
        "total_patterns": int,
        "avg_confidence": float,
        "avg_usage_count": float,
        ...
    },
    "learning_metrics": {
        "knowledge_growth_rate": float,
        "pattern_density": float,
        "system_health_score": float,
        ...
    },
    "generated_at": str
}
```

#### `get_recent_learning_activity(hours, task_type, tenant_id)`

Get recent learning activity.

**Parameters:**
- `hours` (int): Lookback window in hours
- `task_type` (Optional[str]): Filter by task type
- `tenant_id` (Optional[str]): Filter by tenant

**Returns:** Dict with recent activity metrics

#### `run_consolidation_cycle(task_type, tenant_id)`

Run memory consolidation cycle.

**Parameters:**
- `task_type` (Optional[str]): Filter by task type
- `tenant_id` (Optional[str]): Filter by tenant

**Returns:** Dict with consolidation results

#### `health_check()`

Perform system health check.

**Returns:**
```python
{
    "status": str,  # "healthy" or "degraded"
    "database": str,
    "judgment_service": str,
    "recent_activity_1h": int,
    "last_consolidation_run": Optional[str],
    "consolidation_enabled": bool,
    "timestamp": str
}
```

## Performance Considerations

### Caching
- Statistics are cached for 5 minutes by default
- Use `use_cache=False` to bypass cache
- Call `clear_cache()` to manually invalidate

### Batch Processing
- Process trajectories in batches of 50-100
- Use `batch_process_trajectories()` for efficiency
- Individual errors don't stop batch processing

### Database Indexes
- All tables have appropriate indexes
- Use filtering parameters (task_type, tenant_id) for performance
- Vector indexes for semantic search (when implemented)

### Background Tasks
- Consolidation runs periodically (default: 24h)
- Check `should_run_consolidation()` before manual runs
- Disable for testing: `enable_background_consolidation=False`

## Testing

Run comprehensive test suite:

```bash
cd sentinel_backend
source venv/bin/activate
export PYTHONPATH=/workspaces/api-testing-agents/sentinel_backend
pytest tests/unit/test_reasoningbank_service.py -v
```

**Test Coverage:** 29 tests covering:
- Service initialization
- Trajectory processing
- Batch processing
- Knowledge retrieval
- Statistics and monitoring
- Consolidation scheduling
- Health checks
- Helper methods

## Future Enhancements

### Phase 1: Currently Implemented ✅
- Trajectory tracking
- LLM-based judgment
- Statistics and monitoring
- Batch processing
- Health checks

### Phase 2: In Progress 🚧
- Pattern distillation from trajectories
- Semantic retrieval with vector search
- Memory consolidation

### Phase 3: Planned 📋
- Reinforcement learning for confidence updates
- Multi-model judgment consensus
- Automated pattern quality scoring
- Cross-tenant pattern sharing
- Real-time learning metrics dashboard

## Support & Contributing

For issues or questions:
1. Check the test suite for usage examples
2. Review the architecture documentation
3. Examine the agent integration examples
4. Open an issue with detailed information

## License

Copyright © 2025 Sentinel Team. All rights reserved.
