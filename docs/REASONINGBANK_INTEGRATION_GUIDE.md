# ReasoningBank Integration Guide

## Overview

ReasoningBank is Sentinel's self-learning memory system that enables agents to learn from past executions and retrieve relevant patterns for new tasks.

**Status**: ✅ Services Implemented, 🔄 Integration In Progress

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestration Layer                       │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         ReasoningBank Orchestrator                   │  │
│  │  - Trajectory Management                             │  │
│  │  - Background Processing                             │  │
│  │  - Pattern Retrieval API                             │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   ReasoningBank Services                     │
├──────────────────┬───────────────┬──────────────────────────┤
│ Trajectory       │ Judgment      │ Distillation             │
│ Service          │ Service       │ Service                  │
│ - Capture        │ - LLM Judge   │ - Pattern Extraction     │
│ - Storage        │ - Confidence  │ - Embedding Generation   │
├──────────────────┼───────────────┼──────────────────────────┤
│ Retrieval        │ Consolidation │ ReasoningBank            │
│ Service          │ Service       │ Main Service             │
│ - Vector Search  │ - Dedup       │ - Orchestration          │
│ - MMR            │ - Aging       │ - Statistics             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Database (PostgreSQL + pgvector)            │
│  - task_trajectories                                         │
│  - pattern_embeddings                                        │
│  - pattern_links                                             │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Trajectory Service
**File**: `sentinel_backend/reasoningbank/services/trajectory_service.py`
**Status**: ✅ Implemented
**Purpose**: Capture complete execution paths

**Key Features**:
- Create and track trajectories
- Record actions step-by-step
- Store context and final output
- Query by status (judged/unjudged, distilled/undistilled)

### 2. Judgment Service
**File**: `sentinel_backend/reasoningbank/services/judgment_service.py`
**Status**: ✅ Implemented
**Purpose**: LLM-based success/failure evaluation

**Key Features**:
- Claude Sonnet 4.5 for judgment
- Confidence scoring
- Quality assessment
- Structured reasoning

### 3. Distillation Service
**File**: `sentinel_backend/reasoningbank/services/distillation_service.py`
**Status**: ✅ Implemented
**Purpose**: Extract reusable patterns from successful trajectories

**Key Features**:
- Pattern extraction using Claude
- Vector embeddings (OpenAI text-embedding-3-large)
- 3-8 step procedural patterns
- Domain tagging

### 4. Retrieval Service
**File**: `sentinel_backend/reasoningbank/services/retrieval_service.py`
**Status**: ✅ Implemented
**Purpose**: Semantic pattern search

**Key Features**:
- Vector similarity search (pgvector)
- Maximum Marginal Relevance (MMR) for diversity
- Weighted scoring (similarity + recency + reliability)
- Pattern usage tracking

### 5. Consolidation Service
**File**: `sentinel_backend/reasoningbank/services/consolidation_service.py`
**Status**: ✅ Implemented
**Purpose**: Memory quality control

**Key Features**:
- Duplicate detection (cosine similarity ≥ 0.87)
- Contradiction detection
- Pattern aging (exponential decay)
- Confidence updates
- Low-confidence archival

### 6. ReasoningBank Orchestrator
**File**: `sentinel_backend/reasoningbank/integration/reasoningbank_orchestrator.py`
**Status**: ✅ Implemented
**Purpose**: Main integration point with Sentinel

**Key Features**:
- Trajectory lifecycle management
- Background workers (judgment, distillation, consolidation)
- Pattern retrieval API
- Agent execution context manager
- Health checks and statistics

## Integration Points

### 1. Orchestration Service Integration

**File to modify**: `sentinel_backend/orchestration_service/main.py`

```python
from sentinel_backend.reasoningbank.integration import (
    initialize_reasoningbank_orchestrator,
    get_reasoningbank_orchestrator
)

# In app startup
@app.on_event("startup")
async def startup():
    # Initialize ReasoningBank
    orchestrator = initialize_reasoningbank_orchestrator(
        db_session=get_db_session(),
        anthropic_api_key=settings.ANTHROPIC_API_KEY,
        openai_api_key=settings.OPENAI_API_KEY,
        enable_background_tasks=True
    )

    # Start background processing
    await orchestrator.start_background_tasks()

@app.on_event("shutdown")
async def shutdown():
    orchestrator = get_reasoningbank_orchestrator()
    if orchestrator:
        await orchestrator.stop_background_tasks()
```

### 2. Agent Execution Integration

**Pattern for agents** (`sentinel_backend/orchestration_service/agents/*.py`):

```python
from sentinel_backend.reasoningbank.integration import get_reasoningbank_orchestrator

async def execute_agent(spec: dict, config: dict):
    orchestrator = get_reasoningbank_orchestrator()

    if orchestrator:
        async with orchestrator.agent_execution_context(
            agent_type="Functional-Positive-Agent",
            task_description=f"Generate tests for {spec.get('info', {}).get('title')}",
            context_data={"spec": spec, "config": config}
        ) as ctx:
            # 1. Retrieve relevant patterns
            patterns = await ctx.get_patterns(limit=5)

            # 2. Execute agent with patterns
            result = await generate_tests(spec, patterns=patterns)

            # 3. Record actions
            await ctx.record_action("generation", f"Generated {len(result['tests'])} tests")

            # 4. Complete trajectory
            await ctx.complete(
                final_output=result,
                test_success_rate=result.get('success_rate', 0.0),
                coverage_score=result.get('coverage', 0.0)
            )

            return result
    else:
        # Fallback without ReasoningBank
        return await generate_tests(spec)
```

### 3. API Endpoints

**File to modify**: `sentinel_backend/orchestration_service/api/reasoningbank_endpoints.py` (NEW)

```python
from fastapi import APIRouter, Depends
from sentinel_backend.reasoningbank.integration import get_reasoningbank_orchestrator

router = APIRouter(prefix="/api/v1/reasoningbank", tags=["reasoningbank"])

@router.get("/health")
async def health_check():
    orchestrator = get_reasoningbank_orchestrator()
    return await orchestrator.health_check()

@router.get("/statistics")
async def get_statistics():
    orchestrator = get_reasoningbank_orchestrator()
    return await orchestrator.get_statistics()

@router.get("/patterns")
async def search_patterns(
    query: str,
    limit: int = 10,
    agent_type: Optional[str] = None
):
    orchestrator = get_reasoningbank_orchestrator()
    return await orchestrator.get_relevant_patterns(
        task_description=query,
        agent_type=agent_type or "general",
        limit=limit
    )
```

## Database Setup

### Required Tables

1. **task_trajectories**: Store execution paths
2. **pattern_embeddings**: Store learned patterns with vectors
3. **pattern_links**: Store relationships (duplicates, contradictions)

### Migration Command

```bash
cd sentinel_backend
alembic revision --autogenerate -m "Add ReasoningBank tables"
alembic upgrade head
```

## Configuration

### Environment Variables

```bash
# Required for full functionality
ANTHROPIC_API_KEY=sk-ant-...  # For judgment and distillation
OPENAI_API_KEY=sk-...          # For embeddings

# Optional
REASONINGBANK_ENABLED=true
REASONINGBANK_BACKGROUND_TASKS=true
REASONINGBANK_CONSOLIDATION_INTERVAL=24  # hours
```

### Settings

**File**: `sentinel_backend/config/settings.py`

```python
class Settings(BaseSettings):
    # ReasoningBank
    REASONINGBANK_ENABLED: bool = Field(default=True, env="REASONINGBANK_ENABLED")
    REASONINGBANK_BACKGROUND_TASKS: bool = Field(default=True, env="REASONINGBANK_BACKGROUND_TASKS")
    REASONINGBANK_CONSOLIDATION_INTERVAL: int = Field(default=24, env="REASONINGBANK_CONSOLIDATION_INTERVAL")
```

## Testing

### Unit Tests

```bash
# Test individual services
pytest sentinel_backend/tests/unit/test_reasoningbank_service.py -v
pytest sentinel_backend/tests/unit/test_distillation_service.py -v
pytest sentinel_backend/tests/unit/test_retrieval_service.py -v
```

### Integration Tests

```bash
# Test full integration
pytest sentinel_backend/tests/integration/test_reasoningbank_integration.py -v
```

### E2E Test

```bash
# Test with actual agent execution
pytest sentinel_backend/tests/integration/test_reasoningbank_e2e.py -v
```

## Monitoring

### Health Check

```bash
curl http://localhost:8002/api/v1/reasoningbank/health
```

**Response**:
```json
{
  "status": "healthy",
  "database": "ok",
  "judgment_service": "configured",
  "recent_activity_1h": 42,
  "consolidation_enabled": true,
  "timestamp": "2025-10-30T10:00:00Z"
}
```

### Statistics

```bash
curl http://localhost:8002/api/v1/reasoningbank/statistics
```

**Response**:
```json
{
  "trajectories": {
    "total_trajectories": 150,
    "judged_count": 120,
    "distilled_count": 80,
    "success_rate": 0.75
  },
  "patterns": {
    "total_patterns": 45,
    "avg_confidence": 0.82,
    "high_confidence_count": 30
  },
  "learning_metrics": {
    "knowledge_growth_rate": 0.3,
    "pattern_density": 0.3,
    "system_health_score": 0.78
  }
}
```

## Performance Impact

### Expected Overhead

- **Trajectory Recording**: ~5-10ms per agent execution
- **Pattern Retrieval**: ~20-50ms (cached embeddings)
- **Background Judgment**: Asynchronous, no blocking
- **Background Distillation**: Asynchronous, no blocking

### Optimization Tips

1. **Enable Caching**: Statistics cache (5 min TTL)
2. **Batch Processing**: Process 10-50 trajectories per cycle
3. **Aggressive Consolidation**: For high-volume systems
4. **Index Optimization**: Ensure pgvector indexes exist

## Troubleshooting

### Issue: Background tasks not running

**Check**:
```python
orchestrator = get_reasoningbank_orchestrator()
health = await orchestrator.health_check()
print(health)
```

**Solution**: Ensure `enable_background_tasks=True` in initialization

### Issue: No patterns returned

**Possible Causes**:
1. No trajectories distilled yet (wait for background workers)
2. Min confidence too high (lower threshold)
3. OpenAI API key not configured (embeddings fail)

**Check**:
```bash
curl http://localhost:8002/api/v1/reasoningbank/statistics
```

### Issue: High memory usage

**Solution**: Run consolidation manually
```python
orchestrator = get_reasoningbank_orchestrator()
result = await orchestrator.consolidation_service.consolidate_patterns(
    aggressive=True
)
```

## Roadmap

### Phase 1: Current Implementation ✅
- [x] Trajectory service
- [x] Judgment service
- [x] Distillation service
- [x] Retrieval service
- [x] Consolidation service
- [x] Orchestrator

### Phase 2: Integration (In Progress) 🔄
- [x] Orchestrator implementation
- [ ] Orchestration service hooks
- [ ] Agent execution integration
- [ ] API endpoints
- [ ] Database migrations

### Phase 3: Enhancement (Future)
- [ ] Advanced pattern matching
- [ ] Cross-agent learning
- [ ] Pattern versioning
- [ ] A/B testing framework
- [ ] Pattern marketplace

## Support

For issues or questions:
1. Check logs: `tail -f sentinel_backend/logs/reasoningbank.log`
2. Run health check: `curl localhost:8002/api/v1/reasoningbank/health`
3. Review statistics: `curl localhost:8002/api/v1/reasoningbank/statistics`
4. File issue: GitHub Issues

## References

- **Original Proposal**: `docs/USER_FEEDBACK_AND_LEARNING.md`
- **Service Implementation**: `docs/REASONINGBANK_SERVICE_IMPLEMENTATION.md`
- **Distillation Details**: `docs/DISTILLATION_SERVICE_IMPLEMENTATION.md`
- **Retrieval Details**: `docs/RETRIEVAL_SERVICE_IMPLEMENTATION.md`
