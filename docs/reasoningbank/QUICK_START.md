# ReasoningBank Quick Start Guide

Get started with ReasoningBank self-improving memory system in 5 minutes.

---

## 📋 Prerequisites

- PostgreSQL with pgvector extension
- Python 3.9+
- Anthropic API key (for Claude Sonnet 4.5 judgment)
- OpenAI API key (for text-embedding-3-large) OR Anthropic API key (for Claude embeddings)

---

## 🚀 Quick Setup

### 1. Install pgvector Extension

```bash
# Connect to PostgreSQL
psql -U postgres -d sentinel

# Install extension
CREATE EXTENSION IF NOT EXISTS vector;

# Verify installation
SELECT * FROM pg_extension WHERE extname = 'vector';
```

### 2. Run Database Migration

```bash
# From sentinel_backend directory
cd /workspaces/api-testing-agents/sentinel_backend

# Apply ReasoningBank schema
psql -U postgres -d sentinel -f alembic/versions/reasoningbank_schema.sql

# Verify tables created
psql -U postgres -d sentinel -c "
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
AND table_name IN (
    'pattern_embeddings',
    'pattern_links',
    'task_trajectories',
    'matts_runs'
);"
```

### 3. Configure API Keys

```bash
# Add to .env file
echo "ANTHROPIC_API_KEY=your_anthropic_key_here" >> .env
echo "OPENAI_API_KEY=your_openai_key_here" >> .env  # Optional if using OpenAI embeddings
```

### 4. Install Python Dependencies

```python
# Dependencies already in pyproject.toml:
# - anthropic >= 0.25.0
# - openai >= 1.0.0
# - sqlalchemy[asyncio] >= 2.0.0
# - pgvector >= 0.2.0

# Install/update if needed
poetry install
```

---

## 💡 Basic Usage

### Example 1: Capture Test Execution Trajectory

```python
from sqlalchemy.ext.asyncio import AsyncSession
from reasoningbank.services.trajectory_service import TrajectoryService

async def capture_test_execution(db: AsyncSession):
    """Capture a test generation execution."""
    trajectory_service = TrajectoryService(db)

    # 1. Create trajectory
    trajectory = await trajectory_service.create_trajectory(
        task_type="test_generation",
        task_description="Generate REST API tests for UserService /users endpoint",
        context_data={
            "api_spec": "OpenAPI 3.0 spec...",
            "requirements": "Must test CRUD operations",
            "constraints": "Max 50 test cases"
        },
        agent_type="qe-test-generator",
        tenant_id="tenant_123"
    )

    print(f"Created trajectory: {trajectory.trajectory_id}")

    # 2. Track actions as execution progresses
    await trajectory_service.add_action(
        trajectory.trajectory_id,
        "Analyzed OpenAPI spec and extracted 5 endpoints",
        {"endpoints": ["/users", "/users/{id}", ...]}
    )

    await trajectory_service.add_action(
        trajectory.trajectory_id,
        "Generated positive test cases for happy paths",
        {"test_count": 25}
    )

    await trajectory_service.add_action(
        trajectory.trajectory_id,
        "Generated negative test cases for error scenarios",
        {"test_count": 15}
    )

    # 3. Complete with final results
    await trajectory_service.complete_trajectory(
        trajectory.trajectory_id,
        final_output={
            "total_tests": 40,
            "positive_tests": 25,
            "negative_tests": 15,
            "test_file": "test_user_service.py"
        },
        execution_time_ms=3500,
        token_count=1250,
        test_success_rate=0.925,  # 37/40 tests passed
        coverage_score=0.87
    )

    print(f"✅ Trajectory completed: {trajectory.trajectory_id}")
    return trajectory
```

### Example 2: Judge Trajectory Outcome

```python
from anthropic import AsyncAnthropic
from reasoningbank.services.judgment_service import JudgmentService
from reasoningbank.models.task_trajectories import TrajectoryOutcome

async def judge_execution(trajectory, anthropic_api_key: str):
    """Judge if test generation was successful."""
    # Initialize judgment service
    judgment_service = JudgmentService(api_key=anthropic_api_key)

    # Judge the trajectory
    outcome, confidence, reasoning, metadata = await judgment_service.judge_trajectory(
        trajectory
    )

    print(f"Outcome: {outcome.value}")
    print(f"Confidence: {confidence:.2f}")
    print(f"Reasoning: {reasoning}")
    print(f"Quality Score: {metadata['quality_score']:.2f}")

    # Returns:
    # Outcome: success
    # Confidence: 0.85
    # Reasoning: Tests are comprehensive and well-structured. Coverage is good at 87%.
    #            Minor issues: Missing some edge cases for pagination.
    # Quality Score: 0.82

    return outcome, confidence, reasoning
```

### Example 3: Update Trajectory with Judgment

```python
async def update_with_judgment(db: AsyncSession, trajectory_id: str):
    """Update trajectory with judgment results."""
    trajectory_service = TrajectoryService(db)

    # Update judgment
    trajectory = await trajectory_service.update_judgment(
        trajectory_id=trajectory_id,
        outcome=TrajectoryOutcome.SUCCESS,
        confidence=0.85,
        reasoning="Tests are comprehensive with 87% coverage. Minor pagination edge cases missing."
    )

    print(f"✅ Trajectory judged: {trajectory.outcome.value} ({trajectory.outcome_confidence:.2f})")
```

### Example 4: Query Trajectories

```python
async def query_trajectories(db: AsyncSession):
    """Query trajectories for analysis."""
    trajectory_service = TrajectoryService(db)

    # Get unjudged trajectories
    unjudged = await trajectory_service.get_unjudged_trajectories(
        task_type="test_generation",
        limit=10
    )
    print(f"Found {len(unjudged)} unjudged trajectories")

    # Get successful trajectories
    successes = await trajectory_service.get_trajectories_by_outcome(
        outcome=TrajectoryOutcome.SUCCESS,
        task_type="test_generation",
        limit=100
    )
    print(f"Found {len(successes)} successful trajectories")

    # Get statistics
    stats = await trajectory_service.get_trajectory_statistics(
        task_type="test_generation"
    )
    print(f"Success rate: {stats['success_rate']:.1%}")
    print(f"Total trajectories: {stats['total_trajectories']}")
```

---

## 🔌 Integration with Test Agents

### Pre-Task Hook (Future Implementation)

```python
async def pre_task_retrieval(task_description: str, context: dict) -> dict:
    """Retrieve relevant patterns before test generation."""
    # TO BE IMPLEMENTED in Phase 2
    # retrieval_service = RetrievalService(db)

    # patterns = await retrieval_service.retrieve_patterns(
    #     query=task_description,
    #     context=context,
    #     top_k=3
    # )

    # return {
    #     "system_prompt_addition": format_patterns(patterns),
    #     "patterns_used": [p.pattern_id for p in patterns]
    # }
    pass
```

### Post-Task Hook (Future Implementation)

```python
async def post_task_learning(trajectory_id: str, patterns_used: list[str]) -> None:
    """Learn from test execution results."""
    # TO BE IMPLEMENTED in Phase 2
    # 1. Judge trajectory
    # 2. Distill new patterns
    # 3. Update pattern confidence
    # 4. Trigger consolidation
    pass
```

---

## 📊 Monitoring & Metrics

### Check Learning Progress

```python
async def check_learning_progress(db: AsyncSession):
    """Monitor ReasoningBank learning metrics."""
    trajectory_service = TrajectoryService(db)

    stats = await trajectory_service.get_trajectory_statistics()

    print("=== Learning Metrics ===")
    print(f"Total trajectories: {stats['total_trajectories']}")
    print(f"Success rate: {stats['success_rate']:.1%}")
    print(f"Distillation rate: {stats['distillation_rate']:.1%}")
    print(f"Success count: {stats['success_count']}")
    print(f"Failure count: {stats['failure_count']}")
    print(f"Unjudged count: {stats['unjudged_count']}")
```

### Database Queries

```sql
-- Check recent trajectories
SELECT
    trajectory_id,
    task_type,
    outcome,
    outcome_confidence,
    test_success_rate,
    created_at
FROM task_trajectories
ORDER BY created_at DESC
LIMIT 10;

-- Success rate by task type
SELECT
    task_type,
    COUNT(*) as total,
    SUM(CASE WHEN outcome = 'SUCCESS' THEN 1 ELSE 0 END) as successes,
    ROUND(
        100.0 * SUM(CASE WHEN outcome = 'SUCCESS' THEN 1 ELSE 0 END) / COUNT(*),
        1
    ) as success_rate_pct
FROM task_trajectories
WHERE outcome != 'UNKNOWN'
GROUP BY task_type;

-- Judgment confidence distribution
SELECT
    FLOOR(outcome_confidence * 10) / 10 as confidence_bucket,
    COUNT(*) as count
FROM task_trajectories
WHERE outcome != 'UNKNOWN'
GROUP BY confidence_bucket
ORDER BY confidence_bucket;
```

---

## 🧪 Testing

### Run Integration Test

```python
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

async def test_reasoningbank_integration():
    """End-to-end integration test."""
    # Setup database connection
    engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/sentinel")
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as session:
        # 1. Create trajectory
        trajectory_service = TrajectoryService(session)
        trajectory = await trajectory_service.create_trajectory(
            task_type="test_generation",
            task_description="Test ReasoningBank integration"
        )

        # 2. Add actions
        await trajectory_service.add_action(
            trajectory.trajectory_id,
            "Performed test action"
        )

        # 3. Complete trajectory
        await trajectory_service.complete_trajectory(
            trajectory.trajectory_id,
            final_output={"tests": 10},
            execution_time_ms=1000
        )

        # 4. Judge trajectory
        judgment_service = JudgmentService(api_key="your_key")
        outcome, confidence, reasoning, _ = await judgment_service.judge_trajectory(
            trajectory
        )

        # 5. Update with judgment
        await trajectory_service.update_judgment(
            trajectory.trajectory_id,
            outcome,
            confidence,
            reasoning
        )

        print("✅ Integration test passed!")

# Run test
asyncio.run(test_reasoningbank_integration())
```

---

## 📚 Next Steps

### Phase 2 (Coming Soon)

1. **Retrieval Service** - Semantic pattern search
2. **Distillation Service** - Extract learnings from trajectories
3. **Consolidation Service** - Memory quality maintenance
4. **Full Learning Loop** - Automated continuous improvement

### Phase 3 (Future)

1. **MaTTS Parallel Mode** - k=6 exploration rollouts
2. **MaTTS Sequential Mode** - r=3 iterative refinement
3. **Learning Metrics Dashboard** - Visual analytics
4. **Cross-Domain Transfer** - Knowledge sharing between APIs

---

## 🆘 Troubleshooting

### Issue: pgvector extension not found

```bash
# Install pgvector
sudo apt-get install postgresql-14-pgvector  # Adjust version

# Or build from source
git clone https://github.com/pgvector/pgvector.git
cd pgvector
make
sudo make install
```

### Issue: Embedding dimension mismatch

```python
# Ensure using text-embedding-3-large (1536 dimensions)
# Or adjust Vector(1536) in models to match your embedding model
```

### Issue: Judgment parsing fails

```python
# JudgmentService includes fallback heuristic parsing
# Check logs for parsing errors and adjust prompts if needed
```

---

## 📖 Documentation

- **Implementation Progress:** `/docs/reasoningbank/IMPLEMENTATION_PROGRESS.md`
- **Deployment Summary:** `/docs/reasoningbank/DEPLOYMENT_SUMMARY.md`
- **ReasoningBank Gist:** https://gist.github.com/ruvnet/0670d2070a4a75bb70949d7d55d26cd1
- **Gist Analysis:** `/docs/gist-analysis.json`

---

## 💬 Support

For issues or questions:
1. Check documentation in `/docs/reasoningbank/`
2. Review gist analysis for architecture details
3. Consult implementation progress for current status

---

**Status:** Phase 1 Complete - Ready for Basic Usage
**Next:** Phase 2 - Full Learning Pipeline (2 weeks)

*Happy Learning! 🚀*
