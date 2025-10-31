# DistillationService Quick Start Guide

## 🚀 Quick Setup

### 1. Install Dependencies

```bash
pip install anthropic openai sqlalchemy pgvector asyncpg
```

### 2. Set Environment Variables

```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
export OPENAI_API_KEY="sk-your-key-here"
```

### 3. Initialize Service

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sentinel_backend.reasoningbank.services.distillation_service import DistillationService

# Create database session
engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/sentinel_db")
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async with async_session() as session:
    service = DistillationService(db_session=session)
```

## 📖 Common Use Cases

### Extract Patterns from a Trajectory

```python
# Get a trajectory that has been judged
trajectory = await trajectory_service.get_trajectory("traj_abc123")

# Distill patterns
patterns = await service.distill_pattern(trajectory)

print(f"Extracted {len(patterns)} patterns:")
for pattern in patterns:
    print(f"  - {pattern.title} (confidence: {pattern.confidence:.2f})")
```

### Process All Undistilled Trajectories

```python
# Automatic distillation of pending trajectories
summary = await service.distill_undistilled_trajectories(
    task_type="test_generation",
    limit=50  # Process up to 50 at a time
)

print(f"Processed: {summary['trajectories_processed']}")
print(f"Patterns: {summary['patterns_extracted']}")
print(f"Success Rate: {summary['success_count'] / summary['trajectories_processed']:.1%}")
```

### Retrieve Patterns by Domain

```python
# Get patterns for a specific domain
patterns = await service.get_patterns_by_domain(
    domain_tag="api_testing",
    limit=10
)

for pattern in patterns:
    print(f"{pattern.title}:")
    print(f"  {pattern.description}")
    print(f"  Domain Tags: {', '.join(pattern.domain_tags)}")
    print(f"  Confidence: {pattern.confidence:.2f}")
    print(f"  Usage: {pattern.usage_count} times\n")
```

## 🔍 Understanding Patterns

### Pattern Structure

Each extracted pattern contains:

- **Title**: Clear, concise name
- **Description**: 1-2 sentence summary
- **Content**: 3-8 numbered procedural steps
- **Domain Tags**: Applicable domains (e.g., "api_testing", "security")
- **Confidence**: Initial confidence score (0.0-1.0)
- **Embedding**: 1536-dimensional vector for semantic search

### Example Pattern

```json
{
  "title": "Comprehensive API Test Generation",
  "description": "Systematic approach to generating complete test suites for RESTful APIs",
  "content": "1. Analyze API specification to identify all endpoints\n2. Generate tests for each CRUD operation\n3. Add boundary value tests\n4. Include authentication tests\n5. Test error handling\n6. Validate response schemas",
  "domain_tags": ["api_testing", "test_generation", "rest_api"],
  "confidence": 0.9
}
```

## 🎯 Best Practices

### 1. Only Distill Successful Trajectories

The service automatically skips failed trajectories:

```python
# Only SUCCESS or high-confidence PARTIAL trajectories are processed
if trajectory.outcome == TrajectoryOutcome.SUCCESS:
    patterns = await service.distill_pattern(trajectory)
```

### 2. Process in Batches

For large-scale distillation:

```python
# Process 100 trajectories in batches of 10
for i in range(0, 100, 10):
    summary = await service.distill_undistilled_trajectories(limit=10)
    print(f"Batch {i//10 + 1}: {summary['patterns_extracted']} patterns")
```

### 3. Monitor Distillation Quality

```python
# Get statistics to monitor quality
stats = await service.get_distillation_statistics()

print(f"Total Patterns: {stats['total_patterns']}")
print(f"Avg Confidence: {stats['avg_confidence']:.2f}")
print(f"Avg Usage: {stats['avg_usage_count']:.1f}")
print(f"Distillation Rate: {stats['distillation_rate']:.1%}")
```

### 4. Handle Errors Gracefully

```python
try:
    patterns = await service.distill_pattern(trajectory)
except ValueError as e:
    # Trajectory not ready (not judged, already distilled, etc.)
    print(f"Skipping trajectory: {e}")
except Exception as e:
    # Other errors (API failures, etc.)
    print(f"Distillation failed: {e}")
```

## ⚡ Performance Tips

### 1. Use Batch Processing

```python
# Efficient: Process multiple trajectories at once
trajectories = await trajectory_service.get_undistilled_trajectories(limit=20)
results = await service.batch_distill_trajectories(trajectories)
```

### 2. Filter by Domain

```python
# Only process specific task types
summary = await service.distill_undistilled_trajectories(
    task_type="test_generation",  # Focus on one type
    limit=25
)
```

### 3. Monitor API Usage

```python
import logging
logging.basicConfig(level=logging.INFO)

# Logs will show:
# - Pattern extraction start/completion
# - API calls to Claude and OpenAI
# - Validation failures
# - Pattern creation
```

## 🧪 Testing

### Run Unit Tests

```bash
# All tests
pytest tests/unit/test_distillation_service.py -v

# Specific test
pytest tests/unit/test_distillation_service.py::TestDistillationService::test_distill_pattern_success -v

# With coverage
pytest tests/unit/test_distillation_service.py --cov=reasoningbank.services.distillation_service --cov-report=html
```

### Manual Testing

```python
# Create a test trajectory
trajectory = TaskTrajectory(
    trajectory_id="traj_test",
    task_type="test_generation",
    task_description="Test task",
    context_data={},
    actions=[
        {"description": "Step 1", "timestamp": "2025-01-15T10:00:00"},
        {"description": "Step 2", "timestamp": "2025-01-15T10:01:00"},
    ],
    final_output={"result": "success"},
    outcome=TrajectoryOutcome.SUCCESS,
    outcome_confidence=0.95,
    distillation_performed=0
)

# Test distillation
patterns = await service.distill_pattern(trajectory)
assert len(patterns) > 0
assert all(p.confidence > 0.0 for p in patterns)
```

## 🔧 Troubleshooting

### Pattern Extraction Returns Empty

**Cause**: Trajectory may be failed or low-confidence partial

**Solution**:
```python
# Check trajectory outcome
print(f"Outcome: {trajectory.outcome}")
print(f"Confidence: {trajectory.outcome_confidence}")

# Only SUCCESS or high-confidence PARTIAL (>0.7) are distilled
```

### Embedding Generation Fails

**Cause**: OpenAI API key missing or invalid

**Solution**:
```python
# Check API key
import os
print(f"OpenAI Key Set: {'OPENAI_API_KEY' in os.environ}")

# Service falls back to zero vector on error
# Check logs for API errors
```

### Pattern Validation Fails

**Cause**: Pattern doesn't meet quality requirements (3-8 steps)

**Solution**:
```python
# The service automatically validates and filters invalid patterns
# Check logs for validation warnings:
# "Invalid pattern skipped: Pattern Title"
```

### Rate Limit Errors

**Cause**: Too many API requests

**Solution**:
```python
# Add delays between batches
import asyncio

for i in range(0, 100, 10):
    summary = await service.distill_undistilled_trajectories(limit=10)
    await asyncio.sleep(2)  # 2-second delay between batches
```

## 📊 Monitoring Dashboard

### Key Metrics to Track

```python
async def get_distillation_metrics():
    """Get comprehensive distillation metrics."""
    stats = await service.get_distillation_statistics()

    return {
        "total_patterns": stats["total_patterns"],
        "avg_confidence": f"{stats['avg_confidence']:.2%}",
        "avg_usage": f"{stats['avg_usage_count']:.1f}",
        "distillation_rate": f"{stats['distillation_rate']:.1%}",
        "patterns_per_trajectory": f"{stats['patterns_per_trajectory']:.2f}",
    }

# Use in monitoring dashboard
metrics = await get_distillation_metrics()
print(json.dumps(metrics, indent=2))
```

## 🔗 Integration Examples

### With Judgment Service

```python
from sentinel_backend.reasoningbank.services.judgment_service import JudgmentService

# 1. Judge trajectory
judgment_service = JudgmentService()
outcome, confidence, reasoning, _ = await judgment_service.judge_trajectory(trajectory)

# 2. Update trajectory
await trajectory_service.update_judgment(
    trajectory.trajectory_id, outcome, confidence, reasoning
)

# 3. Distill patterns
if outcome == TrajectoryOutcome.SUCCESS:
    patterns = await distillation_service.distill_pattern(trajectory)
```

### With Retrieval Service

```python
from sentinel_backend.reasoningbank.services.retrieval_service import RetrievalService

# 1. Distill patterns from successful trajectories
patterns = await distillation_service.distill_pattern(trajectory)

# 2. Retrieve similar patterns for next task
retrieval_service = RetrievalService(session)
similar_patterns = await retrieval_service.retrieve_patterns(
    query="Generate API tests with high coverage",
    top_k=5
)

# 3. Use patterns to guide next test generation
for pattern in similar_patterns:
    print(f"Using pattern: {pattern.title}")
    print(pattern.content)
```

## 📚 Additional Resources

- [Full Documentation](DISTILLATION_SERVICE_IMPLEMENTATION.md)
- [ReasoningBank Architecture](../reasoningbank/__init__.py)
- [Pattern Embeddings Model](../reasoningbank/models/pattern_embeddings.py)
- [Test Suite](../tests/unit/test_distillation_service.py)

## 💡 Tips

1. **Start Small**: Process 10-20 trajectories first to validate setup
2. **Monitor Quality**: Check avg_confidence in statistics (should be >0.7)
3. **Review Patterns**: Manually review first few patterns for quality
4. **Tune Confidence**: Adjust confidence thresholds based on your needs
5. **Domain Tags**: Use consistent domain tags for better organization

---

**Need Help?** Check the full documentation or contact the Sentinel team.
