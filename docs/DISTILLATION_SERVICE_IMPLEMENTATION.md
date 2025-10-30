# DistillationService Implementation

## Overview

The `DistillationService` is a core component of the ReasoningBank system that extracts reusable strategic patterns from successful test generation trajectories. It uses Claude Sonnet 4.5 for intelligent pattern extraction and OpenAI's text-embedding-3-large for semantic vector generation.

## Architecture

### Core Components

1. **Pattern Extraction**: LLM-based analysis of trajectories to identify strategic principles
2. **Embedding Generation**: Vector representation for semantic similarity search
3. **Pattern Storage**: Persistent storage with confidence tracking and domain tagging
4. **Batch Processing**: Efficient processing of multiple trajectories

### Integration Points

- **TrajectoryService**: Access to execution trajectories
- **Anthropic Claude**: Pattern extraction and analysis
- **OpenAI Embeddings**: Vector generation for semantic search
- **PostgreSQL + pgvector**: Pattern storage and retrieval

## Key Features

### 1. Intelligent Pattern Extraction

Uses Claude Sonnet 4.5 at temperature=0 for deterministic pattern extraction:

```python
service = DistillationService(
    db_session=session,
    anthropic_api_key="your-key"
)

patterns = await service.distill_pattern(trajectory)
```

**Pattern Quality Requirements**:
- 3-8 numbered procedural steps
- Clear, actionable guidance
- Domain-specific expertise
- Success-validated principles

### 2. Vector Embeddings

Generates 1536-dimensional embeddings using OpenAI's text-embedding-3-large:

```python
embedding = await service.generate_embedding(
    "Pattern title and description text"
)
```

**Embedding Features**:
- High-quality semantic representations
- Optimized for similarity search
- Fast retrieval with pgvector
- Automatic fallback to zero vector on error

### 3. Automatic Distillation

Processes undistilled trajectories automatically:

```python
summary = await service.distill_undistilled_trajectories(
    task_type="test_generation",
    limit=10,
    tenant_id="tenant_123"
)
```

**Returns**:
```json
{
    "trajectories_processed": 10,
    "patterns_extracted": 18,
    "success_count": 9,
    "failure_count": 1,
    "avg_patterns_per_trajectory": 2.0
}
```

### 4. Pattern Validation

Strict validation ensures pattern quality:

- **Required Fields**: title, description, content
- **Step Count**: 3-8 numbered steps required
- **Confidence Range**: 0.0-1.0
- **Domain Tags**: List of applicable domains

## Usage Examples

### Basic Pattern Distillation

```python
from sentinel_backend.reasoningbank.services.distillation_service import DistillationService
from sentinel_backend.reasoningbank.services.trajectory_service import TrajectoryService

# Initialize service
distillation_service = DistillationService(
    db_session=session,
    anthropic_api_key="your-anthropic-key",
    openai_api_key="your-openai-key"
)

# Get a trajectory
trajectory_service = TrajectoryService(session)
trajectory = await trajectory_service.get_trajectory("traj_abc123")

# Distill patterns
patterns = await distillation_service.distill_pattern(trajectory)

for pattern in patterns:
    print(f"Pattern: {pattern.title}")
    print(f"Confidence: {pattern.confidence}")
    print(f"Domain Tags: {pattern.domain_tags}")
    print(f"Steps:\n{pattern.content}")
```

### Batch Processing

```python
# Get undistilled trajectories
trajectories = await trajectory_service.get_undistilled_trajectories(
    task_type="test_generation",
    limit=20
)

# Batch distill
results = await distillation_service.batch_distill_trajectories(trajectories)

for trajectory, patterns in results:
    print(f"Trajectory {trajectory.trajectory_id}: {len(patterns)} patterns extracted")
```

### Automatic Distillation Pipeline

```python
# Run automatic distillation
summary = await distillation_service.distill_undistilled_trajectories(
    task_type="test_generation",
    limit=50,
    tenant_id="tenant_123"
)

print(f"Processed: {summary['trajectories_processed']}")
print(f"Extracted: {summary['patterns_extracted']}")
print(f"Success Rate: {summary['success_count'] / summary['trajectories_processed']:.2%}")
```

### Pattern Retrieval

```python
# Get pattern by ID
pattern = await distillation_service.get_pattern_by_id("pat_xyz789")

# Get patterns by domain
api_patterns = await distillation_service.get_patterns_by_domain(
    domain_tag="api_testing",
    limit=10,
    tenant_id="tenant_123"
)

# Get distillation statistics
stats = await distillation_service.get_distillation_statistics(
    task_type="test_generation"
)
```

## Pattern Extraction Prompt

The service uses a sophisticated prompt for Claude Sonnet 4.5:

**Analysis Focus**:
1. Key decision points and reasoning
2. Effective techniques or approaches
3. Domain-specific best practices
4. Reusable problem-solving strategies

**Output Format**:
```json
{
    "patterns": [
        {
            "title": "Clear pattern name",
            "description": "1-2 sentence summary",
            "content": "1. Step one\n2. Step two\n...",
            "domain_tags": ["tag1", "tag2"],
            "confidence": 0.85,
            "applicability": "When to use this pattern"
        }
    ],
    "key_insights": ["Insight 1", "Insight 2"],
    "risk_factors": ["Risk 1", "Risk 2"]
}
```

## Data Model

### PatternEmbedding

```python
class PatternEmbedding:
    pattern_id: str              # Unique identifier
    title: str                   # Pattern name
    description: str             # Brief summary
    content: str                 # 3-8 numbered steps
    embedding: List[float]       # 1536-dimensional vector
    confidence: float            # Initial confidence (0.0-1.0)
    usage_count: int             # Times pattern was used
    success_count: int           # Successful uses
    failure_count: int           # Failed uses
    domain_tags: List[str]       # Domain classifications
    source_trajectory_id: str    # Source trajectory
    tenant_id: str              # Multi-tenancy support
    created_at: datetime        # Creation timestamp
    updated_at: datetime        # Last modification
    last_used_at: datetime      # Last usage time
```

### Pattern Scoring

Patterns are scored using multiple factors:

```
score = α·similarity + β·recency + γ·reliability - δ·diversity

Default Weights:
- α (similarity): 0.65
- β (recency): 0.15
- γ (reliability): 0.20
- δ (diversity): 0.10
```

**Reliability Score**:
```python
reliability = success_rate * 0.7 + usage_boost * 0.3
usage_boost = sigmoid(log(1 + usage_count))
```

**Recency Score** (90-day half-life):
```python
recency = e^(-days_old / 90)
```

## Error Handling

The service includes comprehensive error handling:

### 1. Trajectory Validation

```python
try:
    patterns = await service.distill_pattern(trajectory)
except ValueError as e:
    # Trajectory not ready for distillation
    print(f"Validation error: {e}")
```

### 2. LLM Failures

```python
# Automatic fallback on extraction failure
patterns_data = await service.extract_principles(trajectory)
# Returns empty patterns list with error in risk_factors
```

### 3. Embedding Generation Failures

```python
# Returns zero vector as fallback
embedding = await service.generate_embedding(text)
# [0.0] * 1536 if API fails
```

### 4. Pattern Validation

```python
# Invalid patterns are filtered automatically
# Logs warnings for debugging
valid_patterns = [p for p in patterns if service._validate_pattern(p)]
```

## Performance Considerations

### Batch Processing

Use batch methods for efficiency:

```python
# Process 50 trajectories in one operation
results = await service.batch_distill_trajectories(trajectories[:50])
```

### Rate Limiting

- **Anthropic**: 5000 TPM (tokens per minute) for Claude Sonnet 4.5
- **OpenAI**: 5000 RPM (requests per minute) for embeddings
- Implement exponential backoff for rate limit errors

### Database Optimization

- Patterns stored with pgvector indexes for fast similarity search
- Domain tags indexed with GIN for efficient filtering
- Confidence and usage indexes for sorting

## Monitoring and Metrics

### Key Metrics

```python
stats = await service.get_distillation_statistics(
    task_type="test_generation"
)

# Returns:
{
    "total_patterns": 145,
    "avg_confidence": 0.82,
    "avg_usage_count": 3.5,
    "trajectories_distilled": 87,
    "distillation_rate": 0.85,
    "patterns_per_trajectory": 1.67
}
```

### Logging

The service uses Python's standard logging:

```python
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Key log events:
# - Pattern extraction start/completion
# - Validation failures
# - API errors
# - Pattern creation
# - Batch processing progress
```

## Testing

Comprehensive test suite included:

```bash
# Run unit tests
pytest sentinel_backend/tests/unit/test_distillation_service.py -v

# Run with coverage
pytest sentinel_backend/tests/unit/test_distillation_service.py --cov=reasoningbank.services.distillation_service
```

**Test Coverage**:
- ✅ Service initialization
- ✅ Pattern extraction (success/failure)
- ✅ Embedding generation (success/failure/fallback)
- ✅ Pattern distillation (various trajectory states)
- ✅ Batch processing
- ✅ Pattern validation
- ✅ Prompt formatting
- ✅ Error handling
- ✅ Automatic distillation pipeline

## Integration with ReasoningBank

The DistillationService is part of the complete ReasoningBank pipeline:

```
1. TrajectoryService   → Capture execution paths
2. JudgmentService     → LLM-based success evaluation
3. DistillationService → Extract reusable patterns ✓
4. RetrievalService    → Semantic similarity search
5. ConsolidationService → Deduplication and quality control
```

### Complete Workflow

```python
# 1. Create trajectory
trajectory = await trajectory_service.create_trajectory(
    task_type="test_generation",
    task_description="Generate API tests",
    context_data={"api_spec": spec}
)

# 2. Execute task and record actions
await trajectory_service.add_action(trajectory.trajectory_id, "Analyzed spec")
await trajectory_service.add_action(trajectory.trajectory_id, "Generated tests")

# 3. Complete trajectory
await trajectory_service.complete_trajectory(
    trajectory.trajectory_id,
    final_output={"tests": 15, "coverage": 0.92}
)

# 4. Judge trajectory
outcome, confidence, reasoning, _ = await judgment_service.judge_trajectory(trajectory)
await trajectory_service.update_judgment(
    trajectory.trajectory_id, outcome, confidence, reasoning
)

# 5. Distill patterns
patterns = await distillation_service.distill_pattern(trajectory)

# 6. Retrieve similar patterns for next task
similar = await retrieval_service.retrieve_patterns(
    query="Generate comprehensive API tests",
    top_k=5
)
```

## Configuration

### Environment Variables

```bash
# Required
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."

# Optional
export DISTILLATION_MODEL="claude-sonnet-4-20250514"
export DISTILLATION_TEMPERATURE=0.0
export EMBEDDING_MODEL="text-embedding-3-large"
export EMBEDDING_DIMENSIONS=1536
```

### Service Configuration

```python
service = DistillationService(
    db_session=session,
    anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
    openai_api_key=os.getenv("OPENAI_API_KEY"),
)

# Or use pre-configured clients
anthropic_client = AsyncAnthropic(api_key="...")
openai_client = AsyncOpenAI(api_key="...")

service = DistillationService(
    db_session=session,
    anthropic_client=anthropic_client,
    openai_client=openai_client,
)
```

## Future Enhancements

### Planned Features

1. **Multi-Model Support**: Support for other LLMs (GPT-4, Gemini)
2. **Pattern Evolution**: Track pattern changes over time
3. **Domain-Specific Prompts**: Specialized extraction for different domains
4. **Pattern Clustering**: Group similar patterns automatically
5. **A/B Testing**: Compare pattern effectiveness
6. **Human-in-the-Loop**: Manual pattern review and approval
7. **Pattern Templates**: Pre-defined templates for common scenarios

### Performance Optimizations

1. **Caching**: Cache frequently accessed patterns
2. **Parallel Processing**: Concurrent trajectory processing
3. **Incremental Updates**: Update embeddings incrementally
4. **Batch Embeddings**: Generate multiple embeddings in one call

## References

- [ReasoningBank Architecture](https://gist.github.com/ruvnet/0670d2070a4a75bb70949d7d55d26cd1)
- [Claude Sonnet 4.5 Documentation](https://docs.anthropic.com/claude/docs)
- [OpenAI Embeddings Documentation](https://platform.openai.com/docs/guides/embeddings)
- [pgvector Documentation](https://github.com/pgvector/pgvector)

## Support

For issues or questions:
- File an issue on GitHub
- Contact the Sentinel team
- Check the ReasoningBank documentation

---

**Version**: 1.0.0
**Last Updated**: 2025-01-15
**Status**: Production Ready ✅
