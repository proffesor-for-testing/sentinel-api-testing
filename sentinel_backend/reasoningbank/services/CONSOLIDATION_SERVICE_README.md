# ConsolidationService Implementation

## Overview

The `ConsolidationService` is a production-ready component for the ReasoningBank system that implements memory consolidation and quality control. It ensures the learned pattern database remains clean, consistent, and high-quality through automated maintenance operations.

## Architecture

### Core Responsibilities

1. **Memory Deduplication**: Identify and merge near-identical patterns
2. **Contradiction Detection**: Find conflicting guidance using semantic analysis
3. **Pattern Aging**: Apply exponential decay to unused patterns
4. **Confidence Updates**: Reinforce successful patterns via reinforcement learning
5. **Pattern Merging**: Combine similar patterns to reduce redundancy

### Key Features

- **Asynchronous Operations**: All database operations use `async/await` for scalability
- **Batch Processing**: Processes patterns in configurable batches
- **Tenant Isolation**: Multi-tenant support with proper data isolation
- **Comprehensive Logging**: Detailed logging for debugging and monitoring
- **Error Handling**: Robust error handling with graceful degradation
- **Type Safety**: Full type hints for IDE support and static analysis

## Public API

### Main Methods

#### `consolidate_patterns()`
Run the full consolidation pipeline on all patterns.

```python
async def consolidate_patterns(
    tenant_id: Optional[str] = None,
    batch_size: int = 100,
    aggressive: bool = False,
) -> Dict[str, Any]
```

**Returns**: Statistics dictionary with:
- `patterns_processed`: Total patterns analyzed
- `duplicates_found`: Number of duplicate pairs detected
- `contradictions_found`: Number of contradictions detected
- `patterns_merged`: Number of patterns merged
- `patterns_aged`: Number of patterns with reduced confidence
- `patterns_archived`: Number of patterns removed

**Example Usage**:
```python
service = ConsolidationService(db_session)
stats = await service.consolidate_patterns(
    tenant_id="org_123",
    aggressive=True
)
print(f"Merged {stats['patterns_merged']} patterns")
```

#### `detect_duplicates()`
Identify near-identical patterns using cosine similarity.

```python
async def detect_duplicates(
    tenant_id: Optional[str] = None,
    batch_size: int = 100,
) -> List[PatternLink]
```

**Algorithm**: Compares pattern embeddings using cosine similarity. Patterns with similarity ≥ 0.87 are marked as duplicates.

**Returns**: List of `PatternLink` objects with `link_type=DUPLICATE`

#### `detect_contradictions()`
Find patterns providing conflicting guidance.

```python
async def detect_contradictions(
    tenant_id: Optional[str] = None,
    batch_size: int = 100,
) -> List[PatternLink]
```

**Algorithm**: Uses semantic analysis to detect:
1. Patterns about the same topic (semantic similarity)
2. Opposing recommendations (contradictory keywords)

**Returns**: List of `PatternLink` objects with `link_type=CONTRADICTION`

#### `update_confidence()`
Update pattern confidence based on usage outcome.

```python
async def update_confidence(
    pattern_id: str,
    success: bool,
    learning_rate: Optional[float] = None,
) -> PatternEmbedding
```

**Algorithm**: Reinforcement learning update rule:
```
confidence ← clamp(confidence + η·success_delta, 0, 1)
where success_delta = +1 if success else -1
```

**Parameters**:
- `success`: True if pattern was used successfully
- `learning_rate`: Default 0.05 (configurable)

#### `age_patterns()`
Reduce confidence of unused patterns (exponential decay).

```python
async def age_patterns(
    tenant_id: Optional[str] = None,
    half_life_days: Optional[int] = None,
    min_confidence: Optional[float] = None,
) -> int
```

**Algorithm**: Exponential decay formula:
```
confidence ← confidence × e^(-days_unused / half_life)
```

**Default Parameters**:
- `half_life_days`: 90 days
- `min_confidence`: 0.1

#### `merge_similar_patterns()`
Merge two similar patterns into one.

```python
async def merge_similar_patterns(
    source_pattern_id: str,
    target_pattern_id: str,
    strategy: str = "combine",
) -> Optional[PatternEmbedding]
```

**Strategies**:
- `"combine"`: Combine usage stats, keep higher-quality content
- `"keep_better"`: Keep pattern with better reliability, delete other
- `"average"`: Average confidence, combine content

#### `get_consolidation_status()`
Get current consolidation status and statistics.

```python
async def get_consolidation_status(
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]
```

**Returns**: Dictionary with:
- `total_patterns`: Total pattern count
- `unresolved_duplicates`: Duplicates needing attention
- `unresolved_contradictions`: Contradictions needing resolution
- `low_confidence_patterns`: Patterns below threshold

## Configuration Constants

| Constant | Default | Description |
|----------|---------|-------------|
| `DUPLICATE_THRESHOLD` | 0.87 | Cosine similarity for duplicates |
| `CONTRADICTION_THRESHOLD` | 0.60 | NLI score for contradictions |
| `AGING_HALF_LIFE_DAYS` | 90 | Half-life for exponential decay |
| `MIN_CONFIDENCE` | 0.1 | Minimum confidence before archival |
| `MAX_USAGE_GAP_DAYS` | 180 | Max days without use before aggressive aging |
| `MERGE_SIMILARITY_THRESHOLD` | 0.75 | Threshold for merging similar patterns |
| `LEARNING_RATE` | 0.05 | Default learning rate for confidence updates |

## Database Schema

### Pattern Links

The service creates `PatternLink` records to track relationships:

```python
class PatternLink:
    source_pattern_id: str
    target_pattern_id: str
    link_type: LinkType  # DUPLICATE, CONTRADICTION, REFINEMENT, etc.
    similarity_score: float
    is_resolved: bool
    resolution_action: str  # "merge", "quarantine", "keep_both"
    created_at: datetime
    resolved_at: datetime
```

## Usage Examples

### Basic Consolidation

```python
from sqlalchemy.ext.asyncio import AsyncSession
from reasoningbank.services.consolidation_service import ConsolidationService

async def run_consolidation(db_session: AsyncSession):
    service = ConsolidationService(db_session)

    # Run full consolidation
    stats = await service.consolidate_patterns()

    print(f"✅ Consolidation complete!")
    print(f"   Patterns processed: {stats['patterns_processed']}")
    print(f"   Duplicates merged: {stats['patterns_merged']}")
    print(f"   Contradictions found: {stats['contradictions_found']}")
```

### Scheduled Maintenance

```python
async def nightly_maintenance(db_session: AsyncSession):
    """Run consolidation as part of nightly maintenance."""
    service = ConsolidationService(db_session)

    # Get current status
    status = await service.get_consolidation_status()
    print(f"Pre-consolidation: {status['unresolved_duplicates']} duplicates")

    # Run consolidation
    stats = await service.consolidate_patterns(aggressive=True)

    # Check results
    status = await service.get_consolidation_status()
    print(f"Post-consolidation: {status['unresolved_duplicates']} duplicates")
```

### Pattern Usage Tracking

```python
async def track_pattern_usage(
    db_session: AsyncSession,
    pattern_id: str,
    success: bool
):
    """Update pattern confidence after usage."""
    service = ConsolidationService(db_session)

    # Update confidence based on outcome
    pattern = await service.update_confidence(
        pattern_id=pattern_id,
        success=success,
        learning_rate=0.05
    )

    print(f"Updated {pattern_id}: confidence={pattern.confidence:.3f}")
```

### Tenant-Specific Consolidation

```python
async def consolidate_tenant_patterns(
    db_session: AsyncSession,
    tenant_id: str
):
    """Consolidate patterns for a specific tenant."""
    service = ConsolidationService(db_session)

    stats = await service.consolidate_patterns(
        tenant_id=tenant_id,
        batch_size=50,
        aggressive=False
    )

    return stats
```

## Integration with ReasoningBank

The ConsolidationService integrates seamlessly with other ReasoningBank components:

```python
from reasoningbank import (
    ConsolidationService,
    RetrievalService,
    TrajectoryService,
    JudgmentService,
    DistillationService,
)

async def full_learning_cycle(db_session: AsyncSession):
    """Complete learning cycle with consolidation."""

    # 1. Track trajectory
    trajectory_service = TrajectoryService(db_session)
    trajectory = await trajectory_service.create_trajectory(
        task_type="test_generation",
        task_description="Generate API tests"
    )

    # 2. Judge trajectory
    judgment_service = JudgmentService()
    outcome, confidence, reasoning, _ = await judgment_service.judge_trajectory(trajectory)

    # 3. Distill patterns (if successful)
    if outcome == "SUCCESS":
        distillation_service = DistillationService(db_session)
        patterns = await distillation_service.distill_patterns(trajectory)

    # 4. Consolidate patterns (periodic)
    consolidation_service = ConsolidationService(db_session)
    stats = await consolidation_service.consolidate_patterns()

    return stats
```

## Performance Considerations

### Batch Processing

The service processes patterns in batches to handle large datasets:

```python
# For large databases, use smaller batch sizes
stats = await service.consolidate_patterns(
    batch_size=50,  # Process 50 patterns at a time
    aggressive=False
)
```

### Indexing

Ensure these database indexes exist for optimal performance:

```sql
-- Pattern embeddings
CREATE INDEX idx_pattern_confidence ON pattern_embeddings(confidence);
CREATE INDEX idx_pattern_usage ON pattern_embeddings(usage_count);
CREATE INDEX idx_pattern_created ON pattern_embeddings(created_at);

-- Pattern links
CREATE INDEX idx_link_source_target ON pattern_links(source_pattern_id, target_pattern_id);
CREATE INDEX idx_link_type_resolved ON pattern_links(link_type, is_resolved);
```

### Memory Usage

For vector similarity calculations, memory usage scales with:
- Number of patterns: O(n²) for pairwise comparisons
- Embedding dimensions: 1536 floats per pattern

For datasets > 10,000 patterns, consider:
1. Using approximate nearest neighbor (ANN) algorithms
2. Processing in batches
3. Caching embeddings in memory

## Error Handling

The service implements comprehensive error handling:

```python
try:
    stats = await service.consolidate_patterns()
except ValueError as e:
    # Pattern not found or invalid parameters
    logger.error(f"Validation error: {e}")
except Exception as e:
    # Database errors, connection issues, etc.
    logger.error(f"Consolidation failed: {e}", exc_info=True)
```

All errors are logged with context for debugging.

## Testing

### Unit Tests

```python
import pytest
from reasoningbank.services.consolidation_service import ConsolidationService

@pytest.mark.asyncio
async def test_detect_duplicates(db_session):
    service = ConsolidationService(db_session)

    # Create test patterns with high similarity
    # ... (create patterns)

    links = await service.detect_duplicates()
    assert len(links) > 0
    assert all(link.similarity_score >= 0.87 for link in links)
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_full_consolidation(db_session):
    service = ConsolidationService(db_session)

    # Run consolidation
    stats = await service.consolidate_patterns()

    # Verify results
    assert stats['success'] is True
    assert stats['patterns_processed'] > 0
```

## Monitoring and Observability

### Metrics to Track

1. **Consolidation Runs**:
   - Frequency of consolidation
   - Duration of each run
   - Patterns processed per run

2. **Quality Metrics**:
   - Duplicate detection rate
   - Contradiction resolution rate
   - Average pattern confidence

3. **Health Indicators**:
   - Unresolved duplicates trend
   - Unresolved contradictions trend
   - Low-confidence pattern count

### Logging

The service logs at multiple levels:

```python
# INFO: Normal operations
logger.info(f"Starting consolidation for tenant_id={tenant_id}")

# WARNING: Potential issues
logger.warning(f"Contradiction found: {pattern_a.pattern_id} <-> {pattern_b.pattern_id}")

# ERROR: Failures
logger.error(f"Failed to merge patterns: {e}", exc_info=True)

# DEBUG: Detailed information
logger.debug(f"Aged pattern {pattern_id}: {old_confidence:.3f} -> {new_confidence:.3f}")
```

## Future Enhancements

Potential improvements for future versions:

1. **Parallel Processing**: Use `asyncio.gather()` for concurrent pattern comparisons
2. **ANN Algorithms**: Implement FAISS or Annoy for faster similarity search
3. **Pattern Versioning**: Track pattern evolution over time
4. **Conflict Resolution UI**: Admin interface for manual contradiction resolution
5. **A/B Testing**: Test different consolidation strategies
6. **Pattern Clustering**: Group related patterns using clustering algorithms
7. **Incremental Consolidation**: Only process recently added/updated patterns

## License

Part of the Sentinel API Testing Platform.
Copyright © 2024 Sentinel Team.
