# RetrievalService Implementation Guide

## Overview

The `RetrievalService` provides semantic retrieval of learned patterns using vector similarity search with pgvector integration. It implements Maximum Marginal Relevance (MMR) for diverse, relevant results.

## Features

### 1. **Vector Similarity Search**
- Cosine similarity-based pattern matching
- Weighted scoring combining similarity, recency, and reliability
- Efficient pgvector integration for large-scale retrieval

### 2. **Maximum Marginal Relevance (MMR)**
- Balances relevance with diversity
- Prevents redundant pattern suggestions
- Configurable λ parameter for relevance/diversity trade-off

### 3. **Pattern Filtering**
- Domain-based filtering (e.g., "api_testing", "security")
- Confidence threshold filtering
- Multi-tenancy support

### 4. **Usage Tracking**
- Reinforcement learning-based confidence updates
- Success/failure tracking
- Pattern reliability scoring

## Architecture

```
RetrievalService
├── Similarity Search
│   ├── Vector embedding comparison (1536-dim)
│   ├── Weighted scoring (α·similarity + β·recency + γ·reliability)
│   └── Domain filtering with JSONB queries
├── MMR Search
│   ├── Candidate set retrieval
│   ├── Diversity-aware selection
│   └── Iterative greedy algorithm
├── Pattern Matching
│   ├── Find similar patterns
│   ├── Domain-based search
│   └── Top patterns by reliability
└── Usage Tracking
    ├── Confidence updates
    ├── Success/failure counts
    └── Learning rate control
```

## Usage Examples

### Basic Retrieval

```python
from reasoningbank.services.retrieval_service import RetrievalService
from sqlalchemy.ext.asyncio import AsyncSession

# Initialize service
retrieval_service = RetrievalService(
    db_session=async_session,
    embedding_service=embedding_service
)

# Retrieve relevant patterns
patterns = await retrieval_service.retrieve_relevant_patterns(
    query_text="How do I test OAuth2 authentication?",
    limit=5,
    domain_tags=["api_testing", "security"],
    min_confidence=0.7
)

for pattern in patterns:
    print(f"Pattern: {pattern.title}")
    print(f"Confidence: {pattern.confidence:.2f}")
    print(f"Content:\n{pattern.content}\n")
```

### MMR Search for Diverse Results

```python
# Use MMR for diverse pattern suggestions
patterns = await retrieval_service.retrieve_relevant_patterns(
    query_text="Test REST API endpoints",
    limit=10,
    use_mmr=True,
    mmr_lambda=0.7,  # 0.7 = 70% relevance, 30% diversity
    domain_tags=["api_testing"]
)
```

### Similarity Search with Pre-computed Embedding

```python
# Use pre-computed embedding for efficiency
query_embedding = [0.1, 0.2, ..., 0.3]  # 1536-dim vector

patterns = await retrieval_service.similarity_search(
    query_embedding=query_embedding,
    limit=5,
    min_confidence=0.8
)
```

### Find Similar Patterns (Deduplication)

```python
# Find patterns similar to a specific pattern
similar_patterns = await retrieval_service.find_similar_patterns(
    pattern_id="pat_12345",
    limit=5,
    min_similarity=0.85
)

for pattern, similarity in similar_patterns:
    print(f"{pattern.title}: {similarity:.3f}")
```

### Domain-Based Search

```python
# Get patterns for specific domains
security_patterns = await retrieval_service.search_by_domain(
    domain_tags=["security", "authentication"],
    limit=20,
    min_confidence=0.6
)
```

### Update Pattern Usage (Reinforcement Learning)

```python
# Update pattern confidence after usage
updated_pattern = await retrieval_service.update_pattern_usage(
    pattern_id="pat_12345",
    success=True,  # Pattern worked well
    learning_rate=0.05
)

print(f"New confidence: {updated_pattern.confidence:.3f}")
```

## Scoring Formula

The retrieval service uses a weighted scoring formula:

```
score = α·similarity + β·recency + γ·reliability
```

### Default Weights
- **α (similarity)**: 0.65 - Vector similarity to query
- **β (recency)**: 0.15 - Temporal recency (exponential decay)
- **γ (reliability)**: 0.20 - Success rate × usage boost

### Customize Weights

```python
retrieval_service.set_scoring_weights(
    similarity=0.7,   # Emphasize relevance
    recency=0.1,      # Less weight on recency
    reliability=0.2   # Maintain reliability weight
)
```

## MMR Algorithm

Maximum Marginal Relevance balances relevance with diversity:

```
MMR = argmax[D\S] [λ·sim(q,d) - (1-λ)·max[d'∈S] sim(d,d')]
```

Where:
- `q`: Query vector
- `d`: Candidate document
- `S`: Set of already-selected documents
- `λ`: Balance parameter (0=diversity, 1=relevance)

### MMR Parameters

```python
patterns = await retrieval_service.mmr_search(
    query_embedding=query_vector,
    limit=10,                    # Final result size
    lambda_param=0.7,            # 70% relevance, 30% diversity
    candidate_multiplier=3,      # Fetch 3x candidates for better diversity
)
```

## Configuration

### Scoring Weights

```python
# Configure scoring weights (must sum to 1.0)
retrieval_service.set_scoring_weights(
    similarity=0.65,
    recency=0.15,
    reliability=0.20
)
```

### Learning Rate

```python
# Update pattern with custom learning rate
await retrieval_service.update_pattern_usage(
    pattern_id="pat_12345",
    success=True,
    learning_rate=0.1  # Larger learning rate = faster adaptation
)
```

## Performance Considerations

### 1. **Vector Index**
- Ensure pgvector extension is enabled in PostgreSQL
- Create HNSW or IVFFlat index on `embedding` column:

```sql
CREATE INDEX pattern_embeddings_hnsw_idx
ON pattern_embeddings
USING hnsw (embedding vector_cosine_ops);
```

### 2. **Batch Processing**
```python
# Process multiple queries in parallel
import asyncio

queries = ["query 1", "query 2", "query 3"]
results = await asyncio.gather(*[
    retrieval_service.retrieve_relevant_patterns(q, limit=5)
    for q in queries
])
```

### 3. **Domain Indexing**
- Use GIN index on `domain_tags` JSONB column for fast filtering:

```sql
CREATE INDEX pattern_domain_tags_gin_idx
ON pattern_embeddings
USING gin (domain_tags);
```

## Error Handling

```python
from reasoningbank.services.retrieval_service import RetrievalService

try:
    patterns = await retrieval_service.retrieve_relevant_patterns(
        query_text="test query",
        limit=5
    )
except ValueError as e:
    # Handle missing embedding service or invalid parameters
    print(f"Configuration error: {e}")
except Exception as e:
    # Handle database errors
    print(f"Retrieval error: {e}")
```

## Testing

Run the comprehensive test suite:

```bash
cd sentinel_backend
source venv/bin/activate
python -m pytest tests/unit/test_retrieval_service.py -v
```

### Test Coverage
- **27 unit tests** covering all major functionality
- **99% code coverage** for retrieval_service.py
- Tests include:
  - Cosine similarity calculations
  - Similarity search with filters
  - MMR algorithm validation
  - Pattern usage tracking
  - Edge cases and error handling

## Integration with ReasoningBank

The RetrievalService is part of the ReasoningBank closed-loop learning system:

1. **Trajectory Service** → Captures task execution
2. **Judgment Service** → Evaluates success/failure
3. **Distillation Service** → Extracts patterns
4. **RetrievalService** → Retrieves relevant patterns ← **YOU ARE HERE**
5. **Consolidation Service** → Merges and updates patterns

### Usage in Agent Loop

```python
# 1. Retrieve relevant patterns for new task
patterns = await retrieval_service.retrieve_relevant_patterns(
    query_text=task_description,
    limit=5,
    domain_tags=["api_testing"]
)

# 2. Inject patterns into agent prompt
pattern_context = "\n\n".join([p.to_prompt_format() for p in patterns])
agent_prompt = f"{pattern_context}\n\nTask: {task_description}"

# 3. Execute task with patterns
result = await agent.execute(agent_prompt)

# 4. Update pattern usage based on outcome
for pattern in patterns:
    await retrieval_service.update_pattern_usage(
        pattern_id=pattern.pattern_id,
        success=(result.status == "success"),
        learning_rate=0.05
    )
```

## API Reference

### Core Methods

#### `retrieve_relevant_patterns()`
High-level retrieval with automatic embedding generation.

**Parameters:**
- `query_text` (str): Natural language query
- `query_embedding` (List[float], optional): Pre-computed embedding
- `limit` (int): Maximum results (default: 10)
- `domain_tags` (List[str], optional): Domain filters
- `min_confidence` (float): Confidence threshold (default: 0.5)
- `tenant_id` (str, optional): Multi-tenancy filter
- `use_mmr` (bool): Enable MMR (default: True)
- `mmr_lambda` (float): Relevance/diversity balance (default: 0.7)

**Returns:** `List[PatternEmbedding]`

#### `similarity_search()`
Vector similarity search with weighted scoring.

**Parameters:**
- `query_embedding` (List[float]): Query vector (1536-dim)
- `limit` (int): Maximum results
- `domain_tags`, `min_confidence`, `tenant_id`: Filters

**Returns:** `List[PatternEmbedding]`

#### `mmr_search()`
Maximum Marginal Relevance search for diverse results.

**Parameters:**
- `query_embedding` (List[float]): Query vector
- `limit` (int): Final result count
- `lambda_param` (float): Balance parameter (0-1)
- `candidate_multiplier` (int): Candidate set size multiplier

**Returns:** `List[PatternEmbedding]`

#### `find_similar_patterns()`
Find patterns similar to a given pattern.

**Parameters:**
- `pattern_id` (str): Source pattern ID
- `limit` (int): Maximum results
- `min_similarity` (float): Similarity threshold
- `exclude_self` (bool): Exclude source pattern

**Returns:** `List[Tuple[PatternEmbedding, float]]`

#### `update_pattern_usage()`
Update pattern confidence based on usage outcome.

**Parameters:**
- `pattern_id` (str): Pattern to update
- `success` (bool): Whether usage was successful
- `learning_rate` (float): Learning rate (default: 0.05)

**Returns:** `PatternEmbedding`

## Best Practices

### 1. **Use MMR for User-Facing Results**
Enable MMR when presenting patterns to users to avoid redundant suggestions.

```python
# User-facing: Enable MMR
patterns = await retrieval_service.retrieve_relevant_patterns(
    query_text=user_query,
    use_mmr=True,
    mmr_lambda=0.7
)
```

### 2. **Use Similarity Search for Internal Logic**
Use standard similarity search when you need pure relevance ranking.

```python
# Internal: Pure relevance
patterns = await retrieval_service.retrieve_relevant_patterns(
    query_text=task_context,
    use_mmr=False
)
```

### 3. **Track Pattern Usage**
Always update pattern usage after application to enable learning.

```python
# Always track usage
for pattern in patterns:
    outcome = apply_pattern(pattern)
    await retrieval_service.update_pattern_usage(
        pattern_id=pattern.pattern_id,
        success=outcome.is_success
    )
```

### 4. **Filter by Domain**
Use domain filtering to improve precision and reduce noise.

```python
# Domain-specific retrieval
patterns = await retrieval_service.retrieve_relevant_patterns(
    query_text="authentication testing",
    domain_tags=["security", "api_testing"],  # Narrow scope
    min_confidence=0.7
)
```

### 5. **Adjust Weights for Use Case**
Customize scoring weights based on your application needs.

```python
# High-stakes: Emphasize reliability
retrieval_service.set_scoring_weights(
    similarity=0.5,
    recency=0.1,
    reliability=0.4  # More weight on proven patterns
)

# Exploratory: Emphasize novelty
retrieval_service.set_scoring_weights(
    similarity=0.6,
    recency=0.3,      # More weight on recent patterns
    reliability=0.1
)
```

## Troubleshooting

### Issue: Low Retrieval Quality

**Solution 1:** Adjust scoring weights
```python
retrieval_service.set_scoring_weights(
    similarity=0.8,  # More emphasis on relevance
    recency=0.1,
    reliability=0.1
)
```

**Solution 2:** Increase confidence threshold
```python
patterns = await retrieval_service.retrieve_relevant_patterns(
    query_text=query,
    min_confidence=0.8  # Only high-confidence patterns
)
```

### Issue: Too Similar Results

**Solution:** Enable MMR with lower λ
```python
patterns = await retrieval_service.mmr_search(
    query_embedding=query_vector,
    lambda_param=0.5,  # 50/50 relevance/diversity
    limit=10
)
```

### Issue: Slow Retrieval

**Solution 1:** Create vector index
```sql
CREATE INDEX pattern_embeddings_hnsw_idx
ON pattern_embeddings
USING hnsw (embedding vector_cosine_ops);
```

**Solution 2:** Reduce candidate set
```python
patterns = await retrieval_service.mmr_search(
    query_embedding=query_vector,
    limit=5,
    candidate_multiplier=2  # Fetch fewer candidates
)
```

## Future Enhancements

1. **Hybrid Search**: Combine vector similarity with BM25 keyword search
2. **Cross-Encoder Reranking**: Use BERT-based reranker for top-k results
3. **Personalization**: User-specific pattern preferences
4. **Temporal Decay**: Configurable decay functions for recency
5. **Pattern Clustering**: Automatic pattern grouping and hierarchies

## References

- [pgvector Documentation](https://github.com/pgvector/pgvector)
- [Maximum Marginal Relevance Paper](https://www.cs.cmu.edu/~jgc/publication/The_Use_MMR_Diversity_Based_LTMIR_1998.pdf)
- [ReasoningBank Architecture](https://gist.github.com/ruvnet/0670d2070a4a75bb70949d7d55d26cd1)
- [Sentence Transformers](https://www.sbert.net/)

## License

Copyright (c) 2024 Sentinel Team. All rights reserved.
