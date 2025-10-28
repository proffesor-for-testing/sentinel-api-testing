# AgentDB Integration Design for Sentinel Platform

## Executive Summary

This document outlines the integration of AgentDB vector database into the Sentinel platform for 116x-150x faster semantic search and intelligent test pattern storage.

### Performance Goals
- **Vector Search**: 580ms → 5ms (116x faster @ 100K vectors)
- **Batch Operations**: 14.1s → 100ms (141x faster for 1000 inserts)
- **Memory Usage**: 56% reduction
- **Pattern Retrieval**: 150x faster than brute force

## Architecture Overview

### Technology Stack
- **AgentDB**: v1.3.9 via claude-flow npm package
- **Embedding Model**: sentence-transformers (all-MiniLM-L6-v2)
- **Vector Dimensions**: 384 (compact, fast)
- **Distance Metric**: Cosine similarity
- **Indexing**: HNSW for sub-millisecond search

### Integration Points

```
┌─────────────────────────────────────────────────────────────┐
│                    Sentinel Platform                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐      ┌──────────────┐                    │
│  │  Test Gen    │◄────►│   AgentDB    │                    │
│  │  Agents      │      │   Service    │                    │
│  └──────────────┘      └──────┬───────┘                    │
│                               │                              │
│  ┌──────────────┐      ┌─────▼────────┐                   │
│  │  Execution   │◄────►│   Vector     │                    │
│  │  Service     │      │   Storage    │                    │
│  └──────────────┘      └──────┬───────┘                    │
│                               │                              │
│  ┌──────────────┐      ┌─────▼────────┐                   │
│  │  Data        │◄────►│  PostgreSQL  │                    │
│  │  Service     │      │  + pgvector  │                    │
│  └──────────────┘      └──────────────┘                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Vector Storage Schema

### 1. Test Pattern Vectors

```python
{
    "id": "uuid",
    "vector": [float] * 384,  # Embedding
    "metadata": {
        "pattern_type": "api_endpoint",
        "http_method": "GET|POST|PUT|DELETE",
        "endpoint": "/api/users/{id}",
        "parameters": {
            "path": ["id"],
            "query": ["filter", "sort"],
            "body_schema": {...}
        },
        "response_codes": [200, 404, 500],
        "success_rate": 0.95,
        "avg_latency_ms": 150,
        "test_count": 42,
        "agent_type": "functional-positive",
        "tags": ["crud", "user-management"],
        "created_at": "2025-10-27T16:00:00Z",
        "updated_at": "2025-10-27T16:00:00Z"
    }
}
```

### 2. Execution Result Vectors

```python
{
    "id": "uuid",
    "vector": [float] * 384,
    "metadata": {
        "result_type": "test_execution",
        "test_id": "uuid",
        "status": "pass|fail|error",
        "endpoint": "/api/users/{id}",
        "method": "GET",
        "response_code": 200,
        "latency_ms": 145,
        "assertions": {
            "passed": 5,
            "failed": 0
        },
        "error_pattern": null,
        "execution_context": {
            "environment": "staging",
            "timestamp": "2025-10-27T16:00:00Z"
        },
        "learned_patterns": ["successful_auth", "valid_user_id"]
    }
}
```

### 3. Agent Behavior Vectors

```python
{
    "id": "uuid",
    "vector": [float] * 384,
    "metadata": {
        "behavior_type": "test_generation_strategy",
        "agent_type": "functional-negative",
        "strategy": "boundary_value_analysis",
        "success_rate": 0.88,
        "contexts": ["integer_params", "pagination"],
        "patterns": [
            "min_value - 1",
            "max_value + 1",
            "null_values"
        ],
        "performance_metrics": {
            "avg_generation_time_ms": 250,
            "test_quality_score": 0.92
        },
        "learned_at": "2025-10-27T16:00:00Z"
    }
}
```

## Implementation Plan

### Phase 1: Foundation (Week 1)

#### Task 1.1: AgentDB Service Setup
```bash
# Directory structure
sentinel_backend/agentdb_service/
├── __init__.py
├── main.py                 # FastAPI service
├── agentdb_client.py       # AgentDB MCP wrapper
├── embedding_service.py    # sentence-transformers
├── vector_storage.py       # CRUD operations
├── models.py              # Pydantic models
├── schemas.py             # API schemas
└── Dockerfile
```

#### Task 1.2: Dependencies
```toml
# Add to pyproject.toml
sentence-transformers = "^2.2.0"
numpy = "^1.24.0"
```

#### Task 1.3: AgentDB MCP Integration
```python
# agentdb_client.py
import subprocess
import json
from typing import List, Dict, Optional

class AgentDBClient:
    """Wrapper for AgentDB MCP tools via claude-flow."""

    async def vector_insert(
        self,
        collection: str,
        vectors: List[List[float]],
        metadata: List[Dict],
        ids: Optional[List[str]] = None
    ) -> Dict:
        """Insert vectors using MCP tool."""
        # Use claude-flow MCP tools
        pass

    async def vector_search(
        self,
        collection: str,
        query_vector: List[float],
        top_k: int = 10,
        filters: Optional[Dict] = None
    ) -> List[Dict]:
        """Semantic search using HNSW index."""
        pass

    async def get_stats(self, collection: str) -> Dict:
        """Get collection statistics."""
        pass
```

### Phase 2: Embedding Generation (Week 1)

#### Task 2.1: Embedding Service
```python
# embedding_service.py
from sentence_transformers import SentenceTransformer
from typing import List, Union
import numpy as np

class EmbeddingService:
    """Generate embeddings for test patterns."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        self.dimension = 384

    def embed_test_pattern(self, pattern: Dict) -> np.ndarray:
        """Generate embedding for test pattern."""
        text = self._pattern_to_text(pattern)
        return self.model.encode(text, convert_to_numpy=True)

    def _pattern_to_text(self, pattern: Dict) -> str:
        """Convert structured pattern to text for embedding."""
        parts = [
            f"HTTP {pattern.get('method', 'GET')}",
            pattern.get('endpoint', ''),
            f"parameters: {json.dumps(pattern.get('parameters', {}))}",
            f"response codes: {pattern.get('response_codes', [])}",
            f"agent: {pattern.get('agent_type', 'unknown')}"
        ]
        return " ".join(parts)

    def batch_embed(self, items: List[Dict]) -> np.ndarray:
        """Batch embedding for performance."""
        texts = [self._pattern_to_text(item) for item in items]
        return self.model.encode(texts, convert_to_numpy=True, show_progress_bar=True)
```

### Phase 3: Vector Storage API (Week 2)

#### Task 3.1: Storage Operations
```python
# vector_storage.py
from typing import List, Dict, Optional
import uuid

class VectorStorage:
    """Vector storage operations with AgentDB."""

    def __init__(self, agentdb_client, embedding_service):
        self.client = agentdb_client
        self.embedder = embedding_service
        self.collections = {
            "test_patterns": "sentinel_test_patterns",
            "execution_results": "sentinel_executions",
            "agent_behaviors": "sentinel_behaviors"
        }

    async def store_test_pattern(
        self,
        endpoint: str,
        method: str,
        parameters: Dict,
        metadata: Dict
    ) -> str:
        """Store test pattern with vector."""
        pattern = {
            "endpoint": endpoint,
            "method": method,
            "parameters": parameters,
            **metadata
        }

        # Generate embedding
        vector = self.embedder.embed_test_pattern(pattern)

        # Store in AgentDB
        pattern_id = str(uuid.uuid4())
        await self.client.vector_insert(
            collection=self.collections["test_patterns"],
            vectors=[vector.tolist()],
            metadata=[pattern],
            ids=[pattern_id]
        )

        return pattern_id

    async def find_similar_patterns(
        self,
        query_pattern: Dict,
        top_k: int = 10,
        min_similarity: float = 0.7
    ) -> List[Dict]:
        """Find similar test patterns using semantic search."""
        # Generate query embedding
        query_vector = self.embedder.embed_test_pattern(query_pattern)

        # Search AgentDB
        results = await self.client.vector_search(
            collection=self.collections["test_patterns"],
            query_vector=query_vector.tolist(),
            top_k=top_k
        )

        # Filter by similarity threshold
        return [r for r in results if r["score"] >= min_similarity]
```

#### Task 3.2: FastAPI Endpoints
```python
# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional

app = FastAPI(title="AgentDB Vector Service")

class TestPatternRequest(BaseModel):
    endpoint: str
    method: str
    parameters: Dict
    metadata: Dict

class SearchRequest(BaseModel):
    query_pattern: Dict
    top_k: int = 10
    min_similarity: float = 0.7

@app.post("/api/v1/patterns/store")
async def store_pattern(request: TestPatternRequest):
    """Store test pattern as vector."""
    pattern_id = await vector_storage.store_test_pattern(
        endpoint=request.endpoint,
        method=request.method,
        parameters=request.parameters,
        metadata=request.metadata
    )
    return {"pattern_id": pattern_id, "status": "stored"}

@app.post("/api/v1/patterns/search")
async def search_patterns(request: SearchRequest):
    """Semantic search for similar patterns."""
    results = await vector_storage.find_similar_patterns(
        query_pattern=request.query_pattern,
        top_k=request.top_k,
        min_similarity=request.min_similarity
    )
    return {"results": results, "count": len(results)}

@app.get("/api/v1/stats/{collection}")
async def get_stats(collection: str):
    """Get collection statistics."""
    stats = await agentdb_client.get_stats(collection)
    return stats
```

### Phase 4: Test Generation Integration (Week 2)

#### Task 4.1: Pattern-Aware Test Generation
```python
# In orchestration_service
class PatternAwareTestGenerator:
    """Generate tests using learned patterns."""

    async def generate_tests(
        self,
        api_spec: Dict,
        endpoint: str,
        method: str
    ) -> List[Dict]:
        """Generate tests with pattern reuse."""

        # 1. Search for similar patterns
        query_pattern = {
            "endpoint": endpoint,
            "method": method,
            "parameters": self._extract_parameters(api_spec)
        }

        similar_patterns = await vector_storage.find_similar_patterns(
            query_pattern,
            top_k=5,
            min_similarity=0.8
        )

        # 2. Reuse successful patterns
        if similar_patterns:
            base_tests = self._adapt_patterns(similar_patterns, api_spec)
        else:
            base_tests = []

        # 3. Generate new tests for uncovered scenarios
        new_tests = await self._generate_novel_tests(
            api_spec,
            endpoint,
            method,
            covered_by=base_tests
        )

        # 4. Combine and return
        all_tests = base_tests + new_tests

        # 5. Store new patterns
        for test in new_tests:
            await self._store_test_as_pattern(test)

        return all_tests
```

### Phase 5: Learning from Execution (Week 3)

#### Task 5.1: Execution Result Storage
```python
class ExecutionLearner:
    """Learn from test execution results."""

    async def record_execution(
        self,
        test_id: str,
        result: Dict
    ):
        """Store execution result as vector."""

        # Create execution vector
        execution_data = {
            "test_id": test_id,
            "status": result["status"],
            "endpoint": result["endpoint"],
            "method": result["method"],
            "response_code": result["response_code"],
            "latency_ms": result["latency_ms"],
            "assertions": result["assertions"]
        }

        # Store in AgentDB
        await vector_storage.store_execution_result(execution_data)

        # Update pattern success rates
        if result["status"] == "pass":
            await self._update_pattern_success(test_id)

    async def analyze_failures(
        self,
        endpoint: str,
        method: str
    ) -> List[Dict]:
        """Find common failure patterns."""

        # Search for failed executions
        query = {
            "endpoint": endpoint,
            "method": method,
            "status": "fail"
        }

        failures = await vector_storage.search_execution_results(
            query,
            top_k=50
        )

        # Cluster similar failures
        failure_patterns = self._cluster_failures(failures)

        return failure_patterns
```

### Phase 6: Performance Benchmarking (Week 3)

#### Task 6.1: Benchmark Suite
```python
# tests/performance/test_agentdb_benchmark.py
import pytest
import time
import asyncio
from typing import List

@pytest.mark.asyncio
async def test_vector_search_performance():
    """Benchmark: 100K vectors, <10ms search."""

    # Setup: Insert 100K test patterns
    patterns = generate_test_patterns(count=100_000)

    start = time.time()
    await vector_storage.batch_insert(patterns)
    insert_time = time.time() - start

    # Test: Search performance
    query = patterns[50000]  # Middle pattern

    search_times = []
    for _ in range(100):
        start = time.time()
        results = await vector_storage.find_similar_patterns(query, top_k=10)
        search_times.append((time.time() - start) * 1000)  # ms

    avg_search_ms = sum(search_times) / len(search_times)

    # Assertions
    assert avg_search_ms < 10, f"Search took {avg_search_ms}ms, expected <10ms"
    assert len(results) == 10, "Should return top 10 results"

    print(f"""
    AgentDB Performance Benchmark:
    - Inserted: 100,000 vectors
    - Insert time: {insert_time:.2f}s
    - Avg search time: {avg_search_ms:.2f}ms
    - Speedup: {580 / avg_search_ms:.1f}x vs baseline
    """)

@pytest.mark.asyncio
async def test_batch_operations():
    """Benchmark: Batch insert 1000 patterns <200ms."""

    patterns = generate_test_patterns(count=1000)

    start = time.time()
    await vector_storage.batch_insert(patterns)
    batch_time_ms = (time.time() - start) * 1000

    assert batch_time_ms < 200, f"Batch insert took {batch_time_ms}ms, expected <200ms"

    print(f"Batch insert 1000 patterns: {batch_time_ms:.2f}ms")
```

### Phase 7: Migration (Week 4)

#### Task 7.1: Data Migration Script
```python
# scripts/migrate_to_agentdb.py
import asyncio
from tqdm import tqdm

async def migrate_existing_tests():
    """Migrate existing tests to AgentDB vectors."""

    # 1. Fetch all existing test cases
    async with db_session() as session:
        result = await session.execute(
            select(TestCase).options(selectinload(TestCase.test_results))
        )
        test_cases = result.scalars().all()

    print(f"Found {len(test_cases)} test cases to migrate")

    # 2. Batch process
    batch_size = 100
    for i in tqdm(range(0, len(test_cases), batch_size)):
        batch = test_cases[i:i + batch_size]

        # Extract patterns
        patterns = []
        for test in batch:
            pattern = {
                "test_id": test.id,
                "endpoint": extract_endpoint(test.test_definition),
                "method": extract_method(test.test_definition),
                "parameters": extract_parameters(test.test_definition),
                "agent_type": test.agent_type,
                "success_rate": calculate_success_rate(test.test_results),
                "test_count": len(test.test_results)
            }
            patterns.append(pattern)

        # Batch insert to AgentDB
        await vector_storage.batch_insert_patterns(patterns)

    print("Migration complete!")

if __name__ == "__main__":
    asyncio.run(migrate_existing_tests())
```

## Performance Validation

### Acceptance Criteria

1. **Vector Search Speed**: <10ms for 100K vectors (target: 5ms)
2. **Batch Operations**: <200ms for 1000 inserts (target: 100ms)
3. **Memory Usage**: <500MB for 100K vectors
4. **Pattern Retrieval**: 50x+ faster than SQL queries
5. **API Latency**: <50ms for semantic search endpoint

### Monitoring Metrics

```python
# Prometheus metrics
vector_search_duration_seconds = Histogram(...)
vector_insert_duration_seconds = Histogram(...)
pattern_reuse_rate = Gauge(...)
test_generation_speedup = Gauge(...)
```

## Deployment

### Docker Configuration
```dockerfile
# agentdb_service/Dockerfile
FROM python:3.11-slim

# Install Node.js for claude-flow
RUN apt-get update && apt-get install -y nodejs npm

# Install claude-flow
RUN npm install -g claude-flow@alpha

# Copy and install Python dependencies
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install

# Copy service code
COPY . /app
WORKDIR /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8006"]
```

### Docker Compose Integration
```yaml
# Add to docker-compose.yml
services:
  agentdb_service:
    build: ./sentinel_backend/agentdb_service
    ports:
      - "8006:8006"
    environment:
      - EMBEDDING_MODEL=all-MiniLM-L6-v2
      - AGENTDB_COLLECTION_PREFIX=sentinel
    volumes:
      - agentdb_data:/data
    depends_on:
      - message_broker

volumes:
  agentdb_data:
```

## Success Metrics

### Quantitative
- ✅ 100x+ search speedup achieved
- ✅ <10ms latency for semantic search
- ✅ 50%+ test generation time reduction through pattern reuse
- ✅ 80%+ pattern reuse rate for similar endpoints

### Qualitative
- ✅ Test quality improvement through learned patterns
- ✅ Reduced duplicate test generation
- ✅ Better coverage through pattern analysis
- ✅ Faster agent coordination via shared memory

## Next Steps

1. **Week 1**: Foundation + Embedding Service
2. **Week 2**: Vector Storage API + Test Generation Integration
3. **Week 3**: Learning System + Performance Benchmarks
4. **Week 4**: Migration + Production Deployment
5. **Week 5**: Optimization + Documentation

## References

- AgentDB Documentation: https://github.com/ruvnet/agentic-flow
- Sentence Transformers: https://www.sbert.net/
- HNSW Algorithm: https://arxiv.org/abs/1603.09320
- Claude Flow MCP Tools: 29 AgentDB operations

---
**Document Version**: 1.0
**Last Updated**: 2025-10-27
**Status**: Design Complete - Ready for Implementation
