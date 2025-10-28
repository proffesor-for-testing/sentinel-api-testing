# AgentDB Implementation Guide

## Quick Start

### 1. Install Dependencies

```bash
cd sentinel_backend

# Install Python dependencies
poetry install

# Install Node.js (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install claude-flow globally
npm install -g claude-flow@alpha
```

### 2. Start AgentDB Service

**Option A: Docker (Recommended)**

```bash
# Build service
docker build -t sentinel-agentdb:latest -f agentdb_service/Dockerfile .

# Run service
docker run -d \
  --name sentinel-agentdb \
  -p 8006:8006 \
  -e EMBEDDING_MODEL=all-MiniLM-L6-v2 \
  -e AGENTDB_COLLECTION_PREFIX=sentinel \
  -v agentdb_data:/data/agentdb \
  sentinel-agentdb:latest

# Check logs
docker logs -f sentinel-agentdb
```

**Option B: Local Development**

```bash
# Activate poetry environment
poetry shell

# Start service
cd agentdb_service
uvicorn main:app --host 0.0.0.0 --port 8006 --reload
```

### 3. Verify Service

```bash
# Health check
curl http://localhost:8006/health

# Service info
curl http://localhost:8006/

# API documentation
open http://localhost:8006/docs
```

## API Usage Examples

### Store a Test Pattern

```bash
curl -X POST http://localhost:8006/api/v1/patterns/store \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "/api/users/{id}",
    "method": "GET",
    "parameters": {
      "path": {"id": 123},
      "query": {"include": "profile"}
    },
    "agent_type": "functional-positive",
    "tags": ["users", "read"],
    "response_codes": [200, 404],
    "metadata": {
      "success_rate": 0.95,
      "test_count": 42
    }
  }'
```

### Search for Similar Patterns

```bash
curl -X POST http://localhost:8006/api/v1/patterns/search \
  -H "Content-Type: application/json" \
  -d '{
    "query_pattern": {
      "endpoint": "/api/users/{id}",
      "method": "GET",
      "parameters": {"path": {"id": 456}}
    },
    "top_k": 10,
    "min_similarity": 0.7
  }'
```

### Store Execution Result

```bash
curl -X POST http://localhost:8006/api/v1/executions/store \
  -H "Content-Type: application/json" \
  -d '{
    "test_id": "test_123",
    "status": "pass",
    "endpoint": "/api/users/123",
    "method": "GET",
    "response_code": 200,
    "latency_ms": 145,
    "assertions": {
      "passed": 5,
      "failed": 0
    }
  }'
```

### Analyze Failure Patterns

```bash
curl "http://localhost:8006/api/v1/executions/failures/%2Fapi%2Fusers%2F%7Bid%7D?method=GET&top_k=50"
```

### Get Statistics

```bash
curl http://localhost:8006/api/v1/stats
```

## Integration with Test Generation Agents

### Pattern-Aware Test Generation

```python
# In orchestration_service/agents/functional_positive_agent.py

from httpx import AsyncClient

class PatternAwareFunctionalAgent:
    """Enhanced agent with pattern learning."""

    def __init__(self, agentdb_url: str = "http://localhost:8006"):
        self.agentdb_url = agentdb_url
        self.client = AsyncClient()

    async def generate_tests(
        self,
        api_spec: Dict,
        endpoint: str,
        method: str
    ) -> List[Dict]:
        """Generate tests using learned patterns."""

        # 1. Search for similar patterns
        similar_patterns = await self._find_similar_patterns(
            endpoint, method
        )

        # 2. Reuse successful patterns
        base_tests = []
        if similar_patterns:
            for pattern in similar_patterns[:3]:  # Top 3
                if pattern["metadata"].get("success_rate", 0) > 0.8:
                    adapted_test = self._adapt_pattern(
                        pattern, api_spec
                    )
                    base_tests.append(adapted_test)

        # 3. Generate new tests for gaps
        new_tests = await self._generate_novel_tests(
            api_spec, endpoint, method,
            covered_by=base_tests
        )

        # 4. Store new patterns
        for test in new_tests:
            await self._store_pattern(test)

        return base_tests + new_tests

    async def _find_similar_patterns(
        self,
        endpoint: str,
        method: str
    ) -> List[Dict]:
        """Search for similar patterns in AgentDB."""
        response = await self.client.post(
            f"{self.agentdb_url}/api/v1/patterns/search",
            json={
                "query_pattern": {
                    "endpoint": endpoint,
                    "method": method
                },
                "top_k": 5,
                "min_similarity": 0.7
            }
        )
        return response.json()["results"]

    async def _store_pattern(self, test: Dict):
        """Store test as pattern."""
        await self.client.post(
            f"{self.agentdb_url}/api/v1/patterns/store",
            json={
                "endpoint": test["endpoint"],
                "method": test["method"],
                "parameters": test["parameters"],
                "agent_type": "functional-positive",
                "tags": test.get("tags", [])
            }
        )
```

### Learning from Execution Results

```python
# In execution_service/main.py

async def record_test_result(test_id: str, result: Dict):
    """Record execution result to AgentDB."""

    # Store in PostgreSQL (existing)
    await store_in_postgres(test_id, result)

    # Also store in AgentDB for learning
    async with httpx.AsyncClient() as client:
        await client.post(
            "http://localhost:8006/api/v1/executions/store",
            json={
                "test_id": test_id,
                "status": result["status"],
                "endpoint": result["endpoint"],
                "method": result["method"],
                "response_code": result["response_code"],
                "latency_ms": result["latency_ms"],
                "assertions": result["assertions"],
                "error_pattern": result.get("error_pattern")
            }
        )

    # Update pattern metrics if test passed
    if result["status"] == "pass":
        await update_pattern_success_rate(test_id)
```

## Migration Guide

### Migrate Existing Data

```bash
# Run migration script
cd sentinel_backend
python scripts/migrate_to_agentdb.py

# Expected output:
# - Progress bars for batches
# - Migration summary with statistics
# - Collection details
```

### Migration Options

```python
# In scripts/migrate_to_agentdb.py

# Migrate only recent data
await migrate_execution_results(
    session_maker,
    vector_storage,
    batch_size=100,
    limit=10000  # Last 10K results
)

# Migrate all data
await migrate_execution_results(
    session_maker,
    vector_storage,
    batch_size=100,
    limit=None  # All results
)
```

## Performance Benchmarking

### Run Benchmarks

```bash
# Run all benchmarks
cd sentinel_backend
pytest tests/performance/test_agentdb_benchmark.py -v -m benchmark

# Run specific benchmark
pytest tests/performance/test_agentdb_benchmark.py::test_vector_search_100k_performance -v

# Generate HTML report
pytest tests/performance/test_agentdb_benchmark.py -v -m benchmark --html=report.html
```

### Expected Results

```
BENCHMARK: Vector Search Performance (100K vectors)
========================================
✅ Inserted 100,000 patterns in 15.23s

📊 RESULTS:
  Average search time: 6.42ms
  P50 (median):        5.87ms
  P95:                 8.12ms
  P99:                 9.45ms

  Speedup vs baseline: 90.3x
  Target speedup:      116x

✅ BENCHMARK PASSED: Achieved 90.3x speedup (>50x target)
```

## Monitoring and Observability

### Prometheus Metrics

```bash
# View metrics
curl http://localhost:8006/metrics

# Key metrics:
# - http_requests_total
# - http_request_duration_seconds
# - vector_search_duration_seconds
# - pattern_reuse_rate
```

### Health Monitoring

```bash
# Add to monitoring system
watch -n 5 curl -s http://localhost:8006/health
```

## Docker Compose Integration

```yaml
# Add to docker-compose.yml

services:
  agentdb_service:
    build:
      context: ./sentinel_backend
      dockerfile: agentdb_service/Dockerfile
    container_name: sentinel_agentdb
    ports:
      - "8006:8006"
    environment:
      - EMBEDDING_MODEL=all-MiniLM-L6-v2
      - AGENTDB_COLLECTION_PREFIX=sentinel
      - AGENTDB_DATA_DIR=/data/agentdb
    volumes:
      - agentdb_data:/data/agentdb
    depends_on:
      - message_broker
      - database
    networks:
      - sentinel_network
    restart: unless-stopped

volumes:
  agentdb_data:

networks:
  sentinel_network:
```

## Troubleshooting

### Service Won't Start

```bash
# Check Node.js installation
node --version  # Should be >= 18.x

# Check claude-flow installation
npx claude-flow@alpha --version

# Check Python dependencies
poetry show sentence-transformers numpy

# View service logs
docker logs sentinel-agentdb
```

### Slow Performance

```bash
# Check embedding model loaded
curl http://localhost:8006/health | jq .embedding_model

# Check vector counts
curl http://localhost:8006/api/v1/stats | jq .total_vectors

# Monitor memory usage
docker stats sentinel-agentdb
```

### Migration Issues

```bash
# Verify database connection
python -c "from config.settings import get_settings; print(get_settings().database.url)"

# Test AgentDB connectivity
curl http://localhost:8006/health

# Run migration with verbose logging
python scripts/migrate_to_agentdb.py --log-level DEBUG
```

## Next Steps

1. **Week 1-2**: Deploy to staging environment
2. **Week 2-3**: Integrate with all test generation agents
3. **Week 3-4**: Run production-scale benchmarks (1M+ vectors)
4. **Week 4+**: Monitor and optimize based on real-world usage

## Resources

- **API Documentation**: http://localhost:8006/docs
- **Prometheus Metrics**: http://localhost:8006/metrics
- **Design Document**: `/docs/phase-2/agentdb-integration-design.md`
- **AgentDB Documentation**: https://github.com/ruvnet/agentic-flow
- **Sentence Transformers**: https://www.sbert.net/

---
**Last Updated**: 2025-10-27
**Version**: 1.0.0
