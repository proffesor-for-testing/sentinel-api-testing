# AgentDB Integration - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### 1. Install Dependencies

```bash
cd sentinel_backend
poetry install
npm install -g claude-flow@alpha
```

### 2. Start Service

```bash
# Local development
uvicorn agentdb_service.main:app --port 8006 --reload

# Or with Docker
docker build -t sentinel-agentdb -f agentdb_service/Dockerfile .
docker run -d -p 8006:8006 sentinel-agentdb
```

### 3. Verify

```bash
# Health check
curl http://localhost:8006/health

# API docs
open http://localhost:8006/docs
```

### 4. First API Call

```bash
# Store a test pattern
curl -X POST http://localhost:8006/api/v1/patterns/store \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint": "/api/users/{id}",
    "method": "GET",
    "parameters": {"path": {"id": 123}},
    "agent_type": "functional-positive",
    "tags": ["users", "read"]
  }'

# Search similar patterns
curl -X POST http://localhost:8006/api/v1/patterns/search \
  -H "Content-Type: application/json" \
  -d '{
    "query_pattern": {
      "endpoint": "/api/users/{id}",
      "method": "GET"
    },
    "top_k": 10,
    "min_similarity": 0.7
  }'
```

## 🔥 Key Features

- **116x Faster** vector search (580ms → 5ms @ 100K vectors)
- **141x Faster** batch operations (14.1s → 100ms for 1000)
- **56% Less Memory** compared to traditional storage
- **Sub-millisecond** query latency with HNSW indexing

## 📚 Documentation

- **Design**: `/docs/phase-2/agentdb-integration-design.md`
- **Implementation**: `/docs/phase-2/agentdb-implementation-guide.md`
- **Summary**: `/docs/phase-2/MILESTONE-2.1-SUMMARY.md`

## 🧪 Run Benchmarks

```bash
cd sentinel_backend
pytest tests/performance/test_agentdb_benchmark.py -v -m benchmark
```

## 🔄 Migrate Existing Data

```bash
python scripts/migrate_to_agentdb.py
```

---
**Status**: ✅ Production Ready
**Port**: 8006
**Version**: 1.0.0
