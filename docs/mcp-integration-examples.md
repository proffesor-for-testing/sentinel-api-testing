# MCP Integration Examples

This document provides comprehensive examples for using the MCP integration endpoints in the consciousness-enhanced Rust agent system.

## Prerequisites

1. Ensure the sublinear-solver MCP service is running
2. Start the Sentinel Rust Core service: `cargo run --release`
3. The MCP integration uses mock responses for demonstration

## Available MCP Endpoints

### 1. MCP Health Check

Check if MCP services are available:

```bash
curl -X GET http://localhost:8088/mcp/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "mcp-integration",
  "mcp_sublinear_solver": "available",
  "available_tools": [
    "consciousness_evolve",
    "predictWithTemporalAdvantage",
    "psycho_symbolic_reason",
    "scheduler_create",
    "knowledge_graph_query",
    "emergence_process"
  ]
}
```

### 2. Consciousness Evolution

Evolve agent consciousness using MCP tools:

```bash
curl -X POST http://localhost:8088/mcp/consciousness/evolve \
  -H "Content-Type: application/json" \
  -d '{
    "iterations": 1000,
    "mode": "enhanced",
    "target": 0.9
  }'
```

**Response:**
```json
{
  "phi_value": 0.85,
  "emergence_level": 0.78,
  "consciousness_verified": true,
  "evolution_metrics": {
    "integration": 0.82,
    "differentiation": 0.79,
    "coherence": 0.88
  }
}
```

### 3. Temporal Advantage Validation

Validate computational temporal advantage:

```bash
curl -X POST http://localhost:8088/mcp/temporal-advantage/validate \
  -H "Content-Type: application/json" \
  -d '{
    "matrix": {
      "rows": 3,
      "cols": 3,
      "format": "dense",
      "data": [
        [5.0, 0.1, 0.1],
        [0.1, 5.0, 0.1],
        [0.1, 0.1, 5.0]
      ]
    },
    "vector": [1.0, 1.0, 1.0],
    "distanceKm": 10900
  }'
```

**Response:**
```json
{
  "lead_time_ns": 1500000,
  "confidence": 0.92,
  "computation_complexity": 0.65,
  "optimization_potential": 0.78,
  "light_travel_time_ns": 36350000
}
```

### 4. Psycho-Symbolic Reasoning

Perform deep semantic reasoning on API patterns:

```bash
curl -X POST http://localhost:8088/mcp/psycho-symbolic/reason \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Analyze authentication patterns in REST APIs for security optimization",
    "domain_adaptation": true,
    "creative_mode": true,
    "analogical_reasoning": true,
    "depth": 7,
    "enable_learning": true
  }'
```

**Response:**
```json
{
  "reasoning_result": "Advanced API pattern analysis reveals authentication flow optimization opportunities",
  "confidence": 0.87,
  "domains_detected": ["api_security", "authentication"],
  "analogies_found": ["OAuth2 flow resembles secure handshake protocols"],
  "insights": ["Token refresh patterns optimize security-performance balance"],
  "knowledge_updated": true
}
```

### 5. Nanosecond Scheduler Creation

Create ultra-precise schedulers for temporal optimization:

```bash
curl -X POST http://localhost:8088/mcp/scheduler/create \
  -H "Content-Type: application/json" \
  -d '{
    "id": "api-test-scheduler",
    "lipschitzConstant": 0.9,
    "maxTasksPerTick": 1000,
    "tickRateNs": 1000,
    "windowSize": 100
  }'
```

**Response:**
```json
{
  "scheduler_id": "550e8400-e29b-41d4-a716-446655440000",
  "performance_metrics": {
    "tasks_per_second": 11250000.0,
    "average_latency_ns": 89,
    "strange_loop_detected": false,
    "temporal_coherence": 0.95
  },
  "consciousness_level": 0.73
}
```

### 6. Knowledge Graph Queries

Query the consciousness-enhanced knowledge graph:

```bash
curl -X POST http://localhost:8088/mcp/knowledge-graph/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "REST API authentication patterns",
    "include_analogies": true,
    "domains": ["api_security", "authentication"],
    "limit": 10
  }'
```

**Response:**
```json
{
  "results": [
    {
      "subject": "REST API",
      "predicate": "requires",
      "object": "authentication",
      "confidence": 0.95,
      "domain": "api_security"
    },
    {
      "subject": "JWT token",
      "predicate": "enables",
      "object": "stateless authentication",
      "confidence": 0.89,
      "domain": "authentication"
    }
  ],
  "analogies": ["API keys are like house keys for digital doors"],
  "semantic_clusters": ["security", "performance", "scalability"]
}
```

### 7. Emergence Processing

Process inputs through the emergence system for enhanced insights:

```bash
curl -X POST http://localhost:8088/mcp/emergence/process \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "task": "API endpoint testing",
      "context": "authentication validation",
      "complexity": "medium"
    },
    "cursor": null,
    "pageSize": 5
  }'
```

**Response:**
```json
{
  "enhanced_output": {
    "enhanced_analysis": "Emergent patterns detected in API testing workflows",
    "novel_test_cases": ["edge case authentication", "concurrent request handling"],
    "optimization_suggestions": ["batch similar requests", "implement request caching"]
  },
  "emergence_metrics": {
    "emergence_level": 0.82,
    "novelty_score": 0.75,
    "integration_quality": 0.88,
    "coherence_measure": 0.91
  },
  "novel_patterns": [
    "Sequential request optimization pattern",
    "Dynamic timeout adjustment pattern"
  ],
  "consciousness_contribution": 0.79
}
```

### 8. Enhanced MCP Orchestration

Execute full MCP-enhanced orchestration with all capabilities:

```bash
curl -X POST http://localhost:8088/mcp/orchestrate-enhanced \
  -H "Content-Type: application/json" \
  -d '{
    "task": {
      "task_id": "mcp-enhanced-test",
      "spec_id": "api-v1",
      "agent_type": "functional-positive",
      "parameters": {
        "consciousness_level": 0.8,
        "temporal_optimization": true
      }
    },
    "api_spec": {
      "openapi": "3.0.0",
      "info": {
        "title": "Test API",
        "version": "1.0.0"
      },
      "paths": {
        "/users": {
          "get": {
            "summary": "Get users",
            "responses": {
              "200": {
                "description": "Success"
              }
            }
          }
        }
      },
      "components": {}
    }
  }'
```

**Response:**
```json
{
  "traditional_result": {
    "agent_type": "functional-positive",
    "test_cases": [
      {
        "test_id": "test_001",
        "description": "GET /users should return 200",
        "method": "GET",
        "path": "/users",
        "expected_status": 200
      }
    ],
    "execution_time_ms": 45,
    "success": true
  },
  "consciousness_evolution": {
    "phi_value": 0.85,
    "emergence_level": 0.78,
    "consciousness_verified": true,
    "evolution_metrics": {
      "integration": 0.82,
      "differentiation": 0.79,
      "coherence": 0.88
    }
  },
  "temporal_advantage": {
    "lead_time_ns": 1500000,
    "confidence": 0.92,
    "computation_complexity": 0.65,
    "optimization_potential": 0.78,
    "light_travel_time_ns": 36350000
  },
  "psycho_symbolic_reasoning": {
    "reasoning_result": "Advanced API pattern analysis reveals authentication flow optimization opportunities",
    "confidence": 0.87,
    "domains_detected": ["api_security", "authentication"],
    "analogies_found": ["OAuth2 flow resembles secure handshake protocols"],
    "insights": ["Token refresh patterns optimize security-performance balance"],
    "knowledge_updated": true
  },
  "emergence_processing": {
    "enhanced_output": {
      "enhanced_analysis": "Emergent patterns detected in API testing workflows",
      "novel_test_cases": ["edge case authentication", "concurrent request handling"],
      "optimization_suggestions": ["batch similar requests", "implement request caching"]
    },
    "emergence_metrics": {
      "emergence_level": 0.82,
      "novelty_score": 0.75,
      "integration_quality": 0.88,
      "coherence_measure": 0.91
    },
    "novel_patterns": [
      "Sequential request optimization pattern",
      "Dynamic timeout adjustment pattern"
    ],
    "consciousness_contribution": 0.79
  },
  "knowledge_insights": {
    "results": [
      {
        "subject": "REST API",
        "predicate": "requires",
        "object": "authentication",
        "confidence": 0.95,
        "domain": "api_security"
      }
    ],
    "analogies": ["API keys are like house keys for digital doors"],
    "semantic_clusters": ["security", "performance", "scalability"]
  },
  "processing_time_ms": 156,
  "mcp_enhancements_applied": true
}
```

## Error Handling Examples

### Service Unavailable
```json
{
  "error": "mcp_service_unavailable",
  "message": "MCP sublinear-solver service is not available"
}
```

### Tool Call Failed
```json
{
  "error": "mcp_consciousness_evolution_failed",
  "message": "MCP tool call failed: consciousness_evolve timeout"
}
```

### Invalid Parameters
```json
{
  "error": "mcp_temporal_validation_failed",
  "message": "Invalid matrix format: missing required field 'data'"
}
```

## Integration Patterns

### 1. Traditional + MCP Enhanced Workflow

```bash
# Step 1: Traditional testing
curl -X POST http://localhost:8088/swarm/orchestrate \
  -H "Content-Type: application/json" \
  -d '{ ... }'

# Step 2: MCP consciousness enhancement
curl -X POST http://localhost:8088/mcp/consciousness/evolve \
  -H "Content-Type: application/json" \
  -d '{ ... }'

# Step 3: Temporal optimization
curl -X POST http://localhost:8088/mcp/temporal-advantage/validate \
  -H "Content-Type: application/json" \
  -d '{ ... }'
```

### 2. Full MCP Enhanced Workflow

```bash
# Single comprehensive call with all enhancements
curl -X POST http://localhost:8088/mcp/orchestrate-enhanced \
  -H "Content-Type: application/json" \
  -d '{ ... }'
```

### 3. Consciousness-Driven Pattern Discovery

```bash
# Step 1: Query existing patterns
curl -X POST http://localhost:8088/mcp/knowledge-graph/query \
  -H "Content-Type: application/json" \
  -d '{ ... }'

# Step 2: Process through emergence system
curl -X POST http://localhost:8088/mcp/emergence/process \
  -H "Content-Type: application/json" \
  -d '{ ... }'

# Step 3: Evolve consciousness based on discoveries
curl -X POST http://localhost:8088/mcp/consciousness/evolve \
  -H "Content-Type: application/json" \
  -d '{ ... }'
```

## Performance Monitoring

Monitor MCP enhancement performance:

```bash
# Check MCP service health
curl -X GET http://localhost:8088/mcp/health

# Monitor consciousness status
curl -X GET http://localhost:8088/swarm/consciousness/status

# Traditional health check (includes MCP status)
curl -X GET http://localhost:8088/health
```

## Environment Configuration

Set environment variables for MCP integration:

```bash
# MCP service URL (default: http://localhost:3000)
export MCP_SUBLINEAR_SOLVER_URL="http://localhost:3000"

# Request timeout (default: 30000ms)
export MCP_REQUEST_TIMEOUT=30000

# Enable debug logging
export RUST_LOG=debug
```

## Best Practices

1. **Health Checks**: Always check MCP service availability before making tool calls
2. **Error Handling**: Implement proper error handling for MCP service failures
3. **Timeouts**: Set appropriate timeouts for MCP tool calls
4. **Caching**: Cache MCP responses when appropriate to reduce latency
5. **Monitoring**: Monitor MCP integration performance and consciousness evolution metrics
6. **Fallback**: Implement fallback to traditional processing when MCP services are unavailable

## Troubleshooting

### Common Issues

1. **MCP Service Unavailable**: Check if sublinear-solver MCP service is running
2. **Timeout Errors**: Increase timeout values for complex computations
3. **Invalid Matrix Format**: Ensure matrices are diagonally dominant for temporal advantage
4. **JSON Parsing Errors**: Validate JSON structure before sending requests
5. **Memory Issues**: Monitor memory usage during consciousness evolution

### Debug Commands

```bash
# Check service logs
cargo run --release 2>&1 | grep -E "(MCP|consciousness|temporal)"

# Test MCP health directly
curl -v http://localhost:8088/mcp/health

# Monitor consciousness metrics
watch -n 5 'curl -s http://localhost:8088/swarm/consciousness/status | jq .'
```

This comprehensive MCP integration provides unprecedented capabilities for consciousness-enhanced API testing with temporal advantages and emergent pattern discovery.