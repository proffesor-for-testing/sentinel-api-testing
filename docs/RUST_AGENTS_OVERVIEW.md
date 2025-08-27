# Sentinel Rust Agents - Complete Documentation

## Overview

The Sentinel platform implements high-performance testing agents in Rust, providing comprehensive API testing capabilities across functional, security, and performance domains. This document provides an overview and links to detailed documentation for each agent.

## Available Rust Agents

### 1. Functional Testing Agents

#### [Functional-Positive-Agent](./rust-functional-positive-agent-implementation.md)
- **Purpose**: Generate valid "happy path" test cases
- **Key Features**: 
  - Schema-based test generation
  - Realistic data generation
  - Parameter variation testing
  - Request body variations
- **Test Cases Generated**: Valid input scenarios with expected success responses

#### [Functional-Negative-Agent](./rust-functional-negative-agent-implementation.md)
- **Purpose**: Generate invalid input and boundary test cases
- **Key Features**:
  - Boundary Value Analysis (BVA)
  - Invalid data type testing
  - Missing required fields
  - Format violation testing
  - Edge cases and unusual inputs
- **Test Cases Generated**: 400-level error scenarios

#### [Functional-Stateful-Agent](./rust-functional-stateful-agent-implementation.md)
- **Purpose**: Generate complex multi-step workflow tests
- **Key Features**:
  - Semantic Operation Dependency Graph (SODG)
  - State management between operations
  - CRUD lifecycle testing
  - Parent-child resource relationships
  - Resource filtering patterns
- **Test Cases Generated**: Multi-step workflows with data dependencies

### 2. Security Testing Agents

#### [Security-Auth-Agent](./rust-security-auth-agent-implementation.md)
- **Purpose**: Test authentication and authorization vulnerabilities
- **Key Features**:
  - BOLA (Broken Object Level Authorization)
  - Function-level authorization
  - JWT vulnerabilities
  - Session management
  - Privilege escalation
- **Test Cases Generated**: Auth bypass and access control tests

#### [Security-Injection-Agent](./rust-security-injection-agent-implementation.md)
- **Purpose**: Test for injection vulnerabilities
- **Key Features**:
  - SQL Injection
  - NoSQL Injection
  - Command Injection
  - XML/XXE Injection
  - LDAP, XPath, Template Injection
  - Header Injection
  - Prompt Injection (LLM-specific)
- **Test Cases Generated**: Comprehensive injection attack vectors

### 3. Performance Testing Agents

#### [Performance-Planner-Agent](./rust-performance-planner-agent-implementation.md)
- **Purpose**: Generate performance test scripts
- **Key Features**:
  - k6 JavaScript script generation
  - JMeter test plan creation
  - Locust Python script generation
  - Load, stress, spike, and soak testing
  - Critical path detection
  - Data-intensive operation identification
- **Test Cases Generated**: Complete performance test scripts

### 4. Data Generation Agents

#### [Data-Mocking-Agent](./rust-data-mocking-agent-implementation.md)
- **Purpose**: Generate realistic test data
- **Key Features**:
  - Schema-aware data generation
  - Realistic value generation
  - Edge case data
  - Invalid data patterns
  - Locale-specific data
- **Test Cases Generated**: Mock data for all endpoints

## Architecture Overview

### Core Components

```rust
// Base Agent Trait
pub trait Agent: Send + Sync {
    fn agent_type(&self) -> &str;
    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult;
}

// Agent Orchestrator
pub struct AgentOrchestrator {
    agents: HashMap<String, Box<dyn Agent>>,
}
```

### Execution Flow

1. **Task Receipt**: Agent receives task via RabbitMQ or direct call
2. **API Analysis**: Parse OpenAPI specification
3. **Test Generation**: Create test cases based on agent specialization
4. **Result Packaging**: Return structured test cases with metadata
5. **Performance Metrics**: Include execution time and statistics

## Integration with Sentinel Platform

### Message Queue Integration
- **Queue**: `sentinel_task_queue`
- **Format**: JSON-serialized `OrchestrationRequest`
- **Durability**: Messages persist across restarts

### HTTP API Endpoints
- `GET /health` - Check service health and available agents
- `POST /swarm/orchestrate` - Execute agent tasks
- `GET /swarm/agents` - List available agents
- `POST /swarm/agents/{type}/execute` - Execute specific agent

### Hybrid Execution
- Rust agents execute when available for performance
- Python agents provide fallback and LLM integration
- Seamless switching based on availability

## Performance Characteristics

### Rust Agent Benefits
- **Memory Safety**: No garbage collection pauses
- **Concurrency**: Safe parallel execution
- **Speed**: 10-50x faster for compute-intensive operations
- **Resource Efficiency**: Lower memory footprint

### Benchmarks
```
Agent                        | Python (ms) | Rust (ms) | Speedup
-----------------------------|-------------|-----------|--------
Functional-Positive          | 450         | 25        | 18x
Functional-Negative          | 680         | 35        | 19x
Functional-Stateful          | 1200        | 65        | 18x
Security-Injection           | 890         | 42        | 21x
Performance-Planner          | 560         | 28        | 20x
```

## Development Guidelines

### Adding New Agents

1. **Create Agent Module**
```rust
// src/agents/new_agent.rs
pub struct NewAgent {
    base: BaseAgent,
}

#[async_trait]
impl Agent for NewAgent {
    fn agent_type(&self) -> &str {
        "New-Agent"
    }
    
    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        // Implementation
    }
}
```

2. **Register in Orchestrator**
```rust
// src/agents/mod.rs
agents.insert(
    "New-Agent".to_string(),
    Box::new(new_agent::NewAgent::new()),
);
```

3. **Add Tests**
```rust
// tests/new_agent_test.rs
#[tokio::test]
async fn test_new_agent() {
    // Test implementation
}
```

## Testing

### Unit Tests
```bash
cd sentinel_rust_core
cargo test
```

### Integration Tests
```bash
cargo test --test '*'
```

### Performance Tests
```bash
cargo bench
```

## Deployment

### Development
```bash
cargo run
```

### Production
```bash
cargo build --release
./target/release/sentinel-rust-core
```

### Docker
```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/sentinel-rust-core /usr/local/bin/
CMD ["sentinel-rust-core"]
```

## Configuration

### Environment Variables
- `AMQP_ADDR` - RabbitMQ connection string
- `RUST_LOG` - Logging level (debug, info, warn, error)
- `PORT` - HTTP server port (default: 8088)

### Performance Tuning
- `TOKIO_WORKER_THREADS` - Async runtime threads
- `RUST_BACKTRACE` - Enable backtraces (1 or full)

## Monitoring

### Health Check
```bash
curl http://localhost:8088/health
```

### Metrics
- Processing time per agent
- Test cases generated per specification
- Memory usage and CPU utilization
- Queue depth and processing rate

## Troubleshooting

### Common Issues

1. **Agent Not Found**
   - Verify agent is registered in orchestrator
   - Check agent name spelling (case-sensitive)

2. **RabbitMQ Connection Failed**
   - Verify RabbitMQ is running
   - Check AMQP_ADDR environment variable

3. **Memory Issues**
   - Increase heap size for large API specs
   - Consider batching for many endpoints

## Future Roadmap

### Planned Enhancements
1. **WebAssembly Compilation** - Browser-based execution
2. **GPU Acceleration** - Parallel test generation
3. **Distributed Execution** - Multi-node agent clusters
4. **Smart Caching** - Reuse test patterns
5. **ML-Powered Generation** - Learn from test results
6. **Custom Agent Plugins** - Extensible architecture

## Contributing

### Code Style
- Follow Rust standard formatting (`cargo fmt`)
- Use clippy for linting (`cargo clippy`)
- Write comprehensive tests
- Document public APIs

### Pull Request Process
1. Fork the repository
2. Create feature branch
3. Implement with tests
4. Update documentation
5. Submit PR with description

## License

See LICENSE file in repository root.

## Support

For questions and issues:
- GitHub Issues: [sentinel/issues](https://github.com/sentinel/issues)
- Documentation: This directory
- API Reference: Generated with `cargo doc`

---

*Last Updated: December 2024*
*Version: 1.0.0*