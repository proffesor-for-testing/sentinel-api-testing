# Performance Agent

The Performance Agent is a comprehensive testing agent designed to execute various types of performance tests on API endpoints to identify bottlenecks, validate SLAs, and ensure optimal system performance under different load conditions.

## Features

### 🧪 Test Types Supported

1. **Response Time Testing** - Baseline response time measurement
2. **Load Testing** - Concurrent user simulation with configurable patterns
3. **Stress Testing** - System breaking point identification
4. **Spike Testing** - Sudden load increase handling
5. **Volume Testing** - Large payload processing
6. **Endurance Testing** - Sustained load over time (up to 30 minutes)
7. **Scalability Testing** - Performance at different scales
8. **Rate Limiting Validation** - Rate limit enforcement testing
9. **Caching Behavior** - Cache effectiveness testing
10. **Database Query Performance** - N+1 query detection
11. **Memory Leak Detection** - Memory usage pattern analysis
12. **Connection Pool Testing** - Connection limit validation
13. **Timeout Testing** - Slow response handling
14. **Pagination Performance** - Large dataset pagination testing
15. **Search Performance** - Complex query optimization testing

### 🔧 Key Capabilities

- **Configurable Load Patterns**: Pre-defined patterns from baseline to stress testing
- **Resource Monitoring**: Optional system resource monitoring (when psutil is available)
- **Performance Metrics Collection**: Comprehensive metrics including response times, throughput, error rates
- **Threshold Validation**: Configurable performance thresholds for pass/fail criteria
- **Concurrent Execution**: Asynchronous execution for realistic load simulation
- **LLM Enhancement**: Optional LLM-powered test case enhancement for more realistic scenarios

## Quick Start

### Basic Usage

```python
from performance_agent import PerformanceAgent
from base_agent import AgentTask

# Create the agent
agent = PerformanceAgent()

# Define a task
task = AgentTask(
    task_id='perf-test-001',
    spec_id=1,
    agent_type='performance',
    parameters={
        'test_types': ['response_time', 'load_test', 'stress_test']
    }
)

# Execute against your API spec
result = await agent.execute(task, api_spec)

print(f"Generated {len(result.test_cases)} test cases")
```

### Running the Demo

```bash
cd /workspaces/api-testing-agents/sentinel_backend/orchestration_service/agents
python3 performance_test_example.py
```

## Configuration

### Environment Settings

The agent respects these configuration settings (with fallbacks):

```python
# Performance test settings
performance_default_users = 10          # Default concurrent users
performance_max_users = 1000           # Maximum concurrent users
performance_test_duration = 60         # Default test duration (seconds)
performance_ramp_up_time = 30          # Default ramp-up time (seconds)
performance_think_time = 1             # Default think time between requests
performance_timeout = 30               # Request timeout (seconds)

# Performance thresholds
performance_response_threshold = 1000   # Response time threshold (ms)
performance_throughput_threshold = 100  # Throughput threshold (RPS)
performance_error_threshold = 5.0      # Error rate threshold (%)
```

### Load Patterns

The agent includes pre-configured load patterns:

| Pattern | Users | Duration | Ramp-up | Think Time | Use Case |
|---------|-------|----------|---------|------------|----------|
| baseline | 1 | 30s | 5s | 1.0s | Single user baseline |
| light_load | 5 | 60s | 10s | 1.0s | Light concurrent load |
| normal_load | 10 | 120s | 20s | 1.0s | Normal production load |
| heavy_load | 25 | 180s | 30s | 0.5s | Heavy production load |
| stress_test | 50 | 300s | 60s | 0.2s | Stress testing |
| spike_test | 100 | 60s | 5s | 0.1s | Spike testing |
| endurance_test | 10 | 1800s | 30s | 2.0s | Long-term stability |

## Test Case Structure

Generated test cases follow this structure:

```json
{
  "test_type": "load_test",
  "endpoint": "/api/users",
  "method": "GET",
  "description": "Load test (normal_load) for GET /api/users",
  "performance_config": {
    "concurrent_users": 10,
    "duration_seconds": 120,
    "ramp_up_seconds": 20,
    "think_time": 1.0,
    "timeout": 30
  },
  "headers": {"Content-Type": "application/json"},
  "assertions": [
    {
      "type": "throughput",
      "condition": "greater_than",
      "value": 100,
      "description": "Throughput should exceed 100 requests/second"
    }
  ],
  "performance_thresholds": {
    "avg_response_time_ms": 2000,
    "p95_response_time_ms": 3000,
    "throughput_rps": 100,
    "success_rate_percent": 95.0,
    "error_rate_percent": 5.0
  }
}
```

## Performance Metrics

The agent collects comprehensive metrics:

```python
@dataclass
class PerformanceMetrics:
    response_times: List[float]          # All response times (ms)
    status_codes: Dict[int, int]         # Status code distribution
    errors: List[str]                    # Error messages
    throughput: float                    # Requests per second
    total_requests: int                  # Total requests made
    successful_requests: int             # Successful requests
    failed_requests: int                 # Failed requests
    start_time: datetime                 # Test start time
    end_time: datetime                   # Test end time
    peak_memory_mb: float               # Peak memory usage
    avg_cpu_percent: float              # Average CPU usage

    # Calculated properties
    @property
    def avg_response_time(self) -> float
    @property
    def p95_response_time(self) -> float
    @property
    def p99_response_time(self) -> float
    @property
    def success_rate(self) -> float
```

## Advanced Features

### Resource Monitoring

When `psutil` is available, the agent monitors:
- Memory usage patterns
- CPU utilization
- Peak resource consumption
- Resource efficiency metrics

### Concurrent Execution

The agent uses asyncio for realistic concurrent load simulation:

```python
async def _execute_load_test(self, test_case, base_url, config):
    concurrent_users = config.get("concurrent_users", 10)
    semaphore = asyncio.Semaphore(concurrent_users)

    async def user_session():
        async with semaphore:
            # Execute user session
            pass

    # Ramp up users gradually
    tasks = []
    for i in range(concurrent_users):
        await asyncio.sleep(ramp_up_seconds / concurrent_users)
        task = asyncio.create_task(user_session())
        tasks.append(task)

    await asyncio.gather(*tasks)
```

### LLM Enhancement

When LLM providers are configured, the agent can enhance test cases:

```python
enhanced_cases = await self._enhance_test_cases_with_llm(test_cases, api_spec)
```

## Test Type Details

### Response Time Testing
- Single user baseline measurements
- 10 iterations per endpoint
- Validates against response time thresholds
- Establishes performance baseline

### Load Testing
- Multiple load patterns (1-100 users)
- Gradual ramp-up to simulate realistic traffic
- Throughput and error rate validation
- Configurable test duration

### Stress Testing
- Progressive load increase (50-1000 users)
- Breaking point identification
- System stability monitoring
- Resource exhaustion detection

### Spike Testing
- Sudden load increase simulation
- Recovery time measurement
- System resilience validation
- Three-phase testing (baseline → spike → recovery)

### Volume Testing
- Large payload processing (1KB - 1MB)
- Memory usage monitoring
- Payload handling validation
- Performance impact assessment

### Endurance Testing
- Long-term stability testing (30 minutes - 1 hour)
- Memory leak detection
- Performance degradation monitoring
- Sustained load validation

### Rate Limiting Testing
- High request rate simulation
- Rate limit enforcement validation
- 429 response code verification
- Rate limit header validation

### Caching Testing
- Cache hit ratio measurement
- Cache effectiveness validation
- Response time comparison (cached vs uncached)
- Cache header verification

### Database Performance Testing
- N+1 query detection
- Query count optimization
- Database connection efficiency
- Query execution time monitoring

### Pagination Testing
- Large dataset pagination
- Page size impact analysis
- Pagination consistency validation
- Memory efficiency per item

## Best Practices

### Test Configuration

1. **Start Small**: Begin with baseline tests before scaling up
2. **Gradual Ramp-up**: Use appropriate ramp-up times to avoid overwhelming the system
3. **Think Time**: Include realistic think time between requests
4. **Timeout Management**: Set appropriate timeouts for different test types

### Performance Thresholds

1. **Response Time**: Set realistic thresholds based on user expectations
2. **Throughput**: Define minimum acceptable requests per second
3. **Error Rate**: Keep error rate thresholds low (< 5%)
4. **Success Rate**: Maintain high success rates (> 95%)

### Resource Management

1. **Memory Monitoring**: Watch for memory leaks during endurance tests
2. **Connection Limits**: Test connection pool behavior
3. **CPU Usage**: Monitor CPU efficiency during high-load tests
4. **Cleanup**: Ensure proper cleanup after test completion

## Dependencies

### Required
- `aiohttp`: Async HTTP client for concurrent requests
- `asyncio`: Async execution framework
- Base dependencies from parent project

### Optional
- `psutil`: System resource monitoring (fallback available)
- LLM providers: For enhanced test case generation

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed
2. **Resource Monitoring**: Install `psutil` for full resource monitoring
3. **Timeout Errors**: Increase timeout values for slow endpoints
4. **Memory Issues**: Reduce concurrent users for resource-constrained environments

### Performance Optimization

1. **Async Execution**: Leverages asyncio for efficient concurrent execution
2. **Memory Management**: Includes garbage collection and weak references
3. **Resource Monitoring**: Optional lightweight monitoring
4. **Batched Operations**: Efficient metric collection and aggregation

## Integration

### With Sentinel Platform

The Performance Agent integrates seamlessly with the Sentinel platform:

```python
# Register the agent
from orchestration_service.agents import PerformanceAgent

# Agent is automatically available for task execution
```

### With Test Runners

Generated test cases can be executed by various test runners:
- Sentinel's built-in execution engine
- External tools like k6, JMeter, or artillery
- Custom test execution frameworks

## Future Enhancements

- **Real-time Metrics**: WebSocket-based real-time metric streaming
- **Advanced Analytics**: Statistical analysis and trend detection
- **Auto-scaling**: Automatic test scaling based on system performance
- **Custom Patterns**: User-defined load patterns
- **Integration Tests**: Cross-service performance testing
- **Cloud Metrics**: Integration with cloud monitoring services

## Contributing

When extending the Performance Agent:

1. Follow the existing test case structure
2. Add appropriate assertions and thresholds
3. Include comprehensive error handling
4. Add resource cleanup
5. Update documentation

## Example Output

```
🚀 Performance Agent Demo
==================================================
📋 Step 1: Generating Performance Test Cases
✅ Generated 19 test cases
📊 Test types: response_time, load_test, volume_test
🎯 Endpoints analyzed: 3

📈 Results Summary:
  📊 Average Response Time: 96.30ms
  🚀 Fastest Response: 51.32ms
  🐌 Slowest Response: 141.48ms
  ✅ PASSED: Average response time (96.30ms) is within threshold (1000ms)
```

The Performance Agent provides comprehensive performance testing capabilities essential for validating API performance, identifying bottlenecks, and ensuring optimal system behavior under various load conditions.