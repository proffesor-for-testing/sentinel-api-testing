#!/usr/bin/env python3
"""
Example demonstrating how to use the Performance Agent to execute performance tests.

This script shows how to:
1. Generate performance test cases using the Performance Agent
2. Execute a simple performance test
3. Analyze the results
"""

import asyncio
import json
import time
from performance_agent import PerformanceAgent, PerformanceMetrics
from .base_agent import AgentTask
from datetime import datetime


async def simulate_api_endpoint(delay_ms: float = 100) -> dict:
    """Simulate an API endpoint with configurable delay."""
    await asyncio.sleep(delay_ms / 1000)  # Convert ms to seconds
    return {"status": "success", "timestamp": datetime.now().isoformat()}


async def run_simple_performance_test():
    """Demonstrate a simple performance test execution."""
    agent = PerformanceAgent()

    print("🚀 Performance Agent Demo")
    print("=" * 50)

    # Sample API specification
    sample_api_spec = {
        'openapi': '3.0.0',
        'info': {'title': 'Demo API', 'version': '1.0.0'},
        'paths': {
            '/health': {
                'get': {
                    'summary': 'Health check endpoint',
                    'description': 'Returns the health status of the service',
                    'responses': {'200': {'description': 'Service is healthy'}}
                }
            },
            '/users': {
                'get': {
                    'summary': 'List users',
                    'description': 'Returns a list of users',
                    'responses': {'200': {'description': 'Success'}}
                },
                'post': {
                    'summary': 'Create user',
                    'description': 'Creates a new user',
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'username': {'type': 'string'},
                                        'email': {'type': 'string', 'format': 'email'}
                                    },
                                    'required': ['username', 'email']
                                }
                            }
                        }
                    },
                    'responses': {'201': {'description': 'User created'}}
                }
            }
        }
    }

    # Step 1: Generate test cases
    print("📋 Step 1: Generating Performance Test Cases")

    task = AgentTask(
        task_id='demo-performance-001',
        spec_id=1,
        agent_type='performance',
        parameters={
            'test_types': ['response_time', 'load_test', 'volume_test']
        }
    )

    result = await agent.execute(task, sample_api_spec)

    print(f"✅ Generated {len(result.test_cases)} test cases")
    print(f"📊 Test types: {', '.join(result.metadata['test_types_generated'])}")
    print(f"🎯 Endpoints analyzed: {result.metadata['endpoints_analyzed']}")

    # Step 2: Show example test cases
    print("\n📝 Step 2: Example Generated Test Cases")

    for i, test_case in enumerate(result.test_cases[:5]):  # Show first 5
        print(f"\nTest Case {i+1}:")
        print(f"  🔍 Type: {test_case.get('test_type')}")
        print(f"  🌐 Endpoint: {test_case.get('method')} {test_case.get('endpoint')}")
        print(f"  📄 Description: {test_case.get('description')}")

        config = test_case.get('performance_config', {})
        if 'concurrent_users' in config:
            print(f"  👥 Users: {config.get('concurrent_users')}")
        if 'duration_seconds' in config:
            print(f"  ⏱️  Duration: {config.get('duration_seconds')}s")
        if 'iterations' in config:
            print(f"  🔄 Iterations: {config.get('iterations')}")

    # Step 3: Simulate executing a response time test
    print("\n⚡ Step 3: Simulating Response Time Test Execution")

    response_time_test = None
    for test_case in result.test_cases:
        if test_case.get('test_type') == 'response_time':
            response_time_test = test_case
            break

    if response_time_test:
        print(f"🧪 Testing: {response_time_test.get('method')} {response_time_test.get('endpoint')}")

        # Simulate the test execution
        config = response_time_test.get('performance_config', {})
        iterations = config.get('iterations', 10)

        response_times = []
        print(f"🔄 Running {iterations} iterations...")

        for i in range(iterations):
            start_time = time.time()
            await simulate_api_endpoint(delay_ms=50 + (i * 10))  # Gradual increase in delay
            end_time = time.time()

            response_time_ms = (end_time - start_time) * 1000
            response_times.append(response_time_ms)

            if i % 3 == 0:  # Show progress every 3 iterations
                print(f"  ⏱️  Iteration {i+1}: {response_time_ms:.2f}ms")

        # Analyze results
        avg_response_time = sum(response_times) / len(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)

        print(f"\n📈 Results Summary:")
        print(f"  📊 Average Response Time: {avg_response_time:.2f}ms")
        print(f"  🚀 Fastest Response: {min_response_time:.2f}ms")
        print(f"  🐌 Slowest Response: {max_response_time:.2f}ms")

        # Check against thresholds
        threshold = response_time_test.get('performance_thresholds', {}).get('avg_response_time_ms', 1000)

        if avg_response_time <= threshold:
            print(f"  ✅ PASSED: Average response time ({avg_response_time:.2f}ms) is within threshold ({threshold}ms)")
        else:
            print(f"  ❌ FAILED: Average response time ({avg_response_time:.2f}ms) exceeds threshold ({threshold}ms)")

    # Step 4: Show load testing capabilities
    print("\n🔥 Step 4: Load Testing Capabilities")

    load_test = None
    for test_case in result.test_cases:
        if test_case.get('test_type') == 'load_test':
            load_test = test_case
            break

    if load_test:
        config = load_test.get('performance_config', {})
        print(f"🏋️  Load Test Configuration:")
        print(f"  👥 Concurrent Users: {config.get('concurrent_users', 'N/A')}")
        print(f"  ⏱️  Duration: {config.get('duration_seconds', 'N/A')}s")
        print(f"  📈 Ramp-up Time: {config.get('ramp_up_seconds', 'N/A')}s")
        print(f"  🤔 Think Time: {config.get('think_time', 'N/A')}s")

        assertions = load_test.get('assertions', [])
        if assertions:
            print(f"  🎯 Assertions:")
            for assertion in assertions:
                print(f"    - {assertion.get('description', 'No description')}")

    # Step 5: Show all test types available
    print("\n🛠️  Step 5: Available Performance Test Types")

    test_types = [
        ("response_time", "🕐", "Baseline response time measurement"),
        ("load_test", "🏋️", "Concurrent user simulation"),
        ("stress_test", "💥", "System breaking point identification"),
        ("spike_test", "⚡", "Sudden load increase handling"),
        ("volume_test", "📦", "Large payload processing"),
        ("endurance_test", "🏃‍♂️", "Sustained load over time"),
        ("scalability_test", "📈", "Performance at different scales"),
        ("rate_limiting", "🚧", "Rate limit enforcement"),
        ("caching", "💾", "Cache effectiveness testing"),
        ("database_performance", "🗄️", "N+1 query detection"),
        ("memory_leak", "🧠", "Memory usage pattern analysis"),
        ("connection_pool", "🔗", "Connection limit validation"),
        ("timeout_test", "⏰", "Slow response handling"),
        ("pagination_performance", "📄", "Large dataset pagination"),
        ("search_performance", "🔍", "Complex query optimization")
    ]

    print("The Performance Agent supports the following test types:")
    for test_type, icon, description in test_types:
        print(f"  {icon} {test_type}: {description}")

    print("\n🎉 Performance Agent Demo Complete!")
    print("=" * 50)
    print("💡 Tip: Use different test_types in the task parameters to generate")
    print("   specific types of performance tests for your API endpoints.")


if __name__ == "__main__":
    asyncio.run(run_simple_performance_test())