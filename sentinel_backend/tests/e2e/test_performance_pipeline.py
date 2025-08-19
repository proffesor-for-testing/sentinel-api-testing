"""
End-to-End test for performance testing pipeline.
Tests load generation, performance metrics, and scalability testing.
"""

import pytest
import asyncio
import json
from typing import Dict, Any, List
from unittest.mock import Mock, patch, AsyncMock
import aiohttp
from datetime import datetime, timedelta
import random
import statistics

# Service URLs
ORCHESTRATION_URL = "http://localhost:8002"
EXECUTION_URL = "http://localhost:8003"
AUTH_SERVICE_URL = "http://localhost:8005"
SPEC_SERVICE_URL = "http://localhost:8001"
DATA_SERVICE_URL = "http://localhost:8004"
PERFORMANCE_URL = "http://localhost:8006"  # Hypothetical performance service


class TestPerformancePipeline:
    """E2E tests for performance testing pipeline."""
    
    @pytest.fixture
    async def auth_headers(self):
        """Get authentication headers."""
        return {"Authorization": "Bearer mock-token-for-testing"}
    
    @pytest.fixture
    def high_traffic_api_spec(self) -> Dict[str, Any]:
        """API spec for high-traffic performance testing."""
        return {
            "openapi": "3.0.0",
            "info": {
                "title": "High Traffic API",
                "version": "1.0.0",
                "description": "API designed for high-traffic performance testing"
            },
            "servers": [
                {"url": "https://perf.api.com/v1"}
            ],
            "paths": {
                "/health": {
                    "get": {
                        "summary": "Health check endpoint",
                        "responses": {
                            "200": {"description": "Service healthy"}
                        }
                    }
                },
                "/products": {
                    "get": {
                        "summary": "List products with caching",
                        "parameters": [
                            {"name": "page", "in": "query", "schema": {"type": "integer"}},
                            {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 100}},
                            {"name": "category", "in": "query", "schema": {"type": "string"}},
                            {"name": "sort", "in": "query", "schema": {"type": "string", "enum": ["price", "name", "rating"]}}
                        ],
                        "responses": {
                            "200": {
                                "description": "Product list",
                                "headers": {
                                    "X-Cache": {"schema": {"type": "string"}},
                                    "X-Response-Time": {"schema": {"type": "string"}}
                                }
                            }
                        }
                    }
                },
                "/products/{id}": {
                    "get": {
                        "summary": "Get product by ID",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {"description": "Product details"},
                            "404": {"description": "Product not found"}
                        }
                    }
                },
                "/orders": {
                    "post": {
                        "summary": "Create order (write-heavy)",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "products": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {"type": "string"},
                                                        "quantity": {"type": "integer"}
                                                    }
                                                }
                                            },
                                            "customer_id": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "201": {"description": "Order created"},
                            "400": {"description": "Invalid order"},
                            "503": {"description": "Service overloaded"}
                        }
                    }
                },
                "/search": {
                    "get": {
                        "summary": "Search endpoint (CPU intensive)",
                        "parameters": [
                            {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}},
                            {"name": "filters", "in": "query", "schema": {"type": "string"}}
                        ],
                        "responses": {
                            "200": {"description": "Search results"}
                        }
                    }
                },
                "/analytics/events": {
                    "post": {
                        "summary": "Analytics event tracking (high volume)",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "event": {"type": "string"},
                                            "properties": {"type": "object"},
                                            "timestamp": {"type": "string", "format": "date-time"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "202": {"description": "Event accepted"},
                            "429": {"description": "Rate limit exceeded"}
                        }
                    }
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_load_test_generation(self, auth_headers, high_traffic_api_spec):
        """Test generation of load testing scenarios."""
        async with aiohttp.ClientSession() as session:
            # Upload performance-oriented specification
            spec_data = {
                "name": "Performance Test API",
                "description": "API for performance testing",
                "content": json.dumps(high_traffic_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id", "mock-spec-id")
            
            # Create performance test run
            test_run_data = {
                "name": "Load Test Generation",
                "spec_id": spec_id,
                "agents": ["performance-planner"],
                "configuration": {
                    "test_type": "load",
                    "performance_config": {
                        "target_rps": 1000,  # Requests per second
                        "duration_minutes": 10,
                        "ramp_up_time": 60,  # seconds
                        "concurrent_users": 100,
                        "think_time": 2,  # seconds between requests
                        "scenarios": [
                            {
                                "name": "Browse Products",
                                "weight": 40,  # 40% of traffic
                                "steps": ["GET /products", "GET /products/{id}"]
                            },
                            {
                                "name": "Search and Order",
                                "weight": 30,
                                "steps": ["GET /search", "POST /orders"]
                            },
                            {
                                "name": "Analytics Heavy",
                                "weight": 30,
                                "steps": ["POST /analytics/events"]
                            }
                        ]
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Wait for performance test generation
            await asyncio.sleep(5)
            
            # Retrieve generated performance tests
            async with session.get(
                f"{ORCHESTRATION_URL}/api/test-runs/{test_run_id}/performance-tests",
                headers=auth_headers
            ) as response:
                assert response.status == 200
                perf_tests = await response.json()
                
                # Should generate k6 or JMeter scripts
                assert "test_scripts" in perf_tests
                scripts = perf_tests["test_scripts"]
                
                # Verify script configuration
                for script in scripts:
                    assert "type" in script  # k6, jmeter, gatling
                    assert "content" in script
                    assert "scenario" in script
                    
                    # Check if script contains performance parameters
                    content = script["content"]
                    assert "1000" in content or "target" in content  # RPS target
                    assert "100" in content or "vus" in content  # Virtual users
                
                # Should have test data generation
                assert "test_data" in perf_tests
                test_data = perf_tests["test_data"]
                
                # Should generate realistic test data
                assert "product_ids" in test_data
                assert "customer_ids" in test_data
                assert "search_queries" in test_data
                
                # Verify data volume for load testing
                assert len(test_data["product_ids"]) >= 100
                assert len(test_data["search_queries"]) >= 50
    
    @pytest.mark.asyncio
    async def test_stress_test_execution(self, auth_headers, high_traffic_api_spec):
        """Test stress testing to find breaking points."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Stress Test API",
                "description": "API for stress testing",
                "content": json.dumps(high_traffic_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create stress test configuration
            test_run_data = {
                "name": "Stress Test Execution",
                "spec_id": spec_id,
                "agents": ["performance-planner"],
                "configuration": {
                    "test_type": "stress",
                    "performance_config": {
                        "initial_users": 10,
                        "max_users": 1000,
                        "user_increment": 50,
                        "increment_interval": 30,  # seconds
                        "error_threshold": 5,  # % errors to stop
                        "response_time_threshold": 5000,  # ms
                        "endpoints_to_stress": [
                            "/orders",  # Write-heavy
                            "/search",  # CPU-intensive
                            "/analytics/events"  # High-volume
                        ]
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Start stress test execution
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "stress",
                "target_url": "https://perf.api.com/v1"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/performance/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Monitor stress test progress
                    max_duration = 120  # seconds
                    start_time = datetime.utcnow()
                    breaking_point_found = False
                    
                    while (datetime.utcnow() - start_time).seconds < max_duration:
                        async with session.get(
                            f"{EXECUTION_URL}/api/performance/{execution_id}/metrics",
                            headers=auth_headers
                        ) as metrics_response:
                            if metrics_response.status == 200:
                                metrics = await metrics_response.json()
                                
                                # Check current metrics
                                current_users = metrics.get("current_users", 0)
                                error_rate = metrics.get("error_rate", 0)
                                avg_response_time = metrics.get("avg_response_time", 0)
                                
                                # Check if breaking point reached
                                if error_rate > 5 or avg_response_time > 5000:
                                    breaking_point_found = True
                                    
                                    # Record breaking point
                                    breaking_point = {
                                        "users": current_users,
                                        "error_rate": error_rate,
                                        "response_time": avg_response_time,
                                        "timestamp": datetime.utcnow().isoformat()
                                    }
                                    
                                    # Save breaking point data
                                    async with session.post(
                                        f"{DATA_SERVICE_URL}/api/performance/breaking-points",
                                        json={
                                            "test_run_id": test_run_id,
                                            "breaking_point": breaking_point
                                        },
                                        headers=auth_headers
                                    ) as bp_response:
                                        assert bp_response.status in [200, 201]
                                    
                                    break
                        
                        await asyncio.sleep(5)
                    
                    # Verify stress test results
                    async with session.get(
                        f"{EXECUTION_URL}/api/performance/{execution_id}/results",
                        headers=auth_headers
                    ) as results_response:
                        if results_response.status == 200:
                            results = await results_response.json()
                            
                            # Should have stress test metrics
                            assert "max_users_tested" in results
                            assert "breaking_point" in results or breaking_point_found
                            assert "bottlenecks" in results
    
    @pytest.mark.asyncio
    async def test_spike_test_scenario(self, auth_headers, high_traffic_api_spec):
        """Test sudden spike in traffic handling."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Spike Test API",
                "description": "API for spike testing",
                "content": json.dumps(high_traffic_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create spike test configuration
            test_run_data = {
                "name": "Spike Test",
                "spec_id": spec_id,
                "agents": ["performance-planner"],
                "configuration": {
                    "test_type": "spike",
                    "performance_config": {
                        "baseline_users": 50,
                        "spike_users": 500,
                        "spike_duration": 60,  # seconds
                        "recovery_time": 120,  # seconds after spike
                        "spike_scenarios": [
                            {
                                "name": "Flash Sale",
                                "trigger_time": 30,  # seconds after start
                                "endpoints": ["/products", "/orders"],
                                "user_behavior": "aggressive"  # No think time
                            }
                        ]
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Execute spike test
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "spike"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/performance/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Monitor spike test
                    spike_metrics = {
                        "pre_spike": {},
                        "during_spike": {},
                        "post_spike": {}
                    }
                    
                    # Collect pre-spike metrics
                    await asyncio.sleep(20)
                    async with session.get(
                        f"{EXECUTION_URL}/api/performance/{execution_id}/metrics",
                        headers=auth_headers
                    ) as response:
                        if response.status == 200:
                            spike_metrics["pre_spike"] = await response.json()
                    
                    # Wait for spike
                    await asyncio.sleep(40)
                    async with session.get(
                        f"{EXECUTION_URL}/api/performance/{execution_id}/metrics",
                        headers=auth_headers
                    ) as response:
                        if response.status == 200:
                            spike_metrics["during_spike"] = await response.json()
                    
                    # Wait for recovery
                    await asyncio.sleep(60)
                    async with session.get(
                        f"{EXECUTION_URL}/api/performance/{execution_id}/metrics",
                        headers=auth_headers
                    ) as response:
                        if response.status == 200:
                            spike_metrics["post_spike"] = await response.json()
                    
                    # Analyze spike impact
                    pre_response_time = spike_metrics["pre_spike"].get("avg_response_time", 0)
                    spike_response_time = spike_metrics["during_spike"].get("avg_response_time", 0)
                    post_response_time = spike_metrics["post_spike"].get("avg_response_time", 0)
                    
                    # Response time should spike and recover
                    if pre_response_time > 0:
                        assert spike_response_time > pre_response_time * 1.5  # At least 50% increase
                        # Should recover somewhat after spike
                        assert post_response_time < spike_response_time * 0.8
    
    @pytest.mark.asyncio
    async def test_endurance_test(self, auth_headers, high_traffic_api_spec):
        """Test system endurance over extended period."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Endurance Test API",
                "description": "API for endurance testing",
                "content": json.dumps(high_traffic_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create endurance test (soak test)
            test_run_data = {
                "name": "Endurance Test",
                "spec_id": spec_id,
                "agents": ["performance-planner"],
                "configuration": {
                    "test_type": "endurance",
                    "performance_config": {
                        "duration_hours": 2,  # Shortened for testing
                        "constant_users": 100,
                        "target_rps": 500,
                        "memory_leak_detection": True,
                        "resource_monitoring": {
                            "cpu": True,
                            "memory": True,
                            "disk_io": True,
                            "network": True
                        },
                        "alert_thresholds": {
                            "memory_growth_rate": 10,  # MB per hour
                            "error_rate": 1,  # %
                            "response_time_degradation": 20  # %
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Start endurance test
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "endurance"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/performance/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Monitor for performance degradation
                    samples = []
                    memory_samples = []
                    
                    # Collect samples over time (shortened for testing)
                    for i in range(6):  # 6 samples
                        await asyncio.sleep(10)  # Every 10 seconds
                        
                        async with session.get(
                            f"{EXECUTION_URL}/api/performance/{execution_id}/metrics",
                            headers=auth_headers
                        ) as response:
                            if response.status == 200:
                                metrics = await response.json()
                                samples.append(metrics)
                                
                                if "memory_usage" in metrics:
                                    memory_samples.append(metrics["memory_usage"])
                    
                    # Analyze for degradation
                    if len(samples) >= 2:
                        # Check for response time degradation
                        early_response_time = samples[0].get("avg_response_time", 0)
                        late_response_time = samples[-1].get("avg_response_time", 0)
                        
                        if early_response_time > 0:
                            degradation = ((late_response_time - early_response_time) / early_response_time) * 100
                            
                            # Log degradation for analysis
                            print(f"Response time degradation: {degradation:.2f}%")
                        
                        # Check for memory leaks
                        if len(memory_samples) >= 2:
                            memory_growth = memory_samples[-1] - memory_samples[0]
                            
                            # Log memory growth
                            print(f"Memory growth: {memory_growth} MB")
    
    @pytest.mark.asyncio
    async def test_scalability_test(self, auth_headers, high_traffic_api_spec):
        """Test API scalability with increasing load."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Scalability Test API",
                "description": "API for scalability testing",
                "content": json.dumps(high_traffic_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create scalability test
            test_run_data = {
                "name": "Scalability Test",
                "spec_id": spec_id,
                "agents": ["performance-planner"],
                "configuration": {
                    "test_type": "scalability",
                    "performance_config": {
                        "test_stages": [
                            {"users": 10, "duration": 60},
                            {"users": 50, "duration": 60},
                            {"users": 100, "duration": 60},
                            {"users": 200, "duration": 60},
                            {"users": 500, "duration": 60}
                        ],
                        "metrics_to_track": [
                            "throughput",
                            "response_time",
                            "error_rate",
                            "cpu_utilization",
                            "memory_usage"
                        ],
                        "scalability_goals": {
                            "linear_throughput": True,  # Throughput should scale linearly
                            "stable_response_time": 500,  # ms - should stay under this
                            "error_threshold": 1  # % - should stay under this
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Execute scalability test
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "scalability"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/performance/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Collect metrics for each stage
                    stage_metrics = []
                    
                    for stage in range(5):  # 5 stages
                        await asyncio.sleep(30)  # Sample during each stage
                        
                        async with session.get(
                            f"{EXECUTION_URL}/api/performance/{execution_id}/metrics",
                            headers=auth_headers
                        ) as response:
                            if response.status == 200:
                                metrics = await response.json()
                                stage_metrics.append(metrics)
                    
                    # Analyze scalability
                    if len(stage_metrics) >= 3:
                        throughputs = [m.get("throughput", 0) for m in stage_metrics]
                        response_times = [m.get("avg_response_time", 0) for m in stage_metrics]
                        error_rates = [m.get("error_rate", 0) for m in stage_metrics]
                        
                        # Check if throughput scales
                        if throughputs[0] > 0:
                            # Calculate scaling factor
                            scaling_factors = [throughputs[i] / throughputs[0] for i in range(1, len(throughputs))]
                            
                            # Log scaling analysis
                            print(f"Throughput scaling factors: {scaling_factors}")
                        
                        # Check response time stability
                        if response_times:
                            response_time_variance = statistics.variance(response_times) if len(response_times) > 1 else 0
                            print(f"Response time variance: {response_time_variance}")
                        
                        # Check error rate trend
                        if error_rates:
                            error_trend = error_rates[-1] - error_rates[0]
                            print(f"Error rate trend: {error_trend}%")
    
    @pytest.mark.asyncio
    async def test_performance_baseline_establishment(self, auth_headers, high_traffic_api_spec):
        """Test establishment of performance baselines."""
        async with aiohttp.ClientSession() as session:
            # Upload specification
            spec_data = {
                "name": "Baseline Test API",
                "description": "API for baseline testing",
                "content": json.dumps(high_traffic_api_spec)
            }
            
            async with session.post(
                f"{SPEC_SERVICE_URL}/api/specifications",
                json=spec_data,
                headers=auth_headers
            ) as response:
                spec_response = await response.json()
                spec_id = spec_response.get("id")
            
            # Create baseline test
            test_run_data = {
                "name": "Performance Baseline",
                "spec_id": spec_id,
                "agents": ["performance-planner"],
                "configuration": {
                    "test_type": "baseline",
                    "performance_config": {
                        "baseline_duration": 300,  # 5 minutes
                        "baseline_users": 50,
                        "percentiles_to_track": [50, 75, 90, 95, 99],
                        "endpoints_to_baseline": [
                            "/health",
                            "/products",
                            "/products/{id}",
                            "/search",
                            "/orders"
                        ],
                        "baseline_conditions": {
                            "time_of_day": "peak",  # peak, off-peak, average
                            "cache_state": "warm",  # cold, warm
                            "database_size": "medium"  # small, medium, large
                        }
                    }
                }
            }
            
            async with session.post(
                f"{ORCHESTRATION_URL}/api/test-runs",
                json=test_run_data,
                headers=auth_headers
            ) as response:
                assert response.status in [200, 201]
                test_run_response = await response.json()
                test_run_id = test_run_response.get("id")
            
            # Execute baseline test
            execution_data = {
                "test_run_id": test_run_id,
                "execution_type": "baseline"
            }
            
            async with session.post(
                f"{EXECUTION_URL}/api/performance/execute",
                json=execution_data,
                headers=auth_headers
            ) as response:
                if response.status in [200, 201]:
                    execution_response = await response.json()
                    execution_id = execution_response.get("id")
                    
                    # Wait for baseline to complete
                    await asyncio.sleep(30)
                    
                    # Retrieve baseline results
                    async with session.get(
                        f"{EXECUTION_URL}/api/performance/{execution_id}/baseline",
                        headers=auth_headers
                    ) as response:
                        if response.status == 200:
                            baseline = await response.json()
                            
                            # Verify baseline metrics
                            assert "endpoints" in baseline
                            
                            for endpoint, metrics in baseline["endpoints"].items():
                                # Should have percentile data
                                assert "percentiles" in metrics
                                percentiles = metrics["percentiles"]
                                
                                # Verify percentile values
                                assert "p50" in percentiles
                                assert "p95" in percentiles
                                assert "p99" in percentiles
                                
                                # Should have throughput baseline
                                assert "throughput" in metrics
                                assert metrics["throughput"] > 0
                                
                                # Should have error baseline
                                assert "error_rate" in metrics
                            
                            # Save baseline for future comparison
                            async with session.post(
                                f"{DATA_SERVICE_URL}/api/performance/baselines",
                                json={
                                    "test_run_id": test_run_id,
                                    "baseline": baseline,
                                    "metadata": {
                                        "created_at": datetime.utcnow().isoformat(),
                                        "conditions": test_run_data["configuration"]["performance_config"]["baseline_conditions"]
                                    }
                                },
                                headers=auth_headers
                            ) as save_response:
                                assert save_response.status in [200, 201]