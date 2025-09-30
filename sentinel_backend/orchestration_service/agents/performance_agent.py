"""
Performance Agent for Sentinel Platform

This agent specializes in executing comprehensive performance tests including
response time testing, load testing, stress testing, and performance validation
to identify bottlenecks and validate SLAs.
"""

import asyncio
import json
import logging
import time
import statistics
import threading
from typing import Dict, List, Any, Optional, Tuple, Union, Callable
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import random
import string
import aiohttp
from collections import defaultdict, deque
import gc
import weakref

# Optional dependency - psutil for system monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None

from .base_agent import BaseAgent, AgentTask, AgentResult

# Try to import settings, fallback to defaults if not available
try:
    from sentinel_backend.config.settings import get_application_settings
    app_settings = get_application_settings()
except ImportError:
    # Fallback settings object for when running standalone
    class FallbackSettings:
        performance_default_users = 10
        performance_max_users = 1000
        performance_test_duration = 60
        performance_ramp_up_time = 30
        performance_think_time = 1
        performance_timeout = 30
        performance_response_threshold = 1000
        performance_throughput_threshold = 100
        performance_error_threshold = 5.0

    app_settings = FallbackSettings()

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Container for performance test metrics."""
    response_times: List[float]
    status_codes: Dict[int, int]
    errors: List[str]
    throughput: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    start_time: datetime
    end_time: datetime
    peak_memory_mb: float
    avg_cpu_percent: float

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()

    @property
    def avg_response_time(self) -> float:
        return statistics.mean(self.response_times) if self.response_times else 0.0

    @property
    def p95_response_time(self) -> float:
        return statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) >= 20 else 0.0

    @property
    def p99_response_time(self) -> float:
        return statistics.quantiles(self.response_times, n=100)[98] if len(self.response_times) >= 100 else 0.0

    @property
    def success_rate(self) -> float:
        return (self.successful_requests / self.total_requests * 100) if self.total_requests > 0 else 0.0


@dataclass
class LoadPattern:
    """Defines a load testing pattern."""
    name: str
    concurrent_users: int
    duration_seconds: int
    ramp_up_seconds: int
    think_time_seconds: float
    requests_per_user: Optional[int] = None


class ResourceMonitor:
    """Monitors system resources during performance tests."""

    def __init__(self):
        self.monitoring = False
        self.metrics = []
        self.peak_memory = 0.0
        self.cpu_samples = []

    def start_monitoring(self):
        """Start resource monitoring in a separate thread."""
        self.monitoring = True
        self.metrics = []
        self.peak_memory = 0.0
        self.cpu_samples = []
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def stop_monitoring(self):
        """Stop resource monitoring and return aggregated metrics."""
        self.monitoring = False
        time.sleep(0.1)  # Allow final sample
        return {
            'peak_memory_mb': self.peak_memory,
            'avg_cpu_percent': statistics.mean(self.cpu_samples) if self.cpu_samples else 0.0,
            'memory_samples': len(self.metrics),
            'cpu_samples': len(self.cpu_samples)
        }

    def _monitor_loop(self):
        """Resource monitoring loop."""
        if not PSUTIL_AVAILABLE:
            logger.debug("psutil not available, using fallback resource monitoring")
            return

        while self.monitoring:
            try:
                memory_mb = psutil.virtual_memory().used / (1024 * 1024)
                cpu_percent = psutil.cpu_percent(interval=None)

                self.peak_memory = max(self.peak_memory, memory_mb)
                self.cpu_samples.append(cpu_percent)

                self.metrics.append({
                    'timestamp': time.time(),
                    'memory_mb': memory_mb,
                    'cpu_percent': cpu_percent
                })

                time.sleep(0.5)  # Sample every 500ms
            except Exception as e:
                logger.debug(f"Resource monitoring error: {e}")
                break


class PerformanceAgent(BaseAgent):
    """
    Agent specialized in executing comprehensive performance tests.

    Test Types:
    - Response Time Testing: Baseline response time measurement
    - Load Testing: Concurrent user simulation
    - Stress Testing: System breaking point identification
    - Spike Testing: Sudden load increase handling
    - Volume Testing: Large payload processing
    - Endurance Testing: Sustained load over time
    - Scalability Testing: Performance at different scales
    - Rate Limiting Validation: Rate limit enforcement
    - Caching Behavior: Cache effectiveness testing
    - Database Query Performance: N+1 query detection
    - Memory Leak Detection: Memory usage pattern analysis
    - Connection Pool Testing: Connection limit validation
    - Timeout Testing: Slow response handling
    - Pagination Performance: Large dataset pagination
    - Search Performance: Complex query optimization
    """

    def __init__(self):
        super().__init__("performance")
        self.agent_type = "Performance-Agent"
        self.description = "Performance agent for comprehensive API performance testing"

        # Configuration-driven settings
        self.default_concurrent_users = getattr(app_settings, 'performance_default_users', 10)
        self.max_concurrent_users = getattr(app_settings, 'performance_max_users', 1000)
        self.default_test_duration = getattr(app_settings, 'performance_test_duration', 60)
        self.default_ramp_up_time = getattr(app_settings, 'performance_ramp_up_time', 30)
        self.default_think_time = getattr(app_settings, 'performance_think_time', 1)
        self.timeout_seconds = getattr(app_settings, 'performance_timeout', 30)

        # Performance thresholds (configurable)
        self.response_time_threshold_ms = getattr(app_settings, 'performance_response_threshold', 1000)
        self.throughput_threshold_rps = getattr(app_settings, 'performance_throughput_threshold', 100)
        self.error_rate_threshold_percent = getattr(app_settings, 'performance_error_threshold', 5.0)

        # Test patterns
        self.load_patterns = self._initialize_load_patterns()

        # Resource monitoring
        self.resource_monitor = ResourceMonitor()

    def _initialize_load_patterns(self) -> List[LoadPattern]:
        """Initialize standard load testing patterns."""
        return [
            LoadPattern("baseline", 1, 30, 5, 1.0),
            LoadPattern("light_load", 5, 60, 10, 1.0),
            LoadPattern("normal_load", 10, 120, 20, 1.0),
            LoadPattern("heavy_load", 25, 180, 30, 0.5),
            LoadPattern("stress_test", 50, 300, 60, 0.2),
            LoadPattern("spike_test", 100, 60, 5, 0.1),
            LoadPattern("endurance_test", 10, 1800, 30, 2.0),  # 30 minutes
        ]

    async def execute(self, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
        """
        Execute comprehensive performance testing based on the task parameters.

        Args:
            task: The agent task containing execution parameters
            api_spec: The parsed API specification

        Returns:
            AgentResult containing performance test cases and metrics
        """
        try:
            self.logger.info(f"Starting performance testing for task {task.task_id}")

            # Extract endpoints for testing
            endpoints = self._extract_endpoints(api_spec)

            if not endpoints:
                return AgentResult(
                    task_id=task.task_id,
                    agent_type=self.agent_type,
                    status="failed",
                    error_message="No testable endpoints found in API specification"
                )

            # Generate performance test cases based on task parameters
            test_cases = []

            # Get test types from task parameters
            test_types = task.parameters.get("test_types", [
                "response_time", "load_test", "stress_test", "spike_test"
            ])

            # Generate test cases for each requested test type
            if "response_time" in test_types:
                test_cases.extend(self._generate_response_time_tests(endpoints))

            if "load_test" in test_types:
                test_cases.extend(self._generate_load_tests(endpoints))

            if "stress_test" in test_types:
                test_cases.extend(self._generate_stress_tests(endpoints))

            if "spike_test" in test_types:
                test_cases.extend(self._generate_spike_tests(endpoints))

            if "volume_test" in test_types:
                test_cases.extend(self._generate_volume_tests(endpoints))

            if "endurance_test" in test_types:
                test_cases.extend(self._generate_endurance_tests(endpoints))

            if "scalability_test" in test_types:
                test_cases.extend(self._generate_scalability_tests(endpoints))

            if "rate_limiting" in test_types:
                test_cases.extend(self._generate_rate_limiting_tests(endpoints))

            if "caching" in test_types:
                test_cases.extend(self._generate_caching_tests(endpoints))

            if "database_performance" in test_types:
                test_cases.extend(self._generate_database_performance_tests(endpoints))

            if "memory_leak" in test_types:
                test_cases.extend(self._generate_memory_leak_tests(endpoints))

            if "connection_pool" in test_types:
                test_cases.extend(self._generate_connection_pool_tests(endpoints))

            if "timeout_test" in test_types:
                test_cases.extend(self._generate_timeout_tests(endpoints))

            if "pagination_performance" in test_types:
                test_cases.extend(self._generate_pagination_tests(endpoints))

            if "search_performance" in test_types:
                test_cases.extend(self._generate_search_performance_tests(endpoints))

            # Enhance test cases with LLM if available
            if self.llm_enabled:
                test_cases = await self._enhance_test_cases_with_llm(test_cases, api_spec)

            metadata = {
                "endpoints_analyzed": len(endpoints),
                "test_types_generated": test_types,
                "total_test_cases": len(test_cases),
                "performance_thresholds": {
                    "response_time_ms": self.response_time_threshold_ms,
                    "throughput_rps": self.throughput_threshold_rps,
                    "error_rate_percent": self.error_rate_threshold_percent
                },
                "load_patterns": [asdict(pattern) for pattern in self.load_patterns]
            }

            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="success",
                test_cases=test_cases,
                metadata=metadata
            )

        except Exception as e:
            self.logger.error(f"Performance agent execution failed: {str(e)}")
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="failed",
                error_message=str(e)
            )

    def _generate_response_time_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate response time baseline tests."""
        test_cases = []

        for endpoint in endpoints:
            if endpoint["method"] in ["GET", "POST", "PUT", "PATCH"]:
                test_case = {
                    "test_type": "response_time",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Baseline response time test for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": 1,
                        "iterations": 10,
                        "think_time": 0.1,
                        "timeout": self.timeout_seconds
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "response_time",
                            "condition": "less_than",
                            "value": self.response_time_threshold_ms,
                            "description": f"Response time should be less than {self.response_time_threshold_ms}ms"
                        },
                        {
                            "type": "status_code",
                            "condition": "in",
                            "value": [200, 201, 202, 204],
                            "description": "Should return successful status code"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "avg_response_time_ms": self.response_time_threshold_ms,
                        "p95_response_time_ms": self.response_time_threshold_ms * 1.5,
                        "p99_response_time_ms": self.response_time_threshold_ms * 2,
                        "success_rate_percent": 99.0
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_load_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate load testing scenarios."""
        test_cases = []

        # Test critical endpoints with different load patterns
        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:3]

        for pattern in self.load_patterns[:4]:  # Use first 4 patterns for load tests
            for endpoint in critical_endpoints:
                test_case = {
                    "test_type": "load_test",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Load test ({pattern.name}) for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": pattern.concurrent_users,
                        "duration_seconds": pattern.duration_seconds,
                        "ramp_up_seconds": pattern.ramp_up_seconds,
                        "think_time": pattern.think_time_seconds,
                        "timeout": self.timeout_seconds
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "throughput",
                            "condition": "greater_than",
                            "value": self.throughput_threshold_rps,
                            "description": f"Throughput should exceed {self.throughput_threshold_rps} requests/second"
                        },
                        {
                            "type": "error_rate",
                            "condition": "less_than",
                            "value": self.error_rate_threshold_percent,
                            "description": f"Error rate should be below {self.error_rate_threshold_percent}%"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "avg_response_time_ms": self.response_time_threshold_ms * 2,
                        "p95_response_time_ms": self.response_time_threshold_ms * 3,
                        "throughput_rps": self.throughput_threshold_rps,
                        "success_rate_percent": 95.0,
                        "error_rate_percent": self.error_rate_threshold_percent
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_stress_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate stress testing scenarios to find breaking points."""
        test_cases = []

        # Gradually increase load to find breaking point
        stress_levels = [50, 100, 200, 500, 1000]
        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:2]

        for users in stress_levels:
            if users > self.max_concurrent_users:
                break

            for endpoint in critical_endpoints:
                test_case = {
                    "test_type": "stress_test",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Stress test with {users} concurrent users for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": users,
                        "duration_seconds": 120,
                        "ramp_up_seconds": 30,
                        "think_time": 0.1,
                        "timeout": self.timeout_seconds * 2
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "system_stability",
                            "condition": "stable",
                            "description": "System should remain stable under stress"
                        },
                        {
                            "type": "error_rate",
                            "condition": "less_than",
                            "value": 50.0,  # More lenient for stress tests
                            "description": "Error rate should remain manageable under stress"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "avg_response_time_ms": self.response_time_threshold_ms * 5,
                        "p95_response_time_ms": self.response_time_threshold_ms * 10,
                        "success_rate_percent": 50.0,  # Very lenient for stress
                        "error_rate_percent": 50.0,
                        "memory_leak_detection": True
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_spike_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate spike testing scenarios for sudden load increases."""
        test_cases = []

        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:2]

        spike_patterns = [
            {"users": 100, "spike_duration": 30, "base_users": 5},
            {"users": 200, "spike_duration": 60, "base_users": 10},
            {"users": 500, "spike_duration": 45, "base_users": 20}
        ]

        for pattern in spike_patterns:
            for endpoint in critical_endpoints:
                test_case = {
                    "test_type": "spike_test",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Spike test: {pattern['base_users']} to {pattern['users']} users for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "base_concurrent_users": pattern["base_users"],
                        "spike_concurrent_users": pattern["users"],
                        "spike_duration_seconds": pattern["spike_duration"],
                        "pre_spike_duration": 60,
                        "post_spike_duration": 60,
                        "think_time": 0.1,
                        "timeout": self.timeout_seconds
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "spike_recovery",
                            "condition": "recovers",
                            "description": "System should recover after spike"
                        },
                        {
                            "type": "response_time_degradation",
                            "condition": "acceptable",
                            "description": "Response time degradation should be acceptable"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "spike_response_time_ms": self.response_time_threshold_ms * 3,
                        "recovery_time_seconds": 30,
                        "success_rate_during_spike": 80.0,
                        "success_rate_after_spike": 95.0
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_volume_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate volume testing scenarios for large payloads."""
        test_cases = []

        # Focus on POST/PUT endpoints that accept payloads
        payload_endpoints = [ep for ep in endpoints if ep["method"] in ["POST", "PUT", "PATCH"]]

        payload_sizes = [
            {"name": "small", "size": 1024, "description": "1KB payload"},
            {"name": "medium", "size": 10240, "description": "10KB payload"},
            {"name": "large", "size": 102400, "description": "100KB payload"},
            {"name": "xlarge", "size": 1048576, "description": "1MB payload"}
        ]

        for size_config in payload_sizes:
            for endpoint in payload_endpoints[:2]:  # Limit to 2 endpoints
                test_case = {
                    "test_type": "volume_test",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Volume test with {size_config['description']} for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": 5,
                        "duration_seconds": 120,
                        "payload_size_bytes": size_config["size"],
                        "think_time": 2.0,
                        "timeout": self.timeout_seconds * 3
                    },
                    "body": self._generate_large_payload(endpoint, size_config["size"]),
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "payload_handling",
                            "condition": "successful",
                            "description": f"Should handle {size_config['description']} successfully"
                        },
                        {
                            "type": "memory_usage",
                            "condition": "stable",
                            "description": "Memory usage should remain stable"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "avg_response_time_ms": self.response_time_threshold_ms * (size_config["size"] // 1024),
                        "success_rate_percent": 90.0,
                        "memory_growth_mb": 100  # Maximum acceptable memory growth
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_endurance_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate endurance testing scenarios for sustained load."""
        test_cases = []

        # Select most critical endpoints for endurance testing
        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:2]

        endurance_configs = [
            {"duration": 1800, "users": 10, "name": "30_minute_sustained"},  # 30 minutes
            {"duration": 3600, "users": 5, "name": "1_hour_light"},  # 1 hour
        ]

        for config in endurance_configs:
            for endpoint in critical_endpoints:
                test_case = {
                    "test_type": "endurance_test",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Endurance test ({config['name']}) for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": config["users"],
                        "duration_seconds": config["duration"],
                        "ramp_up_seconds": 60,
                        "think_time": 3.0,
                        "timeout": self.timeout_seconds,
                        "memory_monitoring": True
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "memory_leak",
                            "condition": "no_leak",
                            "description": "No memory leaks during sustained load"
                        },
                        {
                            "type": "performance_degradation",
                            "condition": "acceptable",
                            "description": "Performance should not degrade significantly over time"
                        },
                        {
                            "type": "error_rate",
                            "condition": "stable",
                            "description": "Error rate should remain stable"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "avg_response_time_ms": self.response_time_threshold_ms * 1.5,
                        "response_time_variance": 0.2,  # 20% variance allowed
                        "success_rate_percent": 95.0,
                        "memory_leak_threshold_mb": 50,
                        "performance_degradation_percent": 30
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_scalability_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate scalability testing scenarios at different scales."""
        test_cases = []

        # Test scalability with increasing user loads
        scale_points = [1, 5, 10, 25, 50, 100]
        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:2]

        for users in scale_points:
            if users > self.max_concurrent_users:
                break

            for endpoint in critical_endpoints:
                test_case = {
                    "test_type": "scalability_test",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Scalability test with {users} users for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": users,
                        "duration_seconds": 180,
                        "ramp_up_seconds": 30,
                        "think_time": 1.0,
                        "timeout": self.timeout_seconds
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "linear_scalability",
                            "condition": "acceptable",
                            "description": "Performance should scale acceptably with user load"
                        },
                        {
                            "type": "resource_utilization",
                            "condition": "efficient",
                            "description": "Resource utilization should be efficient"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "response_time_growth_factor": 1.5,  # Response time shouldn't grow more than 1.5x per 10x users
                        "throughput_efficiency": 0.8,  # Should maintain 80% efficiency
                        "success_rate_percent": 95.0
                    },
                    "scalability_metrics": {
                        "user_count": users,
                        "baseline_users": 1,
                        "scale_factor": users
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_rate_limiting_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate rate limiting validation tests."""
        test_cases = []

        # Test rate limiting on all endpoints
        for endpoint in endpoints[:3]:  # Limit to first 3 endpoints
            test_case = {
                "test_type": "rate_limiting",
                "endpoint": endpoint["path"],
                "method": endpoint["method"],
                "description": f"Rate limiting validation for {endpoint['method']} {endpoint['path']}",
                "performance_config": {
                    "requests_per_second": 100,  # High rate to trigger limits
                    "duration_seconds": 60,
                    "burst_requests": 200,
                    "timeout": self.timeout_seconds
                },
                "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                "headers": {"Content-Type": "application/json"},
                "assertions": [
                    {
                        "type": "rate_limit_enforcement",
                        "condition": "enforced",
                        "description": "Rate limits should be properly enforced"
                    },
                    {
                        "type": "rate_limit_headers",
                        "condition": "present",
                        "description": "Rate limit headers should be present"
                    },
                    {
                        "type": "status_code",
                        "condition": "in",
                        "value": [200, 429],
                        "description": "Should return 200 or 429 (Too Many Requests)"
                    }
                ],
                "expected_status": [200, 429],
                "performance_thresholds": {
                    "rate_limit_response_time_ms": 100,  # Rate limit responses should be fast
                    "proper_429_percent": 80.0  # Most excessive requests should get 429
                }
            }
            test_cases.append(test_case)

        return test_cases

    def _generate_caching_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate caching behavior validation tests."""
        test_cases = []

        # Focus on GET endpoints that should be cacheable
        get_endpoints = [ep for ep in endpoints if ep["method"] == "GET"][:3]

        for endpoint in get_endpoints:
            test_case = {
                "test_type": "caching_behavior",
                "endpoint": endpoint["path"],
                "method": endpoint["method"],
                "description": f"Cache effectiveness test for {endpoint['method']} {endpoint['path']}",
                "performance_config": {
                    "concurrent_users": 10,
                    "iterations_per_user": 20,
                    "cache_warm_requests": 5,
                    "think_time": 0.5,
                    "timeout": self.timeout_seconds
                },
                "headers": {
                    "Cache-Control": "no-cache",  # First request without cache
                    "Content-Type": "application/json"
                },
                "assertions": [
                    {
                        "type": "cache_hit_ratio",
                        "condition": "greater_than",
                        "value": 70.0,
                        "description": "Cache hit ratio should be above 70%"
                    },
                    {
                        "type": "cached_response_time",
                        "condition": "faster",
                        "description": "Cached responses should be significantly faster"
                    },
                    {
                        "type": "cache_headers",
                        "condition": "present",
                        "description": "Appropriate cache headers should be present"
                    }
                ],
                "expected_status": 200,
                "performance_thresholds": {
                    "cache_hit_response_time_ms": self.response_time_threshold_ms * 0.3,
                    "cache_miss_response_time_ms": self.response_time_threshold_ms,
                    "cache_effectiveness_ratio": 3.0  # Cached should be 3x faster
                }
            }
            test_cases.append(test_case)

        return test_cases

    def _generate_database_performance_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate database query performance tests including N+1 detection."""
        test_cases = []

        # Focus on endpoints that likely query databases
        data_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"] and
                         any(keyword in ep["path"].lower() for keyword in ["users", "items", "orders", "products"])][:3]

        for endpoint in data_endpoints:
            test_case = {
                "test_type": "database_performance",
                "endpoint": endpoint["path"],
                "method": endpoint["method"],
                "description": f"Database performance and N+1 query detection for {endpoint['method']} {endpoint['path']}",
                "performance_config": {
                    "concurrent_users": 5,
                    "iterations_per_user": 10,
                    "query_monitoring": True,
                    "think_time": 1.0,
                    "timeout": self.timeout_seconds
                },
                "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                "headers": {"Content-Type": "application/json"},
                "assertions": [
                    {
                        "type": "query_count",
                        "condition": "optimal",
                        "description": "Database query count should be optimal (no N+1 queries)"
                    },
                    {
                        "type": "query_time",
                        "condition": "acceptable",
                        "description": "Database query time should be acceptable"
                    },
                    {
                        "type": "connection_pooling",
                        "condition": "efficient",
                        "description": "Database connections should be used efficiently"
                    }
                ],
                "expected_status": 200,
                "performance_thresholds": {
                    "max_queries_per_request": 5,  # Reasonable limit
                    "avg_query_time_ms": 100,
                    "db_connection_time_ms": 10,
                    "n_plus_1_detection": True
                }
            }
            test_cases.append(test_case)

        return test_cases

    def _generate_memory_leak_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate memory leak detection tests."""
        test_cases = []

        # Test memory patterns on critical endpoints
        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:2]

        for endpoint in critical_endpoints:
            test_case = {
                "test_type": "memory_leak",
                "endpoint": endpoint["path"],
                "method": endpoint["method"],
                "description": f"Memory leak detection for {endpoint['method']} {endpoint['path']}",
                "performance_config": {
                    "concurrent_users": 5,
                    "duration_seconds": 900,  # 15 minutes
                    "memory_sampling_interval": 10,  # Every 10 seconds
                    "think_time": 2.0,
                    "timeout": self.timeout_seconds
                },
                "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                "headers": {"Content-Type": "application/json"},
                "assertions": [
                    {
                        "type": "memory_growth",
                        "condition": "stable",
                        "description": "Memory usage should remain stable over time"
                    },
                    {
                        "type": "garbage_collection",
                        "condition": "effective",
                        "description": "Garbage collection should be effective"
                    }
                ],
                "expected_status": 200,
                "performance_thresholds": {
                    "max_memory_growth_mb": 50,
                    "memory_growth_rate_mb_per_hour": 10,
                    "gc_efficiency_percent": 80
                }
            }
            test_cases.append(test_case)

        return test_cases

    def _generate_connection_pool_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate connection pool testing scenarios."""
        test_cases = []

        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:2]

        # Test connection limits and pooling
        connection_levels = [50, 100, 200]  # Concurrent connections

        for connections in connection_levels:
            for endpoint in critical_endpoints:
                test_case = {
                    "test_type": "connection_pool",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Connection pool test with {connections} connections for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_connections": connections,
                        "duration_seconds": 120,
                        "connection_timeout": 5,
                        "keep_alive": True,
                        "think_time": 0.1,
                        "timeout": self.timeout_seconds
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json", "Connection": "keep-alive"},
                    "assertions": [
                        {
                            "type": "connection_handling",
                            "condition": "graceful",
                            "description": "Should handle connection limits gracefully"
                        },
                        {
                            "type": "connection_reuse",
                            "condition": "efficient",
                            "description": "Should reuse connections efficiently"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "connection_success_rate": 95.0,
                        "connection_time_ms": 100,
                        "connection_reuse_rate": 80.0
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_timeout_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate timeout handling tests."""
        test_cases = []

        critical_endpoints = [ep for ep in endpoints if ep["method"] in ["GET", "POST"]][:2]

        timeout_scenarios = [
            {"timeout": 1, "description": "very short timeout"},
            {"timeout": 5, "description": "short timeout"},
            {"timeout": 30, "description": "normal timeout"}
        ]

        for scenario in timeout_scenarios:
            for endpoint in critical_endpoints:
                test_case = {
                    "test_type": "timeout_handling",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Timeout handling test ({scenario['description']}) for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": 10,
                        "request_timeout": scenario["timeout"],
                        "duration_seconds": 60,
                        "think_time": 0.5,
                        "simulate_slow_response": True
                    },
                    "body": self._generate_request_body(endpoint) if endpoint["method"] in ["POST", "PUT", "PATCH"] else None,
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "timeout_handling",
                            "condition": "graceful",
                            "description": "Should handle timeouts gracefully"
                        },
                        {
                            "type": "error_response",
                            "condition": "appropriate",
                            "description": "Should return appropriate error for timeouts"
                        }
                    ],
                    "expected_status": [200, 408, 504],  # OK, Request Timeout, Gateway Timeout
                    "performance_thresholds": {
                        "timeout_handling_rate": 100.0,
                        "proper_timeout_response": True
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_pagination_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate pagination performance tests."""
        test_cases = []

        # Focus on GET endpoints that likely support pagination
        paginated_endpoints = [ep for ep in endpoints if ep["method"] == "GET" and
                             any(keyword in ep["path"].lower() for keyword in ["list", "search", "users", "items"])][:2]

        page_sizes = [10, 50, 100, 500]

        for page_size in page_sizes:
            for endpoint in paginated_endpoints:
                test_case = {
                    "test_type": "pagination_performance",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Pagination performance test (page_size={page_size}) for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": 5,
                        "pages_to_test": 10,
                        "page_size": page_size,
                        "think_time": 1.0,
                        "timeout": self.timeout_seconds
                    },
                    "query_params": {
                        "page_size": page_size,
                        "page": 1
                    },
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "pagination_consistency",
                            "condition": "consistent",
                            "description": "Pagination should be consistent across pages"
                        },
                        {
                            "type": "large_page_performance",
                            "condition": "acceptable",
                            "description": "Large pages should have acceptable performance"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "page_response_time_ms": self.response_time_threshold_ms * (page_size // 10),
                        "pagination_efficiency": 0.9,
                        "memory_per_item_kb": 5
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_search_performance_tests(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate search performance tests."""
        test_cases = []

        # Focus on search endpoints
        search_endpoints = [ep for ep in endpoints if ep["method"] == "GET" and
                           "search" in ep["path"].lower()][:2]

        if not search_endpoints:
            # Look for endpoints that might support search via query params
            search_endpoints = [ep for ep in endpoints if ep["method"] == "GET"][:1]

        search_scenarios = [
            {"query": "test", "description": "simple search"},
            {"query": "complex AND query OR term", "description": "complex search"},
            {"query": "*", "description": "wildcard search"},
            {"query": "a", "description": "short term search"}
        ]

        for scenario in search_scenarios:
            for endpoint in search_endpoints:
                test_case = {
                    "test_type": "search_performance",
                    "endpoint": endpoint["path"],
                    "method": endpoint["method"],
                    "description": f"Search performance test ({scenario['description']}) for {endpoint['method']} {endpoint['path']}",
                    "performance_config": {
                        "concurrent_users": 10,
                        "search_iterations": 20,
                        "think_time": 0.5,
                        "timeout": self.timeout_seconds
                    },
                    "query_params": {
                        "q": scenario["query"],
                        "search": scenario["query"]
                    },
                    "headers": {"Content-Type": "application/json"},
                    "assertions": [
                        {
                            "type": "search_speed",
                            "condition": "fast",
                            "description": "Search should be fast regardless of complexity"
                        },
                        {
                            "type": "search_accuracy",
                            "condition": "relevant",
                            "description": "Search results should be relevant"
                        }
                    ],
                    "expected_status": 200,
                    "performance_thresholds": {
                        "search_response_time_ms": self.response_time_threshold_ms * 2,
                        "search_consistency": True,
                        "relevance_score": 0.8
                    }
                }
                test_cases.append(test_case)

        return test_cases

    def _generate_request_body(self, endpoint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate appropriate request body based on endpoint definition."""
        if endpoint["method"] not in ["POST", "PUT", "PATCH"]:
            return None

        request_body = endpoint.get("requestBody", {})
        if not request_body:
            return {"data": "test"}

        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        schema = json_content.get("schema", {})

        if schema:
            return self._get_schema_example(schema)

        return {"data": "test"}

    def _generate_large_payload(self, endpoint: Dict[str, Any], size_bytes: int) -> Dict[str, Any]:
        """Generate large payload for volume testing."""
        base_payload = self._generate_request_body(endpoint) or {}

        # Calculate how much data we need to add
        current_size = len(json.dumps(base_payload).encode('utf-8'))
        needed_size = max(0, size_bytes - current_size)

        # Add large string field to reach target size
        if needed_size > 0:
            # Generate random string of appropriate size
            large_data = ''.join(random.choices(string.ascii_letters + string.digits, k=needed_size))
            base_payload["large_data"] = large_data

        return base_payload

    async def _enhance_test_cases_with_llm(self, test_cases: List[Dict[str, Any]], api_spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enhance test cases using LLM for more realistic performance scenarios."""
        if not self.llm_enabled:
            return test_cases

        enhanced_cases = []

        for test_case in test_cases:
            try:
                prompt = f"""
                Enhance this performance test case to make it more realistic and comprehensive:

                Test Type: {test_case.get('test_type')}
                Endpoint: {test_case.get('method')} {test_case.get('endpoint')}

                Current configuration: {test_case.get('performance_config', {})}

                Suggestions needed:
                1. More realistic test data
                2. Better performance thresholds
                3. Additional assertions
                4. Edge cases to consider

                Return the enhanced test case maintaining the same structure.
                """

                system_prompt = """You are a performance testing expert. Enhance test cases with:
                - Realistic performance expectations
                - Comprehensive assertions
                - Edge case scenarios
                - Industry-standard thresholds

                Maintain the exact JSON structure of the input."""

                enhanced = await self.enhance_with_llm(
                    test_case,
                    prompt,
                    system_prompt=system_prompt,
                    temperature=0.3
                )

                if isinstance(enhanced, dict) and "test_type" in enhanced:
                    enhanced_cases.append(enhanced)
                else:
                    enhanced_cases.append(test_case)

            except Exception as e:
                self.logger.debug(f"LLM enhancement failed for test case: {e}")
                enhanced_cases.append(test_case)

        return enhanced_cases

    # Helper methods for load generation and metrics collection

    async def execute_performance_test(self, test_case: Dict[str, Any], base_url: str) -> PerformanceMetrics:
        """Execute a single performance test and collect metrics."""
        test_type = test_case.get("test_type")
        config = test_case.get("performance_config", {})

        self.resource_monitor.start_monitoring()

        try:
            if test_type == "response_time":
                return await self._execute_response_time_test(test_case, base_url, config)
            elif test_type == "load_test":
                return await self._execute_load_test(test_case, base_url, config)
            elif test_type == "stress_test":
                return await self._execute_stress_test(test_case, base_url, config)
            elif test_type == "spike_test":
                return await self._execute_spike_test(test_case, base_url, config)
            elif test_type == "volume_test":
                return await self._execute_volume_test(test_case, base_url, config)
            elif test_type == "endurance_test":
                return await self._execute_endurance_test(test_case, base_url, config)
            else:
                return await self._execute_generic_test(test_case, base_url, config)

        finally:
            resource_metrics = self.resource_monitor.stop_monitoring()
            self.logger.info(f"Resource usage: {resource_metrics}")

    async def _execute_response_time_test(self, test_case: Dict[str, Any], base_url: str, config: Dict[str, Any]) -> PerformanceMetrics:
        """Execute response time baseline test."""
        start_time = datetime.now()
        response_times = []
        status_codes = defaultdict(int)
        errors = []

        iterations = config.get("iterations", 10)
        timeout = config.get("timeout", self.timeout_seconds)

        url = f"{base_url.rstrip('/')}{test_case['endpoint']}"

        for i in range(iterations):
            try:
                request_start = time.time()

                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                    async with session.request(
                        method=test_case["method"],
                        url=url,
                        json=test_case.get("body"),
                        headers=test_case.get("headers", {}),
                        params=test_case.get("query_params", {})
                    ) as response:
                        await response.text()  # Ensure full response is read

                        request_time = (time.time() - request_start) * 1000  # Convert to ms
                        response_times.append(request_time)
                        status_codes[response.status] += 1

            except Exception as e:
                errors.append(str(e))
                status_codes[0] += 1  # Use 0 for connection errors

            # Think time between requests
            think_time = config.get("think_time", 0.1)
            if i < iterations - 1:
                await asyncio.sleep(think_time)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return PerformanceMetrics(
            response_times=response_times,
            status_codes=dict(status_codes),
            errors=errors,
            throughput=len(response_times) / duration if duration > 0 else 0,
            total_requests=iterations,
            successful_requests=len(response_times),
            failed_requests=len(errors),
            start_time=start_time,
            end_time=end_time,
            peak_memory_mb=self.resource_monitor.peak_memory,
            avg_cpu_percent=statistics.mean(self.resource_monitor.cpu_samples) if self.resource_monitor.cpu_samples else 0
        )

    async def _execute_load_test(self, test_case: Dict[str, Any], base_url: str, config: Dict[str, Any]) -> PerformanceMetrics:
        """Execute load test with concurrent users."""
        concurrent_users = config.get("concurrent_users", 10)
        duration_seconds = config.get("duration_seconds", 60)
        ramp_up_seconds = config.get("ramp_up_seconds", 10)
        think_time = config.get("think_time", 1.0)

        start_time = datetime.now()
        all_response_times = []
        all_status_codes = defaultdict(int)
        all_errors = []
        total_requests = 0
        successful_requests = 0

        # Create semaphore to control concurrent users
        semaphore = asyncio.Semaphore(concurrent_users)

        async def user_session():
            nonlocal total_requests, successful_requests

            session_start = time.time()
            url = f"{base_url.rstrip('/')}{test_case['endpoint']}"

            async with semaphore:
                while time.time() - session_start < duration_seconds:
                    try:
                        request_start = time.time()

                        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=config.get("timeout", self.timeout_seconds))) as session:
                            async with session.request(
                                method=test_case["method"],
                                url=url,
                                json=test_case.get("body"),
                                headers=test_case.get("headers", {}),
                                params=test_case.get("query_params", {})
                            ) as response:
                                await response.text()

                                request_time = (time.time() - request_start) * 1000
                                all_response_times.append(request_time)
                                all_status_codes[response.status] += 1
                                total_requests += 1
                                successful_requests += 1

                    except Exception as e:
                        all_errors.append(str(e))
                        all_status_codes[0] += 1
                        total_requests += 1

                    await asyncio.sleep(think_time)

        # Ramp up users gradually
        tasks = []
        for i in range(concurrent_users):
            await asyncio.sleep(ramp_up_seconds / concurrent_users)
            task = asyncio.create_task(user_session())
            tasks.append(task)

        # Wait for all tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return PerformanceMetrics(
            response_times=all_response_times,
            status_codes=dict(all_status_codes),
            errors=all_errors,
            throughput=successful_requests / duration if duration > 0 else 0,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=len(all_errors),
            start_time=start_time,
            end_time=end_time,
            peak_memory_mb=self.resource_monitor.peak_memory,
            avg_cpu_percent=statistics.mean(self.resource_monitor.cpu_samples) if self.resource_monitor.cpu_samples else 0
        )

    async def _execute_stress_test(self, test_case: Dict[str, Any], base_url: str, config: Dict[str, Any]) -> PerformanceMetrics:
        """Execute stress test to find breaking point."""
        # Stress test is similar to load test but with higher concurrency and longer timeout
        enhanced_config = config.copy()
        enhanced_config["timeout"] = config.get("timeout", self.timeout_seconds * 2)

        return await self._execute_load_test(test_case, base_url, enhanced_config)

    async def _execute_spike_test(self, test_case: Dict[str, Any], base_url: str, config: Dict[str, Any]) -> PerformanceMetrics:
        """Execute spike test with sudden load increase."""
        base_users = config.get("base_concurrent_users", 5)
        spike_users = config.get("spike_concurrent_users", 50)
        pre_spike_duration = config.get("pre_spike_duration", 60)
        spike_duration = config.get("spike_duration_seconds", 30)
        post_spike_duration = config.get("post_spike_duration", 60)

        start_time = datetime.now()
        all_metrics = []

        # Phase 1: Baseline load
        config_base = config.copy()
        config_base.update({
            "concurrent_users": base_users,
            "duration_seconds": pre_spike_duration,
            "ramp_up_seconds": 10
        })
        metrics_base = await self._execute_load_test(test_case, base_url, config_base)
        all_metrics.append(("baseline", metrics_base))

        # Phase 2: Spike load
        config_spike = config.copy()
        config_spike.update({
            "concurrent_users": spike_users,
            "duration_seconds": spike_duration,
            "ramp_up_seconds": 5
        })
        metrics_spike = await self._execute_load_test(test_case, base_url, config_spike)
        all_metrics.append(("spike", metrics_spike))

        # Phase 3: Recovery
        config_recovery = config.copy()
        config_recovery.update({
            "concurrent_users": base_users,
            "duration_seconds": post_spike_duration,
            "ramp_up_seconds": 10
        })
        metrics_recovery = await self._execute_load_test(test_case, base_url, config_recovery)
        all_metrics.append(("recovery", metrics_recovery))

        # Combine metrics
        combined_response_times = []
        combined_status_codes = defaultdict(int)
        combined_errors = []
        total_requests = 0
        successful_requests = 0

        for phase, metrics in all_metrics:
            combined_response_times.extend(metrics.response_times)
            for code, count in metrics.status_codes.items():
                combined_status_codes[code] += count
            combined_errors.extend(metrics.errors)
            total_requests += metrics.total_requests
            successful_requests += metrics.successful_requests

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return PerformanceMetrics(
            response_times=combined_response_times,
            status_codes=dict(combined_status_codes),
            errors=combined_errors,
            throughput=successful_requests / duration if duration > 0 else 0,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=len(combined_errors),
            start_time=start_time,
            end_time=end_time,
            peak_memory_mb=self.resource_monitor.peak_memory,
            avg_cpu_percent=statistics.mean(self.resource_monitor.cpu_samples) if self.resource_monitor.cpu_samples else 0
        )

    async def _execute_volume_test(self, test_case: Dict[str, Any], base_url: str, config: Dict[str, Any]) -> PerformanceMetrics:
        """Execute volume test with large payloads."""
        # Volume test is similar to load test but with potentially longer timeouts due to large payloads
        enhanced_config = config.copy()
        enhanced_config["timeout"] = config.get("timeout", self.timeout_seconds * 3)
        enhanced_config["concurrent_users"] = config.get("concurrent_users", 5)  # Lower concurrency for volume tests
        enhanced_config["think_time"] = config.get("think_time", 2.0)  # More think time

        return await self._execute_load_test(test_case, base_url, enhanced_config)

    async def _execute_endurance_test(self, test_case: Dict[str, Any], base_url: str, config: Dict[str, Any]) -> PerformanceMetrics:
        """Execute endurance test for sustained load."""
        # Endurance test is a long-running load test with memory monitoring
        enhanced_config = config.copy()
        enhanced_config["duration_seconds"] = config.get("duration_seconds", 1800)  # 30 minutes default
        enhanced_config["concurrent_users"] = config.get("concurrent_users", 5)  # Conservative load
        enhanced_config["think_time"] = config.get("think_time", 3.0)  # Longer think time

        # Start memory monitoring with more frequent sampling for leak detection
        original_monitoring = self.resource_monitor.monitoring
        self.resource_monitor.monitoring = True

        try:
            return await self._execute_load_test(test_case, base_url, enhanced_config)
        finally:
            self.resource_monitor.monitoring = original_monitoring

    async def _execute_generic_test(self, test_case: Dict[str, Any], base_url: str, config: Dict[str, Any]) -> PerformanceMetrics:
        """Execute a generic performance test."""
        # Fallback to basic load test for unknown test types
        return await self._execute_load_test(test_case, base_url, config)

    def generate_performance_report(self, metrics: PerformanceMetrics, thresholds: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a comprehensive performance report."""
        report = {
            "summary": {
                "total_requests": metrics.total_requests,
                "successful_requests": metrics.successful_requests,
                "failed_requests": metrics.failed_requests,
                "success_rate": metrics.success_rate,
                "duration_seconds": metrics.duration_seconds,
                "throughput_rps": metrics.throughput
            },
            "response_times": {
                "average_ms": metrics.avg_response_time,
                "p95_ms": metrics.p95_response_time,
                "p99_ms": metrics.p99_response_time,
                "min_ms": min(metrics.response_times) if metrics.response_times else 0,
                "max_ms": max(metrics.response_times) if metrics.response_times else 0
            },
            "status_codes": metrics.status_codes,
            "errors": metrics.errors[:10],  # Limit to first 10 errors
            "resource_usage": {
                "peak_memory_mb": metrics.peak_memory_mb,
                "avg_cpu_percent": metrics.avg_cpu_percent
            },
            "threshold_compliance": self._check_threshold_compliance(metrics, thresholds),
            "recommendations": self._generate_recommendations(metrics, thresholds)
        }

        return report

    def _check_threshold_compliance(self, metrics: PerformanceMetrics, thresholds: Dict[str, Any]) -> Dict[str, bool]:
        """Check if metrics meet defined thresholds."""
        compliance = {}

        if "avg_response_time_ms" in thresholds:
            compliance["avg_response_time"] = metrics.avg_response_time <= thresholds["avg_response_time_ms"]

        if "p95_response_time_ms" in thresholds:
            compliance["p95_response_time"] = metrics.p95_response_time <= thresholds["p95_response_time_ms"]

        if "throughput_rps" in thresholds:
            compliance["throughput"] = metrics.throughput >= thresholds["throughput_rps"]

        if "success_rate_percent" in thresholds:
            compliance["success_rate"] = metrics.success_rate >= thresholds["success_rate_percent"]

        if "error_rate_percent" in thresholds:
            error_rate = (metrics.failed_requests / metrics.total_requests * 100) if metrics.total_requests > 0 else 0
            compliance["error_rate"] = error_rate <= thresholds["error_rate_percent"]

        return compliance

    def _generate_recommendations(self, metrics: PerformanceMetrics, thresholds: Dict[str, Any]) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []

        if metrics.avg_response_time > thresholds.get("avg_response_time_ms", self.response_time_threshold_ms):
            recommendations.append("Consider optimizing response time - current average exceeds threshold")

        if metrics.success_rate < 95:
            recommendations.append("Investigate error causes - success rate is below acceptable level")

        if metrics.throughput < thresholds.get("throughput_rps", self.throughput_threshold_rps):
            recommendations.append("Consider scaling resources - throughput is below expected level")

        if len(metrics.errors) > 0:
            recommendations.append("Review error patterns for optimization opportunities")

        if metrics.peak_memory_mb > 1000:  # 1GB threshold
            recommendations.append("Monitor memory usage - peak memory consumption is high")

        return recommendations