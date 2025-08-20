"""
Load performance tests for the Sentinel platform.

This module tests system behavior under various load conditions,
including concurrent users, request rates, and sustained load scenarios.
"""

import asyncio
import pytest
import time
from typing import List, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import aiohttp
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import random

from sentinel_backend.config.settings import get_application_settings


@dataclass
class LoadTestResult:
    """Container for load test results."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=datetime.now)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def average_response_time(self) -> float:
        """Calculate average response time."""
        if not self.response_times:
            return 0.0
        return statistics.mean(self.response_times)
    
    @property
    def median_response_time(self) -> float:
        """Calculate median response time."""
        if not self.response_times:
            return 0.0
        return statistics.median(self.response_times)
    
    @property
    def p95_response_time(self) -> float:
        """Calculate 95th percentile response time."""
        if not self.response_times:
            return 0.0
        sorted_times = sorted(self.response_times)
        index = int(len(sorted_times) * 0.95)
        return sorted_times[index] if index < len(sorted_times) else sorted_times[-1]
    
    @property
    def requests_per_second(self) -> float:
        """Calculate requests per second."""
        duration = (self.end_time - self.start_time).total_seconds()
        if duration == 0:
            return 0.0
        return self.total_requests / duration


class LoadPerformanceTests:
    """Load performance test suite."""
    
    @pytest.fixture
    def base_url(self):
        """Get base URL for testing."""
        settings = get_application_settings()
        return f"http://localhost:{settings.port}"
    
    @pytest.fixture
    def test_endpoints(self, base_url):
        """Define test endpoints."""
        return {
            "health": f"{base_url}/health",
            "specs": f"{base_url}/api/v1/specifications",
            "test_cases": f"{base_url}/api/v1/test-cases",
            "test_runs": f"{base_url}/api/v1/test-runs",
            "auth": f"{base_url}/api/v1/auth/login"
        }
    
    async def make_request(self, session: aiohttp.ClientSession, url: str, 
                          method: str = "GET", **kwargs) -> Tuple[float, int, Any]:
        """Make a single HTTP request and measure response time."""
        start_time = time.time()
        try:
            async with session.request(method, url, **kwargs) as response:
                data = await response.text()
                elapsed = time.time() - start_time
                return elapsed, response.status, data
        except Exception as e:
            elapsed = time.time() - start_time
            return elapsed, 0, str(e)
    
    async def run_concurrent_requests(self, url: str, num_requests: int, 
                                     concurrent_limit: int = 10) -> LoadTestResult:
        """Run concurrent requests to a single endpoint."""
        result = LoadTestResult()
        result.start_time = datetime.now()
        
        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(concurrent_limit)
            
            async def bounded_request():
                async with semaphore:
                    return await self.make_request(session, url)
            
            tasks = [bounded_request() for _ in range(num_requests)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                result.total_requests += 1
                if isinstance(response, Exception):
                    result.failed_requests += 1
                    result.errors.append(str(response))
                else:
                    elapsed, status, data = response
                    result.response_times.append(elapsed)
                    if 200 <= status < 300:
                        result.successful_requests += 1
                    else:
                        result.failed_requests += 1
                        result.errors.append(f"HTTP {status}: {data[:100]}")
        
        result.end_time = datetime.now()
        return result
    
    @pytest.mark.asyncio
    async def test_single_endpoint_load(self, test_endpoints):
        """Test load on a single endpoint."""
        url = test_endpoints["health"]
        num_requests = 100
        concurrent_limit = 10
        
        result = await self.run_concurrent_requests(url, num_requests, concurrent_limit)
        
        assert result.success_rate >= 95, f"Success rate too low: {result.success_rate}%"
        assert result.average_response_time < 1.0, f"Average response time too high: {result.average_response_time}s"
        assert result.p95_response_time < 2.0, f"P95 response time too high: {result.p95_response_time}s"
    
    @pytest.mark.asyncio
    async def test_multiple_endpoints_load(self, test_endpoints):
        """Test load distributed across multiple endpoints."""
        endpoints = list(test_endpoints.values())[:3]  # Use first 3 endpoints
        num_requests_per_endpoint = 50
        
        tasks = []
        for endpoint in endpoints:
            task = self.run_concurrent_requests(endpoint, num_requests_per_endpoint)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        for i, result in enumerate(results):
            assert result.success_rate >= 90, f"Endpoint {i} success rate too low: {result.success_rate}%"
            assert result.average_response_time < 2.0, f"Endpoint {i} response time too high: {result.average_response_time}s"
    
    @pytest.mark.asyncio
    async def test_sustained_load(self, test_endpoints):
        """Test system under sustained load for extended period."""
        url = test_endpoints["health"]
        duration_seconds = 30
        requests_per_second = 10
        
        result = LoadTestResult()
        result.start_time = datetime.now()
        
        async with aiohttp.ClientSession() as session:
            end_time = datetime.now() + timedelta(seconds=duration_seconds)
            
            while datetime.now() < end_time:
                start_batch = time.time()
                
                # Send batch of requests
                tasks = [self.make_request(session, url) for _ in range(requests_per_second)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                for response in responses:
                    result.total_requests += 1
                    if isinstance(response, Exception):
                        result.failed_requests += 1
                        result.errors.append(str(response))
                    else:
                        elapsed, status, _ = response
                        result.response_times.append(elapsed)
                        if 200 <= status < 300:
                            result.successful_requests += 1
                        else:
                            result.failed_requests += 1
                
                # Wait to maintain requests per second rate
                batch_duration = time.time() - start_batch
                if batch_duration < 1.0:
                    await asyncio.sleep(1.0 - batch_duration)
        
        result.end_time = datetime.now()
        
        assert result.success_rate >= 95, f"Success rate during sustained load too low: {result.success_rate}%"
        assert result.average_response_time < 1.0, f"Average response time too high: {result.average_response_time}s"
    
    @pytest.mark.asyncio
    async def test_spike_load(self, test_endpoints):
        """Test system behavior during traffic spikes."""
        url = test_endpoints["health"]
        
        # Normal load
        normal_result = await self.run_concurrent_requests(url, 20, 5)
        
        # Spike load (5x normal)
        spike_result = await self.run_concurrent_requests(url, 100, 25)
        
        # Return to normal
        recovery_result = await self.run_concurrent_requests(url, 20, 5)
        
        # System should handle spike
        assert spike_result.success_rate >= 85, f"Success rate during spike too low: {spike_result.success_rate}%"
        
        # System should recover
        assert recovery_result.success_rate >= 95, f"Recovery success rate too low: {recovery_result.success_rate}%"
        assert recovery_result.average_response_time <= normal_result.average_response_time * 1.5
    
    @pytest.mark.asyncio
    async def test_gradual_load_increase(self, test_endpoints):
        """Test system behavior with gradually increasing load."""
        url = test_endpoints["health"]
        stages = [
            (10, 5),   # 10 requests, 5 concurrent
            (25, 10),  # 25 requests, 10 concurrent
            (50, 15),  # 50 requests, 15 concurrent
            (100, 20), # 100 requests, 20 concurrent
        ]
        
        results = []
        for num_requests, concurrent_limit in stages:
            result = await self.run_concurrent_requests(url, num_requests, concurrent_limit)
            results.append(result)
            await asyncio.sleep(2)  # Brief pause between stages
        
        # Check that performance degrades gracefully
        for i in range(1, len(results)):
            # Success rate should not drop below 80%
            assert results[i].success_rate >= 80, f"Stage {i} success rate too low: {results[i].success_rate}%"
            
            # Response time should not increase more than 2x per stage
            if results[i-1].average_response_time > 0:
                ratio = results[i].average_response_time / results[i-1].average_response_time
                assert ratio < 2.0, f"Response time increased too much at stage {i}: {ratio}x"
    
    @pytest.mark.asyncio
    async def test_mixed_workload(self, test_endpoints, base_url):
        """Test system with mixed read/write operations."""
        read_urls = [test_endpoints["health"], test_endpoints["specs"]]
        write_url = f"{base_url}/api/v1/test-cases"
        
        async def mixed_operations(session: aiohttp.ClientSession, num_operations: int):
            results = []
            for i in range(num_operations):
                if random.random() < 0.7:  # 70% reads
                    url = random.choice(read_urls)
                    result = await self.make_request(session, url)
                else:  # 30% writes
                    data = {"name": f"Test {i}", "description": "Load test"}
                    result = await self.make_request(
                        session, write_url, method="POST", 
                        json=data, headers={"Content-Type": "application/json"}
                    )
                results.append(result)
            return results
        
        async with aiohttp.ClientSession() as session:
            tasks = [mixed_operations(session, 20) for _ in range(5)]
            all_results = await asyncio.gather(*tasks)
        
        # Flatten results
        flat_results = [r for sublist in all_results for r in sublist]
        
        success_count = sum(1 for _, status, _ in flat_results if 200 <= status < 300)
        success_rate = (success_count / len(flat_results)) * 100
        
        assert success_rate >= 85, f"Mixed workload success rate too low: {success_rate}%"
    
    def test_connection_pool_limits(self, base_url):
        """Test system behavior at connection pool limits."""
        url = f"{base_url}/health"
        
        def make_blocking_request():
            import requests
            try:
                response = requests.get(url, timeout=5)
                return response.status_code
            except Exception:
                return 0
        
        # Create more connections than typical pool size
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(make_blocking_request) for _ in range(100)]
            results = [f.result() for f in as_completed(futures)]
        
        success_count = sum(1 for status in results if 200 <= status < 300)
        success_rate = (success_count / len(results)) * 100
        
        assert success_rate >= 80, f"Success rate at connection limit too low: {success_rate}%"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])