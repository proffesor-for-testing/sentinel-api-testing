"""
Concurrent execution performance tests for the Sentinel platform.

This module tests the system's ability to handle concurrent operations,
including parallel test execution, multi-agent coordination, and race conditions.
"""

import asyncio
import pytest
import time
from typing import List, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from unittest.mock import Mock, AsyncMock, patch
import threading
import multiprocessing
import random
import uuid
from dataclasses import dataclass
from datetime import datetime

from sentinel_backend.orchestration_service.agents.base_agent import BaseAgent
from sentinel_backend.config.settings import get_application_settings


@dataclass
class ConcurrencyTestResult:
    """Container for concurrency test results."""
    total_operations: int
    successful_operations: int
    failed_operations: int
    start_time: datetime
    end_time: datetime
    operation_times: List[float]
    errors: List[str]
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_operations == 0:
            return 0.0
        return (self.successful_operations / self.total_operations) * 100
    
    @property
    def operations_per_second(self) -> float:
        """Calculate operations per second."""
        duration = (self.end_time - self.start_time).total_seconds()
        if duration == 0:
            return 0.0
        return self.total_operations / duration
    
    @property
    def average_operation_time(self) -> float:
        """Calculate average operation time."""
        if not self.operation_times:
            return 0.0
        return sum(self.operation_times) / len(self.operation_times)


class TestConcurrentExecution:
    """Test suite for concurrent execution performance."""
    
    @pytest.fixture
    def mock_test_runner(self):
        """Create a mock test runner."""
        runner = AsyncMock(spec=TestRunner)
        
        async def mock_run(test_case):
            await asyncio.sleep(random.uniform(0.1, 0.5))
            return {
                "test_id": test_case.get("id", str(uuid.uuid4())),
                "status": "passed" if random.random() > 0.1 else "failed",
                "duration": random.uniform(0.1, 0.5)
            }
        
        runner.run = mock_run
        return runner
    
    @pytest.fixture
    def sample_test_cases(self):
        """Generate sample test cases."""
        return [
            {
                "id": f"test_{i}",
                "name": f"Test Case {i}",
                "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
                "path": f"/api/endpoint{i}",
                "expected_status": 200
            }
            for i in range(50)
        ]
    
    @pytest.mark.asyncio
    async def test_parallel_test_execution(self, mock_test_runner, sample_test_cases):
        """Test parallel execution of multiple test cases."""
        async def run_test_batch(test_cases, max_concurrent=10):
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def run_with_semaphore(test_case):
                async with semaphore:
                    start = time.time()
                    result = await mock_test_runner.run(test_case)
                    return time.time() - start, result
            
            tasks = [run_with_semaphore(tc) for tc in test_cases]
            return await asyncio.gather(*tasks, return_exceptions=True)
        
        # Run tests in parallel
        start_time = time.time()
        results = await run_test_batch(sample_test_cases, max_concurrent=20)
        total_time = time.time() - start_time
        
        # Analyze results
        successful = sum(1 for r in results if not isinstance(r, Exception) and r[1]["status"] == "passed")
        success_rate = (successful / len(sample_test_cases)) * 100
        
        assert total_time < 5.0, f"Parallel execution took too long: {total_time}s"
        assert success_rate >= 85, f"Success rate too low: {success_rate}%"
    
    @pytest.mark.asyncio
    async def test_multi_agent_coordination(self):
        """Test concurrent coordination of multiple agents."""
        class MockAgent:
            def __init__(self, agent_id):
                self.agent_id = agent_id
                self.tasks_completed = 0
            
            async def process_task(self, task):
                await asyncio.sleep(random.uniform(0.05, 0.15))
                self.tasks_completed += 1
                return f"Agent {self.agent_id} completed {task}"
        
        # Create multiple agents
        agents = [MockAgent(i) for i in range(10)]
        tasks = [f"task_{i}" for i in range(100)]
        
        # Distribute tasks among agents
        async def coordinate_agents():
            agent_tasks = []
            for i, task in enumerate(tasks):
                agent = agents[i % len(agents)]
                agent_tasks.append(agent.process_task(task))
            
            return await asyncio.gather(*agent_tasks)
        
        start_time = time.time()
        results = await coordinate_agents()
        elapsed = time.time() - start_time
        
        assert len(results) == len(tasks)
        assert elapsed < 2.0, f"Multi-agent coordination took too long: {elapsed}s"
        
        # Verify work distribution
        total_completed = sum(agent.tasks_completed for agent in agents)
        assert total_completed == len(tasks)
    
    @pytest.mark.asyncio
    async def test_race_condition_handling(self):
        """Test handling of race conditions in concurrent operations."""
        shared_counter = {"value": 0}
        lock = asyncio.Lock()
        
        async def increment_with_lock():
            async with lock:
                current = shared_counter["value"]
                await asyncio.sleep(0.001)  # Simulate processing
                shared_counter["value"] = current + 1
        
        async def increment_without_lock():
            current = shared_counter["value"]
            await asyncio.sleep(0.001)  # Simulate processing
            shared_counter["value"] = current + 1
        
        # Test with lock (should be safe)
        shared_counter["value"] = 0
        tasks = [increment_with_lock() for _ in range(100)]
        await asyncio.gather(*tasks)
        assert shared_counter["value"] == 100, "Lock failed to prevent race condition"
        
        # Test without lock (may have race conditions)
        shared_counter["value"] = 0
        tasks = [increment_without_lock() for _ in range(100)]
        await asyncio.gather(*tasks)
        # Without lock, value might be less than 100 due to race conditions
        assert shared_counter["value"] <= 100
    
    @pytest.mark.asyncio
    async def test_resource_pool_management(self):
        """Test concurrent access to limited resource pool."""
        class ResourcePool:
            def __init__(self, size):
                self.resources = asyncio.Queue(maxsize=size)
                for i in range(size):
                    self.resources.put_nowait(f"resource_{i}")
                self.acquisitions = 0
                self.releases = 0
            
            async def acquire(self):
                resource = await self.resources.get()
                self.acquisitions += 1
                return resource
            
            async def release(self, resource):
                await self.resources.put(resource)
                self.releases += 1
        
        pool = ResourcePool(5)
        
        async def use_resource(pool, duration):
            resource = await pool.acquire()
            try:
                await asyncio.sleep(duration)
                return f"Used {resource}"
            finally:
                await pool.release(resource)
        
        # Create more tasks than resources
        tasks = [use_resource(pool, random.uniform(0.01, 0.05)) for _ in range(20)]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        assert len(results) == 20
        assert pool.acquisitions == pool.releases == 20
        assert elapsed < 1.0, f"Resource pool operations took too long: {elapsed}s"
    
    @pytest.mark.asyncio
    async def test_concurrent_database_operations(self):
        """Test concurrent database operations performance."""
        # Simulate database operations
        db_lock = asyncio.Lock()
        db_state = {"records": [], "version": 0}
        
        async def read_operation():
            await asyncio.sleep(0.01)  # Simulate DB read
            return len(db_state["records"])
        
        async def write_operation(data):
            async with db_lock:  # Ensure write atomicity
                await asyncio.sleep(0.02)  # Simulate DB write
                db_state["records"].append(data)
                db_state["version"] += 1
        
        # Mix of read and write operations
        operations = []
        for i in range(100):
            if random.random() < 0.7:  # 70% reads
                operations.append(read_operation())
            else:  # 30% writes
                operations.append(write_operation(f"data_{i}"))
        
        start_time = time.time()
        results = await asyncio.gather(*operations, return_exceptions=True)
        elapsed = time.time() - start_time
        
        errors = [r for r in results if isinstance(r, Exception)]
        assert len(errors) == 0, f"Database operations failed: {errors}"
        assert elapsed < 3.0, f"Database operations took too long: {elapsed}s"
    
    def test_thread_pool_performance(self):
        """Test performance with thread pool executor."""
        def cpu_bound_task(n):
            """Simulate CPU-bound task."""
            result = 0
            for i in range(n * 1000):
                result += i * i
            return result
        
        # Test with different thread pool sizes
        pool_sizes = [4, 8, 16]
        results = []
        
        for pool_size in pool_sizes:
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=pool_size) as executor:
                futures = [executor.submit(cpu_bound_task, i) for i in range(20)]
                _ = [f.result() for f in as_completed(futures)]
            elapsed = time.time() - start_time
            
            results.append({
                "pool_size": pool_size,
                "time": elapsed
            })
        
        # Larger pool should be faster (up to CPU core limit)
        assert results[1]["time"] <= results[0]["time"] * 1.1
    
    def test_process_pool_performance(self):
        """Test performance with process pool executor."""
        def heavy_computation(n):
            """Heavy computation task."""
            import math
            result = 0
            for i in range(n * 10000):
                result += math.sqrt(i)
            return result
        
        # Test with process pool
        with ProcessPoolExecutor(max_workers=4) as executor:
            start_time = time.time()
            futures = [executor.submit(heavy_computation, i) for i in range(10)]
            results = [f.result() for f in as_completed(futures)]
            elapsed = time.time() - start_time
        
        assert len(results) == 10
        assert elapsed < 10.0, f"Process pool operations took too long: {elapsed}s"
    
    @pytest.mark.asyncio
    async def test_event_driven_concurrency(self):
        """Test event-driven concurrent operations."""
        events = {
            "start": asyncio.Event(),
            "phase1": asyncio.Event(),
            "phase2": asyncio.Event(),
            "complete": asyncio.Event()
        }
        
        results = []
        
        async def worker1():
            await events["start"].wait()
            results.append("worker1_started")
            await asyncio.sleep(0.1)
            events["phase1"].set()
            await events["complete"].wait()
            results.append("worker1_completed")
        
        async def worker2():
            await events["phase1"].wait()
            results.append("worker2_started")
            await asyncio.sleep(0.1)
            events["phase2"].set()
            await events["complete"].wait()
            results.append("worker2_completed")
        
        async def worker3():
            await events["phase2"].wait()
            results.append("worker3_started")
            await asyncio.sleep(0.1)
            events["complete"].set()
            results.append("worker3_completed")
        
        # Start workers
        workers = [worker1(), worker2(), worker3()]
        worker_tasks = [asyncio.create_task(w) for w in workers]
        
        # Trigger start
        await asyncio.sleep(0.05)
        events["start"].set()
        
        # Wait for completion
        await asyncio.gather(*worker_tasks)
        
        # Verify execution order
        assert results[0] == "worker1_started"
        assert "worker2_started" in results
        assert "worker3_started" in results
        assert len(results) == 6
    
    @pytest.mark.asyncio
    async def test_concurrent_timeout_handling(self):
        """Test handling of timeouts in concurrent operations."""
        async def operation_with_timeout(duration, timeout):
            try:
                await asyncio.wait_for(
                    asyncio.sleep(duration),
                    timeout=timeout
                )
                return "completed"
            except asyncio.TimeoutError:
                return "timeout"
        
        # Mix of operations that will timeout and complete
        operations = []
        for i in range(20):
            if i % 3 == 0:
                # Will timeout
                operations.append(operation_with_timeout(2.0, 0.1))
            else:
                # Will complete
                operations.append(operation_with_timeout(0.05, 1.0))
        
        start_time = time.time()
        results = await asyncio.gather(*operations)
        elapsed = time.time() - start_time
        
        timeout_count = sum(1 for r in results if r == "timeout")
        complete_count = sum(1 for r in results if r == "completed")
        
        assert timeout_count > 0, "No timeouts detected"
        assert complete_count > 0, "No completions detected"
        assert elapsed < 1.0, f"Timeout handling took too long: {elapsed}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])