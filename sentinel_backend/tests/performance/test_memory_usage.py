"""
Memory usage performance tests for the Sentinel platform.

This module tests memory consumption, memory leak detection,
and memory optimization strategies.
"""

import gc
import pytest
import psutil
import os
import time
from typing import List, Dict, Any
import tracemalloc
from unittest.mock import Mock, AsyncMock
import asyncio
import sys

from sentinel_backend.orchestration_service.agents.base_agent import BaseAgent
from sentinel_backend.config.settings import get_application_settings


class TestMemoryUsage:
    """Test suite for memory usage and optimization."""
    
    @pytest.fixture(autouse=True)
    def setup_memory_tracking(self):
        """Setup memory tracking for tests."""
        gc.collect()
        tracemalloc.start()
        yield
        tracemalloc.stop()
        gc.collect()
    
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    
    def test_baseline_memory_usage(self):
        """Test baseline memory usage of the application."""
        initial_memory = self.get_memory_usage()
        
        # Import main modules
        from sentinel_backend.config import settings
        from sentinel_backend.database import models
        from sentinel_backend.orchestration_service import agents
        
        # Create some basic objects
        config = settings.get_application_settings()
        
        final_memory = self.get_memory_usage()
        memory_increase = final_memory - initial_memory
        
        assert memory_increase < 50, f"Baseline memory usage too high: {memory_increase}MB"
    
    def test_memory_leak_detection(self):
        """Test for memory leaks in repeated operations."""
        initial_memory = self.get_memory_usage()
        
        class LeakyClass:
            def __init__(self):
                self.data = [0] * 10000
        
        # Perform repeated operations
        for _ in range(100):
            obj = LeakyClass()
            _ = obj.data
            del obj
        
        gc.collect()
        
        final_memory = self.get_memory_usage()
        memory_increase = final_memory - initial_memory
        
        # Should not leak significant memory
        assert memory_increase < 10, f"Memory leak detected: {memory_increase}MB increase"
    
    def test_large_data_structure_handling(self):
        """Test memory usage with large data structures."""
        initial_memory = self.get_memory_usage()
        
        # Create large data structure
        large_list = []
        for i in range(100000):
            large_list.append({
                "id": i,
                "data": f"test_data_{i}",
                "nested": {"value": i * 2}
            })
        
        peak_memory = self.get_memory_usage()
        
        # Clear the data
        large_list.clear()
        del large_list
        gc.collect()
        
        final_memory = self.get_memory_usage()
        
        # Memory should be mostly released
        memory_retained = final_memory - initial_memory
        assert memory_retained < 5, f"Too much memory retained after cleanup: {memory_retained}MB"
    
    @pytest.mark.asyncio
    async def test_async_memory_usage(self):
        """Test memory usage in async operations."""
        initial_memory = self.get_memory_usage()
        
        async def memory_intensive_task():
            data = [i for i in range(10000)]
            await asyncio.sleep(0.01)
            return sum(data)
        
        # Run multiple async tasks
        tasks = [memory_intensive_task() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        
        peak_memory = self.get_memory_usage()
        
        # Cleanup
        del results
        del tasks
        gc.collect()
        
        final_memory = self.get_memory_usage()
        memory_increase = final_memory - initial_memory
        
        assert memory_increase < 20, f"Async operations retained too much memory: {memory_increase}MB"
    
    def test_circular_reference_handling(self):
        """Test memory management with circular references."""
        initial_memory = self.get_memory_usage()
        
        class Node:
            def __init__(self, value):
                self.value = value
                self.next = None
                self.prev = None
        
        # Create circular reference
        nodes = []
        for i in range(1000):
            node = Node(i)
            if nodes:
                node.prev = nodes[-1]
                nodes[-1].next = node
            nodes.append(node)
        
        # Create circular reference
        if nodes:
            nodes[0].prev = nodes[-1]
            nodes[-1].next = nodes[0]
        
        mid_memory = self.get_memory_usage()
        
        # Clear circular references
        for node in nodes:
            node.next = None
            node.prev = None
        nodes.clear()
        
        gc.collect()
        
        final_memory = self.get_memory_usage()
        memory_retained = final_memory - initial_memory
        
        assert memory_retained < 5, f"Circular references not properly cleaned: {memory_retained}MB retained"
    
    def test_cache_memory_management(self):
        """Test memory usage of caching mechanisms."""
        from functools import lru_cache
        
        @lru_cache(maxsize=1000)
        def cached_function(n):
            return [i * 2 for i in range(n)]
        
        initial_memory = self.get_memory_usage()
        
        # Fill cache
        for i in range(1000):
            _ = cached_function(i % 100)
        
        cache_filled_memory = self.get_memory_usage()
        
        # Clear cache
        cached_function.cache_clear()
        gc.collect()
        
        final_memory = self.get_memory_usage()
        
        cache_memory = cache_filled_memory - initial_memory
        released_memory = cache_filled_memory - final_memory
        
        assert cache_memory < 50, f"Cache using too much memory: {cache_memory}MB"
        assert released_memory > cache_memory * 0.5, "Cache not releasing memory properly"
    
    def test_generator_memory_efficiency(self):
        """Test memory efficiency of generators vs lists."""
        # Test with list (memory inefficient)
        initial_memory = self.get_memory_usage()
        
        def create_list(n):
            return [i * 2 for i in range(n)]
        
        large_list = create_list(1000000)
        list_memory = self.get_memory_usage() - initial_memory
        del large_list
        gc.collect()
        
        # Test with generator (memory efficient)
        initial_memory = self.get_memory_usage()
        
        def create_generator(n):
            for i in range(n):
                yield i * 2
        
        large_gen = create_generator(1000000)
        # Consume some values
        for _, value in zip(range(100), large_gen):
            pass
        
        gen_memory = self.get_memory_usage() - initial_memory
        
        assert gen_memory < list_memory * 0.1, "Generator not more memory efficient than list"
    
    def test_memory_profiling_with_tracemalloc(self):
        """Test memory profiling to identify top memory consumers."""
        snapshot1 = tracemalloc.take_snapshot()
        
        # Perform operations
        data_structures = []
        for i in range(100):
            data_structures.append({
                "id": i,
                "large_data": [j for j in range(1000)]
            })
        
        snapshot2 = tracemalloc.take_snapshot()
        
        # Get top memory consumers
        top_stats = snapshot2.compare_to(snapshot1, 'lineno')
        
        # Analyze top memory allocations
        total_allocated = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
        
        # Convert to MB
        total_allocated_mb = total_allocated / 1024 / 1024
        
        assert total_allocated_mb < 100, f"Too much memory allocated: {total_allocated_mb}MB"
        
        # Cleanup
        data_structures.clear()
    
    def test_string_interning_optimization(self):
        """Test string interning for memory optimization."""
        initial_memory = self.get_memory_usage()
        
        # Without interning
        strings_no_intern = []
        for i in range(10000):
            strings_no_intern.append(f"test_string_{i % 100}")
        
        no_intern_memory = self.get_memory_usage()
        
        # With interning
        strings_interned = []
        for i in range(10000):
            strings_interned.append(sys.intern(f"test_string_{i % 100}"))
        
        interned_memory = self.get_memory_usage()
        
        # Interned strings should use less memory for repeated values
        memory_saved = no_intern_memory - interned_memory
        
        # Cleanup
        strings_no_intern.clear()
        strings_interned.clear()
        gc.collect()
    
    def test_memory_usage_under_load(self):
        """Test memory usage under sustained load."""
        initial_memory = self.get_memory_usage()
        memory_samples = []
        
        for iteration in range(10):
            # Simulate load
            temp_data = []
            for i in range(10000):
                temp_data.append({
                    "iteration": iteration,
                    "index": i,
                    "data": [j for j in range(10)]
                })
            
            # Record memory
            current_memory = self.get_memory_usage()
            memory_samples.append(current_memory)
            
            # Cleanup iteration data
            temp_data.clear()
            gc.collect()
        
        final_memory = self.get_memory_usage()
        
        # Memory should stabilize (not continuously grow)
        max_memory = max(memory_samples)
        memory_growth = final_memory - initial_memory
        
        assert memory_growth < 10, f"Memory grew too much under load: {memory_growth}MB"
        assert max_memory - initial_memory < 50, f"Peak memory too high: {max_memory - initial_memory}MB"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])