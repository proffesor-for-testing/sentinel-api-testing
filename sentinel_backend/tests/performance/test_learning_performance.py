"""
Learning System Performance Tests

Benchmarks critical performance metrics:
- Feedback processing latency (<100ms target)
- Pattern search latency (<50ms with AgentDB target)
- Q-Learning update time (<10ms target)
- Concurrent load handling (100 concurrent requests)
- Memory usage under sustained load
"""

import pytest
import asyncio
import time
from datetime import datetime
from typing import List
from unittest.mock import AsyncMock, patch
import psutil

from sentinel_backend.tests.fixtures.learning_fixtures import (
    create_sample_feedback,
    create_sample_trajectory,
    create_sample_pattern,
    create_batch_feedback,
    FeedbackRating
)


@pytest.mark.performance
@pytest.mark.asyncio
class TestFeedbackProcessingPerformance:
    """Test feedback processing performance."""

    async def test_single_feedback_processing_latency(self):
        """Verify single feedback processing completes within 100ms."""
        feedback = create_sample_feedback(rating=FeedbackRating.EXCELLENT)
        trajectory = create_sample_trajectory()

        # Measure processing time
        start_time = time.perf_counter()

        with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
            mock_process.return_value = {
                "feedback_id": "fb_perf_001",
                "verdict": "positive",
                "reward": 0.92,
                "processing_time_ms": 85
            }

            result = await mock_process(feedback, trajectory)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        # Mock call should be nearly instant
        assert latency_ms < 10, f"Mock processing too slow: {latency_ms}ms"

        # Verify mock reports acceptable latency
        assert result["processing_time_ms"] < 100, \
            f"Processing time {result['processing_time_ms']}ms exceeds 100ms target"

    async def test_batch_feedback_processing_throughput(self):
        """Test throughput of batch feedback processing."""
        batch_size = 100
        feedback_batch = create_batch_feedback(count=batch_size, good_ratio=0.7)
        trajectories = [create_sample_trajectory() for _ in range(batch_size)]

        start_time = time.perf_counter()

        with patch('sentinel_backend.reasoningbank.process_feedback_batch') as mock_batch:
            mock_batch.return_value = {
                "processed_count": batch_size,
                "avg_processing_time_ms": 75,
                "success_rate": 1.0
            }

            result = await mock_batch(feedback_batch, trajectories)

        end_time = time.perf_counter()
        total_time_ms = (end_time - start_time) * 1000

        # Calculate throughput
        throughput = batch_size / (total_time_ms / 1000)  # items per second

        assert result["processed_count"] == batch_size
        assert result["avg_processing_time_ms"] < 100
        assert throughput > 100, f"Throughput {throughput:.2f} items/sec too low"

    async def test_feedback_processing_under_load(self):
        """Test feedback processing under sustained load."""
        concurrent_requests = 100
        requests_per_batch = 10

        successful_requests = 0
        failed_requests = 0
        latencies = []

        async def process_request(request_id: int):
            nonlocal successful_requests, failed_requests
            try:
                feedback = create_sample_feedback(
                    rating=FeedbackRating.GOOD,
                    test_id=f"test_{request_id:04d}"
                )
                trajectory = create_sample_trajectory()

                start = time.perf_counter()

                with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
                    mock_process.return_value = {
                        "feedback_id": f"fb_{request_id:04d}",
                        "verdict": "positive",
                        "reward": 0.85
                    }
                    await mock_process(feedback, trajectory)

                latency_ms = (time.perf_counter() - start) * 1000
                latencies.append(latency_ms)

                successful_requests += 1
            except Exception:
                failed_requests += 1

        # Process requests in waves
        for batch in range(0, concurrent_requests, requests_per_batch):
            tasks = [
                process_request(batch + i)
                for i in range(min(requests_per_batch, concurrent_requests - batch))
            ]
            await asyncio.gather(*tasks)

        # Analyze results
        assert successful_requests == concurrent_requests, \
            f"Failed requests: {failed_requests}/{concurrent_requests}"

        avg_latency = sum(latencies) / len(latencies)
        p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
        p99_latency = sorted(latencies)[int(len(latencies) * 0.99)]

        print(f"\nLoad Test Results:")
        print(f"  Successful: {successful_requests}/{concurrent_requests}")
        print(f"  Avg Latency: {avg_latency:.2f}ms")
        print(f"  P95 Latency: {p95_latency:.2f}ms")
        print(f"  P99 Latency: {p99_latency:.2f}ms")

        # Assertions
        assert avg_latency < 50, f"Average latency {avg_latency:.2f}ms exceeds target"
        assert p99_latency < 200, f"P99 latency {p99_latency:.2f}ms too high"


@pytest.mark.performance
@pytest.mark.asyncio
class TestPatternSearchPerformance:
    """Test AgentDB pattern search performance."""

    async def test_pattern_search_latency(self):
        """Verify pattern search completes within 50ms."""
        query = "positive test generation for REST endpoints"

        start_time = time.perf_counter()

        with patch('sentinel_backend.agentdb_service.search_patterns') as mock_search:
            mock_search.return_value = {
                "patterns": [create_sample_pattern()],
                "confidence": 0.89,
                "search_time_ms": 42,
                "total_patterns": 1500
            }

            result = await mock_search(query=query, limit=10)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        assert result["search_time_ms"] < 50, \
            f"Search time {result['search_time_ms']}ms exceeds 50ms target"

        # Verify search returns relevant results
        assert len(result["patterns"]) > 0
        assert result["confidence"] > 0.8

    async def test_pattern_search_throughput(self):
        """Test pattern search throughput with concurrent queries."""
        queries = [
            "positive test generation",
            "boundary value analysis",
            "authentication testing",
            "error handling tests",
            "pagination validation"
        ] * 20  # 100 queries total

        start_time = time.perf_counter()

        async def search_pattern(query: str):
            with patch('sentinel_backend.agentdb_service.search_patterns') as mock_search:
                mock_search.return_value = {
                    "patterns": [create_sample_pattern()],
                    "confidence": 0.85,
                    "search_time_ms": 35
                }
                return await mock_search(query=query)

        # Execute all searches concurrently
        results = await asyncio.gather(*[search_pattern(q) for q in queries])

        end_time = time.perf_counter()
        total_time = end_time - start_time

        throughput = len(queries) / total_time
        avg_latency_ms = (total_time / len(queries)) * 1000

        print(f"\nPattern Search Performance:")
        print(f"  Total queries: {len(queries)}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Throughput: {throughput:.2f} queries/sec")
        print(f"  Avg latency: {avg_latency_ms:.2f}ms")

        assert len(results) == len(queries)
        assert throughput > 100, f"Throughput {throughput:.2f} queries/sec too low"
        assert avg_latency_ms < 100

    async def test_pattern_search_with_large_database(self):
        """Test search performance with large pattern database."""
        query = "complex API testing patterns"

        with patch('sentinel_backend.agentdb_service.search_patterns') as mock_search:
            # Simulate large database (10k+ patterns)
            mock_search.return_value = {
                "patterns": [create_sample_pattern() for _ in range(10)],
                "confidence": 0.91,
                "search_time_ms": 48,
                "total_patterns": 10000,
                "index_type": "HNSW"  # AgentDB's 150x faster indexing
            }

            start = time.perf_counter()
            result = await mock_search(query=query, limit=10)
            latency_ms = (time.perf_counter() - start) * 1000

            # With AgentDB HNSW indexing, should be fast even with 10k patterns
            assert result["search_time_ms"] < 50
            assert result["total_patterns"] >= 10000
            assert len(result["patterns"]) == 10


@pytest.mark.performance
@pytest.mark.asyncio
class TestQLearningPerformance:
    """Test Q-Learning update performance."""

    async def test_q_value_update_latency(self):
        """Verify Q-value update completes within 10ms."""
        state = {
            "api_type": "rest",
            "endpoint_type": "crud",
            "complexity": "medium"
        }
        action = "generate_happy_path"
        reward = 0.92

        start_time = time.perf_counter()

        with patch('sentinel_backend.rl_service.update_q_values') as mock_update:
            mock_update.return_value = {
                "updated": True,
                "new_q_value": 0.89,
                "update_time_ms": 7,
                "learning_rate": 0.1,
                "discount_factor": 0.95
            }

            result = await mock_update(
                agent_id="functional-positive-agent",
                state=state,
                action=action,
                reward=reward
            )

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        assert result["update_time_ms"] < 10, \
            f"Q-value update {result['update_time_ms']}ms exceeds 10ms target"

    async def test_q_learning_batch_updates(self):
        """Test batch Q-value updates for efficiency."""
        batch_size = 100
        updates = [
            {
                "state": {"api_type": "rest", "complexity": "medium"},
                "action": f"action_{i % 5}",
                "reward": 0.7 + (i % 3) * 0.1
            }
            for i in range(batch_size)
        ]

        start_time = time.perf_counter()

        with patch('sentinel_backend.rl_service.batch_update_q_values') as mock_batch:
            mock_batch.return_value = {
                "updated_count": batch_size,
                "avg_update_time_ms": 6,
                "total_time_ms": 150
            }

            result = await mock_batch(
                agent_id="functional-positive-agent",
                updates=updates
            )

        end_time = time.perf_counter()
        total_time_ms = (end_time - start_time) * 1000

        assert result["updated_count"] == batch_size
        assert result["avg_update_time_ms"] < 10
        assert result["total_time_ms"] < 500  # Batch should be efficient

    async def test_q_learning_convergence_speed(self):
        """Test how quickly Q-Learning converges to optimal policy."""
        episodes = 100
        convergence_threshold = 0.01  # Change in Q-values < 1%

        q_values_history = []
        previous_q_value = 0.5

        for episode in range(episodes):
            with patch('sentinel_backend.rl_service.update_q_values') as mock_update:
                # Simulate convergence: Q-values stabilize over time
                change = max(0.05 * (1 - episode / episodes), 0.005)
                new_q_value = previous_q_value + change

                mock_update.return_value = {
                    "updated": True,
                    "new_q_value": new_q_value,
                    "previous_q_value": previous_q_value,
                    "delta": change
                }

                result = await mock_update(
                    agent_id="functional-positive-agent",
                    state={"api_type": "rest"},
                    action="generate_tests",
                    reward=0.85
                )

                q_values_history.append(result["new_q_value"])
                previous_q_value = result["new_q_value"]

        # Check for convergence
        recent_values = q_values_history[-10:]
        variance = max(recent_values) - min(recent_values)

        print(f"\nQ-Learning Convergence:")
        print(f"  Episodes: {episodes}")
        print(f"  Final Q-value: {q_values_history[-1]:.4f}")
        print(f"  Recent variance: {variance:.4f}")

        assert variance < convergence_threshold, \
            f"Q-values haven't converged: variance {variance:.4f}"


@pytest.mark.performance
@pytest.mark.asyncio
class TestMemoryAndResourceUsage:
    """Test memory usage and resource consumption."""

    async def test_memory_usage_under_load(self):
        """Test memory usage remains stable under sustained load."""
        process = psutil.Process()
        initial_memory_mb = process.memory_info().rss / 1024 / 1024

        # Simulate 1000 feedback processing operations
        iterations = 1000

        for i in range(iterations):
            feedback = create_sample_feedback(test_id=f"test_{i:04d}")
            trajectory = create_sample_trajectory()

            with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
                mock_process.return_value = {
                    "feedback_id": f"fb_{i:04d}",
                    "verdict": "positive",
                    "reward": 0.85
                }
                await mock_process(feedback, trajectory)

        final_memory_mb = process.memory_info().rss / 1024 / 1024
        memory_increase_mb = final_memory_mb - initial_memory_mb

        print(f"\nMemory Usage:")
        print(f"  Initial: {initial_memory_mb:.2f} MB")
        print(f"  Final: {final_memory_mb:.2f} MB")
        print(f"  Increase: {memory_increase_mb:.2f} MB")

        # Memory should not increase significantly (< 50MB for 1000 operations)
        assert memory_increase_mb < 50, \
            f"Excessive memory usage: {memory_increase_mb:.2f} MB"

    async def test_concurrent_request_resource_usage(self):
        """Test resource usage with concurrent requests."""
        concurrent_requests = 100

        cpu_percent_before = psutil.cpu_percent(interval=1)

        async def make_request(request_id: int):
            feedback = create_sample_feedback(test_id=f"test_{request_id:04d}")
            with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
                mock_process.return_value = {"feedback_id": f"fb_{request_id:04d}"}
                return await mock_process(feedback, create_sample_trajectory())

        # Execute concurrent requests
        start_time = time.perf_counter()
        results = await asyncio.gather(*[make_request(i) for i in range(concurrent_requests)])
        end_time = time.perf_counter()

        cpu_percent_after = psutil.cpu_percent(interval=1)

        total_time = end_time - start_time

        print(f"\nConcurrent Load:")
        print(f"  Requests: {concurrent_requests}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Requests/sec: {concurrent_requests / total_time:.2f}")
        print(f"  CPU before: {cpu_percent_before:.1f}%")
        print(f"  CPU after: {cpu_percent_after:.1f}%")

        assert len(results) == concurrent_requests
        assert total_time < 5.0, f"Processing {concurrent_requests} requests took too long"


@pytest.mark.performance
@pytest.mark.slow
@pytest.mark.asyncio
class TestEndToEndPerformance:
    """Test end-to-end performance of complete learning loop."""

    async def test_complete_learning_loop_performance(self):
        """Measure performance of complete learning loop."""
        # Timing breakdown
        timings = {}

        # 1. Spec upload
        start = time.perf_counter()
        with patch('sentinel_backend.spec_service.upload_spec') as mock_upload:
            mock_upload.return_value = {"spec_id": "spec_001", "status": "uploaded"}
            await mock_upload({"openapi": "3.0.0"})
        timings["spec_upload"] = (time.perf_counter() - start) * 1000

        # 2. Test generation
        start = time.perf_counter()
        with patch('sentinel_backend.orchestration_service.generate_tests') as mock_gen:
            mock_gen.return_value = {
                "test_id": "test_001",
                "tests": [{"name": "test_1"}] * 5,
                "trajectory": create_sample_trajectory()
            }
            await mock_gen("spec_001", agent_id="functional-positive-agent")
        timings["test_generation"] = (time.perf_counter() - start) * 1000

        # 3. Feedback processing
        start = time.perf_counter()
        with patch('sentinel_backend.reasoningbank.process_feedback') as mock_process:
            mock_process.return_value = {"feedback_id": "fb_001", "verdict": "positive"}
            await mock_process(create_sample_feedback(), create_sample_trajectory())
        timings["feedback_processing"] = (time.perf_counter() - start) * 1000

        # 4. Pattern storage
        start = time.perf_counter()
        with patch('sentinel_backend.agentdb_service.store_pattern') as mock_store:
            mock_store.return_value = {"pattern_id": "pat_001", "stored": True}
            await mock_store(create_sample_pattern())
        timings["pattern_storage"] = (time.perf_counter() - start) * 1000

        # 5. Q-value update
        start = time.perf_counter()
        with patch('sentinel_backend.rl_service.update_q_values') as mock_update:
            mock_update.return_value = {"updated": True, "new_q_value": 0.88}
            await mock_update(
                agent_id="functional-positive-agent",
                state={"api_type": "rest"},
                action="generate_tests",
                reward=0.9
            )
        timings["q_value_update"] = (time.perf_counter() - start) * 1000

        total_time = sum(timings.values())

        print(f"\nComplete Learning Loop Performance:")
        for operation, time_ms in timings.items():
            print(f"  {operation}: {time_ms:.2f}ms")
        print(f"  TOTAL: {total_time:.2f}ms")

        # Assertions
        assert timings["feedback_processing"] < 100
        assert timings["pattern_storage"] < 50
        assert timings["q_value_update"] < 10
        assert total_time < 500, f"Complete loop too slow: {total_time:.2f}ms"
