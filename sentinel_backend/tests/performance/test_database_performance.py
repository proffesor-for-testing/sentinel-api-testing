"""
Database performance tests for the Sentinel platform.

This module tests database query performance, connection pooling,
transaction handling, and database operation optimization.
"""

import asyncio
import pytest
import time
from typing import List, Dict, Any
from unittest.mock import Mock, AsyncMock, patch
import random
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, insert, update, delete
import uuid

from sentinel_backend.database.models import (
    Specification,
    TestCase,
    TestSuite,
    TestRun,
    User
)
from sentinel_backend.config.settings import get_database_settings


class TestDatabasePerformance:
    """Test suite for database performance."""
    
    @pytest.fixture
    async def async_engine(self):
        """Create async database engine for testing."""
        settings = get_database_settings()
        engine = create_async_engine(
            settings.url.replace("postgresql://", "postgresql+asyncpg://"),
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True
        )
        yield engine
        await engine.dispose()
    
    @pytest.fixture
    async def async_session(self, async_engine):
        """Create async database session."""
        async_session_maker = sessionmaker(
            async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        async with async_session_maker() as session:
            yield session
    
    @pytest.mark.asyncio
    async def test_single_query_performance(self, async_session):
        """Test performance of single database queries."""
        # Insert test data
        spec = Specification(
            name="Performance Test Spec",
            content={"openapi": "3.0.0"},
            created_by="test_user"
        )
        async_session.add(spec)
        await async_session.commit()
        
        # Test query performance
        start_time = time.time()
        result = await async_session.execute(
            select(Specification).where(Specification.name == "Performance Test Spec")
        )
        spec_result = result.scalar_one_or_none()
        elapsed = time.time() - start_time
        
        assert elapsed < 0.1, f"Single query took too long: {elapsed}s"
        assert spec_result is not None
        
        # Cleanup
        await async_session.delete(spec)
        await async_session.commit()
    
    @pytest.mark.asyncio
    async def test_bulk_insert_performance(self, async_session):
        """Test performance of bulk insert operations."""
        num_records = 1000
        test_cases = []
        
        for i in range(num_records):
            test_case = TestCase(
                name=f"Test Case {i}",
                method="GET",
                path=f"/endpoint{i}",
                expected_status=200,
                spec_id=1,
                suite_id=1,
                created_by="test_user"
            )
            test_cases.append(test_case)
        
        start_time = time.time()
        async_session.add_all(test_cases)
        await async_session.commit()
        elapsed = time.time() - start_time
        
        # Should insert 1000 records in under 5 seconds
        assert elapsed < 5.0, f"Bulk insert took too long: {elapsed}s"
        
        # Verify insertion
        result = await async_session.execute(
            select(TestCase).where(TestCase.name.like("Test Case%"))
        )
        inserted_count = len(result.scalars().all())
        assert inserted_count == num_records
        
        # Cleanup
        await async_session.execute(
            delete(TestCase).where(TestCase.name.like("Test Case%"))
        )
        await async_session.commit()
    
    @pytest.mark.asyncio
    async def test_concurrent_read_performance(self, async_engine):
        """Test performance of concurrent read operations."""
        async def read_operation(session_maker, query_id):
            async with session_maker() as session:
                start = time.time()
                result = await session.execute(
                    select(Specification).limit(10)
                )
                _ = result.scalars().all()
                return time.time() - start
        
        session_maker = sessionmaker(
            async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Run 20 concurrent read operations
        tasks = [read_operation(session_maker, i) for i in range(20)]
        
        start_time = time.time()
        response_times = await asyncio.gather(*tasks)
        total_elapsed = time.time() - start_time
        
        avg_response_time = sum(response_times) / len(response_times)
        
        assert total_elapsed < 2.0, f"Concurrent reads took too long: {total_elapsed}s"
        assert avg_response_time < 0.5, f"Average read time too high: {avg_response_time}s"
    
    @pytest.mark.asyncio
    async def test_transaction_performance(self, async_session):
        """Test performance of database transactions."""
        async def transaction_operation():
            start = time.time()
            
            # Begin transaction
            async with async_session.begin():
                # Multiple operations in transaction
                spec = Specification(
                    name=f"Transaction Test {uuid.uuid4()}",
                    content={"test": "data"},
                    created_by="test_user"
                )
                async_session.add(spec)
                
                await async_session.flush()
                
                suite = TestSuite(
                    name=f"Suite for {spec.name}",
                    spec_id=spec.id,
                    created_by="test_user"
                )
                async_session.add(suite)
                
                # Transaction commits automatically
            
            return time.time() - start
        
        # Run multiple transactions
        transaction_times = []
        for _ in range(10):
            elapsed = await transaction_operation()
            transaction_times.append(elapsed)
        
        avg_transaction_time = sum(transaction_times) / len(transaction_times)
        
        assert avg_transaction_time < 0.2, f"Average transaction time too high: {avg_transaction_time}s"
    
    @pytest.mark.asyncio
    async def test_index_performance(self, async_session):
        """Test performance impact of database indexes."""
        # Create test data
        num_records = 500
        for i in range(num_records):
            test_run = TestRun(
                suite_id=random.randint(1, 10),
                environment="test",
                base_url=f"http://api{i}.example.com",
                status="completed",
                created_by=f"user_{i % 10}"
            )
            async_session.add(test_run)
        
        await async_session.commit()
        
        # Test indexed query (assuming created_at is indexed)
        start_time = time.time()
        result = await async_session.execute(
            select(TestRun).order_by(TestRun.created_at.desc()).limit(100)
        )
        _ = result.scalars().all()
        indexed_time = time.time() - start_time
        
        # Test non-indexed query (assuming base_url is not indexed)
        start_time = time.time()
        result = await async_session.execute(
            select(TestRun).where(TestRun.base_url.like("%api123%"))
        )
        _ = result.scalars().all()
        non_indexed_time = time.time() - start_time
        
        # Indexed queries should be faster
        assert indexed_time < 0.1, f"Indexed query too slow: {indexed_time}s"
        
        # Cleanup
        await async_session.execute(
            delete(TestRun).where(TestRun.environment == "test")
        )
        await async_session.commit()
    
    @pytest.mark.asyncio
    async def test_connection_pool_performance(self, async_engine):
        """Test database connection pool performance."""
        async def use_connection(session_maker, operation_id):
            async with session_maker() as session:
                # Simulate some database work
                result = await session.execute(
                    select(User).limit(1)
                )
                _ = result.scalar_one_or_none()
                await asyncio.sleep(random.uniform(0.01, 0.05))
                return operation_id
        
        session_maker = sessionmaker(
            async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create more tasks than pool size to test queuing
        num_operations = 50
        tasks = [use_connection(session_maker, i) for i in range(num_operations)]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        assert len(results) == num_operations
        assert elapsed < 5.0, f"Connection pool operations took too long: {elapsed}s"
    
    @pytest.mark.asyncio
    async def test_query_optimization(self, async_session):
        """Test query optimization techniques."""
        # Create test data with relationships
        spec = Specification(
            name="Query Optimization Test",
            content={"test": "data"},
            created_by="test_user"
        )
        async_session.add(spec)
        await async_session.flush()
        
        for i in range(20):
            suite = TestSuite(
                name=f"Suite {i}",
                spec_id=spec.id,
                created_by="test_user"
            )
            async_session.add(suite)
        
        await async_session.commit()
        
        # Test N+1 query problem (bad practice)
        start_time = time.time()
        result = await async_session.execute(select(TestSuite))
        suites = result.scalars().all()
        for suite in suites:
            # This would cause N+1 queries in a real scenario
            _ = suite.spec_id
        n_plus_one_time = time.time() - start_time
        
        # Test with joined loading (good practice)
        from sqlalchemy.orm import joinedload
        start_time = time.time()
        result = await async_session.execute(
            select(TestSuite).options(joinedload(TestSuite.specification))
        )
        suites = result.unique().scalars().all()
        joined_time = time.time() - start_time
        
        # Joined loading should be faster or comparable
        assert joined_time <= n_plus_one_time * 1.5
        
        # Cleanup
        await async_session.execute(
            delete(TestSuite).where(TestSuite.name.like("Suite%"))
        )
        await async_session.delete(spec)
        await async_session.commit()
    
    @pytest.mark.asyncio
    async def test_database_lock_performance(self, async_engine):
        """Test performance under database lock contention."""
        async def update_with_lock(session_maker, record_id):
            async with session_maker() as session:
                async with session.begin():
                    # Simulate row-level locking
                    result = await session.execute(
                        select(Specification)
                        .where(Specification.id == record_id)
                        .with_for_update()
                    )
                    spec = result.scalar_one_or_none()
                    if spec:
                        spec.name = f"Updated {time.time()}"
                        await asyncio.sleep(0.01)  # Simulate processing
        
        session_maker = sessionmaker(
            async_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create a test record
        async with session_maker() as session:
            spec = Specification(
                name="Lock Test",
                content={},
                created_by="test_user"
            )
            session.add(spec)
            await session.commit()
            spec_id = spec.id
        
        # Multiple concurrent updates to same record
        tasks = [update_with_lock(session_maker, spec_id) for _ in range(5)]
        
        start_time = time.time()
        await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        # Should handle lock contention gracefully
        assert elapsed < 2.0, f"Lock contention handling took too long: {elapsed}s"
        
        # Cleanup
        async with session_maker() as session:
            spec = await session.get(Specification, spec_id)
            await session.delete(spec)
            await session.commit()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])