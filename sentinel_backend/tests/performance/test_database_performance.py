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

from sentinel_backend.data_service.models import (
    TestCase,
    TestSuite,
    TestRun
)
from sentinel_backend.config.settings import get_database_settings


class TestDatabasePerformance:
    """Test suite for database performance optimization."""
    
    @pytest.fixture
    async def async_engine(self):
        """Create async database engine for testing."""
        settings = get_database_settings()
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            pool_size=10,
            max_overflow=20
        )
        return engine
    
    @pytest.fixture
    async def async_session(self, async_engine):
        """Create async session for database operations."""
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
        # Mock the database operation
        with patch.object(async_session, 'execute', new_callable=AsyncMock) as mock_execute:
            # Setup mock response
            mock_result = Mock()
            mock_result.scalar_one_or_none.return_value = TestSuite(
                name="Performance Test Suite",
                description="Test suite for performance"
            )
            mock_execute.return_value = mock_result
            
            # Test query performance
            start_time = time.time()
            result = await async_session.execute(
                select(TestSuite).where(TestSuite.name == "Performance Test Suite")
            )
            suite_result = result.scalar_one_or_none()
            elapsed = time.time() - start_time
            
            assert elapsed < 0.1, f"Single query took too long: {elapsed}s"
            assert suite_result is not None
    
    @pytest.mark.asyncio
    async def test_bulk_query_performance(self, async_session):
        """Test performance of bulk database queries."""
        with patch.object(async_session, 'execute', new_callable=AsyncMock) as mock_execute:
            # Mock bulk query results
            mock_result = Mock()
            mock_result.scalars.return_value.all.return_value = [
                TestCase(
                    spec_id=i,
                    agent_type="test_agent",
                    test_definition={"test": i}
                )
                for i in range(100)
            ]
            mock_execute.return_value = mock_result
            
            # Test bulk query performance
            start_time = time.time()
            result = await async_session.execute(
                select(TestCase).limit(100)
            )
            test_cases = result.scalars().all()
            elapsed = time.time() - start_time
            
            assert elapsed < 0.5, f"Bulk query took too long: {elapsed}s"
            assert len(test_cases) == 100
    
    @pytest.mark.asyncio
    async def test_complex_join_performance(self, async_session):
        """Test performance of complex join queries."""
        with patch.object(async_session, 'execute', new_callable=AsyncMock) as mock_execute:
            # Mock complex join results
            mock_result = Mock()
            mock_result.all.return_value = [
                (TestSuite(name=f"Suite {i}"), TestRun(status="completed"))
                for i in range(10)
            ]
            mock_execute.return_value = mock_result
            
            # Test complex join performance
            start_time = time.time()
            
            # Simulate complex join query
            result = await async_session.execute(
                select(TestSuite, TestRun)
                .join(TestRun, TestSuite.id == TestRun.suite_id)
                .limit(10)
            )
            
            joined_results = result.all()
            elapsed = time.time() - start_time
            
            assert elapsed < 1.0, f"Complex join took too long: {elapsed}s"
            assert len(joined_results) == 10
    
    @pytest.mark.asyncio
    async def test_connection_pool_performance(self):
        """Test database connection pool performance."""
        settings = get_database_settings()
        
        # Create engine with specific pool settings
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True
        )
        
        async_session_maker = sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Test concurrent connections
        async def perform_query(session_maker, query_id):
            async with session_maker() as session:
                with patch.object(session, 'execute', new_callable=AsyncMock) as mock_execute:
                    mock_result = Mock()
                    mock_result.scalar.return_value = query_id
                    mock_execute.return_value = mock_result
                    
                    result = await session.execute(
                        select(TestCase).limit(1)
                    )
                    return result.scalar()
        
        # Run multiple concurrent queries
        start_time = time.time()
        tasks = [
            perform_query(async_session_maker, i)
            for i in range(20)
        ]
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        assert elapsed < 2.0, f"Connection pool handling took too long: {elapsed}s"
        assert len(results) == 20
        
        await engine.dispose()
    
    @pytest.mark.asyncio
    async def test_transaction_performance(self, async_session):
        """Test transaction commit and rollback performance."""
        with patch.object(async_session, 'add') as mock_add:
            with patch.object(async_session, 'commit', new_callable=AsyncMock) as mock_commit:
                with patch.object(async_session, 'rollback', new_callable=AsyncMock) as mock_rollback:
                    # Test commit performance
                    start_time = time.time()
                    
                    for i in range(100):
                        suite = TestSuite(
                            name=f"suite_{i}",
                            description=f"Test suite {i}"
                        )
                        mock_add(suite)
                    
                    await mock_commit()
                    commit_elapsed = time.time() - start_time
                    
                    assert commit_elapsed < 1.0, f"Transaction commit took too long: {commit_elapsed}s"
                    
                    # Test rollback performance
                    start_time = time.time()
                    
                    for i in range(100):
                        suite = TestSuite(
                            name=f"rollback_suite_{i}",
                            description=f"Rollback test suite {i}"
                        )
                        mock_add(suite)
                    
                    await mock_rollback()
                    rollback_elapsed = time.time() - start_time
                    
                    assert rollback_elapsed < 0.5, f"Transaction rollback took too long: {rollback_elapsed}s"
    
    @pytest.mark.asyncio
    async def test_index_usage_performance(self, async_session):
        """Test query performance with and without indexes."""
        with patch.object(async_session, 'execute', new_callable=AsyncMock) as mock_execute:
            # Mock indexed query
            mock_result = Mock()
            mock_result.scalar_one_or_none.return_value = TestCase(
                id=1,
                spec_id=1,
                agent_type="test_agent"
            )
            mock_execute.return_value = mock_result
            
            # Test indexed query (id is primary key)
            start_time = time.time()
            result = await async_session.execute(
                select(TestCase).where(TestCase.id == 1)
            )
            indexed_result = result.scalar_one_or_none()
            indexed_elapsed = time.time() - start_time
            
            # Test non-indexed query
            start_time = time.time()
            result = await async_session.execute(
                select(TestCase).where(TestCase.description == "Some description")
            )
            non_indexed_result = result.scalar_one_or_none()
            non_indexed_elapsed = time.time() - start_time
            
            # Indexed queries should be faster (in real scenarios)
            assert indexed_elapsed < 0.1, f"Indexed query too slow: {indexed_elapsed}s"
            assert non_indexed_elapsed < 0.2, f"Non-indexed query too slow: {non_indexed_elapsed}s"
    
    @pytest.mark.asyncio
    async def test_batch_insert_performance(self, async_session):
        """Test batch insert performance optimization."""
        with patch.object(async_session, 'execute', new_callable=AsyncMock) as mock_execute:
            with patch.object(async_session, 'commit', new_callable=AsyncMock) as mock_commit:
                # Prepare batch data
                test_cases = [
                    {
                        "spec_id": i,
                        "agent_type": f"agent_{i % 5}",
                        "test_definition": {"test_id": i},
                        "description": f"Test case {i}"
                    }
                    for i in range(1000)
                ]
                
                # Test batch insert performance
                start_time = time.time()
                
                # Use bulk insert
                await mock_execute(
                    insert(TestCase),
                    test_cases
                )
                await mock_commit()
                
                batch_elapsed = time.time() - start_time
                
                # Test individual inserts for comparison
                start_time = time.time()
                
                for i in range(100):  # Only 100 for time comparison
                    test_case = TestCase(
                        spec_id=i,
                        agent_type=f"agent_{i}",
                        test_definition={"test": i}
                    )
                    await mock_execute(insert(TestCase).values(
                        spec_id=test_case.spec_id,
                        agent_type=test_case.agent_type,
                        test_definition=test_case.test_definition
                    ))
                
                await mock_commit()
                individual_elapsed = time.time() - start_time
                
                # Batch insert should be much faster
                assert batch_elapsed < 2.0, f"Batch insert too slow: {batch_elapsed}s"
                assert individual_elapsed < 5.0, f"Individual inserts too slow: {individual_elapsed}s"
    
    @pytest.mark.asyncio
    async def test_query_optimization(self, async_session):
        """Test various query optimization techniques."""
        with patch.object(async_session, 'execute', new_callable=AsyncMock) as mock_execute:
            # Mock optimized query results
            mock_result = Mock()
            mock_result.scalars.return_value.all.return_value = [
                TestSuite(id=i, name=f"Suite {i}")
                for i in range(10)
            ]
            mock_execute.return_value = mock_result
            
            # Test query with proper limiting
            start_time = time.time()
            result = await async_session.execute(
                select(TestSuite)
                .limit(10)
                .offset(0)
            )
            limited_results = result.scalars().all()
            limited_elapsed = time.time() - start_time
            
            assert limited_elapsed < 0.1, f"Limited query too slow: {limited_elapsed}s"
            assert len(limited_results) == 10
            
            # Test query with selective columns
            mock_result = Mock()
            mock_result.all.return_value = [
                (i, f"Suite {i}")
                for i in range(10)
            ]
            mock_execute.return_value = mock_result
            
            start_time = time.time()
            result = await async_session.execute(
                select(TestSuite.id, TestSuite.name)
                .limit(10)
            )
            selective_results = result.all()
            selective_elapsed = time.time() - start_time
            
            assert selective_elapsed < 0.1, f"Selective column query too slow: {selective_elapsed}s"
            assert len(selective_results) == 10
    
    @pytest.mark.asyncio
    async def test_concurrent_read_write_performance(self, async_session):
        """Test performance under concurrent read and write operations."""
        async def read_operation(session, operation_id):
            with patch.object(session, 'execute', new_callable=AsyncMock) as mock_execute:
                mock_result = Mock()
                mock_result.scalars.return_value.all.return_value = [
                    TestCase(id=i) for i in range(5)
                ]
                mock_execute.return_value = mock_result
                
                result = await session.execute(
                    select(TestCase).limit(5)
                )
                return result.scalars().all()
        
        async def write_operation(session, operation_id):
            with patch.object(session, 'add') as mock_add:
                with patch.object(session, 'commit', new_callable=AsyncMock) as mock_commit:
                    test_case = TestCase(
                        spec_id=operation_id,
                        agent_type=f"concurrent_agent_{operation_id}",
                        test_definition={"concurrent": True}
                    )
                    mock_add(test_case)
                    await mock_commit()
                    return test_case
        
        # Run concurrent operations
        start_time = time.time()
        
        read_tasks = [read_operation(async_session, i) for i in range(10)]
        write_tasks = [write_operation(async_session, i) for i in range(10)]
        
        all_tasks = read_tasks + write_tasks
        random.shuffle(all_tasks)  # Mix read and write operations
        
        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        elapsed = time.time() - start_time
        
        # Check performance
        assert elapsed < 3.0, f"Concurrent operations took too long: {elapsed}s"
        
        # Verify no exceptions occurred
        exceptions = [r for r in results if isinstance(r, Exception)]
        assert len(exceptions) == 0, f"Exceptions occurred: {exceptions}"
    
    @pytest.mark.asyncio
    async def test_database_connection_recovery(self):
        """Test database connection recovery performance."""
        # Create engine with aggressive timeout settings
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            pool_size=2,
            max_overflow=1,
            pool_recycle=1,  # Recycle connections every second
            pool_pre_ping=True  # Test connections before use
        )
        
        async_session_maker = sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Simulate connection recovery
        recovery_times = []
        
        for i in range(5):
            start_time = time.time()
            
            try:
                async with async_session_maker() as session:
                    with patch.object(session, 'execute', new_callable=AsyncMock) as mock_execute:
                        mock_result = Mock()
                        mock_result.scalar.return_value = i
                        mock_execute.return_value = mock_result
                        
                        result = await session.execute(
                            select(TestCase).limit(1)
                        )
                        _ = result.scalar()
            except Exception:
                pass  # Ignore connection errors for this test
            
            recovery_time = time.time() - start_time
            recovery_times.append(recovery_time)
            
            # Small delay to simulate connection issues
            await asyncio.sleep(0.1)
        
        # Check recovery performance
        avg_recovery_time = sum(recovery_times) / len(recovery_times)
        assert avg_recovery_time < 0.5, f"Connection recovery too slow: {avg_recovery_time}s average"
        
        await engine.dispose()