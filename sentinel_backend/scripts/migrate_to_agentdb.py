#!/usr/bin/env python3
"""
Migrate Existing Test Data to AgentDB Vectors

This script migrates existing test cases and execution results from
PostgreSQL to AgentDB vector storage for semantic search.
"""

import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import logging

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, selectinload

from data_service.models import TestCase, TestResult
from agentdb_service.agentdb_client import AgentDBClient
from agentdb_service.embedding_service import EmbeddingService
from agentdb_service.vector_storage import VectorStorage
from config.settings import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def get_db_session():
    """Create async database session."""
    settings = get_settings()
    engine = create_async_engine(settings.database.url, echo=False)
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    return async_session


def extract_endpoint(test_definition: dict) -> str:
    """Extract endpoint from test definition."""
    return test_definition.get("endpoint", test_definition.get("path", "unknown"))


def extract_method(test_definition: dict) -> str:
    """Extract HTTP method from test definition."""
    return test_definition.get("method", "GET")


def extract_parameters(test_definition: dict) -> dict:
    """Extract parameters from test definition."""
    return {
        "path": test_definition.get("path_params", {}),
        "query": test_definition.get("query_params", {}),
        "headers": test_definition.get("headers", {}),
        "body": test_definition.get("body", {})
    }


def calculate_success_rate(test_results: list) -> float:
    """Calculate success rate from test results."""
    if not test_results:
        return 0.0

    passed = sum(1 for r in test_results if r.status == "pass")
    return passed / len(test_results)


async def migrate_test_patterns(
    session_maker,
    vector_storage: VectorStorage,
    batch_size: int = 100
):
    """
    Migrate test cases to vector patterns.

    Args:
        session_maker: SQLAlchemy session maker
        vector_storage: Vector storage instance
        batch_size: Number of patterns per batch
    """
    logger.info("Starting test pattern migration...")

    async with session_maker() as session:
        # Count total test cases
        result = await session.execute(select(TestCase))
        test_cases = result.scalars().all()
        total = len(test_cases)

        logger.info(f"Found {total} test cases to migrate")

        if total == 0:
            logger.warning("No test cases found to migrate")
            return

        # Migrate in batches
        migrated = 0
        for i in tqdm(range(0, total, batch_size), desc="Migrating patterns"):
            batch = test_cases[i:i + batch_size]

            # Extract patterns
            patterns = []
            for test in batch:
                try:
                    # Get test results for success rate
                    result = await session.execute(
                        select(TestResult)
                        .where(TestResult.case_id == test.id)
                    )
                    test_results = result.scalars().all()

                    pattern = {
                        "test_id": test.id,
                        "endpoint": extract_endpoint(test.test_definition),
                        "method": extract_method(test.test_definition),
                        "parameters": extract_parameters(test.test_definition),
                        "agent_type": test.agent_type,
                        "tags": test.tags or [],
                        "success_rate": calculate_success_rate(test_results),
                        "test_count": len(test_results),
                        "created_at": test.created_at.isoformat() if test.created_at else None,
                        "description": test.description
                    }
                    patterns.append(pattern)

                except Exception as e:
                    logger.error(f"Failed to extract pattern from test {test.id}: {e}")

            # Batch insert to AgentDB
            if patterns:
                try:
                    pattern_ids = await vector_storage.batch_store_patterns(patterns)
                    migrated += len(pattern_ids)
                    logger.info(f"Migrated batch {i//batch_size + 1}: {len(pattern_ids)} patterns")
                except Exception as e:
                    logger.error(f"Failed to migrate batch: {e}")

    logger.info(f"✅ Migration complete: {migrated}/{total} test patterns migrated")


async def migrate_execution_results(
    session_maker,
    vector_storage: VectorStorage,
    batch_size: int = 100,
    limit: int = None
):
    """
    Migrate test execution results to vectors.

    Args:
        session_maker: SQLAlchemy session maker
        vector_storage: Vector storage instance
        batch_size: Number of results per batch
        limit: Optional limit on number of results to migrate
    """
    logger.info("Starting execution result migration...")

    async with session_maker() as session:
        # Get test results with test case info
        query = select(TestResult).options(selectinload(TestResult.test_case))

        if limit:
            query = query.limit(limit)

        result = await session.execute(query)
        test_results = result.scalars().all()
        total = len(test_results)

        logger.info(f"Found {total} execution results to migrate")

        if total == 0:
            logger.warning("No execution results found to migrate")
            return

        # Migrate in batches
        migrated = 0
        for i in tqdm(range(0, total, batch_size), desc="Migrating results"):
            batch = test_results[i:i + batch_size]

            for result in batch:
                try:
                    # Extract execution data
                    test_case = result.test_case
                    if not test_case:
                        continue

                    execution_data = {
                        "test_id": result.case_id,
                        "status": result.status,
                        "endpoint": extract_endpoint(test_case.test_definition),
                        "method": extract_method(test_case.test_definition),
                        "response_code": result.response_code or 0,
                        "latency_ms": result.latency_ms or 0,
                        "assertions": {
                            "passed": 1 if result.status == "pass" else 0,
                            "failed": 1 if result.status == "fail" else 0
                        },
                        "error_pattern": None if result.status == "pass" else "failure",
                        "executed_at": result.executed_at.isoformat() if result.executed_at else None
                    }

                    # Store in AgentDB
                    await vector_storage.store_execution_result(
                        test_id=str(result.case_id),
                        result=execution_data
                    )

                    migrated += 1

                except Exception as e:
                    logger.error(f"Failed to migrate result {result.id}: {e}")

            logger.info(f"Migrated batch {i//batch_size + 1}: {min(batch_size, len(batch))} results")

    logger.info(f"✅ Migration complete: {migrated}/{total} execution results migrated")


async def main():
    """Main migration function."""
    print("="*80)
    print("AgentDB Migration Script")
    print("="*80)
    print(f"Started at: {datetime.now().isoformat()}")
    print()

    # Initialize services
    logger.info("Initializing services...")
    agentdb_client = AgentDBClient(collection_prefix="sentinel")
    embedding_service = EmbeddingService(model_name="all-MiniLM-L6-v2")
    vector_storage = VectorStorage(agentdb_client, embedding_service)

    await vector_storage.initialize()
    logger.info("✅ Services initialized")

    # Get database session
    logger.info("Connecting to database...")
    session_maker = await get_db_session()
    logger.info("✅ Database connected")

    print()
    print("-"*80)

    # Migrate test patterns
    await migrate_test_patterns(session_maker, vector_storage, batch_size=100)

    print()
    print("-"*80)

    # Migrate execution results (limit to recent results for performance)
    await migrate_execution_results(
        session_maker,
        vector_storage,
        batch_size=100,
        limit=10000  # Migrate last 10K results
    )

    print()
    print("-"*80)

    # Get statistics
    logger.info("Generating statistics...")
    stats = await vector_storage.get_collection_stats()

    print()
    print("="*80)
    print("MIGRATION SUMMARY")
    print("="*80)
    print(f"Total vectors:     {stats['total_vectors']}")
    print(f"Memory usage:      {stats['total_memory_mb']:.2f} MB")
    print(f"Embedding dim:     {stats['embedding_dimension']}")
    print()
    print("Collections:")
    for name, col_stats in stats['collections'].items():
        print(f"  {name}:")
        print(f"    Vectors: {col_stats['vector_count']}")
        print(f"    Memory:  {col_stats.get('memory_mb', 0):.2f} MB")
    print()
    print(f"Completed at: {datetime.now().isoformat()}")
    print("="*80)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nMigration interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        sys.exit(1)
