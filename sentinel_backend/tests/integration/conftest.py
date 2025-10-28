"""
Integration Test Configuration

Provides shared fixtures for integration tests with real database operations.
"""

import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text

from sentinel_backend.models.feedback import Base as FeedbackBase

# Import trajectory base directly to avoid pgvector dependency
from sqlalchemy.orm import declarative_base
TrajectoryBase = declarative_base()


@pytest_asyncio.fixture(scope="session")
async def test_db_engine():
    """
    Create test database engine for the entire test session.

    Uses a separate test database to avoid interfering with development data.
    """
    # Get database URL from environment or use default
    db_url = os.environ.get(
        "SENTINEL_DB_URL",
        "postgresql+asyncpg://sentinel:sentinel_password@localhost:5432/sentinel_db"
    )

    # Use dedicated test database
    test_db_url = db_url.replace("sentinel_db", "sentinel_test_db")

    # Create engine
    engine = create_async_engine(
        test_db_url,
        pool_size=5,
        max_overflow=10,
        pool_timeout=30,
        pool_recycle=3600,
        echo=False  # Set to True for SQL debugging
    )

    # Ensure test database exists
    async with engine.begin() as conn:
        # Create extensions if needed
        try:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgvector"))
        except Exception:
            pass  # Extension might not be available in test environment

    yield engine

    # Cleanup
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def test_db_session(test_db_engine) -> AsyncGenerator[AsyncSession, None]:
    """
    Create a fresh database session for each test.

    This fixture:
    1. Creates all tables before the test
    2. Provides an isolated session
    3. Cleans up all data after the test
    4. Drops all tables after cleanup

    This ensures complete isolation between tests.
    """
    # Create all tables
    async with test_db_engine.begin() as conn:
        await conn.run_sync(FeedbackBase.metadata.create_all)
        await conn.run_sync(TrajectoryBase.metadata.create_all)

    # Create session
    async_session_maker = async_sessionmaker(
        test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    async with async_session_maker() as session:
        try:
            yield session
        finally:
            # Rollback any uncommitted changes
            await session.rollback()

            # Delete all records from all tables
            async with test_db_engine.begin() as conn:
                for table in reversed(FeedbackBase.metadata.sorted_tables):
                    await conn.execute(table.delete())
                for table in reversed(TrajectoryBase.metadata.sorted_tables):
                    await conn.execute(table.delete())

    # Drop all tables
    async with test_db_engine.begin() as conn:
        await conn.run_sync(FeedbackBase.metadata.drop_all)
        await conn.run_sync(TrajectoryBase.metadata.drop_all)


@pytest.fixture
def sample_api_spec():
    """Sample OpenAPI specification for testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0",
            "description": "API for integration testing"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "List all users",
                    "operationId": "listUsers",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {"type": "integer", "default": 20}
                        },
                        {
                            "name": "offset",
                            "in": "query",
                            "schema": {"type": "integer", "default": 0}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "id": {"type": "integer"},
                                                "name": {"type": "string"},
                                                "email": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create a new user",
                    "operationId": "createUser",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name", "email"],
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string", "format": "email"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "User created successfully"
                        },
                        "400": {
                            "description": "Invalid input"
                        }
                    }
                }
            },
            "/users/{userId}": {
                "get": {
                    "summary": "Get user by ID",
                    "operationId": "getUserById",
                    "parameters": [
                        {
                            "name": "userId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"}
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User found"
                        },
                        "404": {
                            "description": "User not found"
                        }
                    }
                }
            }
        }
    }
