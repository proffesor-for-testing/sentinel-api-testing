"""
Session Manager for ReasoningBank Services

Provides proper database session lifecycle management using the session factory
pattern to prevent resource leaks, connection pool exhaustion, and deadlocks.

Key Features:
- Session factory pattern with context managers
- Automatic commit/rollback handling
- Connection pool management
- Multi-worker safe (each worker gets its own session)
- Proper cleanup on shutdown

Usage:
    ```python
    # Initialize with engine
    manager = SessionManager(db_engine)

    # Use context manager for automatic lifecycle
    async with manager.get_session() as session:
        result = await session.execute(query)
        # Session automatically commits on success, rolls back on error
    ```
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Manages database session lifecycle using the session factory pattern.

    This class solves the single-shared-session anti-pattern by:
    1. Creating a session factory instead of reusing one session
    2. Providing context managers for automatic lifecycle management
    3. Ensuring each operation gets a clean session
    4. Handling commit/rollback transparently
    5. Managing connection pool properly
    """

    def __init__(
        self,
        engine: AsyncEngine,
        expire_on_commit: bool = False,
        autoflush: bool = False,
        autocommit: bool = False,
    ):
        """
        Initialize session manager with database engine.

        Args:
            engine: SQLAlchemy AsyncEngine for database connection
            expire_on_commit: Whether to expire objects after commit
            autoflush: Whether to automatically flush before queries
            autocommit: Whether to automatically commit (should be False)
        """
        self.engine = engine

        # Create async session factory
        self.session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=expire_on_commit,
            autoflush=autoflush,
            autocommit=autocommit,
        )

        logger.info(
            f"SessionManager initialized with "
            f"expire_on_commit={expire_on_commit}, "
            f"autoflush={autoflush}"
        )

    @asynccontextmanager
    async def get_session(
        self,
        commit_on_exit: bool = True,
    ) -> AsyncIterator[AsyncSession]:
        """
        Context manager that provides a database session with automatic lifecycle.

        The session is automatically:
        - Created when entering the context
        - Committed on successful exit (if commit_on_exit=True)
        - Rolled back on exception
        - Closed when exiting the context

        Args:
            commit_on_exit: Whether to auto-commit on successful exit

        Yields:
            AsyncSession: Database session

        Example:
            ```python
            async with session_manager.get_session() as session:
                result = await session.execute(query)
                # Automatically commits and closes session
            ```
        """
        session = self.session_factory()

        try:
            yield session

            if commit_on_exit:
                await session.commit()
                logger.debug("Session committed successfully")

        except Exception as e:
            await session.rollback()
            logger.error(f"Session rolled back due to error: {e}")
            raise

        finally:
            await session.close()
            logger.debug("Session closed")

    @asynccontextmanager
    async def get_read_only_session(self) -> AsyncIterator[AsyncSession]:
        """
        Context manager for read-only operations (no commit).

        Use this for queries that don't modify data to avoid unnecessary commits.

        Yields:
            AsyncSession: Read-only database session
        """
        async with self.get_session(commit_on_exit=False) as session:
            yield session

    async def execute_in_session(
        self,
        func,
        *args,
        commit: bool = True,
        **kwargs
    ):
        """
        Execute a function within a managed session context.

        Args:
            func: Async function to execute (receives session as first arg)
            *args: Additional arguments to pass to function
            commit: Whether to commit on success
            **kwargs: Keyword arguments to pass to function

        Returns:
            Result of the function

        Example:
            ```python
            async def create_pattern(session, pattern_data):
                pattern = PatternEmbedding(**pattern_data)
                session.add(pattern)
                return pattern

            pattern = await session_manager.execute_in_session(
                create_pattern,
                pattern_data={"title": "Test Pattern"}
            )
            ```
        """
        async with self.get_session(commit_on_exit=commit) as session:
            return await func(session, *args, **kwargs)

    async def health_check(self) -> bool:
        """
        Check if database connection is healthy.

        Returns:
            bool: True if connection is healthy
        """
        try:
            async with self.get_read_only_session() as session:
                await session.execute("SELECT 1")
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    async def dispose(self):
        """
        Dispose of the engine and cleanup connections.

        Call this on shutdown to properly clean up resources.
        """
        if self.engine:
            await self.engine.dispose()
            logger.info("Database engine disposed")

    def get_session_factory(self) -> async_sessionmaker:
        """
        Get the underlying session factory.

        Use this when you need more control over session creation.

        Returns:
            async_sessionmaker: The session factory
        """
        return self.session_factory


class ServiceSessionMixin:
    """
    Mixin for services that need database sessions.

    Provides consistent session access patterns across all services.
    """

    def __init__(self, session_manager: SessionManager):
        """
        Initialize service with session manager.

        Args:
            session_manager: SessionManager instance for database access
        """
        self.session_manager = session_manager

    @asynccontextmanager
    async def _get_session(self) -> AsyncIterator[AsyncSession]:
        """Get a database session via the session manager."""
        async with self.session_manager.get_session() as session:
            yield session

    @asynccontextmanager
    async def _get_read_session(self) -> AsyncIterator[AsyncSession]:
        """Get a read-only database session."""
        async with self.session_manager.get_read_only_session() as session:
            yield session


def create_session_manager(
    database_url: str,
    pool_size: int = 20,
    max_overflow: int = 10,
    pool_timeout: int = 30,
    pool_recycle: int = 3600,
    echo: bool = False,
) -> SessionManager:
    """
    Create a SessionManager with a new AsyncEngine.

    Args:
        database_url: Database connection URL
        pool_size: Number of connections to maintain in the pool
        max_overflow: Max additional connections beyond pool_size
        pool_timeout: Seconds to wait for connection before timeout
        pool_recycle: Seconds before recycling connections
        echo: Whether to log all SQL statements

    Returns:
        SessionManager: Configured session manager

    Example:
        ```python
        manager = create_session_manager(
            database_url="postgresql+asyncpg://user:pass@localhost/db",
            pool_size=20,
            echo=False
        )
        ```
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(
        database_url,
        echo=echo,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=pool_recycle,
        pool_pre_ping=True,  # Verify connections before use
    )

    return SessionManager(engine=engine)
