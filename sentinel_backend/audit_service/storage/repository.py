"""
Event Repository - Database operations for audit events

Provides high-performance event storage and retrieval with TimescaleDB optimization.
"""

import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, AsyncEngine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, func, and_, or_, text, desc, asc
from sqlalchemy.dialects.postgresql import insert
import logging

from .database_schema import (
    EventRecord, EventRetentionPolicy, EventSnapshot,
    ComplianceReport, TIMESCALEDB_INIT_SQL
)
from ..models.events import (
    AuditEvent, EventFilter, EventStatistics, EventBatch,
    EventType, EventSeverity, EventOutcome
)

logger = logging.getLogger(__name__)


class EventRepository:
    """
    Repository for audit event persistence and querying.

    Optimized for:
    - Time-series queries
    - High write throughput
    - Efficient pagination
    - Complex filtering
    """

    def __init__(self, database_url: str):
        """
        Initialize repository.

        Args:
            database_url: PostgreSQL connection URL
        """
        self.database_url = database_url
        self.engine: Optional[AsyncEngine] = None
        self.session_maker: Optional[sessionmaker] = None

    async def initialize(self):
        """Initialize database connection and schema."""
        # Create async engine
        self.engine = create_async_engine(
            self.database_url,
            echo=False,
            pool_size=20,
            max_overflow=40,
            pool_pre_ping=True
        )

        # Create session maker
        self.session_maker = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        # Initialize schema
        await self._init_schema()

        logger.info("Event repository initialized")

    async def _init_schema(self):
        """Initialize database schema."""
        try:
            from .database_schema import Base

            async with self.engine.begin() as conn:
                # Create tables
                await conn.run_sync(Base.metadata.create_all)

                # Initialize TimescaleDB if available
                try:
                    await conn.execute(text(TIMESCALEDB_INIT_SQL))
                    logger.info("TimescaleDB hypertable initialized")
                except Exception as e:
                    logger.warning(f"TimescaleDB initialization skipped: {e}")

            logger.info("Database schema initialized")
        except Exception as e:
            logger.error(f"Failed to initialize schema: {e}")
            raise

    async def close(self):
        """Close database connections."""
        if self.engine:
            await self.engine.dispose()
            logger.info("Event repository closed")

    async def save_event(self, event: AuditEvent) -> EventRecord:
        """
        Save single event to database.

        Args:
            event: Event to save

        Returns:
            Saved event record
        """
        async with self.session_maker() as session:
            record = self._event_to_record(event)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            return record

    async def save_batch(self, batch: EventBatch) -> List[EventRecord]:
        """
        Save event batch (optimized bulk insert).

        Args:
            batch: Event batch

        Returns:
            List of saved records
        """
        if not batch.events:
            return []

        async with self.session_maker() as session:
            # Convert to records
            records = [self._event_to_record(event) for event in batch.events]

            # Bulk insert
            session.add_all(records)
            await session.commit()

            # Refresh records
            for record in records:
                await session.refresh(record)

            logger.debug(f"Saved batch of {len(records)} events")
            return records

    async def query_events(
        self,
        filter_criteria: EventFilter
    ) -> Tuple[List[EventRecord], int]:
        """
        Query events with filtering and pagination.

        Args:
            filter_criteria: Filter criteria

        Returns:
            Tuple of (events, total_count)
        """
        async with self.session_maker() as session:
            # Build query
            query = select(EventRecord).where(EventRecord.is_deleted == False)

            # Apply filters
            query = self._apply_filters(query, filter_criteria)

            # Get total count
            count_query = select(func.count()).select_from(query.subquery())
            total_count = await session.scalar(count_query)

            # Apply sorting
            if filter_criteria.sort_order.lower() == "desc":
                query = query.order_by(desc(getattr(EventRecord, filter_criteria.sort_by)))
            else:
                query = query.order_by(asc(getattr(EventRecord, filter_criteria.sort_by)))

            # Apply pagination
            query = query.limit(filter_criteria.limit).offset(filter_criteria.offset)

            # Execute query
            result = await session.execute(query)
            events = result.scalars().all()

            return events, total_count

    async def get_event_by_id(self, event_id: UUID) -> Optional[EventRecord]:
        """Get event by ID."""
        async with self.session_maker() as session:
            result = await session.execute(
                select(EventRecord).where(
                    and_(
                        EventRecord.id == event_id,
                        EventRecord.is_deleted == False
                    )
                )
            )
            return result.scalar_one_or_none()

    async def get_statistics(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> EventStatistics:
        """
        Get event statistics for time range.

        Args:
            start_time: Start time (default: 24 hours ago)
            end_time: End time (default: now)

        Returns:
            Event statistics
        """
        if not start_time:
            start_time = datetime.utcnow() - timedelta(hours=24)
        if not end_time:
            end_time = datetime.utcnow()

        async with self.session_maker() as session:
            # Total events
            total = await session.scalar(
                select(func.count()).select_from(EventRecord).where(
                    and_(
                        EventRecord.timestamp >= start_time,
                        EventRecord.timestamp <= end_time,
                        EventRecord.is_deleted == False
                    )
                )
            )

            # By type
            by_type_result = await session.execute(
                select(
                    EventRecord.event_type,
                    func.count().label('count')
                ).where(
                    and_(
                        EventRecord.timestamp >= start_time,
                        EventRecord.timestamp <= end_time,
                        EventRecord.is_deleted == False
                    )
                ).group_by(EventRecord.event_type)
            )
            by_type = {str(row[0].value): row[1] for row in by_type_result}

            # By severity
            by_severity_result = await session.execute(
                select(
                    EventRecord.severity,
                    func.count().label('count')
                ).where(
                    and_(
                        EventRecord.timestamp >= start_time,
                        EventRecord.timestamp <= end_time,
                        EventRecord.is_deleted == False
                    )
                ).group_by(EventRecord.severity)
            )
            by_severity = {str(row[0].value): row[1] for row in by_severity_result}

            # By outcome
            by_outcome_result = await session.execute(
                select(
                    EventRecord.outcome,
                    func.count().label('count')
                ).where(
                    and_(
                        EventRecord.timestamp >= start_time,
                        EventRecord.timestamp <= end_time,
                        EventRecord.is_deleted == False
                    )
                ).group_by(EventRecord.outcome)
            )
            by_outcome = {str(row[0].value): row[1] for row in by_outcome_result}

            # By actor
            by_actor_result = await session.execute(
                select(
                    EventRecord.actor_id,
                    func.count().label('count')
                ).where(
                    and_(
                        EventRecord.timestamp >= start_time,
                        EventRecord.timestamp <= end_time,
                        EventRecord.is_deleted == False
                    )
                ).group_by(EventRecord.actor_id).limit(10)
            )
            by_actor = {row[0]: row[1] for row in by_actor_result}

            # Events per hour
            events_per_hour_result = await session.execute(
                select(
                    func.date_trunc('hour', EventRecord.timestamp).label('hour'),
                    func.count().label('count')
                ).where(
                    and_(
                        EventRecord.timestamp >= start_time,
                        EventRecord.timestamp <= end_time,
                        EventRecord.is_deleted == False
                    )
                ).group_by(text('hour')).order_by(text('hour'))
            )
            events_per_hour = {
                row[0].isoformat(): row[1] for row in events_per_hour_result
            }

            return EventStatistics(
                total_events=total or 0,
                time_range={"start": start_time, "end": end_time},
                by_type=by_type,
                by_severity=by_severity,
                by_outcome=by_outcome,
                by_actor=by_actor,
                events_per_hour=events_per_hour
            )

    async def anonymize_user_events(self, user_id: str) -> int:
        """
        Anonymize events for GDPR compliance.

        Args:
            user_id: User ID to anonymize

        Returns:
            Number of events anonymized
        """
        async with self.session_maker() as session:
            result = await session.execute(
                select(EventRecord).where(
                    and_(
                        EventRecord.actor_id == user_id,
                        EventRecord.anonymized == False
                    )
                )
            )
            events = result.scalars().all()

            count = 0
            for event in events:
                # Anonymize personal data
                event.actor_name = f"anonymized-user-{hash(user_id) % 10000}"
                event.actor_ip = "0.0.0.0"
                event.actor_user_agent = "anonymized"
                event.anonymized = True

                # Remove sensitive metadata
                if event.metadata:
                    event.metadata = {"anonymized": True}

                count += 1

            await session.commit()
            logger.info(f"Anonymized {count} events for user {user_id}")
            return count

    async def delete_old_events(self, retention_days: int) -> int:
        """
        Delete events older than retention period.

        Args:
            retention_days: Retention period in days

        Returns:
            Number of events deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

        async with self.session_maker() as session:
            result = await session.execute(
                select(func.count()).select_from(EventRecord).where(
                    and_(
                        EventRecord.timestamp < cutoff_date,
                        EventRecord.is_deleted == False
                    )
                )
            )
            count = result.scalar()

            # Soft delete
            await session.execute(
                EventRecord.__table__.update().where(
                    and_(
                        EventRecord.timestamp < cutoff_date,
                        EventRecord.is_deleted == False
                    )
                ).values(
                    is_deleted=True,
                    deleted_at=datetime.utcnow()
                )
            )

            await session.commit()
            logger.info(f"Deleted {count} events older than {retention_days} days")
            return count

    def _apply_filters(self, query, filter_criteria: EventFilter):
        """Apply filter criteria to query."""
        conditions = []

        # Time range
        if filter_criteria.start_time:
            conditions.append(EventRecord.timestamp >= filter_criteria.start_time)
        if filter_criteria.end_time:
            conditions.append(EventRecord.timestamp <= filter_criteria.end_time)

        # Event filters
        if filter_criteria.event_types:
            conditions.append(EventRecord.event_type.in_(filter_criteria.event_types))
        if filter_criteria.severities:
            conditions.append(EventRecord.severity.in_(filter_criteria.severities))
        if filter_criteria.outcomes:
            conditions.append(EventRecord.outcome.in_(filter_criteria.outcomes))

        # Actor filters
        if filter_criteria.actor_ids:
            conditions.append(EventRecord.actor_id.in_(filter_criteria.actor_ids))
        if filter_criteria.actor_types:
            conditions.append(EventRecord.actor_type.in_(filter_criteria.actor_types))

        # Resource filters
        if filter_criteria.resource_ids:
            conditions.append(EventRecord.resource_id.in_(filter_criteria.resource_ids))
        if filter_criteria.resource_types:
            conditions.append(EventRecord.resource_type.in_(filter_criteria.resource_types))

        # Tags filter
        if filter_criteria.tags:
            conditions.append(EventRecord.tags.overlap(filter_criteria.tags))

        # Full-text search
        if filter_criteria.search_query:
            search_term = f"%{filter_criteria.search_query}%"
            conditions.append(
                or_(
                    EventRecord.description.ilike(search_term),
                    EventRecord.action.ilike(search_term),
                    EventRecord.actor_name.ilike(search_term)
                )
            )

        if conditions:
            query = query.where(and_(*conditions))

        return query

    def _event_to_record(self, event: AuditEvent) -> EventRecord:
        """Convert event model to database record."""
        return EventRecord(
            id=event.id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            severity=event.severity,
            outcome=event.outcome,
            actor_id=event.actor.id,
            actor_type=event.actor.type,
            actor_name=event.actor.name,
            actor_ip=event.actor.ip_address,
            actor_user_agent=event.actor.user_agent,
            actor_session_id=event.actor.session_id,
            action=event.action,
            resource_id=event.resource.id if event.resource else None,
            resource_type=event.resource.type if event.resource else None,
            resource_name=event.resource.name if event.resource else None,
            resource_parent_id=event.resource.parent_id if event.resource else None,
            resource_attributes=event.resource.attributes if event.resource else {},
            description=event.description,
            duration_ms=event.duration_ms,
            metadata=event.metadata,
            tags=event.tags,
            trace_id=event.trace_id,
            span_id=event.span_id,
            parent_event_id=event.parent_event_id,
            signature=event.signature,
            signature_algorithm=event.signature_algorithm,
            compliance_flags=event.compliance_flags,
            changes=event.changes
        )
