"""
Database Schema for Audit Trail

Uses PostgreSQL with time-series optimizations (TimescaleDB compatible).
"""

from sqlalchemy import (
    Column, String, DateTime, Integer, Text, Boolean,
    Index, JSON, Enum as SQLEnum, ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from ..models.events import EventType, EventSeverity, EventOutcome

Base = declarative_base()


class EventRecord(Base):
    """
    Main audit event table.

    Optimized for time-series queries with partitioning support.
    """
    __tablename__ = "audit_events"

    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Timestamp (partition key)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True, default=datetime.utcnow)

    # Event classification
    event_type = Column(SQLEnum(EventType), nullable=False, index=True)
    severity = Column(SQLEnum(EventSeverity), nullable=False, index=True)
    outcome = Column(SQLEnum(EventOutcome), nullable=False, index=True)

    # Actor information
    actor_id = Column(String(255), nullable=False, index=True)
    actor_type = Column(String(50), nullable=False, index=True)
    actor_name = Column(String(255))
    actor_ip = Column(String(45))  # IPv6 support
    actor_user_agent = Column(Text)
    actor_session_id = Column(String(255), index=True)

    # Action and resource
    action = Column(String(255), nullable=False)
    resource_id = Column(String(255), index=True)
    resource_type = Column(String(50), index=True)
    resource_name = Column(String(255))
    resource_parent_id = Column(String(255))

    # Details
    description = Column(Text)
    duration_ms = Column(Integer)

    # Metadata and context
    metadata = Column(JSONB, default={})
    resource_attributes = Column(JSONB, default={})
    tags = Column(ARRAY(String), default=[])

    # Distributed tracing
    trace_id = Column(String(255), index=True)
    span_id = Column(String(255))
    parent_event_id = Column(UUID(as_uuid=True), index=True)

    # Compliance and security
    signature = Column(String(512))
    signature_algorithm = Column(String(50))
    compliance_flags = Column(ARRAY(String), default=[])

    # Data changes (for audit trail)
    changes = Column(JSONB)

    # Soft delete support (for GDPR compliance)
    is_deleted = Column(Boolean, default=False)
    deleted_at = Column(DateTime(timezone=True))
    anonymized = Column(Boolean, default=False)

    # Indexing for common queries
    __table_args__ = (
        # Composite indexes for common query patterns
        Index('idx_timestamp_event_type', 'timestamp', 'event_type'),
        Index('idx_timestamp_actor', 'timestamp', 'actor_id'),
        Index('idx_timestamp_resource', 'timestamp', 'resource_id'),
        Index('idx_actor_timestamp', 'actor_id', 'timestamp'),
        Index('idx_resource_timestamp', 'resource_id', 'timestamp'),
        Index('idx_trace_id', 'trace_id'),

        # GIN indexes for JSONB and array columns
        Index('idx_metadata_gin', 'metadata', postgresql_using='gin'),
        Index('idx_tags_gin', 'tags', postgresql_using='gin'),

        # Partitioning configuration (TimescaleDB)
        # This will be enabled via:
        # SELECT create_hypertable('audit_events', 'timestamp', chunk_time_interval => INTERVAL '1 day');
        {'postgresql_partition_by': 'RANGE (timestamp)'}
    )

    def to_dict(self):
        """Convert record to dictionary."""
        return {
            "id": str(self.id),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type.value if self.event_type else None,
            "severity": self.severity.value if self.severity else None,
            "outcome": self.outcome.value if self.outcome else None,
            "actor": {
                "id": self.actor_id,
                "type": self.actor_type,
                "name": self.actor_name,
                "ip_address": self.actor_ip,
                "user_agent": self.actor_user_agent,
                "session_id": self.actor_session_id
            },
            "action": self.action,
            "resource": {
                "id": self.resource_id,
                "type": self.resource_type,
                "name": self.resource_name,
                "parent_id": self.resource_parent_id,
                "attributes": self.resource_attributes
            } if self.resource_id else None,
            "description": self.description,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "tags": self.tags,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_event_id": str(self.parent_event_id) if self.parent_event_id else None,
            "signature": self.signature,
            "signature_algorithm": self.signature_algorithm,
            "compliance_flags": self.compliance_flags,
            "changes": self.changes
        }


class EventRetentionPolicy(Base):
    """Configuration for event retention policies."""
    __tablename__ = "audit_retention_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(SQLEnum(EventType), unique=True, nullable=False)
    retention_days = Column(Integer, nullable=False)
    archive_enabled = Column(Boolean, default=False)
    archive_location = Column(String(512))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class EventSnapshot(Base):
    """Periodic snapshots for reporting and analytics."""
    __tablename__ = "audit_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    snapshot_time = Column(DateTime(timezone=True), nullable=False, index=True)
    period = Column(String(20), nullable=False)  # hourly, daily, weekly, monthly
    statistics = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    __table_args__ = (
        Index('idx_snapshot_period', 'snapshot_time', 'period'),
    )


class ComplianceReport(Base):
    """Generated compliance reports."""
    __tablename__ = "audit_compliance_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_type = Column(String(50), nullable=False)  # SOC2, GDPR, HIPAA, etc.
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    generated_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    generated_by = Column(String(255), nullable=False)

    # Report content
    summary = Column(JSONB, nullable=False)
    details = Column(JSONB, nullable=False)
    findings = Column(JSONB, default={})

    # Export info
    exported = Column(Boolean, default=False)
    export_format = Column(String(20))  # pdf, csv, json
    export_location = Column(String(512))

    __table_args__ = (
        Index('idx_report_type_time', 'report_type', 'generated_at'),
    )


# SQL for TimescaleDB hypertable creation
TIMESCALEDB_INIT_SQL = """
-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Convert to hypertable (partition by day)
SELECT create_hypertable('audit_events', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Create continuous aggregates for common queries
CREATE MATERIALIZED VIEW IF NOT EXISTS audit_events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS hour,
    event_type,
    severity,
    outcome,
    COUNT(*) as event_count,
    AVG(duration_ms) as avg_duration_ms
FROM audit_events
WHERE NOT is_deleted
GROUP BY hour, event_type, severity, outcome;

-- Refresh policy for continuous aggregate
SELECT add_continuous_aggregate_policy('audit_events_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- Compression policy (compress data older than 7 days)
SELECT add_compression_policy('audit_events', INTERVAL '7 days',
    if_not_exists => TRUE
);

-- Retention policy (delete data older than 1 year by default)
SELECT add_retention_policy('audit_events', INTERVAL '365 days',
    if_not_exists => TRUE
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_time
    ON audit_events (actor_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_resource_time
    ON audit_events (resource_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_trace
    ON audit_events (trace_id, timestamp);

-- Full-text search index
CREATE INDEX IF NOT EXISTS idx_audit_events_description_fts
    ON audit_events USING gin(to_tsvector('english', description));
"""
