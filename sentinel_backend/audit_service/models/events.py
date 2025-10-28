"""
Event Models for Audit Trail System

Defines all event types and their schemas for comprehensive audit logging.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, validator
import hashlib
import json


class EventType(str, Enum):
    """Enumeration of all audit event types."""

    # User events
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_PASSWORD_CHANGED = "user.password_changed"
    USER_ROLE_CHANGED = "user.role_changed"
    USER_LOCKED = "user.locked"
    USER_UNLOCKED = "user.unlocked"

    # Agent events
    AGENT_SPAWNED = "agent.spawned"
    AGENT_STARTED = "agent.started"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    AGENT_TIMEOUT = "agent.timeout"
    AGENT_CANCELLED = "agent.cancelled"

    # Test events
    TEST_CREATED = "test.created"
    TEST_UPDATED = "test.updated"
    TEST_DELETED = "test.deleted"
    TEST_EXECUTED = "test.executed"
    TEST_PASSED = "test.passed"
    TEST_FAILED = "test.failed"
    TEST_SKIPPED = "test.skipped"

    # API events
    API_REQUEST = "api.request"
    API_RESPONSE = "api.response"
    API_ERROR = "api.error"
    API_RATE_LIMIT = "api.rate_limit"

    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    SYSTEM_WARNING = "system.warning"
    SYSTEM_CONFIG_CHANGED = "system.config_changed"

    # Data events
    DATA_CREATED = "data.created"
    DATA_UPDATED = "data.updated"
    DATA_DELETED = "data.deleted"
    DATA_ACCESSED = "data.accessed"
    DATA_EXPORTED = "data.exported"

    # Security events
    SECURITY_AUTH_FAILED = "security.auth_failed"
    SECURITY_ACCESS_DENIED = "security.access_denied"
    SECURITY_POLICY_VIOLATED = "security.policy_violated"
    SECURITY_ANOMALY_DETECTED = "security.anomaly_detected"

    # Compliance events
    COMPLIANCE_GDPR_REQUEST = "compliance.gdpr_request"
    COMPLIANCE_DATA_RETENTION = "compliance.data_retention"
    COMPLIANCE_AUDIT_EXPORT = "compliance.audit_export"


class EventSeverity(str, Enum):
    """Event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventOutcome(str, Enum):
    """Event outcome status."""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    PENDING = "pending"
    CANCELLED = "cancelled"


class EventActor(BaseModel):
    """Entity that triggered the event."""

    id: str = Field(..., description="Actor identifier")
    type: str = Field(..., description="Actor type (user, agent, system, service)")
    name: Optional[str] = Field(None, description="Actor display name")
    ip_address: Optional[str] = Field(None, description="Actor IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    session_id: Optional[str] = Field(None, description="Session identifier")

    class Config:
        schema_extra = {
            "example": {
                "id": "user-123",
                "type": "user",
                "name": "john.doe@example.com",
                "ip_address": "192.168.1.100",
                "session_id": "sess_abc123"
            }
        }


class EventResource(BaseModel):
    """Resource affected by the event."""

    id: str = Field(..., description="Resource identifier")
    type: str = Field(..., description="Resource type (test, agent, user, data)")
    name: Optional[str] = Field(None, description="Resource display name")
    parent_id: Optional[str] = Field(None, description="Parent resource ID")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Resource attributes")

    class Config:
        schema_extra = {
            "example": {
                "id": "test-456",
                "type": "test",
                "name": "User Authentication Tests",
                "parent_id": "project-789",
                "attributes": {"framework": "pytest", "category": "functional"}
            }
        }


class AuditEvent(BaseModel):
    """
    Core audit event model.

    Represents a single auditable event in the system with complete
    traceability information.
    """

    # Event identity
    id: UUID = Field(default_factory=uuid4, description="Unique event identifier")
    event_type: EventType = Field(..., description="Type of event")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp (UTC)")

    # Event details
    actor: EventActor = Field(..., description="Entity that triggered the event")
    action: str = Field(..., description="Action performed")
    resource: Optional[EventResource] = Field(None, description="Resource affected")

    # Event metadata
    severity: EventSeverity = Field(default=EventSeverity.INFO, description="Event severity")
    outcome: EventOutcome = Field(..., description="Event outcome")
    duration_ms: Optional[int] = Field(None, description="Event duration in milliseconds")

    # Context and details
    description: Optional[str] = Field(None, description="Human-readable description")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    tags: List[str] = Field(default_factory=list, description="Event tags for categorization")

    # Tracing and correlation
    trace_id: Optional[str] = Field(None, description="Distributed trace ID")
    span_id: Optional[str] = Field(None, description="Span ID within trace")
    parent_event_id: Optional[UUID] = Field(None, description="Parent event ID for correlation")

    # Compliance and security
    signature: Optional[str] = Field(None, description="Cryptographic signature")
    signature_algorithm: Optional[str] = Field(None, description="Signature algorithm used")
    compliance_flags: List[str] = Field(default_factory=list, description="Compliance-related flags")

    # Data changes (for data events)
    changes: Optional[Dict[str, Any]] = Field(None, description="Before/after changes")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }
        schema_extra = {
            "example": {
                "event_type": "user.login",
                "actor": {
                    "id": "user-123",
                    "type": "user",
                    "name": "john.doe@example.com",
                    "ip_address": "192.168.1.100"
                },
                "action": "login",
                "outcome": "success",
                "description": "User successfully logged in",
                "metadata": {"mfa_enabled": True}
            }
        }

    def compute_signature(self, secret_key: str) -> str:
        """
        Compute cryptographic signature for event integrity.

        Args:
            secret_key: Secret key for signing

        Returns:
            HMAC-SHA256 signature
        """
        # Create canonical representation
        canonical = json.dumps({
            "id": str(self.id),
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor.dict(),
            "action": self.action,
            "outcome": self.outcome
        }, sort_keys=True)

        # Compute HMAC-SHA256
        signature = hashlib.sha256(
            f"{secret_key}{canonical}".encode()
        ).hexdigest()

        self.signature = signature
        self.signature_algorithm = "HMAC-SHA256"
        return signature

    @validator('tags', pre=True, always=True)
    def validate_tags(cls, v):
        """Ensure tags are unique and lowercase."""
        if v:
            return list(set(tag.lower() for tag in v))
        return []


class EventBatch(BaseModel):
    """Batch of events for efficient processing."""

    batch_id: UUID = Field(default_factory=uuid4, description="Batch identifier")
    events: List[AuditEvent] = Field(..., description="Events in batch")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Batch creation time")
    processed: bool = Field(default=False, description="Batch processing status")

    def size(self) -> int:
        """Get batch size."""
        return len(self.events)


class EventFilter(BaseModel):
    """Filter criteria for querying events."""

    # Time range
    start_time: Optional[datetime] = Field(None, description="Start time (inclusive)")
    end_time: Optional[datetime] = Field(None, description="End time (inclusive)")

    # Event filters
    event_types: Optional[List[EventType]] = Field(None, description="Filter by event types")
    severities: Optional[List[EventSeverity]] = Field(None, description="Filter by severity")
    outcomes: Optional[List[EventOutcome]] = Field(None, description="Filter by outcome")

    # Actor filters
    actor_ids: Optional[List[str]] = Field(None, description="Filter by actor IDs")
    actor_types: Optional[List[str]] = Field(None, description="Filter by actor types")

    # Resource filters
    resource_ids: Optional[List[str]] = Field(None, description="Filter by resource IDs")
    resource_types: Optional[List[str]] = Field(None, description="Filter by resource types")

    # Text search
    search_query: Optional[str] = Field(None, description="Full-text search query")

    # Tags
    tags: Optional[List[str]] = Field(None, description="Filter by tags")

    # Pagination
    limit: int = Field(default=100, ge=1, le=1000, description="Maximum results")
    offset: int = Field(default=0, ge=0, description="Result offset")

    # Sorting
    sort_by: str = Field(default="timestamp", description="Sort field")
    sort_order: str = Field(default="desc", description="Sort order (asc/desc)")


class EventStatistics(BaseModel):
    """Statistical summary of events."""

    total_events: int = Field(..., description="Total number of events")
    time_range: Dict[str, datetime] = Field(..., description="Time range of events")

    # By type
    by_type: Dict[str, int] = Field(default_factory=dict, description="Event counts by type")

    # By severity
    by_severity: Dict[str, int] = Field(default_factory=dict, description="Event counts by severity")

    # By outcome
    by_outcome: Dict[str, int] = Field(default_factory=dict, description="Event counts by outcome")

    # By actor
    by_actor: Dict[str, int] = Field(default_factory=dict, description="Event counts by actor")

    # Top resources
    top_resources: List[Dict[str, Any]] = Field(default_factory=list, description="Most active resources")

    # Trends
    events_per_hour: Dict[str, int] = Field(default_factory=dict, description="Events per hour")
    events_per_day: Dict[str, int] = Field(default_factory=dict, description="Events per day")
