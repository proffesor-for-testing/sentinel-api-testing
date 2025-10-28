"""
Tests for audit event models
"""

import pytest
from datetime import datetime
from uuid import uuid4

from ..models.events import (
    EventType, EventSeverity, EventOutcome,
    EventActor, EventResource, AuditEvent,
    EventFilter, EventBatch
)


def test_event_actor_creation():
    """Test EventActor model creation."""
    actor = EventActor(
        id="user-123",
        type="user",
        name="test@example.com",
        ip_address="192.168.1.1",
        session_id="sess-abc"
    )

    assert actor.id == "user-123"
    assert actor.type == "user"
    assert actor.name == "test@example.com"


def test_event_resource_creation():
    """Test EventResource model creation."""
    resource = EventResource(
        id="test-456",
        type="test",
        name="Test Suite",
        attributes={"framework": "pytest"}
    )

    assert resource.id == "test-456"
    assert resource.type == "test"
    assert resource.attributes["framework"] == "pytest"


def test_audit_event_creation():
    """Test AuditEvent model creation."""
    actor = EventActor(id="user-123", type="user", name="test@example.com")
    resource = EventResource(id="test-456", type="test", name="Test Suite")

    event = AuditEvent(
        event_type=EventType.TEST_EXECUTED,
        actor=actor,
        action="execute_test",
        outcome=EventOutcome.SUCCESS,
        resource=resource,
        severity=EventSeverity.INFO,
        description="Test executed successfully",
        duration_ms=1500,
        tags=["test", "automated"]
    )

    assert event.event_type == EventType.TEST_EXECUTED
    assert event.actor.id == "user-123"
    assert event.outcome == EventOutcome.SUCCESS
    assert len(event.tags) == 2
    assert "test" in event.tags


def test_event_signature():
    """Test event signature computation."""
    actor = EventActor(id="user-123", type="user")
    event = AuditEvent(
        event_type=EventType.USER_LOGIN,
        actor=actor,
        action="login",
        outcome=EventOutcome.SUCCESS
    )

    signature = event.compute_signature("secret-key")
    assert signature
    assert event.signature == signature
    assert event.signature_algorithm == "HMAC-SHA256"


def test_event_batch():
    """Test event batch creation."""
    actor = EventActor(id="user-123", type="user")
    events = [
        AuditEvent(
            event_type=EventType.USER_LOGIN,
            actor=actor,
            action="login",
            outcome=EventOutcome.SUCCESS
        )
        for _ in range(5)
    ]

    batch = EventBatch(events=events)
    assert batch.size() == 5
    assert not batch.processed


def test_event_filter():
    """Test event filter creation."""
    event_filter = EventFilter(
        start_time=datetime.utcnow(),
        event_types=[EventType.USER_LOGIN, EventType.USER_LOGOUT],
        severities=[EventSeverity.INFO],
        limit=100,
        offset=0
    )

    assert len(event_filter.event_types) == 2
    assert EventType.USER_LOGIN in event_filter.event_types
    assert event_filter.limit == 100


def test_tag_normalization():
    """Test that tags are normalized to lowercase."""
    actor = EventActor(id="user-123", type="user")
    event = AuditEvent(
        event_type=EventType.TEST_EXECUTED,
        actor=actor,
        action="test",
        outcome=EventOutcome.SUCCESS,
        tags=["TEST", "Automated", "IMPORTANT"]
    )

    # Tags should be lowercase and unique
    assert "test" in event.tags
    assert "automated" in event.tags
    assert "important" in event.tags
    assert "TEST" not in event.tags
