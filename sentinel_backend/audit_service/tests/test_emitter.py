"""
Tests for event emitter
"""

import pytest
import asyncio
from datetime import datetime

from ..emitter import EventEmitter
from ..models.events import (
    EventType, EventSeverity, EventOutcome,
    EventActor, EventResource
)


@pytest.fixture
async def emitter():
    """Create event emitter for testing."""
    emitter = EventEmitter(
        batch_size=5,
        flush_interval_seconds=1,
        enable_deduplication=True
    )
    await emitter.start()
    yield emitter
    await emitter.stop()


@pytest.mark.asyncio
async def test_emit_single_event(emitter):
    """Test emitting a single event."""
    actor = EventActor(id="user-123", type="user")

    event = await emitter.emit(
        event_type=EventType.USER_LOGIN,
        actor=actor,
        action="login",
        outcome=EventOutcome.SUCCESS
    )

    assert event is not None
    assert event.event_type == EventType.USER_LOGIN
    assert event.actor.id == "user-123"


@pytest.mark.asyncio
async def test_event_batching(emitter):
    """Test that events are batched correctly."""
    actor = EventActor(id="user-123", type="user")
    batch_received = asyncio.Event()
    batch_data = []

    def batch_handler(batch):
        batch_data.append(batch)
        batch_received.set()

    emitter.register_handler(batch_handler)

    # Emit enough events to trigger batching
    for i in range(5):
        await emitter.emit(
            event_type=EventType.API_REQUEST,
            actor=actor,
            action=f"request-{i}",
            outcome=EventOutcome.SUCCESS
        )

    # Wait for batch to be processed
    await asyncio.wait_for(batch_received.wait(), timeout=2.0)

    assert len(batch_data) > 0
    assert batch_data[0].size() == 5


@pytest.mark.asyncio
async def test_event_deduplication(emitter):
    """Test event deduplication."""
    actor = EventActor(id="user-123", type="user")

    # Emit same event multiple times
    event1 = await emitter.emit(
        event_type=EventType.USER_LOGIN,
        actor=actor,
        action="login",
        outcome=EventOutcome.SUCCESS
    )

    event2 = await emitter.emit(
        event_type=EventType.USER_LOGIN,
        actor=actor,
        action="login",
        outcome=EventOutcome.SUCCESS
    )

    # First event should succeed, second should be deduplicated
    assert event1 is not None
    assert event2 is None

    stats = emitter.get_statistics()
    assert stats["events_deduplicated"] >= 1


@pytest.mark.asyncio
async def test_convenience_methods(emitter):
    """Test convenience methods for common events."""
    # Test user login
    event = await emitter.emit_user_login(
        user_id="user-123",
        user_email="test@example.com",
        ip_address="192.168.1.1",
        success=True
    )

    assert event.event_type == EventType.USER_LOGIN
    assert event.outcome == EventOutcome.SUCCESS

    # Test agent execution
    event = await emitter.emit_agent_execution(
        agent_id="agent-456",
        agent_type="functional",
        action="generate_tests",
        outcome=EventOutcome.SUCCESS,
        duration_ms=1500
    )

    assert event.duration_ms == 1500
    assert "agent" in event.tags


@pytest.mark.asyncio
async def test_event_context_manager(emitter):
    """Test event context manager for duration tracking."""
    actor = EventActor(id="user-123", type="user")

    async with emitter.event_context(
        EventType.TEST_EXECUTED,
        actor,
        "run_tests"
    ):
        await asyncio.sleep(0.1)

    # Event should be emitted after context exit
    await emitter.flush()

    stats = emitter.get_statistics()
    assert stats["events_emitted"] >= 1


@pytest.mark.asyncio
async def test_manual_flush(emitter):
    """Test manual buffer flushing."""
    actor = EventActor(id="user-123", type="user")

    # Emit events without triggering batch
    for i in range(3):
        await emitter.emit(
            event_type=EventType.API_REQUEST,
            actor=actor,
            action=f"request-{i}",
            outcome=EventOutcome.SUCCESS
        )

    # Manual flush
    await emitter.flush()

    stats = emitter.get_statistics()
    assert stats["buffer_size"] == 0


@pytest.mark.asyncio
async def test_statistics(emitter):
    """Test emitter statistics tracking."""
    actor = EventActor(id="user-123", type="user")

    # Emit some events
    for i in range(10):
        await emitter.emit(
            event_type=EventType.API_REQUEST,
            actor=actor,
            action=f"request-{i}",
            outcome=EventOutcome.SUCCESS
        )

    stats = emitter.get_statistics()
    assert stats["events_emitted"] == 10
    assert "batches_created" in stats
    assert "buffer_size" in stats
