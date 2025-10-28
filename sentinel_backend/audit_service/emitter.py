"""
Event Emitter - Collects and buffers audit events

Provides thread-safe event emission with buffering, batching, and deduplication.
"""

import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from collections import deque
from contextlib import asynccontextmanager
import logging

from .models.events import (
    AuditEvent, EventBatch, EventType, EventSeverity,
    EventOutcome, EventActor, EventResource
)

logger = logging.getLogger(__name__)


class EventEmitter:
    """
    Thread-safe event emitter with buffering and batching.

    Features:
    - Automatic batching for performance
    - Event deduplication
    - Buffer overflow protection
    - Async event processing
    """

    def __init__(
        self,
        batch_size: int = 100,
        flush_interval_seconds: int = 5,
        max_buffer_size: int = 10000,
        enable_deduplication: bool = True,
        dedup_window_seconds: int = 60
    ):
        """
        Initialize event emitter.

        Args:
            batch_size: Number of events per batch
            flush_interval_seconds: Automatic flush interval
            max_buffer_size: Maximum buffer size before forced flush
            enable_deduplication: Enable event deduplication
            dedup_window_seconds: Deduplication time window
        """
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.max_buffer_size = max_buffer_size
        self.enable_deduplication = enable_deduplication
        self.dedup_window = timedelta(seconds=dedup_window_seconds)

        # Event buffer
        self._buffer: deque = deque(maxlen=max_buffer_size)
        self._buffer_lock = asyncio.Lock()

        # Deduplication cache
        self._dedup_cache: Dict[str, datetime] = {}
        self._dedup_lock = asyncio.Lock()

        # Statistics
        self._stats = {
            "events_emitted": 0,
            "events_deduplicated": 0,
            "batches_created": 0,
            "buffer_overflows": 0
        }

        # Background tasks
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

        # Event handlers
        self._handlers: List[callable] = []

    async def start(self):
        """Start background flush task."""
        if self._running:
            return

        self._running = True
        self._flush_task = asyncio.create_task(self._auto_flush())
        logger.info(f"Event emitter started (batch_size={self.batch_size}, flush_interval={self.flush_interval}s)")

    async def stop(self):
        """Stop background tasks and flush remaining events."""
        if not self._running:
            return

        self._running = False

        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass

        # Flush remaining events
        await self.flush()
        logger.info("Event emitter stopped")

    async def emit(
        self,
        event_type: EventType,
        actor: EventActor,
        action: str,
        outcome: EventOutcome,
        resource: Optional[EventResource] = None,
        severity: EventSeverity = EventSeverity.INFO,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        tags: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
        sign_event: bool = False,
        signing_key: Optional[str] = None
    ) -> Optional[AuditEvent]:
        """
        Emit an audit event.

        Args:
            event_type: Type of event
            actor: Entity that triggered the event
            action: Action performed
            outcome: Event outcome
            resource: Resource affected (optional)
            severity: Event severity
            description: Human-readable description
            metadata: Additional metadata
            duration_ms: Event duration
            tags: Event tags
            trace_id: Distributed trace ID
            sign_event: Whether to sign the event
            signing_key: Key for signing

        Returns:
            Created event if not deduplicated, None otherwise
        """
        # Create event
        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            action=action,
            outcome=outcome,
            resource=resource,
            severity=severity,
            description=description,
            metadata=metadata or {},
            duration_ms=duration_ms,
            tags=tags or [],
            trace_id=trace_id
        )

        # Sign event if required
        if sign_event and signing_key:
            event.compute_signature(signing_key)

        # Check deduplication
        if self.enable_deduplication:
            if await self._is_duplicate(event):
                async with self._buffer_lock:
                    self._stats["events_deduplicated"] += 1
                return None

        # Add to buffer
        async with self._buffer_lock:
            if len(self._buffer) >= self.max_buffer_size:
                self._stats["buffer_overflows"] += 1
                logger.warning(f"Event buffer overflow (size={len(self._buffer)})")
                # Force flush
                await self._flush_buffer()

            self._buffer.append(event)
            self._stats["events_emitted"] += 1

            # Auto-flush if batch size reached
            if len(self._buffer) >= self.batch_size:
                await self._flush_buffer()

        return event

    async def emit_user_login(
        self,
        user_id: str,
        user_email: str,
        ip_address: str,
        success: bool,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Convenience method for user login events."""
        return await self.emit(
            event_type=EventType.USER_LOGIN,
            actor=EventActor(
                id=user_id,
                type="user",
                name=user_email,
                ip_address=ip_address,
                session_id=session_id
            ),
            action="login",
            outcome=EventOutcome.SUCCESS if success else EventOutcome.FAILURE,
            severity=EventSeverity.INFO if success else EventSeverity.WARNING,
            description=f"User {'successfully logged in' if success else 'failed to log in'}",
            metadata=metadata
        )

    async def emit_agent_execution(
        self,
        agent_id: str,
        agent_type: str,
        action: str,
        outcome: EventOutcome,
        duration_ms: int,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Convenience method for agent execution events."""
        return await self.emit(
            event_type=EventType.AGENT_COMPLETED if outcome == EventOutcome.SUCCESS else EventType.AGENT_FAILED,
            actor=EventActor(
                id=agent_id,
                type="agent",
                name=agent_type
            ),
            action=action,
            outcome=outcome,
            severity=EventSeverity.INFO if outcome == EventOutcome.SUCCESS else EventSeverity.ERROR,
            duration_ms=duration_ms,
            description=f"Agent {action} {outcome.value}",
            metadata=metadata,
            tags=["agent", agent_type]
        )

    async def emit_api_request(
        self,
        user_id: str,
        method: str,
        path: str,
        status_code: int,
        duration_ms: int,
        ip_address: str,
        user_agent: Optional[str] = None
    ):
        """Convenience method for API request events."""
        outcome = EventOutcome.SUCCESS if 200 <= status_code < 300 else EventOutcome.FAILURE
        severity = EventSeverity.INFO if outcome == EventOutcome.SUCCESS else EventSeverity.WARNING

        return await self.emit(
            event_type=EventType.API_REQUEST,
            actor=EventActor(
                id=user_id,
                type="user",
                ip_address=ip_address,
                user_agent=user_agent
            ),
            action=f"{method} {path}",
            outcome=outcome,
            severity=severity,
            duration_ms=duration_ms,
            description=f"{method} {path} -> {status_code}",
            metadata={
                "method": method,
                "path": path,
                "status_code": status_code
            },
            tags=["api", method.lower()]
        )

    async def flush(self):
        """Manually flush buffer."""
        async with self._buffer_lock:
            await self._flush_buffer()

    async def _flush_buffer(self):
        """Flush events from buffer (must be called with lock held)."""
        if not self._buffer:
            return

        # Create batch
        events = list(self._buffer)
        self._buffer.clear()

        batch = EventBatch(events=events)
        self._stats["batches_created"] += 1

        # Process batch with handlers
        await self._process_batch(batch)

        logger.debug(f"Flushed batch of {len(events)} events")

    async def _auto_flush(self):
        """Background task for automatic flushing."""
        while self._running:
            try:
                await asyncio.sleep(self.flush_interval)
                await self.flush()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto-flush: {e}")

    async def _is_duplicate(self, event: AuditEvent) -> bool:
        """Check if event is a duplicate within dedup window."""
        # Create event signature
        signature = self._event_signature(event)

        async with self._dedup_lock:
            now = datetime.utcnow()

            # Clean expired entries
            expired_keys = [
                k for k, v in self._dedup_cache.items()
                if now - v > self.dedup_window
            ]
            for key in expired_keys:
                del self._dedup_cache[key]

            # Check if duplicate
            if signature in self._dedup_cache:
                return True

            # Add to cache
            self._dedup_cache[signature] = now
            return False

    def _event_signature(self, event: AuditEvent) -> str:
        """Generate event signature for deduplication."""
        sig_data = f"{event.event_type}:{event.actor.id}:{event.action}"
        if event.resource:
            sig_data += f":{event.resource.id}"
        return hashlib.sha256(sig_data.encode()).hexdigest()[:16]

    async def _process_batch(self, batch: EventBatch):
        """Process batch with registered handlers."""
        for handler in self._handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(batch)
                else:
                    handler(batch)
            except Exception as e:
                logger.error(f"Error in batch handler: {e}")

    def register_handler(self, handler: callable):
        """Register a batch handler."""
        self._handlers.append(handler)
        logger.info(f"Registered batch handler: {handler.__name__}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get emitter statistics."""
        return {
            **self._stats,
            "buffer_size": len(self._buffer),
            "dedup_cache_size": len(self._dedup_cache),
            "handlers_registered": len(self._handlers)
        }

    @asynccontextmanager
    async def event_context(
        self,
        event_type: EventType,
        actor: EventActor,
        action: str,
        resource: Optional[EventResource] = None,
        **kwargs
    ):
        """
        Context manager for automatic event emission with duration tracking.

        Usage:
            async with emitter.event_context(
                EventType.TEST_EXECUTED,
                actor,
                "run_tests"
            ):
                # Do work
                pass
        """
        start_time = datetime.utcnow()
        exception: Optional[Exception] = None

        try:
            yield
        except Exception as e:
            exception = e
            raise
        finally:
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            outcome = EventOutcome.FAILURE if exception else EventOutcome.SUCCESS
            severity = EventSeverity.ERROR if exception else kwargs.get('severity', EventSeverity.INFO)

            await self.emit(
                event_type=event_type,
                actor=actor,
                action=action,
                outcome=outcome,
                resource=resource,
                severity=severity,
                duration_ms=duration_ms,
                metadata=kwargs.get('metadata', {}),
                description=kwargs.get('description')
            )


# Global emitter instance
_global_emitter: Optional[EventEmitter] = None


def get_global_emitter() -> EventEmitter:
    """Get global event emitter instance."""
    global _global_emitter
    if _global_emitter is None:
        _global_emitter = EventEmitter()
    return _global_emitter


async def init_global_emitter(**kwargs):
    """Initialize global event emitter."""
    global _global_emitter
    _global_emitter = EventEmitter(**kwargs)
    await _global_emitter.start()


async def shutdown_global_emitter():
    """Shutdown global event emitter."""
    global _global_emitter
    if _global_emitter:
        await _global_emitter.stop()
        _global_emitter = None
