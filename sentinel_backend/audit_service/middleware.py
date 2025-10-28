"""
Audit Middleware for FastAPI Integration

Automatic event emission for all API requests.
"""

import time
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import logging

from .emitter import get_global_emitter
from .models.events import EventType, EventSeverity, EventOutcome, EventActor

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Middleware for automatic API request auditing.

    Captures:
    - All HTTP requests and responses
    - Request duration
    - User information
    - Error details
    """

    def __init__(
        self,
        app: ASGIApp,
        exclude_paths: list[str] = None,
        exclude_methods: list[str] = None
    ):
        """
        Initialize audit middleware.

        Args:
            app: FastAPI application
            exclude_paths: Paths to exclude from auditing
            exclude_methods: HTTP methods to exclude
        """
        super().__init__(app)
        self.exclude_paths = exclude_paths or ["/health", "/metrics", "/docs", "/openapi.json"]
        self.exclude_methods = exclude_methods or ["OPTIONS"]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and emit audit event."""
        # Check if path should be excluded
        if self._should_exclude(request):
            return await call_next(request)

        # Start timing
        start_time = time.time()

        # Extract actor information
        actor = self._extract_actor(request)

        # Process request
        response = None
        error = None
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            error = e
            raise
        finally:
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)

            # Emit audit event
            try:
                await self._emit_event(
                    request=request,
                    response=response,
                    actor=actor,
                    duration_ms=duration_ms,
                    error=error
                )
            except Exception as e:
                logger.error(f"Failed to emit audit event: {e}")

    def _should_exclude(self, request: Request) -> bool:
        """Check if request should be excluded from auditing."""
        # Check path
        for path in self.exclude_paths:
            if request.url.path.startswith(path):
                return True

        # Check method
        if request.method in self.exclude_methods:
            return True

        return False

    def _extract_actor(self, request: Request) -> EventActor:
        """Extract actor information from request."""
        # Try to get user from auth context
        user = getattr(request.state, "user", None)
        user_id = "anonymous"
        user_email = None

        if user:
            user_id = str(getattr(user, "id", "anonymous"))
            user_email = getattr(user, "email", None)

        return EventActor(
            id=user_id,
            type="user" if user else "anonymous",
            name=user_email,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            session_id=request.headers.get("x-session-id")
        )

    async def _emit_event(
        self,
        request: Request,
        response: Response,
        actor: EventActor,
        duration_ms: int,
        error: Exception = None
    ):
        """Emit audit event for request."""
        emitter = get_global_emitter()

        # Determine outcome and severity
        if error:
            outcome = EventOutcome.FAILURE
            severity = EventSeverity.ERROR
            status_code = 500
        elif response:
            status_code = response.status_code
            outcome = EventOutcome.SUCCESS if 200 <= status_code < 300 else EventOutcome.FAILURE
            severity = EventSeverity.INFO if outcome == EventOutcome.SUCCESS else EventSeverity.WARNING
        else:
            outcome = EventOutcome.FAILURE
            severity = EventSeverity.ERROR
            status_code = 500

        # Build metadata
        metadata = {
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "query_params": dict(request.query_params) if request.query_params else {},
            "user_agent": request.headers.get("user-agent")
        }

        if error:
            metadata["error"] = str(error)
            metadata["error_type"] = type(error).__name__

        # Emit event
        await emitter.emit(
            event_type=EventType.API_REQUEST,
            actor=actor,
            action=f"{request.method} {request.url.path}",
            outcome=outcome,
            severity=severity,
            duration_ms=duration_ms,
            description=f"{request.method} {request.url.path} -> {status_code}",
            metadata=metadata,
            tags=["api", request.method.lower()]
        )


def install_audit_middleware(app: ASGIApp, **kwargs):
    """
    Install audit middleware on FastAPI application.

    Args:
        app: FastAPI application
        **kwargs: Additional middleware configuration
    """
    app.add_middleware(AuditMiddleware, **kwargs)
    logger.info("Audit middleware installed")
