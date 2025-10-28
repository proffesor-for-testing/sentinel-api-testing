"""
Example integration of audit service with existing Sentinel services.

This shows how to integrate the audit trail into existing services.
"""

from fastapi import FastAPI, Depends
from contextlib import asynccontextmanager
import logging

from .middleware import install_audit_middleware
from .emitter import init_global_emitter, shutdown_global_emitter, get_global_emitter
from .storage.repository import EventRepository
from .models.events import EventType, EventActor, EventOutcome, EventResource
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


# Example: Integrate into orchestration service
@asynccontextmanager
async def orchestration_lifespan(app: FastAPI):
    """Lifespan with audit trail integration."""
    # Startup
    logger.info("Starting Orchestration Service with Audit Trail...")

    # Initialize audit emitter
    await init_global_emitter(
        batch_size=100,
        flush_interval_seconds=5,
        enable_deduplication=True
    )

    # Initialize repository and register batch handler
    settings = get_settings()
    repo = EventRepository(settings.database.url)
    await repo.initialize()

    emitter = get_global_emitter()

    async def save_batch_handler(batch):
        """Save event batches to database."""
        try:
            await repo.save_batch(batch)
        except Exception as e:
            logger.error(f"Failed to save audit batch: {e}")

    emitter.register_handler(save_batch_handler)

    # Emit system startup event
    await emitter.emit(
        event_type=EventType.SYSTEM_STARTUP,
        actor=EventActor(id="system", type="system", name="orchestration_service"),
        action="service_startup",
        outcome=EventOutcome.SUCCESS,
        description="Orchestration service started successfully",
        tags=["system", "startup"]
    )

    yield

    # Shutdown
    logger.info("Shutting down Orchestration Service...")

    # Emit shutdown event
    await emitter.emit(
        event_type=EventType.SYSTEM_SHUTDOWN,
        actor=EventActor(id="system", type="system", name="orchestration_service"),
        action="service_shutdown",
        outcome=EventOutcome.SUCCESS,
        description="Orchestration service shutdown",
        tags=["system", "shutdown"]
    )

    await shutdown_global_emitter()
    await repo.close()


def create_orchestration_app():
    """Create orchestration service with audit trail."""
    app = FastAPI(lifespan=orchestration_lifespan)

    # Install audit middleware
    install_audit_middleware(
        app,
        exclude_paths=["/health", "/metrics"],
        exclude_methods=["OPTIONS"]
    )

    # Example endpoint with manual event emission
    @app.post("/api/v1/agents/spawn")
    async def spawn_agent(
        agent_type: str,
        user_id: str = Depends(lambda: "user-123")  # Example dependency
    ):
        emitter = get_global_emitter()

        # Create actor
        actor = EventActor(
            id=user_id,
            type="user"
        )

        # Use context manager for automatic duration tracking
        async with emitter.event_context(
            EventType.AGENT_SPAWNED,
            actor,
            f"spawn_{agent_type}",
            description=f"Spawning {agent_type} agent"
        ):
            # Actual agent spawning logic
            agent_id = f"agent-{agent_type}-123"

            # Create resource for the agent
            resource = EventResource(
                id=agent_id,
                type="agent",
                name=f"{agent_type} Agent",
                attributes={"type": agent_type}
            )

            return {"agent_id": agent_id, "status": "spawned"}

    return app


# Example: Integration with test execution
async def execute_test_with_audit(test_id: str, user_id: str):
    """Execute test with comprehensive audit trail."""
    emitter = get_global_emitter()

    # Create actor and resource
    actor = EventActor(id=user_id, type="user")
    resource = EventResource(id=test_id, type="test", name=f"Test {test_id}")

    # Test creation event
    await emitter.emit(
        event_type=EventType.TEST_CREATED,
        actor=actor,
        action="create_test",
        outcome=EventOutcome.SUCCESS,
        resource=resource,
        description=f"Test {test_id} created",
        tags=["test", "creation"]
    )

    # Test execution with context manager
    try:
        async with emitter.event_context(
            EventType.TEST_EXECUTED,
            actor,
            "execute_test",
            resource=resource,
            description=f"Executing test {test_id}"
        ):
            # Actual test execution
            result = await run_test(test_id)

            # Emit test result event
            if result.passed:
                await emitter.emit(
                    event_type=EventType.TEST_PASSED,
                    actor=actor,
                    action="test_passed",
                    outcome=EventOutcome.SUCCESS,
                    resource=resource,
                    metadata={"assertions": result.assertions},
                    tags=["test", "passed"]
                )
            else:
                await emitter.emit(
                    event_type=EventType.TEST_FAILED,
                    actor=actor,
                    action="test_failed",
                    outcome=EventOutcome.FAILURE,
                    resource=resource,
                    metadata={"error": result.error, "line": result.line},
                    tags=["test", "failed"]
                )

            return result

    except Exception as e:
        # Automatic failure event from context manager
        logger.error(f"Test execution failed: {e}")
        raise


# Example: Security event tracking
async def track_authentication_attempt(
    email: str,
    ip_address: str,
    success: bool,
    session_id: str = None
):
    """Track authentication attempts for security auditing."""
    emitter = get_global_emitter()

    await emitter.emit_user_login(
        user_id=email if success else "unknown",
        user_email=email,
        ip_address=ip_address,
        success=success,
        session_id=session_id,
        metadata={
            "timestamp": datetime.utcnow().isoformat(),
            "attempt": "success" if success else "failure"
        }
    )

    # Track failed attempts for security monitoring
    if not success:
        await emitter.emit(
            event_type=EventType.SECURITY_AUTH_FAILED,
            actor=EventActor(id="unknown", type="anonymous", ip_address=ip_address),
            action="login_failed",
            outcome=EventOutcome.FAILURE,
            severity=EventSeverity.WARNING,
            description=f"Failed login attempt for {email}",
            metadata={"email": email},
            tags=["security", "authentication", "failed"]
        )


# Example: Data access tracking for compliance
async def track_data_access(
    user_id: str,
    data_id: str,
    data_type: str,
    operation: str,
    contains_phi: bool = False
):
    """Track data access for GDPR/HIPAA compliance."""
    emitter = get_global_emitter()

    tags = ["data", operation.lower()]
    if contains_phi:
        tags.append("phi")
        tags.append("healthcare")

    await emitter.emit(
        event_type=EventType.DATA_ACCESSED,
        actor=EventActor(id=user_id, type="user"),
        action=f"access_{data_type}",
        outcome=EventOutcome.SUCCESS,
        resource=EventResource(
            id=data_id,
            type=data_type,
            attributes={"contains_phi": contains_phi}
        ),
        description=f"User accessed {data_type} data",
        tags=tags,
        compliance_flags=["HIPAA"] if contains_phi else ["GDPR"]
    )


# Helper function placeholder
async def run_test(test_id: str):
    """Placeholder for test execution."""
    class TestResult:
        passed = True
        assertions = 10
        error = None
        line = None

    return TestResult()
