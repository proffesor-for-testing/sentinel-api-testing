"""
Enhanced Tracing Configuration for Sentinel Platform

Provides advanced OpenTelemetry tracing with:
- Context propagation
- Custom span attributes
- Sampling strategies
- Error tracking
- Performance monitoring
"""
from opentelemetry import trace, context, baggage
from opentelemetry.sdk.trace import TracerProvider, sampling
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.sdk.trace.sampling import ParentBasedTraceIdRatio, ALWAYS_ON, ALWAYS_OFF
from opentelemetry.trace import Status, StatusCode, SpanKind
from opentelemetry.context import attach, detach
from typing import Optional, Dict, Any
import structlog
from sentinel_backend.config.settings import get_network_settings, get_application_settings

logger = structlog.get_logger(__name__)


class SentinelSampler(sampling.Sampler):
    """
    Custom sampler for Sentinel platform.

    Sampling rules:
    - Always sample errors
    - Sample critical operations at higher rate
    - Sample regular operations at lower rate
    - Never sample health checks in production
    """

    def __init__(self, base_rate: float = 0.1):
        self.base_rate = base_rate
        self.critical_operations = {
            'generate_tests',
            'execute_agent',
            'analyze_spec',
            'authenticate',
        }
        self.always_sample = sampling.ALWAYS_ON
        self.never_sample = sampling.ALWAYS_OFF
        self.parent_based = sampling.ParentBased(
            root=sampling.TraceIdRatioBased(base_rate)
        )

    def should_sample(self, parent_context, trace_id, name, kind=None, attributes=None, links=None, trace_state=None):
        """Determine if a span should be sampled."""
        # Always sample if error occurred
        if attributes and attributes.get('error') == True:
            return self.always_sample.should_sample(
                parent_context, trace_id, name, kind, attributes, links, trace_state
            )

        # Never sample health checks and metrics
        if name in ['/health', '/metrics', 'health_check']:
            return self.never_sample.should_sample(
                parent_context, trace_id, name, kind, attributes, links, trace_state
            )

        # Higher sampling for critical operations
        if any(op in name for op in self.critical_operations):
            critical_sampler = sampling.TraceIdRatioBased(min(self.base_rate * 5, 1.0))
            return critical_sampler.should_sample(
                parent_context, trace_id, name, kind, attributes, links, trace_state
            )

        # Default parent-based sampling
        return self.parent_based.should_sample(
            parent_context, trace_id, name, kind, attributes, links, trace_state
        )

    def get_description(self):
        return f"SentinelSampler(base_rate={self.base_rate})"


def setup_enhanced_tracing(
    app,
    service_name: str,
    service_version: str = "1.0.0",
    environment: str = "production",
    enable_console_export: bool = False
):
    """
    Set up enhanced OpenTelemetry tracing for the application.

    Args:
        app: FastAPI application instance
        service_name: Name of the service
        service_version: Version of the service
        environment: Environment (development, staging, production)
        enable_console_export: Enable console span export for debugging
    """
    network_settings = get_network_settings()
    app_settings = get_application_settings()

    # Create resource with service information
    resource = Resource.create({
        SERVICE_NAME: service_name,
        SERVICE_VERSION: service_version,
        "service.namespace": "sentinel",
        "deployment.environment": environment,
        "service.instance.id": f"{service_name}-{id(app)}",
    })

    # Configure sampler based on environment
    if environment == "development":
        sampler = sampling.ALWAYS_ON
    elif environment == "staging":
        sampler = SentinelSampler(base_rate=0.5)
    else:  # production
        sampler = SentinelSampler(base_rate=0.1)

    # Create tracer provider
    provider = TracerProvider(
        resource=resource,
        sampler=sampler
    )

    # Configure Jaeger exporter
    jaeger_exporter = JaegerExporter(
        agent_host_name=network_settings.jaeger_agent_host,
        agent_port=network_settings.jaeger_agent_port,
        max_tag_value_length=1024,
    )

    # Add batch span processor for Jaeger
    provider.add_span_processor(
        BatchSpanProcessor(
            jaeger_exporter,
            max_queue_size=2048,
            max_export_batch_size=512,
            schedule_delay_millis=5000,
        )
    )

    # Optional: OTLP exporter for other backends (e.g., Grafana Tempo)
    # Uncomment if needed
    # otlp_exporter = OTLPSpanExporter(
    #     endpoint="http://tempo:4317",
    #     insecure=True
    # )
    # provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

    # Optional: Console exporter for debugging
    if enable_console_export:
        console_exporter = ConsoleSpanExporter()
        provider.add_span_processor(BatchSpanProcessor(console_exporter))

    # Set global tracer provider
    trace.set_tracer_provider(provider)

    # Instrument FastAPI
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        excluded_urls="/health,/metrics",  # Don't trace health checks
    )

    # Instrument HTTP client
    HTTPXClientInstrumentor().instrument()

    # Instrument SQLAlchemy (if database is used)
    try:
        SQLAlchemyInstrumentor().instrument(
            enable_commenter=True,
            commenter_options={
                "db_driver": True,
                "db_framework": True,
            }
        )
    except Exception as e:
        logger.warning("Failed to instrument SQLAlchemy", error=str(e))

    logger.info(
        "tracing_configured",
        service_name=service_name,
        environment=environment,
        jaeger_host=network_settings.jaeger_agent_host,
        jaeger_port=network_settings.jaeger_agent_port,
    )


def create_span(
    name: str,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None
):
    """
    Create a new span with the given name and attributes.

    Usage:
        with create_span("operation_name", attributes={"key": "value"}):
            # Do work
            pass
    """
    tracer = trace.get_tracer(__name__)
    return tracer.start_as_current_span(
        name,
        kind=kind,
        attributes=attributes or {}
    )


def add_span_attributes(attributes: Dict[str, Any]):
    """Add attributes to the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        for key, value in attributes.items():
            span.set_attribute(key, value)


def add_span_event(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Add an event to the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.add_event(name, attributes or {})


def record_exception(exception: Exception):
    """Record an exception in the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.record_exception(exception)
        span.set_status(Status(StatusCode.ERROR, str(exception)))


def set_span_status(status_code: StatusCode, description: Optional[str] = None):
    """Set the status of the current span."""
    span = trace.get_current_span()
    if span and span.is_recording():
        span.set_status(Status(status_code, description or ""))


def propagate_context(carrier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract trace context from carrier and propagate it.
    Useful for cross-service communication.
    """
    from opentelemetry.propagate import extract, inject

    # Extract context from carrier
    ctx = extract(carrier)

    # Attach to current context
    token = attach(ctx)

    return token


def inject_context(carrier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inject current trace context into carrier.
    Useful for passing context to other services.
    """
    from opentelemetry.propagate import inject

    inject(carrier)
    return carrier


# Convenience decorators
def traced(span_name: Optional[str] = None, kind: SpanKind = SpanKind.INTERNAL):
    """
    Decorator to automatically trace a function.

    Usage:
        @traced("my_operation")
        def my_function():
            pass
    """
    def decorator(func):
        import functools

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            name = span_name or func.__name__
            with create_span(name, kind):
                try:
                    result = await func(*args, **kwargs)
                    set_span_status(StatusCode.OK)
                    return result
                except Exception as e:
                    record_exception(e)
                    raise

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            name = span_name or func.__name__
            with create_span(name, kind):
                try:
                    result = func(*args, **kwargs)
                    set_span_status(StatusCode.OK)
                    return result
                except Exception as e:
                    record_exception(e)
                    raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
