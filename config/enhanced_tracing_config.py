"""
Enhanced Tracing Configuration for Sentinel Platform

This module configures OpenTelemetry distributed tracing with Jaeger backend
for comprehensive request tracing across all microservices.
"""

from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.sdk.trace.sampling import (
    TraceIdRatioBased,
    ParentBased,
    ALWAYS_ON,
    ALWAYS_OFF
)
from typing import Optional
import logging
import os

logger = logging.getLogger(__name__)


class AdaptiveSampler:
    """
    Adaptive sampler that adjusts sampling rate based on error conditions.

    - Normal operations: 1% sampling
    - Errors detected: 100% sampling for 5 minutes
    - High load: Reduces to 0.1% sampling
    """

    def __init__(self, base_rate: float = 0.01):
        self.base_rate = base_rate
        self.current_rate = base_rate
        self.error_mode = False
        self.error_mode_until = 0

        # Create samplers for different scenarios
        self.base_sampler = TraceIdRatioBased(base_rate)
        self.error_sampler = ALWAYS_ON
        self.high_load_sampler = TraceIdRatioBased(0.001)

    def should_sample(self, context, trace_id, name, kind, attributes, links, trace_state):
        """Determine if this trace should be sampled."""
        import time

        # Check if we're in error mode
        if self.error_mode and time.time() < self.error_mode_until:
            return self.error_sampler.should_sample(
                context, trace_id, name, kind, attributes, links, trace_state
            )
        elif self.error_mode:
            # Exit error mode
            self.error_mode = False
            logger.info("Exiting error sampling mode, returning to base rate")

        # Use base sampler
        return self.base_sampler.should_sample(
            context, trace_id, name, kind, attributes, links, trace_state
        )

    def trigger_error_mode(self, duration_seconds: int = 300):
        """Trigger 100% sampling for the specified duration."""
        import time
        self.error_mode = True
        self.error_mode_until = time.time() + duration_seconds
        logger.warning(f"Entering error sampling mode for {duration_seconds} seconds")

    def get_description(self):
        """Get sampler description."""
        return f"AdaptiveSampler(base_rate={self.base_rate})"


class TracingConfiguration:
    """
    Centralized tracing configuration for Sentinel platform.
    """

    def __init__(
        self,
        service_name: str,
        service_version: str = "1.0.0",
        jaeger_host: str = "localhost",
        jaeger_port: int = 6831,
        sampling_rate: float = 0.01,
        enable_console_export: bool = False,
        adaptive_sampling: bool = True
    ):
        self.service_name = service_name
        self.service_version = service_version
        self.jaeger_host = jaeger_host
        self.jaeger_port = jaeger_port
        self.sampling_rate = sampling_rate
        self.enable_console_export = enable_console_export
        self.adaptive_sampling = adaptive_sampling

        self.tracer_provider: Optional[TracerProvider] = None
        self.tracer: Optional[trace.Tracer] = None
        self.adaptive_sampler: Optional[AdaptiveSampler] = None

    def initialize(self) -> trace.Tracer:
        """
        Initialize OpenTelemetry tracing with Jaeger exporter.

        Returns:
            Configured tracer instance
        """

        # Create resource with service information
        resource = Resource.create({
            SERVICE_NAME: self.service_name,
            SERVICE_VERSION: self.service_version,
            "deployment.environment": os.getenv("ENVIRONMENT", "development"),
            "host.name": os.getenv("HOSTNAME", "unknown"),
        })

        # Configure sampler
        if self.adaptive_sampling:
            self.adaptive_sampler = AdaptiveSampler(base_rate=self.sampling_rate)
            sampler = ParentBased(root=self.adaptive_sampler)
        else:
            sampler = ParentBased(
                root=TraceIdRatioBased(self.sampling_rate)
            )

        # Create tracer provider
        self.tracer_provider = TracerProvider(
            resource=resource,
            sampler=sampler
        )

        # Configure Jaeger exporter
        jaeger_exporter = JaegerExporter(
            agent_host_name=self.jaeger_host,
            agent_port=self.jaeger_port,
        )

        # Add batch span processor for Jaeger
        self.tracer_provider.add_span_processor(
            BatchSpanProcessor(jaeger_exporter)
        )

        # Optionally add console exporter for debugging
        if self.enable_console_export:
            console_exporter = ConsoleSpanExporter()
            self.tracer_provider.add_span_processor(
                BatchSpanProcessor(console_exporter)
            )

        # Set as global tracer provider
        trace.set_tracer_provider(self.tracer_provider)

        # Get tracer instance
        self.tracer = trace.get_tracer(
            instrumenting_module_name=self.service_name,
            instrumenting_library_version=self.service_version
        )

        logger.info(
            f"Tracing initialized for {self.service_name} v{self.service_version} "
            f"with Jaeger at {self.jaeger_host}:{self.jaeger_port}"
        )

        return self.tracer

    def instrument_fastapi(self, app):
        """
        Instrument FastAPI application with automatic tracing.

        Args:
            app: FastAPI application instance
        """
        FastAPIInstrumentor.instrument_app(app)
        logger.info(f"FastAPI instrumentation enabled for {self.service_name}")

    def instrument_requests(self):
        """Instrument requests library for outgoing HTTP calls."""
        RequestsInstrumentor().instrument()
        logger.info("Requests library instrumented for outgoing HTTP tracing")

    def instrument_sqlalchemy(self, engine):
        """
        Instrument SQLAlchemy for database query tracing.

        Args:
            engine: SQLAlchemy engine instance
        """
        SQLAlchemyInstrumentor().instrument(engine=engine)
        logger.info("SQLAlchemy instrumented for database query tracing")

    def instrument_logging(self):
        """Instrument Python logging to include trace context."""
        LoggingInstrumentor().instrument()
        logger.info("Logging instrumented with trace context")

    def instrument_all(self, app=None, db_engine=None):
        """
        Convenience method to instrument all common components.

        Args:
            app: Optional FastAPI application
            db_engine: Optional SQLAlchemy engine
        """
        if app:
            self.instrument_fastapi(app)

        self.instrument_requests()
        self.instrument_logging()

        if db_engine:
            self.instrument_sqlalchemy(db_engine)

    def trigger_error_sampling(self, duration_seconds: int = 300):
        """
        Trigger 100% sampling for error investigation.

        Args:
            duration_seconds: How long to sample at 100%
        """
        if self.adaptive_sampler:
            self.adaptive_sampler.trigger_error_mode(duration_seconds)
        else:
            logger.warning("Adaptive sampling not enabled, cannot trigger error mode")

    def shutdown(self):
        """Gracefully shutdown tracing and flush remaining spans."""
        if self.tracer_provider:
            self.tracer_provider.shutdown()
            logger.info("Tracing shutdown complete")


# =============================================================================
# Factory Functions
# =============================================================================

def create_tracer(
    service_name: str,
    service_version: str = "1.0.0",
    jaeger_host: Optional[str] = None,
    jaeger_port: Optional[int] = None,
    sampling_rate: Optional[float] = None,
    enable_console: bool = False
) -> trace.Tracer:
    """
    Factory function to create and initialize a tracer.

    Args:
        service_name: Name of the service
        service_version: Version of the service
        jaeger_host: Jaeger agent hostname (default: from env or localhost)
        jaeger_port: Jaeger agent port (default: from env or 6831)
        sampling_rate: Sampling rate 0.0-1.0 (default: from env or 0.01)
        enable_console: Enable console export for debugging

    Returns:
        Configured tracer instance
    """

    # Read configuration from environment
    jaeger_host = jaeger_host or os.getenv("JAEGER_AGENT_HOST", "localhost")
    jaeger_port = jaeger_port or int(os.getenv("JAEGER_AGENT_PORT", "6831"))
    sampling_rate = sampling_rate or float(os.getenv("TRACING_SAMPLING_RATE", "0.01"))

    # Create configuration
    config = TracingConfiguration(
        service_name=service_name,
        service_version=service_version,
        jaeger_host=jaeger_host,
        jaeger_port=jaeger_port,
        sampling_rate=sampling_rate,
        enable_console_export=enable_console,
        adaptive_sampling=True
    )

    # Initialize and return tracer
    return config.initialize()


def get_current_span():
    """Get the current active span."""
    return trace.get_current_span()


def add_span_attributes(**attributes):
    """
    Add attributes to the current span.

    Args:
        **attributes: Key-value pairs to add as span attributes
    """
    span = get_current_span()
    if span:
        for key, value in attributes.items():
            span.set_attribute(key, value)


def add_span_event(name: str, **attributes):
    """
    Add an event to the current span.

    Args:
        name: Event name
        **attributes: Key-value pairs to add as event attributes
    """
    span = get_current_span()
    if span:
        span.add_event(name, attributes=attributes)


def set_span_error(exception: Exception):
    """
    Mark the current span as error and record exception.

    Args:
        exception: Exception that occurred
    """
    span = get_current_span()
    if span:
        span.set_status(trace.Status(trace.StatusCode.ERROR))
        span.record_exception(exception)


# =============================================================================
# Example Usage
# =============================================================================

if __name__ == "__main__":
    # Initialize tracing for a service
    config = TracingConfiguration(
        service_name="api-gateway",
        service_version="1.0.0",
        jaeger_host="localhost",
        jaeger_port=6831,
        sampling_rate=0.01,
        enable_console_export=True
    )

    tracer = config.initialize()

    # Example: Create a span
    with tracer.start_as_current_span("example-operation") as span:
        span.set_attribute("example.attribute", "value")
        span.add_event("Processing started")

        # Simulate work
        import time
        time.sleep(0.1)

        span.add_event("Processing completed")

    # Shutdown
    config.shutdown()
