from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from sentinel_backend.config.settings import get_network_settings

def setup_tracing(app, service_name: str):
    """
    Set up Jaeger tracing for the application.
    """
    network_settings = get_network_settings()

    # Create a resource with the service name
    resource = Resource.create({"service.name": service_name})

    # Set up a tracer provider with the resource
    trace.set_tracer_provider(TracerProvider(resource=resource))

    # Configure the Jaeger exporter with the service name
    jaeger_exporter = JaegerExporter(
        agent_host_name=network_settings.jaeger_agent_host,
        agent_port=network_settings.jaeger_agent_port,
    )

    # Use a BatchSpanProcessor to send spans in batches
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(jaeger_exporter)
    )

    # Instrument the FastAPI application (without service_name parameter)
    FastAPIInstrumentor.instrument_app(app, tracer_provider=trace.get_tracer_provider())
