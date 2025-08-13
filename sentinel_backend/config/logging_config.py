import logging
import sys
import structlog
from sentinel_backend.config.settings import get_application_settings

def setup_logging():
    """
    Set up structured logging for the application.
    """
    app_settings = get_application_settings()
    log_level = getattr(logging, app_settings.log_level.upper(), logging.INFO)

    # Common processors for all logs
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    # Configure structlog
    structlog.configure(
        processors=shared_processors + [
            # Prepare event dict for rendering.
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure the renderer for structlog
    formatter = structlog.stdlib.ProcessorFormatter(
        # These run on the event dict after the shared processors.
        processor=structlog.processors.JSONRenderer(),
        # These run on the string rendered by the processor.
        foreign_pre_chain=shared_processors,
    )

    # Configure standard logging
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)

    # Silence other loggers
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
