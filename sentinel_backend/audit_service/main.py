"""
Audit Service Main Application

Standalone audit service that can run independently or as part of Sentinel platform.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router as audit_router
from .emitter import init_global_emitter, shutdown_global_emitter
from .storage.repository import EventRepository
from ..config.settings import get_settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Audit Service...")

    # Initialize global emitter
    await init_global_emitter(
        batch_size=100,
        flush_interval_seconds=5,
        enable_deduplication=True
    )

    # Initialize repository
    settings = get_settings()
    repo = EventRepository(settings.database.url)
    await repo.initialize()

    # Register batch handler
    from .emitter import get_global_emitter
    emitter = get_global_emitter()

    async def save_batch_handler(batch):
        """Save batches to database."""
        try:
            await repo.save_batch(batch)
        except Exception as e:
            logger.error(f"Failed to save batch: {e}")

    emitter.register_handler(save_batch_handler)

    logger.info("Audit Service started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Audit Service...")
    await shutdown_global_emitter()
    await repo.close()
    logger.info("Audit Service stopped")


# Create FastAPI application
app = FastAPI(
    title="Sentinel Audit Service",
    description="Event-driven audit trail system for complete traceability",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.security.cors_origins,
    allow_credentials=settings.security.cors_allow_credentials,
    allow_methods=settings.security.cors_allow_methods,
    allow_headers=settings.security.cors_allow_headers
)

# Include routers
app.include_router(audit_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Sentinel Audit Service",
        "version": "1.0.0",
        "status": "operational"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8006,
        reload=True,
        log_level="info"
    )
