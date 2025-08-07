import os
import json
import yaml
from typing import List
from fastapi import FastAPI, HTTPException, Depends, status, Request
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from prance import ResolvingParser
from openapi_core import Spec
import sys
import structlog
import uuid
from prometheus_fastapi_instrumentator import Instrumentator

from sentinel_backend.config.settings import get_database_settings, get_application_settings
from sentinel_backend.config.logging_config import setup_logging
from sentinel_backend.config.tracing_config import setup_tracing

from sentinel_backend.spec_service.models import Base, ApiSpecification
from sentinel_backend.spec_service.schemas import (
    SpecificationCreate,
    SpecificationResponse,
    SpecificationSummary,
    DeleteResponse
)

# Get configuration settings
db_settings = get_database_settings()
app_settings = get_application_settings()

# Set up structured logging
setup_logging()
logger = structlog.get_logger(__name__)

app = FastAPI(
    title="Sentinel Specification Service",
    description="Service for ingesting, parsing, and managing API specifications",
    version=app_settings.app_version
)

# Instrument for Prometheus
Instrumentator().instrument(app).expose(app)

# Set up Jaeger tracing
setup_tracing(app, "spec-service")

@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """
    Injects a correlation ID into every request and log context.
    """
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    
    # Bind the correlation ID to the logger context for this request
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

    response = await call_next(request)
    
    # Add the correlation ID to the response headers
    response.headers["X-Correlation-ID"] = correlation_id
    
    return response

# Create async engine and session with configuration
engine = create_async_engine(
    db_settings.url,
    pool_size=db_settings.pool_size,
    max_overflow=db_settings.max_overflow,
    pool_timeout=db_settings.pool_timeout,
    pool_recycle=db_settings.pool_recycle
)
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def create_tables():
    """Create database tables if they don't exist"""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        print(f"Warning: Could not connect to database: {e}")
        print("Service will run without database persistence")

@app.on_event("startup")
async def startup_event():
    await create_tables()

def parse_specification(raw_spec: str) -> dict:
    """Parse and validate an OpenAPI specification using prance"""
    try:
        # Try to parse as JSON first
        try:
            spec_dict = json.loads(raw_spec)
        except json.JSONDecodeError:
            # If JSON parsing fails, try YAML
            spec_dict = yaml.safe_load(raw_spec)
        
        # Use prance to resolve references and validate
        parser = ResolvingParser(spec_dict=spec_dict)
        resolved_spec = parser.specification
        
        # Additional validation with openapi-core
        Spec.from_dict(resolved_spec)
        
        return resolved_spec
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid OpenAPI specification: {str(e)}"
        )

def extract_version(parsed_spec: dict) -> str:
    """Extract version from the OpenAPI specification"""
    try:
        return parsed_spec.get("info", {}).get("version", "unknown")
    except:
        return "unknown"

@app.get("/")
async def root():
    return {"message": "Sentinel Specification Service is running"}

@app.post("/api/v1/specifications", response_model=SpecificationResponse)
async def create_specification(
    spec_data: SpecificationCreate, 
    db: AsyncSession = Depends(get_db)
):
    """
    Ingest a new API specification from raw content.
    Parses and validates the specification before storing.
    """
    try:
        # Parse the specification
        parsed_spec = parse_specification(spec_data.raw_spec)
        
        # Extract version from parsed spec
        version = extract_version(parsed_spec)
        
        # Create new specification record
        db_spec = ApiSpecification(
            raw_spec=spec_data.raw_spec,
            parsed_spec=parsed_spec,
            source_url=spec_data.source_url,
            source_filename=spec_data.source_filename,
            version=version
        )
        
        db.add(db_spec)
        await db.commit()
        await db.refresh(db_spec)
        
        return SpecificationResponse.model_validate(db_spec)
    
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating specification: {str(e)}"
        )

@app.get("/api/v1/specifications", response_model=List[SpecificationSummary])
async def list_specifications(db: AsyncSession = Depends(get_db)):
    """
    List all ingested API specifications with summary information.
    """
    try:
        result = await db.execute(select(ApiSpecification))
        specifications = result.scalars().all()
        
        return [SpecificationSummary.model_validate(spec) for spec in specifications]
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving specifications: {str(e)}"
        )

@app.get("/api/v1/specifications/{spec_id}", response_model=SpecificationResponse)
async def get_specification(spec_id: int, db: AsyncSession = Depends(get_db)):
    """
    Retrieve a specific API specification by its ID, including full parsed content.
    """
    try:
        result = await db.execute(
            select(ApiSpecification).where(ApiSpecification.id == spec_id)
        )
        specification = result.scalar_one_or_none()
        
        if not specification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Specification with ID {spec_id} not found"
            )
        
        return SpecificationResponse.model_validate(specification)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving specification: {str(e)}"
        )

@app.delete("/api/v1/specifications/{spec_id}", response_model=DeleteResponse)
async def delete_specification(spec_id: int, db: AsyncSession = Depends(get_db)):
    """
    Delete an API specification by its ID.
    """
    try:
        result = await db.execute(
            select(ApiSpecification).where(ApiSpecification.id == spec_id)
        )
        specification = result.scalar_one_or_none()
        
        if not specification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Specification with ID {spec_id} not found"
            )
        
        await db.delete(specification)
        await db.commit()
        
        return DeleteResponse(
            message=f"Specification {spec_id} successfully deleted",
            deleted_id=spec_id
        )
    
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting specification: {str(e)}"
        )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "specification-service"}
