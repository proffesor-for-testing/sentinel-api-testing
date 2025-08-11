"""
Application factory for Spec Service.

This module provides a factory pattern for creating testable FastAPI instances
for the specification parsing and management service.
"""
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
import yaml
from datetime import datetime


class SpecificationUpload(BaseModel):
    """Model for specification upload."""
    raw_spec: str
    source_filename: Optional[str] = None
    source_url: Optional[str] = None
    project_id: Optional[int] = None


class SpecificationResponse(BaseModel):
    """Model for specification response."""
    id: int
    raw_spec: Dict[str, Any]
    parsed_spec: Dict[str, Any]
    internal_graph: Optional[Dict[str, Any]] = None
    source_filename: Optional[str] = None
    source_url: Optional[str] = None
    version: str
    created_at: str
    updated_at: str
    llm_readiness_score: float = 0.0


class SpecConfig:
    """Configuration for specification service."""
    def __init__(self, 
                 storage_backend: str = "memory",
                 max_spec_size: int = 10 * 1024 * 1024,  # 10MB
                 enable_validation: bool = True):
        self.storage_backend = storage_backend
        self.max_spec_size = max_spec_size
        self.enable_validation = enable_validation
        self.specifications = {}  # In-memory storage for testing
        self.next_id = 1


def parse_openapi_spec(raw_spec: str) -> Dict[str, Any]:
    """Parse OpenAPI specification from string."""
    try:
        # Try JSON first
        spec = json.loads(raw_spec)
    except json.JSONDecodeError:
        try:
            # Try YAML
            spec = yaml.safe_load(raw_spec)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid specification format: {str(e)}")
    
    # Handle None or non-dict results
    if spec is None or not isinstance(spec, dict):
        raise ValueError("Not a valid OpenAPI/Swagger specification")
    
    # Basic validation
    if "openapi" not in spec and "swagger" not in spec:
        raise ValueError("Not a valid OpenAPI/Swagger specification")
    
    return spec


def calculate_llm_readiness_score(spec: Dict[str, Any]) -> float:
    """Calculate LLM readiness score for a specification."""
    score = 0.0
    max_score = 100.0
    
    # Check for required fields
    if "info" in spec:
        score += 10
        if "description" in spec["info"]:
            score += 5
    
    if "paths" in spec:
        score += 20
        # Check path documentation
        total_operations = 0
        documented_operations = 0
        
        for path, methods in spec.get("paths", {}).items():
            for method, operation in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    total_operations += 1
                    if "summary" in operation or "description" in operation:
                        documented_operations += 1
                    if "parameters" in operation:
                        score += 1
                    if "responses" in operation:
                        score += 1
        
        if total_operations > 0:
            doc_ratio = documented_operations / total_operations
            score += doc_ratio * 30
    
    # Check for schemas/components
    if "components" in spec and "schemas" in spec["components"]:
        score += 20
    elif "definitions" in spec:  # Swagger 2.0
        score += 20
    
    # Check for security definitions
    if "security" in spec or "securityDefinitions" in spec:
        score += 15
    
    return min(score, max_score) / max_score


def create_spec_app(
    config: Optional[SpecConfig] = None,
    dependency_overrides: Optional[Dict] = None
) -> FastAPI:
    """
    Create a FastAPI application for specification service.
    
    Args:
        config: Specification service configuration
        dependency_overrides: Optional dependency overrides for testing
    
    Returns:
        Configured FastAPI application
    """
    if config is None:
        config = SpecConfig()
    
    app = FastAPI(
        title="Sentinel Spec Service",
        description="OpenAPI specification parsing and management service",
        version="1.0.0"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Apply dependency overrides if provided
    if dependency_overrides:
        for dep, override in dependency_overrides.items():
            app.dependency_overrides[dep] = override
    
    # Routes
    @app.get("/")
    async def root():
        return {
            "service": "Sentinel Spec Service",
            "version": "1.0.0",
            "status": "operational"
        }
    
    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @app.post("/api/v1/specifications", response_model=SpecificationResponse)
    async def upload_specification(spec_upload: SpecificationUpload):
        """Upload and parse an API specification."""
        
        # Check size
        if len(spec_upload.raw_spec) > config.max_spec_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Specification exceeds maximum size of {config.max_spec_size} bytes"
            )
        
        # Parse specification
        try:
            parsed_spec = parse_openapi_spec(spec_upload.raw_spec)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        
        # Calculate LLM readiness score
        llm_score = calculate_llm_readiness_score(parsed_spec)
        
        # Extract version
        version = parsed_spec.get("info", {}).get("version", "1.0.0")
        
        # Store specification
        spec_id = config.next_id
        config.next_id += 1
        
        now = datetime.utcnow().isoformat()
        
        specification = {
            "id": spec_id,
            "raw_spec": parsed_spec,  # Store as dict for easier testing
            "parsed_spec": parsed_spec,
            "internal_graph": None,  # TODO: Generate internal graph
            "source_filename": spec_upload.source_filename,
            "source_url": spec_upload.source_url,
            "version": version,
            "created_at": now,
            "updated_at": now,
            "llm_readiness_score": llm_score,
            "project_id": spec_upload.project_id
        }
        
        config.specifications[spec_id] = specification
        
        return SpecificationResponse(**specification)
    
    @app.get("/api/v1/specifications")
    async def list_specifications(
        skip: int = 0,
        limit: int = 100,
        project_id: Optional[int] = None
    ):
        """List all specifications."""
        specs = list(config.specifications.values())
        
        # Filter by project if specified
        if project_id is not None:
            specs = [s for s in specs if s.get("project_id") == project_id]
        
        # Apply pagination
        specs = specs[skip:skip + limit]
        
        return specs
    
    @app.get("/api/v1/specifications/{spec_id}", response_model=SpecificationResponse)
    async def get_specification(spec_id: int):
        """Get a specific specification by ID."""
        if spec_id not in config.specifications:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Specification {spec_id} not found"
            )
        
        return SpecificationResponse(**config.specifications[spec_id])
    
    @app.put("/api/v1/specifications/{spec_id}", response_model=SpecificationResponse)
    async def update_specification(spec_id: int, spec_upload: SpecificationUpload):
        """Update an existing specification."""
        if spec_id not in config.specifications:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Specification {spec_id} not found"
            )
        
        # Parse new specification
        try:
            parsed_spec = parse_openapi_spec(spec_upload.raw_spec)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )
        
        # Update specification
        spec = config.specifications[spec_id]
        spec["raw_spec"] = parsed_spec
        spec["parsed_spec"] = parsed_spec
        spec["source_filename"] = spec_upload.source_filename or spec["source_filename"]
        spec["source_url"] = spec_upload.source_url or spec["source_url"]
        spec["version"] = parsed_spec.get("info", {}).get("version", spec["version"])
        spec["updated_at"] = datetime.utcnow().isoformat()
        spec["llm_readiness_score"] = calculate_llm_readiness_score(parsed_spec)
        
        return SpecificationResponse(**spec)
    
    @app.delete("/api/v1/specifications/{spec_id}")
    async def delete_specification(spec_id: int):
        """Delete a specification."""
        if spec_id not in config.specifications:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Specification {spec_id} not found"
            )
        
        del config.specifications[spec_id]
        return {"message": f"Specification {spec_id} deleted successfully"}
    
    @app.post("/api/v1/specifications/{spec_id}/validate")
    async def validate_specification(spec_id: int):
        """Validate a specification against OpenAPI schema."""
        if spec_id not in config.specifications:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Specification {spec_id} not found"
            )
        
        spec = config.specifications[spec_id]["parsed_spec"]
        
        # Basic validation
        errors = []
        warnings = []
        
        # Check required fields
        if "openapi" not in spec and "swagger" not in spec:
            errors.append("Missing OpenAPI/Swagger version field")
        
        if "info" not in spec:
            errors.append("Missing 'info' section")
        elif "title" not in spec["info"]:
            errors.append("Missing API title in 'info' section")
        
        if "paths" not in spec:
            warnings.append("No paths defined")
        
        # Check for deprecated features
        if "swagger" in spec and spec["swagger"] == "2.0":
            warnings.append("Using Swagger 2.0 - consider upgrading to OpenAPI 3.0")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    return app


def create_test_spec_app(specifications: Optional[Dict[int, Dict]] = None) -> FastAPI:
    """
    Create a test app with predefined specifications.
    
    Args:
        specifications: Optional dictionary of test specifications
    
    Returns:
        Configured FastAPI app for testing
    """
    config = SpecConfig()
    
    if specifications:
        config.specifications = specifications
        config.next_id = max(specifications.keys()) + 1 if specifications else 1
    
    return create_spec_app(config)