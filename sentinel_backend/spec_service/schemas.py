from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class SpecificationCreate(BaseModel):
    raw_spec: str = Field(..., description="The original specification content (JSON or YAML)")
    source_url: Optional[str] = Field(None, description="URL from which the spec was fetched")
    source_filename: Optional[str] = Field(None, description="Original filename if uploaded")

class SpecificationResponse(BaseModel):
    id: int
    project_id: Optional[int] = None
    raw_spec: str
    parsed_spec: Dict[str, Any]
    internal_graph: Optional[Dict[str, Any]] = None
    source_url: Optional[str] = None
    source_filename: Optional[str] = None
    llm_readiness_score: Optional[float] = None
    version: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class SpecificationSummary(BaseModel):
    """Lighter version for list endpoints"""
    id: int
    source_filename: Optional[str] = None
    source_url: Optional[str] = None
    version: Optional[str] = None
    llm_readiness_score: Optional[float] = None
    created_at: datetime

    class Config:
        from_attributes = True

class DeleteResponse(BaseModel):
    message: str
    deleted_id: int
