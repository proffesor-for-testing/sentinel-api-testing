"""
Pydantic schemas for AgentDB service API.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from enum import Enum


class HTTPMethod(str, Enum):
    """HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class TestPatternRequest(BaseModel):
    """Request to store a test pattern."""
    endpoint: str = Field(..., description="API endpoint path", example="/api/users/{id}")
    method: HTTPMethod = Field(..., description="HTTP method")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Request parameters")
    agent_type: str = Field(..., description="Agent type that generated the pattern", example="functional-positive")
    tags: List[str] = Field(default_factory=list, description="Pattern tags")
    response_codes: List[int] = Field(default_factory=list, description="Expected response codes")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class TestPatternResponse(BaseModel):
    """Response after storing a pattern."""
    pattern_id: str = Field(..., description="Unique pattern ID")
    status: str = Field(default="stored", description="Operation status")


class SearchPatternRequest(BaseModel):
    """Request to search for similar patterns."""
    query_pattern: Dict[str, Any] = Field(..., description="Pattern to search for")
    top_k: int = Field(default=10, ge=1, le=100, description="Number of results")
    min_similarity: float = Field(default=0.7, ge=0.0, le=1.0, description="Minimum similarity score")
    filters: Optional[Dict[str, Any]] = Field(default=None, description="Metadata filters")


class PatternResult(BaseModel):
    """Single pattern search result."""
    pattern_id: str = Field(..., description="Pattern ID")
    score: float = Field(..., description="Similarity score [0, 1]", ge=0.0, le=1.0)
    endpoint: str = Field(..., description="Endpoint path")
    method: str = Field(..., description="HTTP method")
    parameters: Dict[str, Any] = Field(..., description="Parameters")
    agent_type: str = Field(..., description="Agent type")
    metadata: Dict[str, Any] = Field(..., description="Full metadata")


class SearchPatternResponse(BaseModel):
    """Response with search results."""
    results: List[PatternResult] = Field(..., description="Search results")
    count: int = Field(..., description="Number of results")
    query_time_ms: float = Field(..., description="Query execution time in milliseconds")


class ExecutionResultRequest(BaseModel):
    """Request to store an execution result."""
    test_id: str = Field(..., description="Test case ID")
    status: str = Field(..., description="Execution status (pass, fail, error)")
    endpoint: str = Field(..., description="API endpoint")
    method: str = Field(..., description="HTTP method")
    response_code: int = Field(..., description="HTTP response code")
    latency_ms: int = Field(..., description="Response latency in milliseconds")
    assertions: Dict[str, int] = Field(..., description="Assertion results")
    error_pattern: Optional[str] = Field(default=None, description="Error pattern if failed")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class ExecutionResultResponse(BaseModel):
    """Response after storing execution result."""
    result_id: str = Field(..., description="Unique result ID")
    status: str = Field(default="stored", description="Operation status")


class FailurePattern(BaseModel):
    """Failure pattern cluster."""
    pattern: Dict[str, Any] = Field(..., description="Common failure pattern")
    occurrences: int = Field(..., description="Number of occurrences")
    examples: List[Dict[str, Any]] = Field(..., description="Example failures")


class FailureAnalysisResponse(BaseModel):
    """Response with failure pattern analysis."""
    endpoint: str = Field(..., description="Analyzed endpoint")
    method: str = Field(..., description="HTTP method")
    failure_patterns: List[FailurePattern] = Field(..., description="Identified failure patterns")
    total_failures: int = Field(..., description="Total number of failures analyzed")


class AgentBehaviorRequest(BaseModel):
    """Request to store agent behavior."""
    agent_type: str = Field(..., description="Agent type")
    strategy: str = Field(..., description="Behavior strategy")
    contexts: List[str] = Field(..., description="Applicable contexts")
    patterns: List[str] = Field(..., description="Behavior patterns")
    performance_metrics: Dict[str, float] = Field(..., description="Performance metrics")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class AgentBehaviorResponse(BaseModel):
    """Response after storing behavior."""
    behavior_id: str = Field(..., description="Unique behavior ID")
    status: str = Field(default="stored", description="Operation status")


class BehaviorSearchRequest(BaseModel):
    """Request to search for agent behaviors."""
    agent_type: str = Field(..., description="Agent type")
    context: Dict[str, Any] = Field(..., description="Execution context")
    top_k: int = Field(default=10, ge=1, le=50, description="Number of results")
    min_success_rate: float = Field(default=0.8, ge=0.0, le=1.0, description="Minimum success rate")


class BehaviorResult(BaseModel):
    """Agent behavior search result."""
    behavior_id: str = Field(..., description="Behavior ID")
    score: float = Field(..., description="Similarity score")
    agent_type: str = Field(..., description="Agent type")
    strategy: str = Field(..., description="Behavior strategy")
    performance_metrics: Dict[str, float] = Field(..., description="Performance metrics")
    metadata: Dict[str, Any] = Field(..., description="Full metadata")


class BehaviorSearchResponse(BaseModel):
    """Response with behavior search results."""
    results: List[BehaviorResult] = Field(..., description="Search results")
    count: int = Field(..., description="Number of results")


class CollectionStats(BaseModel):
    """Statistics for a vector collection."""
    collection: str = Field(..., description="Collection name")
    vector_count: int = Field(..., description="Number of vectors")
    dimension: int = Field(..., description="Vector dimension")
    index_type: str = Field(default="HNSW", description="Index type")
    memory_mb: float = Field(..., description="Memory usage in MB")


class SystemStatsResponse(BaseModel):
    """Response with system statistics."""
    collections: Dict[str, CollectionStats] = Field(..., description="Collection statistics")
    total_vectors: int = Field(..., description="Total vectors across all collections")
    total_memory_mb: float = Field(..., description="Total memory usage in MB")
    embedding_dimension: int = Field(..., description="Embedding vector dimension")


class BatchPatternRequest(BaseModel):
    """Request to batch store patterns."""
    patterns: List[Dict[str, Any]] = Field(..., description="List of test patterns", min_items=1, max_items=1000)


class BatchPatternResponse(BaseModel):
    """Response after batch storing patterns."""
    pattern_ids: List[str] = Field(..., description="List of pattern IDs")
    count: int = Field(..., description="Number of patterns stored")
    status: str = Field(default="stored", description="Operation status")


class UpdateMetricsRequest(BaseModel):
    """Request to update pattern metrics."""
    success_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Success rate")
    test_count: Optional[int] = Field(default=None, ge=0, description="Total test count")
    avg_latency_ms: Optional[int] = Field(default=None, ge=0, description="Average latency")


class UpdateMetricsResponse(BaseModel):
    """Response after updating metrics."""
    pattern_id: str = Field(..., description="Pattern ID")
    status: str = Field(default="updated", description="Operation status")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(default="healthy", description="Service status")
    embedding_model: str = Field(..., description="Embedding model name")
    embedding_dimension: int = Field(..., description="Embedding dimension")
    collections: List[str] = Field(..., description="Available collections")
