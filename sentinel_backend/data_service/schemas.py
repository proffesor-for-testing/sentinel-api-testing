from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums for status fields
class TestStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"

class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

# Test Case schemas
class TestCaseCreate(BaseModel):
    spec_id: int
    agent_type: str = Field(..., description="Type of agent that generated the test")
    description: Optional[str] = Field(None, description="Natural language description")
    test_definition: Dict[str, Any] = Field(..., description="Complete test definition")
    tags: Optional[List[str]] = Field(None, description="Tags for categorization")

class TestCaseResponse(BaseModel):
    id: int
    spec_id: int
    agent_type: str
    description: Optional[str] = None
    test_definition: Dict[str, Any]
    tags: Optional[List[str]] = None
    created_at: datetime

    class Config:
        from_attributes = True

class TestCaseSummary(BaseModel):
    """Lighter version for list endpoints"""
    id: int
    spec_id: int
    agent_type: str
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Test Suite schemas
class TestSuiteCreate(BaseModel):
    name: str = Field(..., description="Name of the test suite")
    description: Optional[str] = Field(None, description="Description of the suite")

class TestSuiteResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    test_cases: Optional[List[TestCaseSummary]] = None

    class Config:
        from_attributes = True

class TestSuiteSummary(BaseModel):
    """Lighter version for list endpoints"""
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    test_case_count: Optional[int] = None

    class Config:
        from_attributes = True

# Test Suite Entry schemas
class TestSuiteEntryCreate(BaseModel):
    case_id: int
    execution_order: Optional[int] = Field(0, description="Order of execution within suite")

class TestSuiteEntryResponse(BaseModel):
    suite_id: int
    case_id: int
    execution_order: int
    test_case: Optional[TestCaseSummary] = None

    class Config:
        from_attributes = True

# Test Run schemas
class TestRunCreate(BaseModel):
    suite_id: int
    target_environment: str = Field(..., description="Base URL of the environment under test")

class TestRunResponse(BaseModel):
    id: int
    suite_id: int
    status: RunStatus
    target_environment: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    test_suite: Optional[TestSuiteSummary] = None

    class Config:
        from_attributes = True

class TestRunSummary(BaseModel):
    """Lighter version for list endpoints"""
    id: int
    suite_id: int
    status: RunStatus
    target_environment: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# Test Result schemas
class TestResultCreate(BaseModel):
    run_id: int
    case_id: int
    status: TestStatus
    response_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    latency_ms: Optional[int] = None
    assertion_failures: Optional[List[Dict[str, Any]]] = None

class TestResultResponse(BaseModel):
    id: int
    run_id: int
    case_id: int
    status: TestStatus
    response_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[str] = None
    latency_ms: Optional[int] = None
    assertion_failures: Optional[List[Dict[str, Any]]] = None
    executed_at: datetime
    test_case: Optional[TestCaseSummary] = None

    class Config:
        from_attributes = True

# Analytics schemas
class FailureRateData(BaseModel):
    date: datetime
    total_tests: int
    failed_tests: int
    failure_rate: float

class LatencyData(BaseModel):
    date: datetime
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float

class HealthSummary(BaseModel):
    overall_health_score: float = Field(..., description="Overall health score (0-100)")
    total_test_cases: int
    total_test_runs: int
    recent_failure_rate: float
    avg_latency_ms: float
    last_run_status: Optional[RunStatus] = None
    critical_issues: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

# Response schemas
class DeleteResponse(BaseModel):
    message: str
    deleted_id: int
