from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import httpx
import os
import structlog
import uuid
from prometheus_fastapi_instrumentator import Instrumentator
from sentinel_backend.config.logging_config import setup_logging
from sentinel_backend.config.tracing_config import setup_tracing
from sentinel_backend.config.settings import get_service_settings, get_application_settings, get_network_settings
from sentinel_backend.auth_service.auth_middleware import get_current_user, require_permission, Permissions, optional_auth
from sentinel_backend.api_gateway.bff_service import router as bff_router

# Set up structured logging
setup_logging()

# Get configuration settings
service_settings = get_service_settings()
app_settings = get_application_settings()
network_settings = get_network_settings()

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="Sentinel API Gateway",
    description="Main entry point for the Sentinel AI-powered API testing platform",
    version=app_settings.app_version
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Frontend development server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instrument for Prometheus
Instrumentator().instrument(app).expose(app)

# Set up Jaeger tracing
setup_tracing(app, "api-gateway")

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


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Adds security headers to every response.
    """
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # Loosen CSP to allow Swagger UI resources
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "img-src 'self' fastapi.tiangolo.com; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    return response


def get_correlation_id_headers(request: Request) -> Dict[str, str]:
    """
    Get correlation ID from request to propagate to downstream services.
    """
    correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
    if correlation_id:
        return {"X-Correlation-ID": correlation_id}
    return {}


def get_json_data(request):
    """
    Helper to get JSON data from either a dict or Pydantic model.
    """
    if hasattr(request, 'dict'):
        return request.dict()
    return request


# Request/Response Models
class SpecificationUploadRequest(BaseModel):
    """Request model for uploading API specifications."""
    raw_spec: str
    source_filename: Optional[str] = None
    source_url: Optional[str] = None


class TestGenerationRequest(BaseModel):
    """Request model for generating tests."""
    spec_id: int
    agent_types: List[str] = ["Functional-Positive-Agent"]
    target_environment: Optional[str] = None


class TestSuiteCreateRequest(BaseModel):
    """Request model for creating test suites."""
    name: str
    description: Optional[str] = None
    test_case_ids: List[int] = []


class TestRunRequest(BaseModel):
    """Request model for executing test runs."""
    suite_id: int
    target_environment: str


class EndToEndTestRequest(BaseModel):
    """Request model for complete end-to-end testing workflow."""
    raw_spec: str
    target_environment: str
    source_filename: Optional[str] = None
    agent_types: List[str] = ["Functional-Positive-Agent"]


# Authentication Models
class UserLogin(BaseModel):
    """Request model for user login."""
    email: str
    password: str


class UserCreate(BaseModel):
    """Request model for user registration."""
    email: str
    full_name: str
    password: str
    role: str = "viewer"


class UserUpdate(BaseModel):
    """Request model for user updates."""
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


@app.get("/")
async def root():
    return {
        "message": "Sentinel API Gateway is running",
        "version": "1.0.0",
        "phase": "Phase 2 - MVP",
        "endpoints": {
            "upload_spec": "/api/v1/specifications",
            "generate_tests": "/api/v1/generate-tests",
            "create_suite": "/api/v1/test-suites",
            "run_tests": "/api/v1/test-runs",
            "end_to_end": "/api/v1/test-complete-flow"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint that verifies all services are running."""
    services = {
        "spec_service": service_settings.spec_service_url,
        "orchestration_service": service_settings.orchestration_service_url,
        "data_service": service_settings.data_service_url,
        "execution_service": service_settings.execution_service_url
    }
    
    health_status = {"status": "healthy", "services": {}}
    
    async with httpx.AsyncClient(timeout=service_settings.health_check_timeout) as client:
        for service_name, service_url in services.items():
            try:
                response = await client.get(f"{service_url}/") # No correlation ID for health checks
                health_status["services"][service_name] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time_ms": int(response.elapsed.total_seconds() * 1000)
                }
            except Exception as e:
                health_status["services"][service_name] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health_status["status"] = "degraded"
    
    return health_status


# Phase 2 MVP: Complete End-to-End Flow
@app.post("/api/v1/test-complete-flow")
async def complete_testing_flow(fastapi_request: Request, request: EndToEndTestRequest):
    """
    Complete end-to-end testing flow for Phase 2 MVP.
    
    This endpoint demonstrates the full workflow:
    1. Upload API specification
    2. Generate test cases using agents
    3. Create a test suite
    4. Execute tests against target environment
    5. Return results
    """
    try:
        logger.info("Starting complete testing flow")
        
        # Step 1: Upload API specification
        logger.info("Step 1: Uploading API specification")
        spec_response = await upload_specification(fastapi_request, SpecificationUploadRequest(
            raw_spec=request.raw_spec,
            source_filename=request.source_filename
        ))
        spec_id = spec_response["id"]
        logger.info(f"Specification uploaded with ID: {spec_id}")
        
        # Step 2: Generate test cases
        logger.info("Step 2: Generating test cases")
        generation_response = await generate_tests(fastapi_request, TestGenerationRequest(
            spec_id=spec_id,
            agent_types=request.agent_types,
            target_environment=request.target_environment
        ))
        logger.info(f"Generated {generation_response['total_test_cases']} test cases")
        
        # Step 3: Get generated test cases and create a suite
        logger.info("Step 3: Creating test suite")
        test_cases = await get_test_cases_for_spec(fastapi_request, spec_id)
        test_case_ids = [tc["id"] for tc in test_cases]
        
        suite_response = await create_test_suite(fastapi_request, TestSuiteCreateRequest(
            name=f"Generated Tests - {request.source_filename or 'API'}",
            description="Auto-generated test suite from complete flow",
            test_case_ids=test_case_ids
        ))
        suite_id = suite_response["id"]
        logger.info(f"Test suite created with ID: {suite_id}")
        
        # Step 4: Execute tests
        logger.info("Step 4: Executing tests")
        execution_response = await run_tests(fastapi_request, TestRunRequest(
            suite_id=suite_id,
            target_environment=request.target_environment
        ))
        run_id = execution_response["run_id"]
        logger.info(f"Test execution completed with run ID: {run_id}")
        
        # Step 5: Get detailed results
        logger.info("Step 5: Fetching detailed results")
        results = await get_test_run_results(fastapi_request, run_id)
        
        return {
            "message": "Complete testing flow executed successfully",
            "spec_id": spec_id,
            "suite_id": suite_id,
            "run_id": run_id,
            "summary": {
                "total_test_cases": generation_response["total_test_cases"],
                "total_tests_executed": execution_response["total_tests"],
                "passed": execution_response["passed"],
                "failed": execution_response["failed"],
                "errors": execution_response["errors"]
            },
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Error in complete testing flow: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Complete flow failed: {str(e)}")


# Individual API endpoints
@app.post("/api/v1/specifications")
async def upload_specification(
    fastapi_request: Request,
    request: SpecificationUploadRequest,
    auth_data: Dict[str, Any] = Depends(require_permission(Permissions.SPEC_CREATE))
):
    """Upload and parse an API specification."""
    headers = get_correlation_id_headers(fastapi_request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            json_data = get_json_data(request)
            
            response = await client.post(
                f"{service_settings.spec_service_url}/api/v1/specifications",
                json=json_data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.get("/api/v1/specifications")
async def list_specifications(
    request: Request,
    current_user: dict = Depends(optional_auth)
):
    """List all uploaded API specifications."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.spec_service_url}/api/v1/specifications", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.get("/api/v1/specifications/{spec_id}")
async def get_specification(request: Request, spec_id: int):
    """Get a specific API specification."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.spec_service_url}/api/v1/specifications/{spec_id}", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.put("/api/v1/specifications/{spec_id}")
async def update_specification(request: Request, spec_id: int):
    """Update a specific API specification."""
    headers = get_correlation_id_headers(request)
    body = await request.json()
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.put(
                f"{service_settings.spec_service_url}/api/v1/specifications/{spec_id}",
                json=body,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.delete("/api/v1/specifications/{spec_id}")
async def delete_specification(request: Request, spec_id: int):
    """Delete a specific API specification."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.delete(f"{service_settings.spec_service_url}/api/v1/specifications/{spec_id}", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.post("/api/v1/generate-tests")
async def generate_tests(fastapi_request: Request, request: TestGenerationRequest):
    """Generate test cases using AI agents."""
    headers = get_correlation_id_headers(fastapi_request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            json_data = get_json_data(request)
            
            response = await client.post(
                f"{service_settings.orchestration_service_url}/generate-tests",
                json=json_data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Orchestration service is unavailable")


@app.get("/api/v1/test-cases")
async def list_test_cases(request: Request, spec_id: Optional[int] = None):
    """List test cases, optionally filtered by specification ID."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            url = f"{service_settings.data_service_url}/api/v1/test-cases"
            if spec_id:
                url += f"?spec_id={spec_id}"
            
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


async def get_test_cases_for_spec(request: Request, spec_id: int) -> List[Dict[str, Any]]:
    """Helper function to get test cases for a specific specification."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        response = await client.get(f"{service_settings.data_service_url}/api/v1/test-cases?spec_id={spec_id}", headers=headers)
        response.raise_for_status()
        return response.json()


@app.post("/api/v1/test-suites")
async def create_test_suite(fastapi_request: Request, request: TestSuiteCreateRequest):
    """Create a new test suite."""
    headers = get_correlation_id_headers(fastapi_request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            json_data = get_json_data(request)
            
            response = await client.post(
                f"{service_settings.data_service_url}/api/v1/test-suites",
                json=json_data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.get("/api/v1/test-suites")
async def list_test_suites(request: Request):
    """List all test suites."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.data_service_url}/api/v1/test-suites", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.get("/api/v1/test-suites/{suite_id}")
async def get_test_suite(request: Request, suite_id: int):
    """Get a specific test suite with its test cases."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.data_service_url}/api/v1/test-suites/{suite_id}", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.put("/api/v1/test-suites/{suite_id}")
async def update_test_suite(request: Request, suite_id: int):
    """Update a test suite."""
    headers = get_correlation_id_headers(request)
    body = await request.json()
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.put(
                f"{service_settings.data_service_url}/api/v1/test-suites/{suite_id}",
                json=body,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.delete("/api/v1/test-suites/{suite_id}")
async def delete_test_suite(request: Request, suite_id: int):
    """Delete a test suite."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.delete(f"{service_settings.data_service_url}/api/v1/test-suites/{suite_id}", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.post("/api/v1/test-suites/{suite_id}/cases")
async def add_test_case_to_suite(request: Request, suite_id: int):
    """Add a test case to a test suite."""
    headers = get_correlation_id_headers(request)
    body = await request.json()
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.post(
                f"{service_settings.data_service_url}/api/v1/test-suites/{suite_id}/cases",
                json=body,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.delete("/api/v1/test-suites/{suite_id}/cases/{case_id}")
async def remove_test_case_from_suite(request: Request, suite_id: int, case_id: int):
    """Remove a test case from a test suite."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.delete(
                f"{service_settings.data_service_url}/api/v1/test-suites/{suite_id}/cases/{case_id}",
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.post("/api/v1/test-runs")
async def run_tests(fastapi_request: Request, request: TestRunRequest):
    """Execute a test suite against a target environment."""
    headers = get_correlation_id_headers(fastapi_request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            json_data = get_json_data(request)
            
            response = await client.post(
                f"{service_settings.execution_service_url}/test-runs",
                json=json_data,
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Execution service is unavailable")


@app.get("/api/v1/test-runs")
async def list_test_runs(request: Request):
    """List all test runs."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.data_service_url}/api/v1/test-runs", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.get("/api/v1/test-runs/{run_id}")
async def get_test_run(request: Request, run_id: int):
    """Get details of a specific test run."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.execution_service_url}/test-runs/{run_id}", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Execution service is unavailable")


async def get_test_run_results(request: Request, run_id: int) -> Dict[str, Any]:
    """Helper function to get detailed test run results."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        response = await client.get(f"{service_settings.execution_service_url}/test-runs/{run_id}", headers=headers)
        response.raise_for_status()
        return response.json()


@app.get("/api/v1/test-runs/{run_id}/results")
async def get_test_run_results_endpoint(request: Request, run_id: int):
    """Get detailed results for a test run."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.data_service_url}/api/v1/test-runs/{run_id}/results", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


# Authentication Endpoints
@app.post("/auth/login")
async def login(fastapi_request: Request, request: UserLogin):
    """Authenticate user and return access token."""
    headers = get_correlation_id_headers(fastapi_request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.post(
                f"{service_settings.auth_service_url}/auth/login",
                json=get_json_data(request),
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")


@app.post("/auth/register")
async def register(
    fastapi_request: Request,
    request: UserCreate,
    auth_data: Dict[str, Any] = Depends(require_permission(Permissions.USER_CREATE))
):
    """Register a new user (admin only)."""
    headers = get_correlation_id_headers(fastapi_request)
    headers["Authorization"] = f"Bearer {auth_data.get('token', '')}"
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.post(
                f"{service_settings.auth_service_url}/auth/register",
                json=get_json_data(request),
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")


@app.get("/auth/profile")
async def get_profile(auth_data: Dict[str, Any] = Depends(get_current_user)):
    """Get current user's profile."""
    return auth_data["user"]


@app.put("/auth/profile")
async def update_profile(
    fastapi_request: Request,
    request: UserUpdate,
    auth_data: Dict[str, Any] = Depends(get_current_user)
):
    """Update current user's profile."""
    headers = get_correlation_id_headers(fastapi_request)
    headers["Authorization"] = f"Bearer {auth_data.get('token', '')}"
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.put(
                f"{service_settings.auth_service_url}/auth/profile",
                json=get_json_data(request),
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")


@app.get("/auth/users")
async def list_users(
    request: Request,
    auth_data: Dict[str, Any] = Depends(require_permission(Permissions.USER_READ))
):
    """List all users (requires user read permission)."""
    headers = get_correlation_id_headers(request)
    headers["Authorization"] = f"Bearer {auth_data.get('token', '')}"
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(
                f"{service_settings.auth_service_url}/auth/users",
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")


@app.get("/auth/users/{user_id}")
async def get_user(
    request: Request,
    user_id: int,
    auth_data: Dict[str, Any] = Depends(require_permission(Permissions.USER_READ))
):
    """Get a specific user by ID."""
    headers = get_correlation_id_headers(request)
    headers["Authorization"] = f"Bearer {auth_data.get('token', '')}"
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(
                f"{service_settings.auth_service_url}/auth/users/{user_id}",
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")


@app.put("/auth/users/{user_id}")
async def update_user(
    fastapi_request: Request,
    user_id: int,
    request: UserUpdate,
    auth_data: Dict[str, Any] = Depends(require_permission(Permissions.USER_UPDATE))
):
    """Update a user (admin only)."""
    headers = get_correlation_id_headers(fastapi_request)
    headers["Authorization"] = f"Bearer {auth_data.get('token', '')}"
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.put(
                f"{service_settings.auth_service_url}/auth/users/{user_id}",
                json=get_json_data(request),
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")


@app.delete("/auth/users/{user_id}")
async def delete_user(
    request: Request,
    user_id: int,
    auth_data: Dict[str, Any] = Depends(require_permission(Permissions.USER_DELETE))
):
    """Delete a user (admin only)."""
    headers = get_correlation_id_headers(request)
    headers["Authorization"] = f"Bearer {auth_data.get('token', '')}"
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.delete(
                f"{service_settings.auth_service_url}/auth/users/{user_id}",
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")

app.include_router(bff_router, prefix="/api/v1/bff", tags=["BFF"])


@app.get("/auth/roles")
async def list_roles(request: Request):
    """List all available roles and their permissions."""
    headers = get_correlation_id_headers(request)
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            response = await client.get(f"{service_settings.auth_service_url}/auth/roles", headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Authentication service is unavailable")
