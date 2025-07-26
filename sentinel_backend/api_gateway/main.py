from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import httpx
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Sentinel API Gateway",
    description="Main entry point for the Sentinel AI-powered API testing platform",
    version="1.0.0"
)

# Service URLs
SPEC_SERVICE_URL = os.getenv("SPEC_SERVICE_URL", "http://spec_service:8000")
ORCHESTRATION_SERVICE_URL = os.getenv("ORCHESTRATION_SERVICE_URL", "http://orchestration_service:8000")
DATA_SERVICE_URL = os.getenv("DATA_SERVICE_URL", "http://data_service:8000")
EXECUTION_SERVICE_URL = os.getenv("EXECUTION_SERVICE_URL", "http://execution_service:8000")


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
        "spec_service": SPEC_SERVICE_URL,
        "orchestration_service": ORCHESTRATION_SERVICE_URL,
        "data_service": DATA_SERVICE_URL,
        "execution_service": EXECUTION_SERVICE_URL
    }
    
    health_status = {"status": "healthy", "services": {}}
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        for service_name, service_url in services.items():
            try:
                response = await client.get(f"{service_url}/")
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
async def complete_testing_flow(request: EndToEndTestRequest):
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
        spec_response = await upload_specification(SpecificationUploadRequest(
            raw_spec=request.raw_spec,
            source_filename=request.source_filename
        ))
        spec_id = spec_response["id"]
        logger.info(f"Specification uploaded with ID: {spec_id}")
        
        # Step 2: Generate test cases
        logger.info("Step 2: Generating test cases")
        generation_response = await generate_tests(TestGenerationRequest(
            spec_id=spec_id,
            agent_types=request.agent_types,
            target_environment=request.target_environment
        ))
        logger.info(f"Generated {generation_response['total_test_cases']} test cases")
        
        # Step 3: Get generated test cases and create a suite
        logger.info("Step 3: Creating test suite")
        test_cases = await get_test_cases_for_spec(spec_id)
        test_case_ids = [tc["id"] for tc in test_cases]
        
        suite_response = await create_test_suite(TestSuiteCreateRequest(
            name=f"Generated Tests - {request.source_filename or 'API'}",
            description="Auto-generated test suite from complete flow",
            test_case_ids=test_case_ids
        ))
        suite_id = suite_response["id"]
        logger.info(f"Test suite created with ID: {suite_id}")
        
        # Step 4: Execute tests
        logger.info("Step 4: Executing tests")
        execution_response = await run_tests(TestRunRequest(
            suite_id=suite_id,
            target_environment=request.target_environment
        ))
        run_id = execution_response["run_id"]
        logger.info(f"Test execution completed with run ID: {run_id}")
        
        # Step 5: Get detailed results
        logger.info("Step 5: Fetching detailed results")
        results = await get_test_run_results(run_id)
        
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
async def upload_specification(request: SpecificationUploadRequest):
    """Upload and parse an API specification."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SPEC_SERVICE_URL}/api/v1/specifications",
                json=request.dict()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.get("/api/v1/specifications")
async def list_specifications():
    """List all uploaded API specifications."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SPEC_SERVICE_URL}/api/v1/specifications")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.get("/api/v1/specifications/{spec_id}")
async def get_specification(spec_id: int):
    """Get a specific API specification."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SPEC_SERVICE_URL}/api/v1/specifications/{spec_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")


@app.post("/api/v1/generate-tests")
async def generate_tests(request: TestGenerationRequest):
    """Generate test cases using AI agents."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{ORCHESTRATION_SERVICE_URL}/generate-tests",
                json=request.dict()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Orchestration service is unavailable")


@app.get("/api/v1/test-cases")
async def list_test_cases(spec_id: Optional[int] = None):
    """List test cases, optionally filtered by specification ID."""
    async with httpx.AsyncClient() as client:
        try:
            url = f"{DATA_SERVICE_URL}/api/v1/test-cases"
            if spec_id:
                url += f"?spec_id={spec_id}"
            
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


async def get_test_cases_for_spec(spec_id: int) -> List[Dict[str, Any]]:
    """Helper function to get test cases for a specific specification."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{DATA_SERVICE_URL}/api/v1/test-cases?spec_id={spec_id}")
        response.raise_for_status()
        return response.json()


@app.post("/api/v1/test-suites")
async def create_test_suite(request: TestSuiteCreateRequest):
    """Create a new test suite."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{DATA_SERVICE_URL}/api/v1/test-suites",
                json=request.dict()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.get("/api/v1/test-suites")
async def list_test_suites():
    """List all test suites."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{DATA_SERVICE_URL}/api/v1/test-suites")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.post("/api/v1/test-runs")
async def run_tests(request: TestRunRequest):
    """Execute a test suite against a target environment."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{EXECUTION_SERVICE_URL}/test-runs",
                json=request.dict()
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Execution service is unavailable")


@app.get("/api/v1/test-runs")
async def list_test_runs():
    """List all test runs."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{DATA_SERVICE_URL}/api/v1/test-runs")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")


@app.get("/api/v1/test-runs/{run_id}")
async def get_test_run(run_id: int):
    """Get details of a specific test run."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{EXECUTION_SERVICE_URL}/test-runs/{run_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Execution service is unavailable")


async def get_test_run_results(run_id: int) -> Dict[str, Any]:
    """Helper function to get detailed test run results."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{EXECUTION_SERVICE_URL}/test-runs/{run_id}")
        response.raise_for_status()
        return response.json()


@app.get("/api/v1/test-runs/{run_id}/results")
async def get_test_run_results_endpoint(run_id: int):
    """Get detailed results for a test run."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{DATA_SERVICE_URL}/api/v1/test-runs/{run_id}/results")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Data service is unavailable")
