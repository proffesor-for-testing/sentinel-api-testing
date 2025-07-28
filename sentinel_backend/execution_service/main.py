from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import os
import uuid
import httpx
import asyncio
import logging
from datetime import datetime

# Import configuration
from config.settings import get_settings, get_service_settings, get_application_settings, get_network_settings

# Get configuration
settings = get_settings()
service_settings = get_service_settings()
app_settings = get_application_settings()
network_settings = get_network_settings()

# Configure logging
logging.basicConfig(
    level=getattr(logging, app_settings.log_level),
    format=app_settings.log_format
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel Execution Service")


class TestRunRequest(BaseModel):
    """Request model for test run execution."""
    suite_id: int
    target_environment: str
    parameters: Dict[str, Any] = {}


class TestRunResponse(BaseModel):
    """Response model for test run execution."""
    run_id: int
    status: str
    started_at: str
    total_tests: int
    passed: int = 0
    failed: int = 0
    errors: int = 0


class TestCaseResult(BaseModel):
    """Model for individual test case results."""
    case_id: int
    status: str  # "passed", "failed", "error"
    response_code: Optional[int] = None
    response_headers: Dict[str, str] = {}
    response_body: Optional[str] = None
    latency_ms: Optional[int] = None
    assertion_failures: List[Dict[str, Any]] = []
    error_message: Optional[str] = None


@app.get("/")
async def root():
    return {"message": "Sentinel Execution Service is running"}


@app.post("/test-runs", response_model=TestRunResponse)
async def execute_test_run(request: TestRunRequest):
    """
    Execute a test suite against a target environment.
    
    This is the main endpoint for Phase 2 MVP - it executes generated test cases
    and stores the results for analysis.
    """
    try:
        logger.info(f"Starting test run for suite_id: {request.suite_id}")
        
        # Create a new test run record
        run_id = await create_test_run(request.suite_id, request.target_environment)
        if not run_id:
            raise HTTPException(status_code=500, detail="Failed to create test run")
        
        # Fetch test cases for the suite
        test_cases = await fetch_test_cases(request.suite_id)
        if not test_cases:
            raise HTTPException(status_code=404, detail="No test cases found for suite")
        
        logger.info(f"Executing {len(test_cases)} test cases for run {run_id}")
        
        # Execute test cases
        results = await execute_test_cases(test_cases, request.target_environment)
        
        # Store results
        await store_test_results(run_id, results)
        
        # Calculate summary statistics
        passed = sum(1 for r in results if r.status == "passed")
        failed = sum(1 for r in results if r.status == "failed")
        errors = sum(1 for r in results if r.status == "error")
        
        # Update test run status
        final_status = "completed" if errors == 0 else "failed"
        await update_test_run_status(run_id, final_status)
        
        logger.info(f"Test run {run_id} completed: {passed} passed, {failed} failed, {errors} errors")
        
        return TestRunResponse(
            run_id=run_id,
            status=final_status,
            started_at=datetime.now().isoformat(),
            total_tests=len(test_cases),
            passed=passed,
            failed=failed,
            errors=errors
        )
        
    except Exception as e:
        logger.error(f"Error executing test run: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Test execution failed: {str(e)}")


async def create_test_run(suite_id: int, target_environment: str) -> Optional[int]:
    """Create a new test run record in the database."""
    try:
        async with httpx.AsyncClient() as client:
            run_data = {
                "suite_id": suite_id,
                "status": "running",
                "target_environment": target_environment,
                "started_at": datetime.now().isoformat()
            }
            
            response = await client.post(
                f"{service_settings.data_service_url}/api/v1/test-runs",
                json=run_data,
                timeout=service_settings.service_timeout
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                return result.get("id")
            else:
                logger.error(f"Error creating test run: {response.status_code}")
                return None
                
    except Exception as e:
        logger.error(f"Error creating test run: {str(e)}")
        return None


async def fetch_test_cases(suite_id: int) -> List[Dict[str, Any]]:
    """Fetch test cases for a given suite."""
    try:
        async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
            response = await client.get(
                f"{service_settings.data_service_url}/api/v1/test-suites/{suite_id}/cases"
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Error fetching test cases: {response.status_code}")
                return []
                
    except Exception as e:
        logger.error(f"Error fetching test cases: {str(e)}")
        return []


async def execute_test_cases(
    test_cases: List[Dict[str, Any]], 
    target_environment: str
) -> List[TestCaseResult]:
    """
    Execute a list of test cases against the target environment.
    
    This is a basic HTTP client-based test executor for the MVP.
    In a full implementation, this would use pytest or similar framework.
    """
    results = []
    
    async with httpx.AsyncClient(timeout=app_settings.test_execution_timeout) as client:
        for test_case in test_cases:
            result = await execute_single_test_case(client, test_case, target_environment)
            results.append(result)
    
    return results


async def execute_single_test_case(
    client: httpx.AsyncClient,
    test_case: Dict[str, Any],
    target_environment: str
) -> TestCaseResult:
    """Execute a single test case and return the result."""
    case_id = test_case.get("id")
    test_definition = test_case.get("test_definition", {})
    
    try:
        # Extract test parameters
        endpoint = test_definition.get("endpoint", "")
        method = test_definition.get("method", "GET").upper()
        headers = test_definition.get("headers", {})
        query_params = test_definition.get("query_params", {})
        body = test_definition.get("body")
        expected_status = test_definition.get("expected_status", 200)
        assertions = test_definition.get("assertions", [])
        
        # Build full URL
        url = f"{target_environment.rstrip('/')}{endpoint}"
        
        # Record start time for latency measurement
        start_time = asyncio.get_event_loop().time()
        
        # Execute HTTP request
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            params=query_params,
            json=body if body else None
        )
        
        # Calculate latency
        end_time = asyncio.get_event_loop().time()
        latency_ms = int((end_time - start_time) * 1000)
        
        # Validate response
        assertion_failures = []
        status = "passed"
        
        # Check status code
        if response.status_code != expected_status:
            assertion_failures.append({
                "type": "status_code",
                "expected": expected_status,
                "actual": response.status_code,
                "message": f"Expected status {expected_status}, got {response.status_code}"
            })
            status = "failed"
        
        # Run additional assertions
        for assertion in assertions:
            failure = await validate_assertion(assertion, response)
            if failure:
                assertion_failures.append(failure)
                status = "failed"
        
        return TestCaseResult(
            case_id=case_id,
            status=status,
            response_code=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text[:1000],  # Limit response body size
            latency_ms=latency_ms,
            assertion_failures=assertion_failures
        )
        
    except Exception as e:
        logger.error(f"Error executing test case {case_id}: {str(e)}")
        return TestCaseResult(
            case_id=case_id,
            status="error",
            error_message=str(e)
        )


async def validate_assertion(assertion: Dict[str, Any], response: httpx.Response) -> Optional[Dict[str, Any]]:
    """Validate a single assertion against the response."""
    assertion_type = assertion.get("type")
    
    if assertion_type == "response_schema":
        # Basic schema validation (simplified for MVP)
        try:
            response.json()  # Just check if it's valid JSON
            return None
        except:
            return {
                "type": "response_schema",
                "message": "Response is not valid JSON"
            }
    
    # Add more assertion types as needed
    return None


async def store_test_results(run_id: int, results: List[TestCaseResult]) -> bool:
    """Store test results in the database."""
    try:
        async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
            for result in results:
                result_data = {
                    "run_id": run_id,
                    "case_id": result.case_id,
                    "status": result.status,
                    "response_code": result.response_code,
                    "response_headers": result.response_headers,
                    "response_body": result.response_body,
                    "latency_ms": result.latency_ms,
                    "assertion_failures": result.assertion_failures,
                    "executed_at": datetime.now().isoformat()
                }
                
                if result.error_message:
                    result_data["error_message"] = result.error_message
                
                response = await client.post(
                    f"{service_settings.data_service_url}/api/v1/test-results",
                    json=result_data
                )
                
                if response.status_code not in [200, 201]:
                    logger.error(f"Error storing test result: {response.status_code}")
                    return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error storing test results: {str(e)}")
        return False


async def update_test_run_status(run_id: int, status: str) -> bool:
    """Update the status of a test run."""
    try:
        async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
            update_data = {
                "status": status,
                "completed_at": datetime.now().isoformat()
            }
            
            response = await client.patch(
                f"{service_settings.data_service_url}/api/v1/test-runs/{run_id}",
                json=update_data
            )
            
            return response.status_code in [200, 204]
            
    except Exception as e:
        logger.error(f"Error updating test run status: {str(e)}")
        return False


@app.get("/test-runs/{run_id}")
async def get_test_run_status(run_id: int):
    """Get the status and results of a test run."""
    try:
        async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
            # Get run details
            run_response = await client.get(f"{service_settings.data_service_url}/api/v1/test-runs/{run_id}")
            if run_response.status_code != 200:
                raise HTTPException(status_code=404, detail="Test run not found")
            
            # Get run results
            results_response = await client.get(f"{service_settings.data_service_url}/api/v1/test-runs/{run_id}/results")
            
            run_data = run_response.json()
            results_data = results_response.json() if results_response.status_code == 200 else []
            
            return {
                "run": run_data,
                "results": results_data
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching test run status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch test run status")
