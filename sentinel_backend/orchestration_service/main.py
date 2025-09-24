from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import os
import uuid
import httpx
import structlog
import hashlib
import json
import asyncio
from datetime import datetime
from prometheus_fastapi_instrumentator import Instrumentator

from sentinel_backend.orchestration_service.agents.base_agent import AgentTask, AgentResult
from sentinel_backend.config.tracing_config import setup_tracing
from sentinel_backend.orchestration_service.agents.functional_positive_agent import FunctionalPositiveAgent
from sentinel_backend.orchestration_service.agents.functional_negative_agent import FunctionalNegativeAgent
from sentinel_backend.orchestration_service.agents.functional_stateful_agent import FunctionalStatefulAgent
from sentinel_backend.orchestration_service.agents.security_auth_agent import SecurityAuthAgent
from sentinel_backend.orchestration_service.agents.security_injection_agent import SecurityInjectionAgent
from sentinel_backend.orchestration_service.agents.performance_planner_agent import PerformancePlannerAgent
from sentinel_backend.orchestration_service.agents.data_mocking_agent import DataMockingAgent
from sentinel_backend.orchestration_service.broker import publish_task
from sentinel_backend.orchestration_service.agent_performance_tracker import (
    get_performance_tracker, 
    track_agent_execution,
    PerformanceMetric
)

# Import configuration
from sentinel_backend.config.settings import get_settings, get_service_settings, get_application_settings
from sentinel_backend.config.logging_config import setup_logging

# Set up structured logging
setup_logging()

# Get configuration
settings = get_settings()
service_settings = get_service_settings()
app_settings = get_application_settings()

logger = structlog.get_logger(__name__)

app = FastAPI(title="Sentinel Orchestration Service")

# Instrument for Prometheus
Instrumentator().instrument(app).expose(app)

# Set up Jaeger tracing
setup_tracing(app, "orchestration-service")

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

# Rust Core Integration
RUST_CORE_URL = getattr(service_settings, 'rust_core_service_url', 'http://127.0.0.1:8088')
USE_RUST_AGENTS = getattr(app_settings, 'use_rust_agents', True)

# Task tracking for async execution
task_status_store = {}

# Agents that are available in Rust
# All agents now have Rust implementations for better performance
RUST_AVAILABLE_AGENTS = {
    "Functional-Positive-Agent",
    "Functional-Negative-Agent",
    "Functional-Stateful-Agent",
    "Security-Auth-Agent",
    "Security-Injection-Agent",
    "Performance-Planner-Agent",
    "data-mocking",
    # Note: Data-Mocking-Agent maps to "data-mocking" in Rust
}


class TestGenerationRequest(BaseModel):
    """Request model for test generation."""
    spec_id: int
    agent_types: list[str] = ["Functional-Positive-Agent"]
    target_environment: Optional[str] = None
    parameters: Dict[str, Any] = {}


class TestGenerationResponse(BaseModel):
    """Response model for test generation."""
    task_id: str
    status: str
    total_test_cases: int
    agent_results: list[Dict[str, Any]]


class DataGenerationRequest(BaseModel):
    """Request model for mock data generation."""
    spec_id: int
    strategy: str = "realistic"  # realistic, edge_cases, invalid, boundary
    count: int = 10
    seed: Optional[int] = None


class DataGenerationResponse(BaseModel):
    """Response model for mock data generation."""
    task_id: str
    status: str
    mock_data: Dict[str, Any]
    global_data: Dict[str, Any]
    metadata: Dict[str, Any]


class AsyncTestGenerationResponse(BaseModel):
    """Response model for async test generation initiation."""
    task_id: str
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    """Response model for task status check."""
    task_id: str
    status: str  # "pending", "in_progress", "completed", "failed"
    progress: Optional[Dict[str, Any]] = None
    result: Optional[TestGenerationResponse] = None
    error: Optional[str] = None
    created_at: str
    updated_at: str


@app.get("/")
async def root():
    return {"message": "Sentinel Orchestration Service is running"}


@app.get("/performance-metrics")
async def get_performance_metrics(agent_type: Optional[str] = None):
    """
    Get performance metrics for agents.
    
    Args:
        agent_type: Optional specific agent type to get metrics for
        
    Returns:
        Performance metrics summary
    """
    tracker = get_performance_tracker()
    summary = tracker.get_performance_summary(agent_type)
    
    return {
        "agent_type": agent_type,
        "metrics": summary,
        "timestamp": datetime.now().isoformat()
    }


async def execute_rust_agent(request: Request, agent_type: str, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
   """
   Execute a task using the Rust agent via HTTP API.
   
   Args:
       agent_type: The type of agent to execute
       task: The agent task
       api_spec: The API specification
       
   Returns:
       An AgentResult with the test cases generated by the Rust agent.
   """
   try:
       # Prepare request data for Rust service
       request_data = {
           "task": {
               "task_id": task.task_id,
               "spec_id": str(task.spec_id),  # Rust expects string
               "agent_type": agent_type,
               "parameters": task.parameters,
               "target_environment": task.target_environment
           },
           "api_spec": api_spec
       }
       
       # Get correlation ID for tracing
       correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
       headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
       
       # Call Rust service directly via HTTP
       async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
           response = await client.post(
               f"{RUST_CORE_URL}/swarm/orchestrate",
               json=request_data,
               headers=headers
           )
           
           if response.status_code == 200:
               result_data = response.json()
               rust_result = result_data.get("result", {})
               
               # Extract test cases and metadata from Rust response
               test_cases = rust_result.get("test_cases", [])
               metadata = rust_result.get("metadata", {})
               metadata["execution_engine"] = "rust"
               metadata["processing_time_ms"] = result_data.get("processing_time_ms", 0)
               
               return AgentResult(
                   task_id=task.task_id,
                   agent_type=agent_type,
                   status=rust_result.get("status", "success"),
                   test_cases=test_cases,
                   metadata=metadata,
                   error_message=rust_result.get("error_message")
               )
           else:
               logger.warning(f"Rust service returned error: {response.status_code}")
               return AgentResult(
                   task_id=task.task_id,
                   agent_type=agent_type,
                   status="failed",
                   test_cases=[],
                   metadata={"execution_engine": "rust"},
                   error_message=f"Rust service error: {response.status_code}"
               )
               
   except Exception as e:
       logger.error(f"Failed to execute Rust agent: {str(e)}")
       return AgentResult(
           task_id=task.task_id,
           agent_type=agent_type,
           status="failed",
           test_cases=[],
           metadata={"execution_engine": "rust"},
           error_message=f"Failed to execute Rust agent: {str(e)}"
       )


async def check_rust_core_availability() -> bool:
    """
    Check if the Rust core service is available.
    
    Returns:
        True if Rust core is available, False otherwise
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{RUST_CORE_URL}/health")
            return response.status_code == 200
    except Exception:
        return False


def deduplicate_test_cases(test_cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate test cases based on test definition content.
    
    Args:
        test_cases: List of test case dictionaries
        
    Returns:
        List of unique test cases
    """
    seen_hashes = set()
    unique_test_cases = []
    
    for test_case in test_cases:
        # Create a hash of the test definition
        # We'll use the test name, method, path, and test type as the key
        test_def = test_case
        
        # Extract key fields for comparison
        key_fields = {
            'test_name': test_def.get('test_name', ''),
            'method': test_def.get('method', ''),
            'path': test_def.get('path', ''),
            'test_type': test_def.get('test_type', ''),
            'body': json.dumps(test_def.get('body', {}), sort_keys=True) if test_def.get('body') else '',
            'query_params': json.dumps(test_def.get('query_params', {}), sort_keys=True) if test_def.get('query_params') else ''
        }
        
        # Create a hash from the key fields
        hash_key = hashlib.md5(json.dumps(key_fields, sort_keys=True).encode()).hexdigest()
        
        if hash_key not in seen_hashes:
            seen_hashes.add(hash_key)
            unique_test_cases.append(test_case)
    
    return unique_test_cases


@app.post("/generate-tests", response_model=TestGenerationResponse)
async def generate_tests(fastapi_request: Request, request: TestGenerationRequest):
    """
    Generate test cases using specified agents.
    
    This is the main endpoint for Phase 2 MVP - it orchestrates the generation
    of test cases from API specifications using the available agents.
    Now supports both Python and Rust agents with automatic fallback.
    """
    try:
        task_id = str(uuid.uuid4())
        logger.info(f"Starting test generation task {task_id} for spec_id: {request.spec_id}")
        
        # Check Rust core availability
        rust_available = USE_RUST_AGENTS and await check_rust_core_availability()
        if rust_available:
            logger.info("Rust core service is available - using hybrid execution")
        else:
            logger.info("Rust core service not available - using Python agents only")
        
        # Fetch the API specification from the Spec Service
        api_spec = await fetch_api_specification(fastapi_request, request.spec_id)
        if not api_spec:
            raise HTTPException(status_code=404, detail="API specification not found")
        
        # Initialize available Python agents
        python_agents = {
            "Functional-Positive-Agent": FunctionalPositiveAgent(),
            "Functional-Negative-Agent": FunctionalNegativeAgent(),
            "Functional-Stateful-Agent": FunctionalStatefulAgent(),
            "Security-Auth-Agent": SecurityAuthAgent(),
            "Security-Injection-Agent": SecurityInjectionAgent(),
            "Performance-Planner-Agent": PerformancePlannerAgent(),
            "Data-Mocking-Agent": DataMockingAgent()
        }
        
        agent_results = []
        total_test_cases = 0
        
        # Get performance tracker
        perf_tracker = get_performance_tracker()
        
        # Execute each requested agent
        for agent_type in request.agent_types:
            logger.info(f"Executing {agent_type}")
            
            # Create agent task
            agent_task = AgentTask(
                task_id=f"{task_id}_{agent_type}",
                spec_id=request.spec_id,
                agent_type=agent_type,
                parameters=request.parameters,
                target_environment=request.target_environment
            )
            
            # Map Python agent names to Rust agent names if needed
            rust_agent_type = "data-mocking" if agent_type == "Data-Mocking-Agent" else agent_type
            
            # TEMPORARY: Force Rust usage for testing
            FORCE_RUST_FOR_TESTING = False  # Set to False to use normal performance-based selection

            # Get performance-based execution order
            if FORCE_RUST_FOR_TESTING and rust_available and (agent_type in RUST_AVAILABLE_AGENTS):
                execution_order = ['rust', 'python']  # Force Rust first
                logger.info(f"FORCING Rust execution for testing {agent_type}")
            else:
                execution_order = perf_tracker.get_fallback_order(agent_type)
                logger.info(f"Performance-based execution order for {agent_type}: {execution_order}")
            
            result = None
            used_language = None
            
            # Try each language in order of performance
            for language in execution_order:
                try:
                    # Check if we can use this language
                    if language == "rust" and not rust_available:
                        continue
                    if language == "python" and agent_type not in python_agents:
                        continue
                    
                    # Track execution performance
                    async with track_agent_execution(agent_type, language, request.spec_id) as tracker:
                        if language == "rust":
                            logger.info(f"Using Rust agent for {agent_type} (performance-based)")
                            # Use mapped name for Rust agent if needed
                            if rust_agent_type != agent_type:
                                agent_task.agent_type = rust_agent_type
                            result = await execute_rust_agent(fastapi_request, rust_agent_type, agent_task, api_spec)
                        else:
                            logger.info(f"Using Python agent for {agent_type} (performance-based)")
                            agent = python_agents[agent_type]
                            result = await agent.execute(agent_task, api_spec)
                        
                        # Track result
                        if result and result.status == "success":
                            tracker.set_result(
                                test_cases=len(result.test_cases) if result.test_cases else 0,
                                success=True
                            )
                            used_language = language
                            break  # Success, no need for fallback
                        else:
                            tracker.set_result(
                                test_cases=0,
                                success=False,
                                error=result.error_message if result else "Unknown error"
                            )
                            logger.warning(f"{language} agent failed for {agent_type}, trying fallback")
                            
                except Exception as e:
                    logger.error(f"Error executing {language} agent for {agent_type}: {str(e)}")
                    # Record failure metric
                    metric = PerformanceMetric(
                        agent_type=agent_type,
                        language=language,
                        execution_time_ms=0,
                        test_cases_generated=0,
                        success=False,
                        timestamp=datetime.now(),
                        spec_id=request.spec_id,
                        error=str(e)
                    )
                    perf_tracker.record_metric(metric)
                    continue
            
            # If no result after trying all options, create a failure result
            if not result:
                logger.error(f"All execution attempts failed for {agent_type}")
                result = AgentResult(
                    task_id=f"{task_id}_{agent_type}",
                    agent_type=agent_type,
                    status="failed",
                    test_cases=[],
                    metadata={"error": "All execution attempts failed"},
                    error_message="Failed to execute agent with any available language"
                )
                used_language = "none"
            
            # Deduplicate and store test cases in the Data Service
            unique_test_cases = []
            if result.status == "success" and result.test_cases:
                # Deduplicate test cases before storing
                unique_test_cases = deduplicate_test_cases(result.test_cases)
                logger.info(f"Agent {agent_type} generated {len(result.test_cases)} test cases, {len(unique_test_cases)} unique")
                
                await store_test_cases(fastapi_request, request.spec_id, agent_type, unique_test_cases)
                total_test_cases += len(unique_test_cases)
            
            agent_results.append({
                "agent_type": agent_type,
                "status": result.status,
                "test_cases_generated": len(unique_test_cases) if result.status == "success" else 0,
                "metadata": result.metadata,
                "error_message": result.error_message,
                "execution_engine": used_language if used_language else "unknown",
                "execution_order": execution_order
            })
        
        logger.info(f"Test generation task {task_id} completed. Total test cases: {total_test_cases}")
        
        return TestGenerationResponse(
            task_id=task_id,
            status="completed",
            total_test_cases=total_test_cases,
            agent_results=agent_results
        )
        
    except Exception as e:
        logger.error(f"Error in test generation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Test generation failed: {str(e)}")


async def execute_test_generation_task(
    task_id: str,
    request: TestGenerationRequest,
    fastapi_request: Request
):
    """
    Background task for test generation.
    """
    try:
        # Update task status to in_progress
        task_status_store[task_id]["status"] = "in_progress"
        task_status_store[task_id]["updated_at"] = datetime.now().isoformat()
        
        logger.info(f"Starting async test generation task {task_id}")
        
        # Check Rust core availability
        rust_available = USE_RUST_AGENTS and await check_rust_core_availability()
        if rust_available:
            logger.info("Rust core service is available - using hybrid execution")
        else:
            logger.info("Rust core service not available - using Python agents only")
        
        # Fetch the API specification from the Spec Service
        api_spec = await fetch_api_specification(fastapi_request, request.spec_id)
        if not api_spec:
            raise Exception("API specification not found")
        
        # Initialize available Python agents
        python_agents = {
            "Functional-Positive-Agent": FunctionalPositiveAgent(),
            "Functional-Negative-Agent": FunctionalNegativeAgent(),
            "Functional-Stateful-Agent": FunctionalStatefulAgent(),
            "Security-Auth-Agent": SecurityAuthAgent(),
            "Security-Injection-Agent": SecurityInjectionAgent(),
            "Performance-Planner-Agent": PerformancePlannerAgent(),
            "Data-Mocking-Agent": DataMockingAgent()
        }
        
        agent_results = []
        total_test_cases = 0
        completed_agents = 0
        
        # Execute each requested agent
        for agent_type in request.agent_types:
            logger.info(f"Executing {agent_type}")
            
            # Update progress
            task_status_store[task_id]["progress"] = {
                "current_agent": agent_type,
                "completed_agents": completed_agents,
                "total_agents": len(request.agent_types)
            }
            
            # Create agent task
            agent_task = AgentTask(
                task_id=f"{task_id}_{agent_type}",
                spec_id=request.spec_id,
                agent_type=agent_type,
                parameters=request.parameters,
                target_environment=request.target_environment
            )
            
            # Map Python agent names to Rust agent names if needed
            rust_agent_type = "data-mocking" if agent_type == "Data-Mocking-Agent" else agent_type
            
            # Determine whether to use Rust or Python agent
            use_rust = rust_available and (agent_type in RUST_AVAILABLE_AGENTS or rust_agent_type in RUST_AVAILABLE_AGENTS)

            # Initialize execution tracking variables
            used_language = None
            execution_order = []

            if use_rust:
                logger.info(f"Using Rust agent for {agent_type}")
                # Use mapped name for Rust agent if needed
                if rust_agent_type != agent_type:
                    agent_task.agent_type = rust_agent_type
                result = await execute_rust_agent(fastapi_request, rust_agent_type, agent_task, api_spec)
                used_language = "rust"
                execution_order = ["rust"]
            else:
                if agent_type not in python_agents:
                    logger.warning(f"Unknown agent type: {agent_type}")
                    continue

                logger.info(f"Using Python agent for {agent_type}")
                agent = python_agents[agent_type]
                result = await agent.execute(agent_task, api_spec)
                used_language = "python"
                execution_order = ["python"]
            
            # Deduplicate and store test cases in the Data Service
            unique_test_cases = []
            if result.status == "success" and result.test_cases:
                # Deduplicate test cases before storing
                unique_test_cases = deduplicate_test_cases(result.test_cases)
                logger.info(f"Agent {agent_type} generated {len(result.test_cases)} test cases, {len(unique_test_cases)} unique")
                
                await store_test_cases(fastapi_request, request.spec_id, agent_type, unique_test_cases)
                total_test_cases += len(unique_test_cases)
            
            agent_results.append({
                "agent_type": agent_type,
                "status": result.status,
                "test_cases_generated": len(unique_test_cases) if result.status == "success" else 0,
                "metadata": result.metadata,
                "error_message": result.error_message,
                "execution_engine": used_language if used_language else "unknown",
                "execution_order": execution_order
            })
            
            completed_agents += 1
        
        logger.info(f"Async test generation task {task_id} completed. Total test cases: {total_test_cases}")
        
        # Store the final result
        task_status_store[task_id]["status"] = "completed"
        task_status_store[task_id]["result"] = {
            "task_id": task_id,
            "status": "completed",
            "total_test_cases": total_test_cases,
            "agent_results": agent_results
        }
        task_status_store[task_id]["updated_at"] = datetime.now().isoformat()
        
    except Exception as e:
        logger.error(f"Error in async test generation task {task_id}: {str(e)}")
        task_status_store[task_id]["status"] = "failed"
        task_status_store[task_id]["error"] = str(e)
        task_status_store[task_id]["updated_at"] = datetime.now().isoformat()


@app.post("/generate-tests-async", response_model=AsyncTestGenerationResponse)
async def generate_tests_async(
    fastapi_request: Request,
    request: TestGenerationRequest,
    background_tasks: BackgroundTasks
):
    """
    Generate test cases asynchronously using specified agents.
    Returns immediately with a task ID that can be used to check status.
    """
    try:
        task_id = str(uuid.uuid4())
        
        # Initialize task status
        task_status_store[task_id] = {
            "task_id": task_id,
            "status": "pending",
            "progress": None,
            "result": None,
            "error": None,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        # Add the task to background tasks
        background_tasks.add_task(
            execute_test_generation_task,
            task_id,
            request,
            fastapi_request
        )
        
        logger.info(f"Created async test generation task {task_id} for spec_id: {request.spec_id}")
        
        return AsyncTestGenerationResponse(
            task_id=task_id,
            status="pending",
            message=f"Test generation task created. Check status at /task-status/{task_id}"
        )
        
    except Exception as e:
        logger.error(f"Error creating async test generation task: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create test generation task: {str(e)}")


@app.get("/task-status/{task_id}", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """
    Check the status of an async test generation task.
    """
    if task_id not in task_status_store:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
    
    task_info = task_status_store[task_id]
    
    return TaskStatusResponse(**task_info)


@app.post("/generate-data", response_model=DataGenerationResponse)
async def generate_data(fastapi_request: Request, request: DataGenerationRequest):
    """
    Generate mock data using the Data Mocking Agent.
    
    This endpoint generates realistic test data based on API specifications
    for use in testing scenarios. Now supports both Python and Rust implementations.
    """
    try:
        task_id = str(uuid.uuid4())
        logger.info(f"Starting data generation task {task_id} for spec_id: {request.spec_id}")
        
        # Check Rust core availability
        rust_available = USE_RUST_AGENTS and await check_rust_core_availability()
        use_rust = rust_available and "data-mocking" in RUST_AVAILABLE_AGENTS
        
        # Fetch the API specification from the Spec Service
        api_spec = await fetch_api_specification(fastapi_request, request.spec_id)
        if not api_spec:
            raise HTTPException(status_code=404, detail="API specification not found")
        
        if use_rust:
            logger.info("Using Rust data mocking agent")
            
            # Create agent task for Rust execution
            agent_task = AgentTask(
                task_id=task_id,
                spec_id=request.spec_id,
                agent_type="data-mocking",
                parameters={
                    'strategy': request.strategy,
                    'count': request.count,
                    'seed': request.seed
                },
                target_environment=None
            )
            
            # Execute using Rust core
            correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
            headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
            try:
                async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
                    request_data = {
                        "task": {
                            "task_id": agent_task.task_id,
                            "spec_id": str(agent_task.spec_id),  # Rust expects string
                            "agent_type": agent_task.agent_type,
                            "parameters": agent_task.parameters,
                            "target_environment": agent_task.target_environment
                        },
                        "api_spec": api_spec
                    }
                    
                    response = await client.post(
                        f"{RUST_CORE_URL}/swarm/mock-data",
                        json=request_data,
                        headers=headers
                    )
                    
                    if response.status_code == 200:
                        result_data = response.json()
                        rust_result = result_data["result"]
                        
                        logger.info(f"Data generation task {task_id} completed successfully using Rust")
                        
                        return DataGenerationResponse(
                            task_id=task_id,
                            status="completed",
                            mock_data=rust_result.get('metadata', {}).get('mock_data', {}),
                            global_data=rust_result.get('metadata', {}).get('global_data', {}),
                            metadata=rust_result.get('metadata', {})
                        )
                    else:
                        logger.warning(f"Rust data generation failed: {response.status_code}, falling back to Python")
                        use_rust = False
                        
            except Exception as e:
                logger.warning(f"Rust data generation error: {str(e)}, falling back to Python")
                use_rust = False
        
        if not use_rust:
            logger.info("Using Python data mocking agent")
            
            # Initialize data mocking agent
            data_agent = DataMockingAgent()
            
            # Configure data generation
            config = {
                'strategy': request.strategy,
                'count': request.count,
                'seed': request.seed
            }
            
            # Execute data generation
            logger.info(f"Executing Python Data-Mocking-Agent with strategy: {request.strategy}")
            result = await data_agent.execute(api_spec, config)
            
            if 'error' in result:
                raise HTTPException(status_code=500, detail=result['error'])
            
            logger.info(f"Data generation task {task_id} completed successfully using Python")
            
            return DataGenerationResponse(
                task_id=task_id,
                status="completed",
                mock_data=result.get('mock_data', {}),
                global_data=result.get('global_data', {}),
                metadata=result.get('metadata', {})
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in data generation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Data generation failed: {str(e)}")


async def fetch_api_specification(request: Request, spec_id: int) -> Optional[Dict[str, Any]]:
    """
    Fetch an API specification from the Spec Service.
    
    Args:
        spec_id: The ID of the specification to fetch
        
    Returns:
        The parsed API specification or None if not found
    """
    correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
    headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
    try:
        async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
            response = await client.get(f"{service_settings.spec_service_url}/api/v1/specifications/{spec_id}", headers=headers)
            
            if response.status_code == 200:
                spec_data = response.json()
                return spec_data.get("parsed_spec", {})
            elif response.status_code == 404:
                return None
            else:
                logger.error(f"Error fetching spec {spec_id}: {response.status_code}")
                return None
                
    except Exception as e:
        logger.error(f"Error connecting to Spec Service: {str(e)}")
        return None


async def store_test_cases(request: Request, spec_id: int, agent_type: str, test_cases: list[Dict[str, Any]]) -> bool:
    """
    Store generated test cases in the Data Service.
    
    Args:
        spec_id: The ID of the API specification
        agent_type: The type of agent that generated the test cases
        test_cases: List of test case definitions
        
    Returns:
        True if successful, False otherwise
    """
    correlation_id = structlog.contextvars.get_contextvars().get("correlation_id")
    headers = {"X-Correlation-ID": correlation_id} if correlation_id else {}
    try:
        async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
            for test_case in test_cases:
                # Determine appropriate tags based on agent type
                tags = ["generated"]
                if agent_type == "Functional-Positive-Agent":
                    tags.append("positive")
                elif agent_type == "Functional-Negative-Agent":
                    tags.append("negative")
                elif agent_type == "Functional-Stateful-Agent":
                    tags.append("stateful")
                elif agent_type == "Security-Auth-Agent":
                    tags.extend(["security", "authentication", "authorization"])
                elif agent_type == "Security-Injection-Agent":
                    tags.extend(["security", "injection", "vulnerability"])
                elif agent_type == "Performance-Planner-Agent":
                    tags.extend(["performance", "load-testing", "planning"])
                
                test_case_data = {
                    "spec_id": spec_id,
                    "agent_type": agent_type,
                    "description": test_case.get("description", ""),
                    "test_definition": test_case,
                    "tags": tags
                }
                
                response = await client.post(
                    f"{service_settings.data_service_url}/api/v1/test-cases",
                    json=test_case_data,
                    headers=headers
                )
                
                if response.status_code not in [200, 201]:
                    logger.error(f"Error storing test case: {response.status_code}")
                    return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error storing test cases: {str(e)}")
        return False


@app.post("/agent-tasks")
async def delegate_agent_task(request: dict):
    """
    Legacy endpoint for agent task delegation.
    
    This endpoint is maintained for backward compatibility but the new
    /generate-tests endpoint should be used for Phase 2 functionality.
    """
    logger.info(f"Received legacy agent task. Execution URL: {service_settings.execution_service_url}, Data URL: {service_settings.data_service_url}")
    return {"message": "Agent task delegated (legacy endpoint)", "task_id": 1}
