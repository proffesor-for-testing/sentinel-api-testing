from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os
import uuid
import httpx
import structlog
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

# Agents that are available in Rust
RUST_AVAILABLE_AGENTS = {
    "Functional-Positive-Agent",
    "data-mocking",
    "Security-Auth-Agent",
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


@app.get("/")
async def root():
    return {"message": "Sentinel Orchestration Service is running"}


async def execute_rust_agent(request: Request, agent_type: str, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
   """
   Publish a task for a Rust agent to the message broker.
   
   Args:
       agent_type: The type of agent to execute
       task: The agent task
       api_spec: The API specification
       
   Returns:
       An AgentResult indicating the task has been queued.
   """
   request_data = {
       "task": {
           "task_id": task.task_id,
           "spec_id": task.spec_id,
           "agent_type": agent_type,
           "parameters": task.parameters,
           "target_environment": task.target_environment
       },
       "api_spec": api_spec
   }

   if publish_task(request_data):
       return AgentResult(
           task_id=task.task_id,
           agent_type=agent_type,
           status="queued",
           test_cases=[],
           metadata={"message": "Task has been queued for processing by the Rust core."},
           error_message=None
       )
   else:
       return AgentResult(
           task_id=task.task_id,
           agent_type=agent_type,
           status="failed",
           test_cases=[],
           metadata={},
           error_message="Failed to publish task to the message broker."
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
            
            # Determine whether to use Rust or Python agent
            use_rust = rust_available and agent_type in RUST_AVAILABLE_AGENTS
            
            if use_rust:
                logger.info(f"Using Rust agent for {agent_type}")
                result = await execute_rust_agent(fastapi_request, agent_type, agent_task, api_spec)
            else:
                if agent_type not in python_agents:
                    logger.warning(f"Unknown agent type: {agent_type}")
                    continue
                
                logger.info(f"Using Python agent for {agent_type}")
                agent = python_agents[agent_type]
                result = await agent.execute(agent_task, api_spec)
            
            # Store test cases in the Data Service
            if result.status == "success" and result.test_cases:
                await store_test_cases(fastapi_request, request.spec_id, agent_type, result.test_cases)
                total_test_cases += len(result.test_cases)
            
            agent_results.append({
                "agent_type": agent_type,
                "status": result.status,
                "test_cases_generated": len(result.test_cases),
                "metadata": result.metadata,
                "error_message": result.error_message,
                "execution_engine": "rust" if use_rust else "python"
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
                            "spec_id": agent_task.spec_id,
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
