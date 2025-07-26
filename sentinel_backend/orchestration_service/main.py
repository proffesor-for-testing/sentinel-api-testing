from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os
import uuid
import httpx
import logging

from agents.base_agent import AgentTask, AgentResult
from agents.functional_positive_agent import FunctionalPositiveAgent
from agents.functional_negative_agent import FunctionalNegativeAgent
from agents.functional_stateful_agent import FunctionalStatefulAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Sentinel Orchestration Service")

EXECUTION_SERVICE_URL = os.getenv("EXECUTION_SERVICE_URL", "http://execution_service:8000")
DATA_SERVICE_URL = os.getenv("DATA_SERVICE_URL", "http://data_service:8000")
SPEC_SERVICE_URL = os.getenv("SPEC_SERVICE_URL", "http://spec_service:8000")


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


@app.get("/")
async def root():
    return {"message": "Sentinel Orchestration Service is running"}


@app.post("/generate-tests", response_model=TestGenerationResponse)
async def generate_tests(request: TestGenerationRequest):
    """
    Generate test cases using specified agents.
    
    This is the main endpoint for Phase 2 MVP - it orchestrates the generation
    of test cases from API specifications using the available agents.
    """
    try:
        task_id = str(uuid.uuid4())
        logger.info(f"Starting test generation task {task_id} for spec_id: {request.spec_id}")
        
        # Fetch the API specification from the Spec Service
        api_spec = await fetch_api_specification(request.spec_id)
        if not api_spec:
            raise HTTPException(status_code=404, detail="API specification not found")
        
        # Initialize available agents
        agents = {
            "Functional-Positive-Agent": FunctionalPositiveAgent(),
            "Functional-Negative-Agent": FunctionalNegativeAgent(),
            "Functional-Stateful-Agent": FunctionalStatefulAgent()
        }
        
        agent_results = []
        total_test_cases = 0
        
        # Execute each requested agent
        for agent_type in request.agent_types:
            if agent_type not in agents:
                logger.warning(f"Unknown agent type: {agent_type}")
                continue
            
            logger.info(f"Executing {agent_type}")
            
            # Create agent task
            agent_task = AgentTask(
                task_id=f"{task_id}_{agent_type}",
                spec_id=request.spec_id,
                agent_type=agent_type,
                parameters=request.parameters,
                target_environment=request.target_environment
            )
            
            # Execute the agent
            agent = agents[agent_type]
            result = await agent.execute(agent_task, api_spec)
            
            # Store test cases in the Data Service
            if result.status == "success" and result.test_cases:
                await store_test_cases(request.spec_id, agent_type, result.test_cases)
                total_test_cases += len(result.test_cases)
            
            agent_results.append({
                "agent_type": agent_type,
                "status": result.status,
                "test_cases_generated": len(result.test_cases),
                "metadata": result.metadata,
                "error_message": result.error_message
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


async def fetch_api_specification(spec_id: int) -> Optional[Dict[str, Any]]:
    """
    Fetch an API specification from the Spec Service.
    
    Args:
        spec_id: The ID of the specification to fetch
        
    Returns:
        The parsed API specification or None if not found
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{SPEC_SERVICE_URL}/api/v1/specifications/{spec_id}")
            
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


async def store_test_cases(spec_id: int, agent_type: str, test_cases: list[Dict[str, Any]]) -> bool:
    """
    Store generated test cases in the Data Service.
    
    Args:
        spec_id: The ID of the API specification
        agent_type: The type of agent that generated the test cases
        test_cases: List of test case definitions
        
    Returns:
        True if successful, False otherwise
    """
    try:
        async with httpx.AsyncClient() as client:
            for test_case in test_cases:
                # Determine appropriate tags based on agent type
                tags = ["generated"]
                if agent_type == "Functional-Positive-Agent":
                    tags.append("positive")
                elif agent_type == "Functional-Negative-Agent":
                    tags.append("negative")
                elif agent_type == "Functional-Stateful-Agent":
                    tags.append("stateful")
                
                test_case_data = {
                    "spec_id": spec_id,
                    "agent_type": agent_type,
                    "description": test_case.get("description", ""),
                    "test_definition": test_case,
                    "tags": tags
                }
                
                response = await client.post(
                    f"{DATA_SERVICE_URL}/api/v1/test-cases",
                    json=test_case_data
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
    logger.info(f"Received legacy agent task. Execution URL: {EXECUTION_SERVICE_URL}, Data URL: {DATA_SERVICE_URL}")
    return {"message": "Agent task delegated (legacy endpoint)", "task_id": 1}
