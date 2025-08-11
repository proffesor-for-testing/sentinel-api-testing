"""
Application factory for Orchestration Service.

This module provides a factory pattern for creating testable FastAPI instances
for the AI agent orchestration service.
"""
from typing import Optional, Dict, Any, List, Callable
from fastapi import FastAPI, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from enum import Enum
import asyncio
import json
from unittest.mock import Mock


class AgentType(str, Enum):
    """Available agent types."""
    FUNCTIONAL_POSITIVE = "Functional-Positive-Agent"
    FUNCTIONAL_NEGATIVE = "Functional-Negative-Agent"
    FUNCTIONAL_STATEFUL = "Functional-Stateful-Agent"
    SECURITY_AUTH = "Security-Auth-Agent"
    SECURITY_INJECTION = "Security-Injection-Agent"
    PERFORMANCE_PLANNER = "Performance-Planner-Agent"
    DATA_MOCKING = "Data-Mocking-Agent"


class TestGenerationRequest(BaseModel):
    """Request model for test generation."""
    spec_id: int
    agent_types: List[AgentType] = [AgentType.FUNCTIONAL_POSITIVE]
    target_environment: Optional[str] = None
    options: Optional[Dict[str, Any]] = {}


class TestGenerationResponse(BaseModel):
    """Response model for test generation."""
    task_id: str
    spec_id: int
    agent_types: List[str]
    status: str
    total_test_cases: int = 0
    created_at: str


class TaskStatus(str, Enum):
    """Task status values."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class OrchestrationConfig:
    """Configuration for orchestration service."""
    def __init__(self,
                 enable_background_tasks: bool = True,
                 mock_agents: bool = False,
                 mock_spec_service: bool = True,
                 mock_data_service: bool = True,
                 spec_service_url: str = "http://spec-service:8001",
                 data_service_url: str = "http://data-service:8004"):
        self.enable_background_tasks = enable_background_tasks
        self.mock_agents = mock_agents
        self.mock_spec_service = mock_spec_service
        self.mock_data_service = mock_data_service
        self.spec_service_url = spec_service_url
        self.data_service_url = data_service_url
        self.tasks = {}  # Task storage
        self.test_cases = {}  # Test case storage
        self.next_task_id = 1


class MockAgent:
    """Mock agent for testing."""
    def __init__(self, agent_type: str):
        self.agent_type = agent_type
    
    async def generate_tests(self, spec: Dict[str, Any], options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate mock test cases."""
        # Return different test cases based on agent type
        test_cases = []
        
        if "Positive" in self.agent_type:
            test_cases = [
                {
                    "name": f"Test positive case 1",
                    "type": "positive",
                    "method": "GET",
                    "path": "/test",
                    "expected_status": 200
                }
            ]
        elif "Negative" in self.agent_type:
            test_cases = [
                {
                    "name": f"Test negative case 1",
                    "type": "negative",
                    "method": "GET",
                    "path": "/test",
                    "expected_status": 400
                }
            ]
        elif "Security" in self.agent_type:
            test_cases = [
                {
                    "name": f"Test security case 1",
                    "type": "security",
                    "method": "POST",
                    "path": "/test",
                    "payload": "'; DROP TABLE users; --",
                    "expected_status": 400
                }
            ]
        else:
            test_cases = [
                {
                    "name": f"Test {self.agent_type} case 1",
                    "type": "generic",
                    "method": "GET",
                    "path": "/test",
                    "expected_status": 200
                }
            ]
        
        return test_cases


def create_orchestration_app(
    config: Optional[OrchestrationConfig] = None,
    dependency_overrides: Optional[Dict] = None
) -> FastAPI:
    """
    Create a FastAPI application for orchestration service.
    
    Args:
        config: Orchestration service configuration
        dependency_overrides: Optional dependency overrides for testing
    
    Returns:
        Configured FastAPI application
    """
    if config is None:
        config = OrchestrationConfig()
    
    app = FastAPI(
        title="Sentinel Orchestration Service",
        description="AI agent orchestration and test generation service",
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
    
    # Helper functions
    async def get_specification(spec_id: int) -> Dict[str, Any]:
        """Get specification from spec service."""
        if config.mock_spec_service:
            # Return mock specification
            return {
                "id": spec_id,
                "parsed_spec": {
                    "openapi": "3.0.0",
                    "info": {"title": "Mock API", "version": "1.0.0"},
                    "paths": {
                        "/test": {
                            "get": {"summary": "Test endpoint", "responses": {"200": {}}}
                        }
                    }
                }
            }
        else:
            # Real implementation would call spec service
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{config.spec_service_url}/api/v1/specifications/{spec_id}")
                response.raise_for_status()
                return response.json()
    
    async def save_test_cases(spec_id: int, test_cases: List[Dict[str, Any]], agent_type: str):
        """Save test cases to data service."""
        if config.mock_data_service:
            # Store in memory
            if spec_id not in config.test_cases:
                config.test_cases[spec_id] = []
            for test_case in test_cases:
                test_case["agent_type"] = agent_type
                test_case["spec_id"] = spec_id
                test_case["id"] = len(config.test_cases[spec_id]) + 1
                config.test_cases[spec_id].append(test_case)
        else:
            # Real implementation would call data service
            import httpx
            async with httpx.AsyncClient() as client:
                for test_case in test_cases:
                    test_case["spec_id"] = spec_id
                    test_case["agent_type"] = agent_type
                    await client.post(
                        f"{config.data_service_url}/api/v1/test-cases",
                        json=test_case
                    )
    
    async def run_agent_orchestration(task_id: str, spec_id: int, agent_types: List[str], options: Dict[str, Any]):
        """Run agent orchestration in background."""
        task = config.tasks[task_id]
        task["status"] = TaskStatus.RUNNING
        task["started_at"] = datetime.utcnow().isoformat()
        
        try:
            # Get specification
            spec = await get_specification(spec_id)
            
            total_test_cases = 0
            
            # Run each agent
            for agent_type in agent_types:
                if config.mock_agents:
                    agent = MockAgent(agent_type)
                else:
                    # Real implementation would import actual agents
                    # For now, use mock
                    agent = MockAgent(agent_type)
                
                # Generate test cases
                test_cases = await agent.generate_tests(spec["parsed_spec"], options)
                
                # Save test cases
                await save_test_cases(spec_id, test_cases, agent_type)
                
                total_test_cases += len(test_cases)
            
            # Update task
            task["status"] = TaskStatus.COMPLETED
            task["total_test_cases"] = total_test_cases
            task["completed_at"] = datetime.utcnow().isoformat()
            
        except Exception as e:
            task["status"] = TaskStatus.FAILED
            task["error"] = str(e)
            task["failed_at"] = datetime.utcnow().isoformat()
    
    # Routes
    @app.get("/")
    async def root():
        return {
            "service": "Sentinel Orchestration Service",
            "version": "1.0.0",
            "status": "operational",
            "available_agents": [agent.value for agent in AgentType]
        }
    
    @app.get("/health")
    async def health():
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @app.post("/generate-tests", response_model=TestGenerationResponse)
    async def generate_tests(request: TestGenerationRequest, background_tasks: BackgroundTasks):
        """Generate test cases using AI agents."""
        
        # Create task
        task_id = f"task-{config.next_task_id}"
        config.next_task_id += 1
        
        task = {
            "task_id": task_id,
            "spec_id": request.spec_id,
            "agent_types": [a.value if isinstance(a, AgentType) else a for a in request.agent_types],
            "status": TaskStatus.PENDING,
            "total_test_cases": 0,
            "created_at": datetime.utcnow().isoformat(),
            "options": request.options
        }
        
        config.tasks[task_id] = task
        
        # Run orchestration in background
        if config.enable_background_tasks:
            background_tasks.add_task(
                run_agent_orchestration,
                task_id,
                request.spec_id,
                task["agent_types"],
                request.options
            )
        else:
            # For testing, run synchronously
            await run_agent_orchestration(
                task_id,
                request.spec_id,
                task["agent_types"],
                request.options
            )
        
        return TestGenerationResponse(
            task_id=task_id,
            spec_id=request.spec_id,
            agent_types=task["agent_types"],
            status=task["status"],
            total_test_cases=task.get("total_test_cases", 0),
            created_at=task["created_at"]
        )
    
    @app.get("/tasks/{task_id}")
    async def get_task_status(task_id: str):
        """Get task status."""
        if task_id not in config.tasks:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {task_id} not found"
            )
        
        return config.tasks[task_id]
    
    @app.get("/tasks")
    async def list_tasks(
        skip: int = 0,
        limit: int = 100,
        status: Optional[TaskStatus] = None
    ):
        """List all tasks."""
        tasks = list(config.tasks.values())
        
        # Filter by status if specified
        if status:
            tasks = [t for t in tasks if t["status"] == status]
        
        # Apply pagination
        tasks = tasks[skip:skip + limit]
        
        return tasks
    
    @app.get("/agents")
    async def list_agents():
        """List available agents and their capabilities."""
        agents = []
        
        for agent_type in AgentType:
            agent_info = {
                "type": agent_type.value,
                "name": agent_type.value.replace("-", " "),
                "description": f"Generates {agent_type.value.lower()} test cases",
                "capabilities": []
            }
            
            # Add capabilities based on agent type
            if "Positive" in agent_type.value:
                agent_info["capabilities"] = ["happy_path", "valid_inputs", "schema_validation"]
            elif "Negative" in agent_type.value:
                agent_info["capabilities"] = ["boundary_values", "invalid_inputs", "error_handling"]
            elif "Stateful" in agent_type.value:
                agent_info["capabilities"] = ["workflow_testing", "state_management", "dependencies"]
            elif "Security" in agent_type.value:
                if "Auth" in agent_type.value:
                    agent_info["capabilities"] = ["authentication", "authorization", "rbac"]
                else:
                    agent_info["capabilities"] = ["injection", "xss", "sql_injection"]
            elif "Performance" in agent_type.value:
                agent_info["capabilities"] = ["load_testing", "stress_testing", "scalability"]
            elif "Data" in agent_type.value:
                agent_info["capabilities"] = ["data_generation", "mocking", "fixtures"]
            
            agents.append(agent_info)
        
        return agents
    
    @app.get("/test-cases/{spec_id}")
    async def get_test_cases_for_spec(spec_id: int):
        """Get test cases generated for a specification."""
        if config.mock_data_service:
            return config.test_cases.get(spec_id, [])
        else:
            # Real implementation would call data service
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{config.data_service_url}/api/v1/test-cases",
                    params={"spec_id": spec_id}
                )
                response.raise_for_status()
                return response.json()
    
    @app.post("/agents/{agent_type}/test")
    async def test_agent(agent_type: str, spec: Dict[str, Any]):
        """Test a specific agent with a specification."""
        try:
            agent_enum = AgentType(agent_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid agent type: {agent_type}"
            )
        
        if config.mock_agents:
            agent = MockAgent(agent_type)
        else:
            # Real implementation would use actual agent
            agent = MockAgent(agent_type)
        
        test_cases = await agent.generate_tests(spec, {})
        
        return {
            "agent_type": agent_type,
            "test_cases": test_cases,
            "count": len(test_cases)
        }
    
    return app


def create_test_orchestration_app(
    tasks: Optional[Dict[str, Dict]] = None,
    test_cases: Optional[Dict[int, List]] = None
) -> FastAPI:
    """
    Create a test app with predefined data.
    
    Args:
        tasks: Optional dictionary of tasks
        test_cases: Optional dictionary of test cases by spec_id
    
    Returns:
        Configured FastAPI app for testing
    """
    config = OrchestrationConfig(
        enable_background_tasks=False,  # Disable for testing
        mock_agents=True,
        mock_spec_service=True,
        mock_data_service=True
    )
    
    if tasks:
        config.tasks = tasks
        config.next_task_id = len(tasks) + 1
    
    if test_cases:
        config.test_cases = test_cases
    
    return create_orchestration_app(config)