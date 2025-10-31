"""
Python Agent Wrappers for Performance Benchmarking

This module provides function-based wrappers around class-based agent implementations
to enable consistent benchmarking between Python and Rust implementations.

Each function:
1. Instantiates the appropriate agent class
2. Creates an AgentTask with the provided specification
3. Executes the agent
4. Returns the result in a consistent format
"""

from typing import Dict, Any, Optional
import asyncio
from datetime import datetime

from .base_agent import AgentTask, AgentResult
from .functional_positive_agent import FunctionalPositiveAgent
from .functional_negative_agent import FunctionalNegativeAgent
from .functional_stateful_agent import FunctionalStatefulAgent
from .security_auth_agent import SecurityAuthAgent
from .security_injection_agent import SecurityInjectionAgent
from .performance_planner_agent import PerformancePlannerAgent


async def functional_positive_python(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate positive functional test cases using Python implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    agent = FunctionalPositiveAgent()

    task = AgentTask(
        task_id=f"bench_pos_{datetime.now().timestamp()}",
        agent_type="Functional-Positive-Agent",
        spec_id=spec.get("info", {}).get("title", "unknown"),
        parameters=config or {},
        enable_llm=False  # Disable LLM for consistent benchmarking
    )

    result: AgentResult = await agent.execute(task, spec, db_session=None)

    return {
        "test_cases": result.test_cases,
        "success": result.success,
        "error": result.error,
        "metadata": result.metadata
    }


async def functional_negative_python(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate negative functional test cases using Python implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    agent = FunctionalNegativeAgent()

    task = AgentTask(
        task_id=f"bench_neg_{datetime.now().timestamp()}",
        agent_type="Functional-Negative-Agent",
        spec_id=spec.get("info", {}).get("title", "unknown"),
        parameters=config or {},
        enable_llm=False
    )

    result: AgentResult = await agent.execute(task, spec, db_session=None)

    return {
        "test_cases": result.test_cases,
        "success": result.success,
        "error": result.error,
        "metadata": result.metadata
    }


async def functional_stateful_python(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate stateful functional test cases using Python implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    agent = FunctionalStatefulAgent()

    task = AgentTask(
        task_id=f"bench_state_{datetime.now().timestamp()}",
        agent_type="Functional-Stateful-Agent",
        spec_id=spec.get("info", {}).get("title", "unknown"),
        parameters=config or {},
        enable_llm=False
    )

    result: AgentResult = await agent.execute(task, spec, db_session=None)

    return {
        "test_cases": result.test_cases,
        "success": result.success,
        "error": result.error,
        "metadata": result.metadata
    }


async def security_auth_python(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate authentication security test cases using Python implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    agent = SecurityAuthAgent()

    task = AgentTask(
        task_id=f"bench_auth_{datetime.now().timestamp()}",
        agent_type="Security-Auth-Agent",
        spec_id=spec.get("info", {}).get("title", "unknown"),
        parameters=config or {},
        enable_llm=False
    )

    result: AgentResult = await agent.execute(task, spec, db_session=None)

    return {
        "test_cases": result.test_cases,
        "success": result.success,
        "error": result.error,
        "metadata": result.metadata
    }


async def security_injection_python(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate injection security test cases using Python implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    agent = SecurityInjectionAgent()

    task = AgentTask(
        task_id=f"bench_inj_{datetime.now().timestamp()}",
        agent_type="Security-Injection-Agent",
        spec_id=spec.get("info", {}).get("title", "unknown"),
        parameters=config or {},
        enable_llm=False
    )

    result: AgentResult = await agent.execute(task, spec, db_session=None)

    return {
        "test_cases": result.test_cases,
        "success": result.success,
        "error": result.error,
        "metadata": result.metadata
    }


async def performance_planner_python(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate performance test scripts using Python implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    agent = PerformancePlannerAgent()

    task = AgentTask(
        task_id=f"bench_perf_{datetime.now().timestamp()}",
        agent_type="Performance-Planner-Agent",
        spec_id=spec.get("info", {}).get("title", "unknown"),
        parameters=config or {},
        enable_llm=False
    )

    result: AgentResult = await agent.execute(task, spec, db_session=None)

    return {
        "test_cases": result.test_cases,
        "success": result.success,
        "error": result.error,
        "metadata": result.metadata
    }


async def data_mocking_python(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate mock data using Python implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    from .data_mocking_agent import DataMockingAgent

    agent = DataMockingAgent()

    task = AgentTask(
        task_id=f"bench_mock_{datetime.now().timestamp()}",
        agent_type="Data-Mocking-Agent",
        spec_id=spec.get("info", {}).get("title", "unknown"),
        parameters=config or {},
        enable_llm=False
    )

    result: AgentResult = await agent.execute(task, spec, db_session=None)

    return {
        "test_cases": result.test_cases,
        "success": result.success,
        "error": result.error,
        "metadata": result.metadata
    }


# Export all agent functions
__all__ = [
    "functional_positive_python",
    "functional_negative_python",
    "functional_stateful_python",
    "security_auth_python",
    "security_injection_python",
    "performance_planner_python",
    "data_mocking_python",
]
