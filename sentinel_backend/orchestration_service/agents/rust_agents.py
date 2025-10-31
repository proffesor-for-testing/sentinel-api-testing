"""
Rust Agent Wrappers for Performance Benchmarking

This module provides function-based wrappers that communicate with the Rust core
service running on port 8088 to enable performance benchmarking between Python
and Rust implementations.

Each function:
1. Prepares the task payload
2. Makes an HTTP request to the Rust core service
3. Handles errors and timeouts
4. Returns the result in a consistent format
"""

from typing import Dict, Any, Optional
import httpx
import asyncio
from datetime import datetime
import logging

from sentinel_backend.config.settings import get_application_settings

logger = logging.getLogger(__name__)

# Get Rust core service URL from settings
try:
    settings = get_application_settings()
    # Try multiple possible settings locations
    if hasattr(settings, 'service') and hasattr(settings.service, 'rust_core_service_url'):
        RUST_CORE_URL = settings.service.rust_core_service_url
    elif hasattr(settings, 'rust_core_service_url'):
        RUST_CORE_URL = settings.rust_core_service_url
    else:
        RUST_CORE_URL = 'http://sentinel_rust_core:8088'
except Exception:
    RUST_CORE_URL = 'http://sentinel_rust_core:8088'

REQUEST_TIMEOUT = 30.0  # 30 second timeout for agent execution


async def _execute_rust_agent(
    agent_type: str,
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Execute a Rust agent via HTTP request to the Rust core service.

    Args:
        agent_type: The agent type identifier (e.g., "Functional-Positive-Agent")
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata

    Raises:
        httpx.TimeoutException: If request times out
        httpx.HTTPError: If HTTP request fails
    """
    payload = {
        "task": {
            "task_id": f"bench_{agent_type}_{datetime.now().timestamp()}",
            "agent_type": agent_type,
            "spec_id": spec.get("info", {}).get("title", "unknown"),
            "parameters": config or {},
            "enable_llm": False  # Disable LLM for consistent benchmarking
        },
        "api_spec": spec
    }

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(
                f"{RUST_CORE_URL}/api/v1/execute",
                json=payload
            )
            response.raise_for_status()
            result = response.json()

            return {
                "test_cases": result.get("test_cases", []),
                "success": result.get("success", False),
                "error": result.get("error"),
                "metadata": result.get("metadata", {})
            }

    except httpx.TimeoutException as e:
        logger.error(f"Rust agent {agent_type} timed out after {REQUEST_TIMEOUT}s: {e}")
        return {
            "test_cases": [],
            "success": False,
            "error": f"Request timed out after {REQUEST_TIMEOUT}s",
            "metadata": {
                "agent_type": agent_type,
                "language": "rust",
                "error_type": "timeout"
            }
        }

    except httpx.HTTPStatusError as e:
        logger.error(f"Rust agent {agent_type} HTTP error {e.response.status_code}: {e}")
        return {
            "test_cases": [],
            "success": False,
            "error": f"HTTP {e.response.status_code}: {e.response.text}",
            "metadata": {
                "agent_type": agent_type,
                "language": "rust",
                "error_type": "http_error",
                "status_code": e.response.status_code
            }
        }

    except httpx.ConnectError as e:
        logger.error(f"Cannot connect to Rust core service at {RUST_CORE_URL}: {e}")
        return {
            "test_cases": [],
            "success": False,
            "error": f"Cannot connect to Rust core service: {RUST_CORE_URL}",
            "metadata": {
                "agent_type": agent_type,
                "language": "rust",
                "error_type": "connection_error",
                "rust_core_url": RUST_CORE_URL
            }
        }

    except Exception as e:
        logger.error(f"Unexpected error executing Rust agent {agent_type}: {e}")
        return {
            "test_cases": [],
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "metadata": {
                "agent_type": agent_type,
                "language": "rust",
                "error_type": "unexpected"
            }
        }


async def functional_positive_rust(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate positive functional test cases using Rust implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    return await _execute_rust_agent("Functional-Positive-Agent", spec, config)


async def functional_negative_rust(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate negative functional test cases using Rust implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    return await _execute_rust_agent("Functional-Negative-Agent", spec, config)


async def functional_stateful_rust(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate stateful functional test cases using Rust implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    return await _execute_rust_agent("Functional-Stateful-Agent", spec, config)


async def security_auth_rust(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate authentication security test cases using Rust implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    return await _execute_rust_agent("Security-Auth-Agent", spec, config)


async def security_injection_rust(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate injection security test cases using Rust implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    return await _execute_rust_agent("Security-Injection-Agent", spec, config)


async def performance_planner_rust(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate performance test scripts using Rust implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    return await _execute_rust_agent("Performance-Planner-Agent", spec, config)


async def data_mocking_rust(
    spec: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate mock data using Rust implementation.

    Args:
        spec: OpenAPI specification dictionary
        config: Optional configuration parameters

    Returns:
        Dictionary with test_cases, success status, and metadata
    """
    return await _execute_rust_agent("data-mocking", spec, config)


# Export all agent functions
__all__ = [
    "functional_positive_rust",
    "functional_negative_rust",
    "functional_stateful_rust",
    "security_auth_rust",
    "security_injection_rust",
    "performance_planner_rust",
    "data_mocking_rust",
]
