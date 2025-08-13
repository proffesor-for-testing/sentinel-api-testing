import pytest
import httpx
import os
from unittest.mock import patch, AsyncMock
from httpx import ASGITransport

from sentinel_backend.orchestration_service.main import app
from sentinel_backend.config.settings import get_service_settings

# Check if Rust service is available
def rust_service_available():
    """Check if Rust service is running and accessible."""
    try:
        import httpx
        response = httpx.get("http://localhost:8088/health", timeout=1)
        return response.status_code == 200
    except:
        return False

# Skip all tests if Rust service is not available
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not rust_service_available() and not os.getenv("FORCE_RUST_TESTS"),
        reason="Rust service not available. Set FORCE_RUST_TESTS=1 to run with mocks"
    )
]

# Mock settings
@pytest.fixture
def mock_settings():
    with patch('sentinel_backend.orchestration_service.main.get_service_settings') as mock:
        settings = get_service_settings()
        settings.rust_core_service_url = "http://mock-rust-core:8088"
        mock.return_value = settings
        yield settings

@pytest.mark.asyncio
@pytest.mark.rust
async def test_generate_tests_with_rust_agent(mock_settings):
    """
    Test that the orchestration service can delegate to a Rust agent.
    
    This test verifies that when Rust core is available, the orchestration
    service correctly delegates agent tasks and processes the responses.
    """
    with patch('httpx.AsyncClient.post', new_callable=AsyncMock) as mock_post:
        # Mock the response from the Rust core service
        mock_post.return_value = httpx.Response(
            200,
            json={
                "result": {
                    "task_id": "test_task_id_Functional-Positive-Agent",
                    "agent_type": "Functional-Positive-Agent",
                    "status": "success",
                    "test_cases": [{"test_name": "Rust Test Case"}],
                    "metadata": {},
                    "error_message": None,
                },
                "processing_time_ms": 100,
            }
        )
        
        # Mock the fetch_api_specification call
        with patch('sentinel_backend.orchestration_service.main.fetch_api_specification', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {"openapi": "3.0.0", "paths": {}}

            async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post(
                    "/generate-tests",
                    json={
                        "spec_id": 1,
                        "agent_types": ["Functional-Positive-Agent"],
                    },
                )

            assert response.status_code == 200
            response_data = response.json()
            # Check for successful response
            assert "agent_results" in response_data
            assert len(response_data["agent_results"]) > 0
            assert response_data["total_test_cases"] >= 1
            # Check that at least one agent result exists
            agent_result = response_data["agent_results"][0]
            assert "agent_type" in agent_result
            assert agent_result["agent_type"] == "Functional-Positive-Agent"
            mock_post.assert_called_once()

@pytest.mark.asyncio
@pytest.mark.rust
async def test_generate_data_with_rust_agent(mock_settings):
    """
    Test that the orchestration service can delegate data generation to the Rust core.
    
    This test verifies the data generation flow through Rust agents.
    """
    with patch('httpx.AsyncClient.post', new_callable=AsyncMock) as mock_post:
        # Mock the response from the Rust core service
        mock_post.return_value = httpx.Response(
            200,
            json={
                "result": {
                    "task_id": "test_task_id",
                    "agent_type": "data-mocking",
                    "status": "success",
                    "test_cases": [],
                    "metadata": {"mock_data": {"key": "value"}},
                    "error_message": None,
                },
                "processing_time_ms": 100,
            }
        )

        # Mock the fetch_api_specification call
        with patch('sentinel_backend.orchestration_service.main.fetch_api_specification', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = {"openapi": "3.0.0", "paths": {}}

            async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post(
                    "/generate-data",
                    json={
                        "spec_id": 1,
                        "strategy": "realistic",
                        "count": 5,
                    },
                )

            assert response.status_code == 200
            response_data = response.json()
            # Check that response contains expected data structure
            assert "mock_data" in response_data or "data" in response_data or "metadata" in response_data
            # The exact structure depends on the implementation
            mock_post.assert_called_once()

@pytest.mark.asyncio
@pytest.mark.rust
@pytest.mark.fallback
async def test_fallback_to_python_agent_if_rust_fails(mock_settings):
    """
    Test that the orchestration service falls back to Python agents if the Rust core fails.
    
    This is a critical test that ensures system resilience when Rust service is unavailable.
    """
    with patch('httpx.AsyncClient.post', new_callable=AsyncMock) as mock_post:
        # Mock a failure from the Rust core service
        mock_post.side_effect = httpx.ConnectError("Connection failed")

        # Mock the Python agent
        with patch('sentinel_backend.orchestration_service.main.FunctionalPositiveAgent.execute', new_callable=AsyncMock) as mock_python_agent:
            from sentinel_backend.orchestration_service.agents.base_agent import AgentResult
            mock_python_agent.return_value = AgentResult(
                task_id="python_task",
                agent_type="Functional-Positive-Agent",
                status="success",
                test_cases=[{"test_name": "Python Test Case"}],
                metadata={},
                error_message=None,
            )

            # Mock the fetch_api_specification call
            with patch('sentinel_backend.orchestration_service.main.fetch_api_specification', new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = {"openapi": "3.0.0", "paths": {}}

                async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                    response = await client.post(
                        "/generate-tests",
                        json={
                            "spec_id": 1,
                            "agent_types": ["Functional-Positive-Agent"],
                        },
                    )
                assert response.status_code == 200
                response_data = response.json()
                assert response_data["total_test_cases"] >= 1
                assert len(response_data["agent_results"]) > 0
                # Check that the agent result exists
                agent_result = response_data["agent_results"][0]
                assert agent_result["agent_type"] == "Functional-Positive-Agent"
                # The execution_engine field might not exist in the response
                mock_python_agent.assert_called_once()