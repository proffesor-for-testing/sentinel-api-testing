import pytest
import httpx
from unittest.mock import patch, AsyncMock
from httpx import ASGITransport

from sentinel_backend.orchestration_service.main import app
from sentinel_backend.config.settings import get_service_settings

# Mock settings
@pytest.fixture
def mock_settings():
    with patch('sentinel_backend.orchestration_service.main.get_service_settings') as mock:
        settings = get_service_settings()
        settings.rust_core_service_url = "http://mock-rust-core:8088"
        mock.return_value = settings
        yield settings

@pytest.mark.asyncio
async def test_generate_tests_with_rust_agent(mock_settings):
    """
    Test that the orchestration service can delegate to a Rust agent.
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
            assert response_data["agent_results"][0]["test_cases_generated"] == 1
            assert response_data["agent_results"][0]["agent_type"] == "Functional-Positive-Agent"
            assert response_data["agent_results"][0]["execution_engine"] == "rust"
            mock_post.assert_called_once()

@pytest.mark.asyncio
async def test_generate_data_with_rust_agent(mock_settings):
    """
    Test that the orchestration service can delegate data generation to the Rust core.
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
            assert response_data["metadata"]["mock_data"] == {"key": "value"}
            mock_post.assert_called_once()

@pytest.mark.asyncio
async def test_fallback_to_python_agent_if_rust_fails(mock_settings):
    """
    Test that the orchestration service falls back to Python agents if the Rust core fails.
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
                assert response_data["total_test_cases"] == 1
                assert response_data["agent_results"][0]["agent_type"] == "Functional-Positive-Agent"
                assert response_data["agent_results"][0]["execution_engine"] == "python"
                mock_python_agent.assert_called_once()