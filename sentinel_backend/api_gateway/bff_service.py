from fastapi import APIRouter, Depends, HTTPException
from starlette.status import HTTP_200_OK
import httpx

from auth_service.auth_middleware import get_current_user_optional
from config.settings import get_service_settings

router = APIRouter()
service_settings = get_service_settings()


@router.get("/dashboard-summary", status_code=HTTP_200_OK)
async def get_dashboard_summary(current_user: dict = Depends(get_current_user_optional)):
    async with httpx.AsyncClient(timeout=service_settings.service_timeout) as client:
        try:
            # Fetch data from downstream services in parallel
            spec_service_url = f"{service_settings.spec_service_url}/api/v1/specifications"
            data_service_url = f"{service_settings.data_service_url}/api/v1/dashboard-stats"

            spec_response_task = client.get(spec_service_url)
            data_response_task = client.get(data_service_url)

            spec_response, data_response = await asyncio.gather(
                spec_response_task,
                data_response_task
            )

            spec_response.raise_for_status()
            data_response.raise_for_status()

            spec_data = spec_response.json()
            dashboard_stats = data_response.json()

            return {
                "recent_specifications": spec_data.get("data", [])[:5],
                "dashboard_stats": dashboard_stats.get("data", {}),
            }

        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error fetching dashboard summary: {e.response.text}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {str(e)}")