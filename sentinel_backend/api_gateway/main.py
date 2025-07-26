from fastapi import FastAPI, HTTPException
import httpx
import os

app = FastAPI(title="Sentinel API Gateway")

SPEC_SERVICE_URL = os.getenv("SPEC_SERVICE_URL")
ORCHESTRATION_SERVICE_URL = os.getenv("ORCHESTRATION_SERVICE_URL")
DATA_SERVICE_URL = os.getenv("DATA_SERVICE_URL")

@app.get("/")
async def root():
    return {"message": "Sentinel API Gateway is running"}

# Example of routing to the spec_service
@app.post("/api/v1/specifications")
async def create_specification(request: dict):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(f"{SPEC_SERVICE_URL}/", json=request)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=e.response.json())
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Specification service is unavailable")

# Add more routing endpoints here for other services...
