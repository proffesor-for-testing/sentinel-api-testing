from fastapi import FastAPI
import os

app = FastAPI(title="Sentinel Specification Service")

DATABASE_URL = os.getenv("DATABASE_URL")

@app.get("/")
async def root():
    return {"message": "Sentinel Specification Service is running"}

@app.post("/")
async def create_specification(request: dict):
    # In a real implementation, this would:
    # 1. Connect to the database using DATABASE_URL
    # 2. Parse the incoming spec from the request
    # 3. Save the raw and parsed spec to the `api_specifications` table
    # 4. Return the ID of the newly created spec
    print(f"Received spec request. DB_URL: {DATABASE_URL}")
    return {"message": "Specification received (not implemented yet)", "spec_id": 1}
