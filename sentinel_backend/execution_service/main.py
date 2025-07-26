from fastapi import FastAPI
import os

app = FastAPI(title="Sentinel Execution Service")

DATABASE_URL = os.getenv("DATABASE_URL")

@app.get("/")
async def root():
    return {"message": "Sentinel Execution Service is running"}

@app.post("/test-runs")
async def execute_test_run(request: dict):
    # In a real implementation, this would:
    # 1. Connect to the database using DATABASE_URL
    # 2. Retrieve the test suite and its test cases
    # 3. Execute the tests using pytest dynamically
    # 4. Store the results in the test_results table
    # 5. Return the run status and summary
    print(f"Received test run request. DB_URL: {DATABASE_URL}")
    return {"message": "Test run executed (not implemented yet)", "run_id": 1}
