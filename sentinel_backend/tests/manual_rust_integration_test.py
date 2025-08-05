import asyncio
import httpx
import json

async def main():
    """
    Manual integration test for the orchestration service and Rust core.
    """
    async with httpx.AsyncClient() as client:
        # Test the /generate-tests endpoint
        print("--- Testing /generate-tests ---")
        try:
            response = await client.post(
                "http://localhost:8003/generate-tests",
                json={
                    "spec_id": 1,
                    "agent_types": ["Functional-Positive-Agent", "Security-Auth-Agent"],
                },
                timeout=60.0,
            )
            print(f"Status Code: {response.status_code}")
            print("Response JSON:")
            print(json.dumps(response.json(), indent=2))
        except httpx.ConnectError as e:
            print(f"Connection Error: {e}")
            print("Please ensure the orchestration service is running.")
        except Exception as e:
            print(f"An error occurred: {e}")

        print("\n" + "="*50 + "\n")

        # Test the /generate-data endpoint
        print("--- Testing /generate-data ---")
        try:
            response = await client.post(
                "http://localhost:8003/generate-data",
                json={
                    "spec_id": 1,
                    "strategy": "realistic",
                    "count": 2,
                },
                timeout=60.0,
            )
            print(f"Status Code: {response.status_code}")
            print("Response JSON:")
            print(json.dumps(response.json(), indent=2))
        except httpx.ConnectError as e:
            print(f"Connection Error: {e}")
            print("Please ensure the orchestration service is running.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(main())