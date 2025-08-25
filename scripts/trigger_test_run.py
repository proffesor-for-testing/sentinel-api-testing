#!/usr/bin/env python3
"""
Script to trigger a test run with the correct configuration for the Petstore API.
"""

import requests
import json
import time

# Configuration
API_GATEWAY_URL = "http://localhost:8000"
PETSTORE_API_URL = "http://host.docker.internal:8080/api/v1"  # Docker containers can reach host

def main():
    # First, let's check if we have a test suite
    print("Fetching test suites...")
    response = requests.get(f"{API_GATEWAY_URL}/api/v1/test-suites")
    if response.status_code != 200:
        print(f"Failed to fetch test suites: {response.status_code}")
        return
    
    test_suites = response.json()
    print(f"Found {len(test_suites)} test suites")
    
    # Find the Petstore test suite
    petstore_suite = None
    for suite in test_suites:
        if "petstore" in suite["name"].lower():
            petstore_suite = suite
            break
    
    if not petstore_suite:
        print("No Petstore test suite found!")
        return
    
    print(f"\nUsing test suite: {petstore_suite['name']} (ID: {petstore_suite['id']})")
    print(f"Test cases in suite: {petstore_suite.get('test_case_count', 0)}")
    
    # Create a new test run
    print(f"\nCreating test run with target URL: {PETSTORE_API_URL}")
    
    test_run_data = {
        "suite_id": petstore_suite["id"],
        "target_environment": PETSTORE_API_URL
    }
    
    response = requests.post(
        f"{API_GATEWAY_URL}/api/v1/test-runs",
        json=test_run_data
    )
    
    if response.status_code == 200:
        test_run = response.json()
        print(f"✅ Test run created successfully!")
        print(f"   Run ID: {test_run.get('id')}")
        print(f"   Status: {test_run.get('status')}")
        
        # Wait a moment for execution
        print("\nWaiting for test execution to complete...")
        time.sleep(5)
        
        # Check the test run status
        run_id = test_run.get('id')
        response = requests.get(f"{API_GATEWAY_URL}/api/v1/test-runs/{run_id}")
        if response.status_code == 200:
            updated_run = response.json()
            print(f"\nTest Run Results:")
            print(f"   Status: {updated_run.get('status')}")
            print(f"   Test Results: {updated_run.get('test_results', [])}")
            
            # Get detailed results if available
            if updated_run.get('test_results'):
                print("\nDetailed Results:")
                for result in updated_run['test_results']:
                    print(f"   - Test {result.get('test_case_id')}: {result.get('status')}")
                    if result.get('assertion_failures'):
                        print(f"     Failures: {result['assertion_failures']}")
        else:
            print(f"Failed to fetch test run details: {response.status_code}")
            
    else:
        print(f"❌ Failed to create test run: {response.status_code}")
        print(f"   Response: {response.text}")

if __name__ == "__main__":
    main()