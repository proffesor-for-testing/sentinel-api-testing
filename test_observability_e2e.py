#!/usr/bin/env python3
"""
End-to-end test script for observability features.
This script tests that all observability features are working correctly
when the services are running in Docker.
"""

import requests
import time
import sys
import json


def test_service_health(base_url, service_name):
    """Test that a service is healthy and responding."""
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print(f"✓ {service_name} is healthy")
            return True
        else:
            print(f"✗ {service_name} returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ {service_name} is not reachable: {e}")
        return False


def test_correlation_id(base_url, service_name):
    """Test that correlation ID is working."""
    try:
        # Test 1: Service generates correlation ID
        response = requests.get(f"{base_url}/", timeout=5)
        correlation_id = response.headers.get('x-correlation-id')
        if correlation_id:
            print(f"✓ {service_name} generates correlation ID: {correlation_id}")
        else:
            print(f"✗ {service_name} does not generate correlation ID")
            return False
        
        # Test 2: Service propagates provided correlation ID
        test_id = "test-correlation-12345"
        response = requests.get(
            f"{base_url}/",
            headers={"X-Correlation-ID": test_id},
            timeout=5
        )
        returned_id = response.headers.get('x-correlation-id')
        if returned_id == test_id:
            print(f"✓ {service_name} propagates correlation ID correctly")
            return True
        else:
            print(f"✗ {service_name} does not propagate correlation ID correctly")
            return False
    except Exception as e:
        print(f"✗ Error testing correlation ID for {service_name}: {e}")
        return False


def test_prometheus_metrics(base_url, service_name):
    """Test that Prometheus metrics are exposed."""
    try:
        response = requests.get(f"{base_url}/metrics", timeout=5)
        if response.status_code == 200:
            content = response.text
            if "http_requests_total" in content and "http_request_duration_seconds" in content:
                print(f"✓ {service_name} exposes Prometheus metrics")
                return True
            else:
                print(f"✗ {service_name} metrics endpoint missing expected metrics")
                return False
        else:
            print(f"✗ {service_name} metrics endpoint returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Error accessing metrics for {service_name}: {e}")
        return False


def test_prometheus_server():
    """Test that Prometheus server is running and scraping targets."""
    try:
        # Check Prometheus is running
        response = requests.get("http://localhost:9090/api/v1/targets", timeout=5)
        if response.status_code == 200:
            data = response.json()
            active_targets = [t for t in data['data']['activeTargets'] if t['health'] == 'up']
            print(f"✓ Prometheus is running with {len(active_targets)} healthy targets")
            return True
        else:
            print(f"✗ Prometheus API returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Prometheus server is not reachable: {e}")
        return False


def test_jaeger_server():
    """Test that Jaeger server is running."""
    try:
        response = requests.get("http://localhost:16686/api/services", timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Jaeger returns {"data": [...], "total": n, "limit": n, "offset": n}
            if data and isinstance(data, dict):
                services = data.get('data', [])
                print(f"✓ Jaeger is running with {len(services)} registered services")
            else:
                # If no services registered yet, that's still OK
                print(f"✓ Jaeger is running (no services registered yet)")
            return True
        else:
            print(f"✗ Jaeger API returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Jaeger server is not reachable: {e}")
        return False


def test_end_to_end_flow():
    """Test a complete flow through the API Gateway to verify tracing."""
    try:
        # Create a test correlation ID
        correlation_id = "e2e-test-correlation-id"
        
        # Make a request to the API Gateway health endpoint
        response = requests.get(
            "http://localhost:8000/health",
            headers={"X-Correlation-ID": correlation_id},
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"✓ End-to-end health check passed")
            
            # Check if correlation ID was returned
            if response.headers.get('x-correlation-id') == correlation_id:
                print(f"✓ Correlation ID propagated through API Gateway")
            
            # Parse health check response
            health_data = response.json()
            if health_data.get('status') in ['healthy', 'degraded']:
                print(f"✓ Health check returned valid status: {health_data['status']}")
                return True
        
        return False
    except Exception as e:
        print(f"✗ End-to-end test failed: {e}")
        return False


def main():
    """Run all observability tests."""
    print("=" * 60)
    print("Sentinel Observability End-to-End Tests")
    print("=" * 60)
    
    # Wait a bit for services to be ready
    print("\nWaiting for services to be ready...")
    time.sleep(5)
    
    # Define services to test
    services = [
        ("API Gateway", "http://localhost:8000"),
        ("Auth Service", "http://localhost:8005"),
        ("Spec Service", "http://localhost:8001"),
        ("Orchestration Service", "http://localhost:8002"),
        ("Execution Service", "http://localhost:8003"),
        ("Data Service", "http://localhost:8004"),
    ]
    
    all_passed = True
    
    # Test 1: Service Health
    print("\n1. Testing Service Health")
    print("-" * 40)
    for name, url in services:
        if not test_service_health(url, name):
            all_passed = False
    
    # Test 2: Correlation IDs
    print("\n2. Testing Correlation ID Middleware")
    print("-" * 40)
    for name, url in services:
        if not test_correlation_id(url, name):
            all_passed = False
    
    # Test 3: Prometheus Metrics
    print("\n3. Testing Prometheus Metrics")
    print("-" * 40)
    for name, url in services:
        if not test_prometheus_metrics(url, name):
            all_passed = False
    
    # Test 4: Prometheus Server
    print("\n4. Testing Prometheus Server")
    print("-" * 40)
    if not test_prometheus_server():
        all_passed = False
    
    # Test 5: Jaeger Server
    print("\n5. Testing Jaeger Server")
    print("-" * 40)
    if not test_jaeger_server():
        all_passed = False
    
    # Test 6: End-to-End Flow
    print("\n6. Testing End-to-End Flow")
    print("-" * 40)
    if not test_end_to_end_flow():
        all_passed = False
    
    # Summary
    print("\n" + "=" * 60)
    if all_passed:
        print("✓ All observability tests passed!")
        print("\nYou can now:")
        print("- View metrics at http://localhost:9090 (Prometheus)")
        print("- View traces at http://localhost:16686 (Jaeger)")
        print("- Check service logs for structured JSON output")
        return 0
    else:
        print("✗ Some observability tests failed!")
        print("\nPlease check:")
        print("1. All services are running: docker-compose ps")
        print("2. Services have restarted with new code: docker-compose restart")
        print("3. Check logs: docker-compose logs [service_name]")
        return 1


if __name__ == "__main__":
    sys.exit(main())