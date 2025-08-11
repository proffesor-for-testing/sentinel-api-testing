#!/bin/bash

# Sentinel Platform - Complete Test Suite Runner
# This script runs all tests (backend + frontend + E2E) in Docker containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Sentinel Platform Test Suite Runner"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -b, --backend-only     Run backend tests only"
    echo "  -f, --frontend-only    Run frontend tests only"  
    echo "  -e, --e2e-only         Run E2E tests only"
    echo "  -t, --type TYPE        Test type: unit, integration, performance, etc."
    echo "  -v, --verbose          Enable verbose output"
    echo "  -n, --no-cleanup       Skip cleanup after tests"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                     # Run complete test suite"
    echo "  $0 -b                  # Run backend tests only"
    echo "  $0 -f                  # Run frontend tests only"
    echo "  $0 -e                  # Run E2E tests only"
    echo "  $0 -t unit -v          # Run unit tests with verbose output"
    echo ""
    echo "All tests run in Docker containers for consistency and isolation."
}

# Default values
BACKEND_ONLY=false
FRONTEND_ONLY=false
E2E_ONLY=false
TEST_TYPE=""
VERBOSE=false
NO_CLEANUP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--backend-only)
            BACKEND_ONLY=true
            shift
            ;;
        -f|--frontend-only)
            FRONTEND_ONLY=true
            shift
            ;;
        -e|--e2e-only)
            E2E_ONLY=true
            shift
            ;;
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -n|--no-cleanup)
            NO_CLEANUP=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate that only one test type is selected
selected_count=0
if [ "$BACKEND_ONLY" = true ]; then ((selected_count++)); fi
if [ "$FRONTEND_ONLY" = true ]; then ((selected_count++)); fi
if [ "$E2E_ONLY" = true ]; then ((selected_count++)); fi

if [ $selected_count -gt 1 ]; then
    print_error "Cannot specify multiple test type flags simultaneously"
    exit 1
fi

print_status "Sentinel Platform Test Suite Runner"
print_status "================================="

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not running"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_error "docker-compose is not installed"
    exit 1
fi

# Change to backend directory where docker-compose.test.yml is located
cd sentinel_backend

# Build test runner arguments
TEST_ARGS=""
if [ "$VERBOSE" = true ]; then
    TEST_ARGS="$TEST_ARGS -v"
fi
if [ "$NO_CLEANUP" = true ]; then
    TEST_ARGS="$TEST_ARGS -n"
fi
if [ -n "$TEST_TYPE" ]; then
    TEST_ARGS="$TEST_ARGS -t $TEST_TYPE"
fi

# Always use Docker mode
TEST_ARGS="$TEST_ARGS -d"

# Add specific test type flags
if [ "$BACKEND_ONLY" = true ]; then
    TEST_ARGS="$TEST_ARGS -b"
elif [ "$FRONTEND_ONLY" = true ]; then
    TEST_ARGS="$TEST_ARGS -f"
elif [ "$E2E_ONLY" = true ]; then
    TEST_ARGS="$TEST_ARGS -t e2e"
fi

print_status "Running tests with arguments: $TEST_ARGS"

# Execute the test runner
if ./run_tests.sh $TEST_ARGS; then
    print_success "All tests completed successfully!"
    
    # Show coverage reports information
    print_status ""
    print_status "Test Reports Available:"
    print_status "- Backend Coverage: ./sentinel_backend/test_reports/htmlcov/index.html"
    print_status "- Frontend Coverage: ./sentinel_frontend/coverage/lcov-report/index.html" 
    print_status "- E2E Results: ./sentinel_frontend/test-results/"
    print_status "- Playwright Report: ./sentinel_frontend/playwright-report/index.html"
else
    print_error "Tests failed!"
    exit 1
fi

print_success "Test execution completed!"