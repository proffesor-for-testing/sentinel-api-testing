#!/bin/bash

# Sentinel Test Runner Script
# This script provides various options for running tests in the Sentinel platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
ENVIRONMENT="testing"
COVERAGE=true
VERBOSE=false
PARALLEL=false
DOCKER=false
CLEANUP=true

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
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE        Test type: unit, integration, functional, security, performance, all (default: all)"
    echo "  -e, --env ENV          Environment: testing, development (default: testing)"
    echo "  -c, --no-coverage      Disable coverage reporting"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -p, --parallel         Run tests in parallel"
    echo "  -d, --docker           Run tests in Docker containers"
    echo "  -n, --no-cleanup       Skip cleanup after tests"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                     # Run all tests with default settings"
    echo "  $0 -t unit -v          # Run unit tests with verbose output"
    echo "  $0 -t integration -d   # Run integration tests in Docker"
    echo "  $0 -p -c               # Run all tests in parallel without coverage"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -e|--env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -c|--no-coverage)
            COVERAGE=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -p|--parallel)
            PARALLEL=true
            shift
            ;;
        -d|--docker)
            DOCKER=true
            shift
            ;;
        -n|--no-cleanup)
            CLEANUP=false
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

# Validate test type
case $TEST_TYPE in
    unit|integration|functional|security|performance|all)
        ;;
    *)
        print_error "Invalid test type: $TEST_TYPE"
        print_error "Valid types: unit, integration, functional, security, performance, all"
        exit 1
        ;;
esac

# Set environment variable
export SENTINEL_ENVIRONMENT=$ENVIRONMENT

print_status "Starting Sentinel test suite..."
print_status "Test type: $TEST_TYPE"
print_status "Environment: $ENVIRONMENT"
print_status "Coverage: $COVERAGE"
print_status "Verbose: $VERBOSE"
print_status "Parallel: $PARALLEL"
print_status "Docker: $DOCKER"

# Build pytest command
PYTEST_CMD="pytest"

# Add test markers based on type
case $TEST_TYPE in
    unit)
        PYTEST_CMD="$PYTEST_CMD -m unit"
        ;;
    integration)
        PYTEST_CMD="$PYTEST_CMD -m integration"
        ;;
    functional)
        PYTEST_CMD="$PYTEST_CMD -m functional"
        ;;
    security)
        PYTEST_CMD="$PYTEST_CMD -m security"
        ;;
    performance)
        PYTEST_CMD="$PYTEST_CMD -m performance"
        ;;
    all)
        # Run all tests
        ;;
esac

# Add verbose flag
if [ "$VERBOSE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -v"
fi

# Add parallel execution
if [ "$PARALLEL" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -n auto"
fi

# Add coverage options
if [ "$COVERAGE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=. --cov-report=term-missing --cov-report=html:htmlcov --cov-report=xml:coverage.xml"
fi

# Add other pytest options
PYTEST_CMD="$PYTEST_CMD --tb=short --strict-markers --color=yes"

# Function to run tests locally
run_tests_local() {
    print_status "Running tests locally..."
    
    # Check if pytest is installed
    if ! command -v pytest &> /dev/null; then
        print_error "pytest is not installed. Please install it with: pip install pytest"
        exit 1
    fi
    
    # Create test reports directory
    mkdir -p test_reports
    
    # Run tests
    print_status "Executing: $PYTEST_CMD"
    if eval $PYTEST_CMD; then
        print_success "Tests completed successfully!"
    else
        print_error "Tests failed!"
        exit 1
    fi
}

# Function to run tests in Docker
run_tests_docker() {
    print_status "Running tests in Docker..."
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not running"
        exit 1
    fi
    
    # Check if docker-compose is available
    if ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is not installed"
        exit 1
    fi
    
    # Start test environment
    print_status "Starting test environment..."
    docker-compose -f docker-compose.test.yml up -d test_db
    
    # Wait for database to be ready
    print_status "Waiting for test database to be ready..."
    sleep 10
    
    # Run tests in container
    print_status "Running tests in container..."
    docker-compose -f docker-compose.test.yml run --rm test_runner $PYTEST_CMD
    
    # Cleanup if requested
    if [ "$CLEANUP" = true ]; then
        print_status "Cleaning up test environment..."
        docker-compose -f docker-compose.test.yml down -v
    fi
}

# Function to setup test environment
setup_test_env() {
    print_status "Setting up test environment..."
    
    # Create necessary directories
    mkdir -p test_reports
    mkdir -p logs
    
    # Set environment variables
    export PYTHONPATH=$(pwd)
    export SENTINEL_ENVIRONMENT=$ENVIRONMENT
    
    print_success "Test environment setup complete"
}

# Function to cleanup after tests
cleanup_test_env() {
    if [ "$CLEANUP" = true ]; then
        print_status "Cleaning up test environment..."
        
        # Remove temporary files
        find . -name "*.pyc" -delete
        find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
        find . -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null || true
        
        print_success "Cleanup complete"
    fi
}

# Main execution
main() {
    # Setup test environment
    setup_test_env
    
    # Run tests based on mode
    if [ "$DOCKER" = true ]; then
        run_tests_docker
    else
        run_tests_local
    fi
    
    # Cleanup
    cleanup_test_env
    
    print_success "Test execution completed!"
}

# Trap to ensure cleanup on exit
trap cleanup_test_env EXIT

# Run main function
main
