#!/bin/bash

# Script to run tests with proper filtering based on available services

echo "🧪 Sentinel Test Runner"
echo "======================"

# Parse arguments
INCLUDE_RUST=false
DOCKER_MODE=false
TEST_TYPE="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        --with-rust)
            INCLUDE_RUST=true
            shift
            ;;
        -d|--docker)
            DOCKER_MODE=true
            shift
            ;;
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --with-rust     Include Rust integration tests"
            echo "  -d, --docker    Run tests in Docker"
            echo "  -t, --type      Test type: unit, integration, all"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if Rust service is available
check_rust_service() {
    curl -s -o /dev/null -w "%{http_code}" http://localhost:8088/health 2>/dev/null | grep -q "200"
    return $?
}

# Build pytest command
PYTEST_ARGS=""

if [ "$TEST_TYPE" = "unit" ]; then
    PYTEST_ARGS="-m unit"
elif [ "$TEST_TYPE" = "integration" ]; then
    PYTEST_ARGS="-m integration"
fi

# Exclude Rust tests unless explicitly requested or service is available
if [ "$INCLUDE_RUST" = false ]; then
    if ! check_rust_service; then
        echo "⚠️  Rust service not available. Excluding Rust integration tests."
        echo "   Use --with-rust to force running them with mocks."
        if [ -z "$PYTEST_ARGS" ]; then
            PYTEST_ARGS="-m 'not rust'"
        else
            PYTEST_ARGS="$PYTEST_ARGS and not rust"
            PYTEST_ARGS="-m \"($PYTEST_ARGS)\""
        fi
    else
        echo "✅ Rust service detected. Including Rust integration tests."
    fi
else
    echo "🔧 Forcing Rust tests to run (may use mocks if service unavailable)"
    export FORCE_RUST_TESTS=1
fi

# Run tests
if [ "$DOCKER_MODE" = true ]; then
    echo "🐳 Running tests in Docker..."
    ./run_tests.sh -d
else
    echo "🖥️  Running tests locally..."
    echo "Command: pytest $PYTEST_ARGS"
    eval "pytest $PYTEST_ARGS"
fi