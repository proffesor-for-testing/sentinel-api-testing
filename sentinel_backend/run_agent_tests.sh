#!/bin/bash

# Sentinel AI Agent Test Runner
# This script runs the comprehensive test suite for all AI agents

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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

print_header() {
    echo -e "${CYAN}$1${NC}"
}

print_agent() {
    echo -e "${MAGENTA}[AGENT]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Sentinel AI Agent Test Runner"
    echo ""
    echo "Usage: $0 [OPTIONS] [AGENT_NAME]"
    echo ""
    echo "Options:"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -c, --coverage         Generate coverage report"
    echo "  -m, --markers          Show available test markers"
    echo "  -p, --parallel         Run tests in parallel"
    echo "  -f, --failfast         Stop on first failure"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Agent Names (optional):"
    echo "  base                   Run BaseAgent tests only"
    echo "  data-mocking           Run DataMockingAgent tests only"
    echo "  negative               Run FunctionalNegativeAgent tests only"
    echo "  positive               Run FunctionalPositiveAgent tests only"
    echo "  stateful               Run FunctionalStatefulAgent tests only"
    echo "  performance            Run PerformancePlannerAgent tests only"
    echo "  auth                   Run SecurityAuthAgent tests only"
    echo "  injection              Run SecurityInjectionAgent tests only"
    echo ""
    echo "Examples:"
    echo "  $0                     # Run all agent tests"
    echo "  $0 -v                  # Run all tests with verbose output"
    echo "  $0 -c                  # Run all tests with coverage"
    echo "  $0 base                # Run only BaseAgent tests"
    echo "  $0 auth injection      # Run auth and injection agent tests"
    echo "  $0 -v -c positive      # Run positive agent tests with verbose and coverage"
}

# Default values
VERBOSE=false
COVERAGE=false
PARALLEL=false
FAILFAST=false
SHOW_MARKERS=false
AGENTS=()

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -m|--markers)
            SHOW_MARKERS=true
            shift
            ;;
        -p|--parallel)
            PARALLEL=true
            shift
            ;;
        -f|--failfast)
            FAILFAST=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        base|data-mocking|negative|positive|stateful|performance|auth|injection)
            AGENTS+=("$1")
            shift
            ;;
        *)
            print_error "Unknown option or agent: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Show test markers if requested
if [ "$SHOW_MARKERS" = true ]; then
    print_header "Available Test Markers:"
    echo "  @pytest.mark.unit          - Unit tests"
    echo "  @pytest.mark.integration   - Integration tests"
    echo "  @pytest.mark.slow          - Slow tests"
    echo "  @pytest.mark.asyncio       - Async tests"
    echo "  @pytest.mark.llm           - LLM-related tests"
    exit 0
fi

print_header "==========================================="
print_header "    Sentinel AI Agent Test Suite"
print_header "==========================================="
echo ""

# Build pytest command
PYTEST_CMD="pytest"

# Determine which tests to run
if [ ${#AGENTS[@]} -eq 0 ]; then
    # Run all agent tests
    PYTEST_CMD="$PYTEST_CMD tests/unit/agents/"
    print_status "Running all AI agent tests..."
else
    # Run specific agent tests
    print_status "Running tests for: ${AGENTS[*]}"
    for agent in "${AGENTS[@]}"; do
        case $agent in
            base)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_base_agent.py"
                print_agent "BaseAgent"
                ;;
            data-mocking)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_data_mocking_agent.py"
                print_agent "DataMockingAgent"
                ;;
            negative)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_functional_negative_agent.py"
                print_agent "FunctionalNegativeAgent"
                ;;
            positive)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_functional_positive_agent.py"
                print_agent "FunctionalPositiveAgent"
                ;;
            stateful)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_functional_stateful_agent.py"
                print_agent "FunctionalStatefulAgent"
                ;;
            performance)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_performance_planner_agent.py"
                print_agent "PerformancePlannerAgent"
                ;;
            auth)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_security_auth_agent.py"
                print_agent "SecurityAuthAgent"
                ;;
            injection)
                PYTEST_CMD="$PYTEST_CMD tests/unit/agents/test_security_injection_agent.py"
                print_agent "SecurityInjectionAgent"
                ;;
        esac
    done
fi

# Add verbose flag
if [ "$VERBOSE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -v -s"
    print_status "Verbose mode enabled"
fi

# Add coverage options
if [ "$COVERAGE" = true ]; then
    PYTEST_CMD="$PYTEST_CMD --cov=orchestration_service/agents --cov-report=term-missing --cov-report=html:htmlcov/agents"
    print_status "Coverage reporting enabled"
fi

# Add parallel execution
if [ "$PARALLEL" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -n auto"
    print_status "Parallel execution enabled"
fi

# Add fail fast
if [ "$FAILFAST" = true ]; then
    PYTEST_CMD="$PYTEST_CMD -x"
    print_status "Fail-fast mode enabled"
fi

# Add other pytest options
PYTEST_CMD="$PYTEST_CMD --tb=short --color=yes"

# Create test reports directory
mkdir -p test_reports/agents
mkdir -p htmlcov/agents

echo ""
print_header "Test Configuration:"
echo "  Command: $PYTEST_CMD"
echo "  Coverage: $COVERAGE"
echo "  Verbose: $VERBOSE"
echo "  Parallel: $PARALLEL"
echo "  Fail Fast: $FAILFAST"
echo ""

# Run the tests
print_header "Executing Agent Tests..."
echo "-------------------------------------------"

if eval $PYTEST_CMD; then
    echo ""
    print_success "✅ All agent tests passed successfully!"
    
    if [ "$COVERAGE" = true ]; then
        echo ""
        print_header "Coverage Report:"
        echo "  HTML Report: htmlcov/agents/index.html"
        echo ""
        print_status "To view coverage report, run:"
        echo "    open htmlcov/agents/index.html"
    fi
    
    # Show test statistics
    echo ""
    print_header "Test Summary:"
    
    # Count test files and test functions
    total_files=$(ls tests/unit/agents/test_*.py 2>/dev/null | wc -l | tr -d ' ')
    total_tests=$(grep -h "def test_" tests/unit/agents/test_*.py 2>/dev/null | wc -l | tr -d ' ')
    
    echo "  Test Files: $total_files"
    echo "  Test Functions: ~$total_tests"
    echo ""
    print_success "Agent test suite execution completed!"
else
    echo ""
    print_error "❌ Some agent tests failed!"
    print_error "Please review the output above for details."
    exit 1
fi