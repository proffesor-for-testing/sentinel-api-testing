#!/bin/bash

# Sentinel LLM Provider Test Runner Script
# This script runs comprehensive tests for all LLM provider implementations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
LLM_TEST_DIR="tests/unit/llm_providers"
COVERAGE_REPORT="htmlcov"
MIN_COVERAGE_PERCENT=80

# Statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Test categories
declare -a PROVIDER_TESTS=(
    "google"
    "mistral"
    "ollama"
    "vllm"
    "factory"
)

declare -a UTILITY_TESTS=(
    "model_registry"
    "cost_tracker"
    "response_cache"
    "token_counter"
)

# Function to print colored output
print_header() {
    echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}   $1${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"
}

print_section() {
    echo -e "\n${BOLD}${BLUE}──────────────────────────────────────────────────────────────${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}──────────────────────────────────────────────────────────────${NC}\n"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_test_result() {
    local test_name=$1
    local status=$2
    local count=$3
    
    if [ "$status" = "PASSED" ]; then
        echo -e "  ${GREEN}✓${NC} ${test_name} ${GREEN}(${count} tests)${NC}"
    elif [ "$status" = "FAILED" ]; then
        echo -e "  ${RED}✗${NC} ${test_name} ${RED}(failures detected)${NC}"
    else
        echo -e "  ${YELLOW}⚠${NC} ${test_name} ${YELLOW}(skipped)${NC}"
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [PROVIDER_OR_UTILITY]"
    echo ""
    echo "Run tests for LLM provider implementations and utilities"
    echo ""
    echo "Arguments:"
    echo "  PROVIDER_OR_UTILITY   Specific provider or utility to test:"
    echo "                        Providers: google, mistral, ollama, vllm, factory"
    echo "                        Utilities: registry, cost, cache, token"
    echo "                        Categories: providers, utilities"
    echo "                        Default: all tests"
    echo ""
    echo "Options:"
    echo "  -c, --coverage        Generate coverage report (default)"
    echo "  -n, --no-coverage     Skip coverage report"
    echo "  -v, --verbose         Verbose output"
    echo "  -q, --quiet           Minimal output"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all LLM provider tests"
    echo "  $0 google             # Run Google provider tests only"
    echo "  $0 providers          # Run all provider tests"
    echo "  $0 utilities          # Run all utility tests"
    echo "  $0 -v                 # Run all tests with verbose output"
    echo "  $0 cache token        # Run cache and token counter tests"
}

# Parse command line arguments
COVERAGE=true
VERBOSE=false
QUIET=false
SPECIFIC_TESTS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -n|--no-coverage)
            COVERAGE=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quiet)
            QUIET=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        providers)
            SPECIFIC_TESTS+=("providers")
            shift
            ;;
        utilities)
            SPECIFIC_TESTS+=("utilities")
            shift
            ;;
        google|mistral|ollama|vllm|factory)
            SPECIFIC_TESTS+=("$1")
            shift
            ;;
        registry|cost|cache|token)
            SPECIFIC_TESTS+=("$1")
            shift
            ;;
        *)
            print_error "Unknown option or test: $1"
            show_usage
            exit 1
            ;;
    esac
done

# If no specific tests requested, run all
if [ ${#SPECIFIC_TESTS[@]} -eq 0 ]; then
    SPECIFIC_TESTS=("all")
fi

# Function to run a specific test file
run_test_file() {
    local test_file=$1
    local test_name=$2
    
    if [ ! -f "$LLM_TEST_DIR/$test_file" ]; then
        print_warning "Test file not found: $test_file"
        return 1
    fi
    
    local pytest_cmd="pytest $LLM_TEST_DIR/$test_file"
    
    if [ "$VERBOSE" = true ]; then
        pytest_cmd="$pytest_cmd -v"
    elif [ "$QUIET" = true ]; then
        pytest_cmd="$pytest_cmd -q"
    fi
    
    if [ "$COVERAGE" = true ]; then
        pytest_cmd="$pytest_cmd --cov=llm_providers --cov-append"
    fi
    
    # Add other options
    pytest_cmd="$pytest_cmd --tb=short --color=yes"
    
    if [ "$QUIET" != true ]; then
        print_status "Running $test_name tests..."
    fi
    
    # Run the test and capture output
    if eval $pytest_cmd 2>&1 | tee /tmp/llm_test_output.txt; then
        # Extract test counts
        local passed=$(grep -E "([0-9]+) passed" /tmp/llm_test_output.txt | grep -oE "[0-9]+ passed" | grep -oE "[0-9]+")
        local failed=$(grep -E "([0-9]+) failed" /tmp/llm_test_output.txt | grep -oE "[0-9]+ failed" | grep -oE "[0-9]+")
        
        passed=${passed:-0}
        failed=${failed:-0}
        
        PASSED_TESTS=$((PASSED_TESTS + passed))
        if [ "$failed" -gt 0 ]; then
            FAILED_TESTS=$((FAILED_TESTS + failed))
            print_test_result "$test_name" "FAILED" "$failed"
            return 1
        else
            print_test_result "$test_name" "PASSED" "$passed"
            return 0
        fi
    else
        print_test_result "$test_name" "FAILED" "?"
        return 1
    fi
}

# Function to run provider tests
run_provider_tests() {
    print_section "Provider Implementation Tests"
    
    local providers_to_test=()
    
    # Determine which providers to test
    for test in "${SPECIFIC_TESTS[@]}"; do
        case $test in
            all|providers)
                providers_to_test=("${PROVIDER_TESTS[@]}")
                break
                ;;
            google|mistral|ollama|vllm|factory)
                providers_to_test+=("$test")
                ;;
        esac
    done
    
    # Run provider tests
    for provider in "${providers_to_test[@]}"; do
        case $provider in
            google)
                run_test_file "test_google_provider.py" "Google Gemini Provider"
                ;;
            mistral)
                run_test_file "test_mistral_provider.py" "Mistral AI Provider"
                ;;
            ollama)
                run_test_file "test_ollama_provider.py" "Ollama Local Provider"
                ;;
            vllm)
                run_test_file "test_vllm_provider.py" "vLLM Provider"
                ;;
            factory)
                run_test_file "test_provider_factory.py" "Provider Factory"
                ;;
        esac
    done
}

# Function to run utility tests
run_utility_tests() {
    print_section "Utility Component Tests"
    
    local utilities_to_test=()
    
    # Determine which utilities to test
    for test in "${SPECIFIC_TESTS[@]}"; do
        case $test in
            all|utilities)
                utilities_to_test=("${UTILITY_TESTS[@]}")
                break
                ;;
            registry|cost|cache|token)
                utilities_to_test+=("$test")
                ;;
        esac
    done
    
    # Run utility tests
    for utility in "${utilities_to_test[@]}"; do
        case $utility in
            model_registry|registry)
                run_test_file "test_model_registry.py" "Model Registry"
                ;;
            cost_tracker|cost)
                run_test_file "test_cost_tracker.py" "Cost Tracker"
                ;;
            response_cache|cache)
                run_test_file "test_response_cache.py" "Response Cache"
                ;;
            token_counter|token)
                run_test_file "test_token_counter.py" "Token Counter"
                ;;
        esac
    done
}

# Function to generate coverage report
generate_coverage_report() {
    if [ "$COVERAGE" = true ]; then
        print_section "Coverage Report"
        
        # Generate HTML coverage report
        coverage html --directory=$COVERAGE_REPORT 2>/dev/null || true
        
        # Display coverage summary
        coverage report --include="llm_providers/*" 2>/dev/null || true
        
        print_success "Coverage report generated at: $COVERAGE_REPORT/index.html"
    fi
}

# Function to display summary
display_summary() {
    print_header "Test Summary"
    
    TOTAL_TESTS=$((PASSED_TESTS + FAILED_TESTS + SKIPPED_TESTS))
    
    echo -e "${BOLD}Total Tests Run:${NC} $TOTAL_TESTS"
    echo -e "${GREEN}${BOLD}Passed:${NC} ${GREEN}$PASSED_TESTS${NC}"
    if [ $FAILED_TESTS -gt 0 ]; then
        echo -e "${RED}${BOLD}Failed:${NC} ${RED}$FAILED_TESTS${NC}"
    fi
    if [ $SKIPPED_TESTS -gt 0 ]; then
        echo -e "${YELLOW}${BOLD}Skipped:${NC} ${YELLOW}$SKIPPED_TESTS${NC}"
    fi
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}✓ All LLM provider tests passed successfully!${NC}"
    else
        echo -e "\n${RED}${BOLD}✗ Some tests failed. Please review the output above.${NC}"
    fi
}

# Main execution
main() {
    print_header "Sentinel LLM Provider Test Suite"
    
    # Set up Python path
    export PYTHONPATH=$(pwd):$PYTHONPATH
    
    # Clean previous coverage data
    if [ "$COVERAGE" = true ]; then
        rm -f .coverage* 2>/dev/null || true
    fi
    
    # Check if specific tests were requested
    local run_providers=false
    local run_utilities=false
    
    for test in "${SPECIFIC_TESTS[@]}"; do
        case $test in
            all)
                run_providers=true
                run_utilities=true
                break
                ;;
            providers|google|mistral|ollama|vllm|factory)
                run_providers=true
                ;;
            utilities|registry|cost|cache|token)
                run_utilities=true
                ;;
        esac
    done
    
    # Run requested tests
    if [ "$run_providers" = true ]; then
        run_provider_tests
    fi
    
    if [ "$run_utilities" = true ]; then
        run_utility_tests
    fi
    
    # Generate coverage report
    generate_coverage_report
    
    # Display summary
    display_summary
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main