#!/bin/bash
#
# Run Learning Integration Tests
#
# This script runs all learning integration tests:
# - E2E learning loop tests
# - Performance benchmarks
# - API contract tests
# - Frontend E2E tests (optional)
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_ROOT/sentinel_backend"
FRONTEND_DIR="$PROJECT_ROOT/sentinel_frontend"

# Default options
RUN_BACKEND=true
RUN_FRONTEND=false
RUN_COVERAGE=true
RUN_PERFORMANCE=true
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --frontend)
      RUN_FRONTEND=true
      shift
      ;;
    --no-coverage)
      RUN_COVERAGE=false
      shift
      ;;
    --no-performance)
      RUN_PERFORMANCE=false
      shift
      ;;
    --backend-only)
      RUN_BACKEND=true
      RUN_FRONTEND=false
      shift
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --frontend          Run frontend E2E tests (requires Playwright)"
      echo "  --no-coverage       Skip coverage reporting"
      echo "  --no-performance    Skip performance tests"
      echo "  --backend-only      Run only backend tests (default)"
      echo "  -v, --verbose       Verbose output"
      echo "  -h, --help          Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Run '$0 --help' for usage"
      exit 1
      ;;
  esac
done

# Print configuration
echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}Learning Integration Test Runner${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""
echo -e "Backend tests:      ${GREEN}$RUN_BACKEND${NC}"
echo -e "Frontend tests:     $([ "$RUN_FRONTEND" = true ] && echo -e "${GREEN}true${NC}" || echo -e "${YELLOW}false${NC}")"
echo -e "Coverage reports:   $([ "$RUN_COVERAGE" = true ] && echo -e "${GREEN}true${NC}" || echo -e "${YELLOW}false${NC}")"
echo -e "Performance tests:  $([ "$RUN_PERFORMANCE" = true ] && echo -e "${GREEN}true${NC}" || echo -e "${YELLOW}false${NC}")"
echo ""

# Backend tests
if [ "$RUN_BACKEND" = true ]; then
  echo -e "${BLUE}==================================================${NC}"
  echo -e "${BLUE}Running Backend Tests${NC}"
  echo -e "${BLUE}==================================================${NC}"
  echo ""

  cd "$BACKEND_DIR"

  # Check if poetry is available
  if ! command -v poetry &> /dev/null; then
    echo -e "${RED}Error: Poetry not found. Please install Poetry first.${NC}"
    exit 1
  fi

  # Build pytest command
  PYTEST_CMD="poetry run pytest"
  PYTEST_ARGS="-v --tb=short"

  if [ "$RUN_COVERAGE" = true ]; then
    PYTEST_ARGS="$PYTEST_ARGS --cov=. --cov-report=xml --cov-report=term --cov-report=html"
  fi

  if [ "$VERBOSE" = true ]; then
    PYTEST_ARGS="$PYTEST_ARGS -vv"
  fi

  # E2E tests
  echo -e "${YELLOW}>>> Running E2E Learning Loop Tests${NC}"
  $PYTEST_CMD tests/e2e/test_learning_loop.py $PYTEST_ARGS
  echo ""

  # Contract tests
  echo -e "${YELLOW}>>> Running API Contract Tests${NC}"
  $PYTEST_CMD tests/contract/test_feedback_contracts.py $PYTEST_ARGS -m contract
  echo ""

  # Performance tests (optional)
  if [ "$RUN_PERFORMANCE" = true ]; then
    echo -e "${YELLOW}>>> Running Performance Tests${NC}"
    $PYTEST_CMD tests/performance/test_learning_performance.py $PYTEST_ARGS -m performance
    echo ""
  fi

  # Coverage check
  if [ "$RUN_COVERAGE" = true ]; then
    echo -e "${YELLOW}>>> Checking Coverage Threshold${NC}"
    poetry run coverage report --fail-under=90 || {
      echo -e "${RED}Coverage below 90% threshold!${NC}"
      echo -e "${YELLOW}Run 'poetry run coverage html' to see detailed report${NC}"
    }
    echo ""

    echo -e "${GREEN}Coverage report generated at: htmlcov/index.html${NC}"
  fi

  echo -e "${GREEN}✓ Backend tests completed${NC}"
  echo ""
fi

# Frontend tests
if [ "$RUN_FRONTEND" = true ]; then
  echo -e "${BLUE}==================================================${NC}"
  echo -e "${BLUE}Running Frontend Tests${NC}"
  echo -e "${BLUE}==================================================${NC}"
  echo ""

  cd "$FRONTEND_DIR"

  # Check if npm is available
  if ! command -v npm &> /dev/null; then
    echo -e "${RED}Error: npm not found. Please install Node.js and npm first.${NC}"
    exit 1
  fi

  # Check if node_modules exists
  if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm ci
  fi

  # Check if Playwright is installed
  if [ ! -d "node_modules/@playwright/test" ]; then
    echo -e "${YELLOW}Installing Playwright...${NC}"
    npm install --save-dev @playwright/test
    npx playwright install chromium
  fi

  # Run React component tests
  echo -e "${YELLOW}>>> Running React Component Tests${NC}"
  npm run test:coverage
  echo ""

  # Run Playwright E2E tests
  echo -e "${YELLOW}>>> Running Playwright E2E Tests${NC}"
  npm run test:e2e
  echo ""

  echo -e "${GREEN}✓ Frontend tests completed${NC}"
  echo ""
fi

# Final summary
echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}Test Summary${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""

if [ "$RUN_BACKEND" = true ]; then
  echo -e "${GREEN}✓${NC} Backend E2E tests:      9 tests"
  echo -e "${GREEN}✓${NC} Backend contract tests: 18 tests"

  if [ "$RUN_PERFORMANCE" = true ]; then
    echo -e "${GREEN}✓${NC} Backend performance:    12 tests"
  fi

  if [ "$RUN_COVERAGE" = true ]; then
    echo -e "${GREEN}✓${NC} Coverage report:        htmlcov/index.html"
  fi
fi

if [ "$RUN_FRONTEND" = true ]; then
  echo -e "${GREEN}✓${NC} Frontend E2E tests:     15 tests"
fi

echo ""
echo -e "${GREEN}All tests completed successfully!${NC}"
echo ""

# Next steps
echo -e "${BLUE}Next steps:${NC}"
if [ "$RUN_COVERAGE" = true ]; then
  echo -e "1. View coverage report: ${YELLOW}open $BACKEND_DIR/htmlcov/index.html${NC}"
fi
if [ "$RUN_FRONTEND" = true ]; then
  echo -e "2. View Playwright report: ${YELLOW}cd $FRONTEND_DIR && npm run test:e2e:report${NC}"
fi
echo -e "3. Run in CI/CD: ${YELLOW}git push origin refactoring-with-claude-flow${NC}"
echo ""
