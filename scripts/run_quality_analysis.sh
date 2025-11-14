#!/bin/bash
# Quick Quality Analysis for Sentinel Platform using traditional tools
# This provides immediate value while lionagi-qe-fleet is being fixed

set -e

echo "================================================================================================"
echo "  🔍 SENTINEL PLATFORM QUALITY ANALYSIS"
echo "================================================================================================"
echo ""
echo "Using traditional proven tools for immediate insights"
echo ""

REPORT_DIR="/workspaces/api-testing-agents/docs/analysis/traditional_tools"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "================================================================================================"
echo "  📊 1. CODE COMPLEXITY ANALYSIS (Python)"
echo "================================================================================================"
echo ""

if command -v radon &> /dev/null; then
    echo "${GREEN}✓${NC} radon found, analyzing complexity..."
    radon cc sentinel_backend/ -a -nb --total-average > "$REPORT_DIR/complexity_${TIMESTAMP}.txt" 2>&1 || true
    radon mi sentinel_backend/ -s >> "$REPORT_DIR/complexity_${TIMESTAMP}.txt" 2>&1 || true
    echo "${GREEN}✓${NC} Results saved to: $REPORT_DIR/complexity_${TIMESTAMP}.txt"
    echo ""
    echo "Top 5 most complex functions:"
    radon cc sentinel_backend/ -nc | head -20 || true
else
    echo "${YELLOW}⚠${NC} radon not installed. Run: pip install radon"
fi

echo ""
echo "================================================================================================"
echo "  🔒 2. SECURITY ANALYSIS (Python)"
echo "================================================================================================"
echo ""

if command -v bandit &> /dev/null; then
    echo "${GREEN}✓${NC} bandit found, scanning for security issues..."
    bandit -r sentinel_backend/ -f json -o "$REPORT_DIR/security_${TIMESTAMP}.json" 2>&1 || true
    bandit -r sentinel_backend/ -f txt -o "$REPORT_DIR/security_${TIMESTAMP}.txt" 2>&1 || true
    echo "${GREEN}✓${NC} Results saved to: $REPORT_DIR/security_${TIMESTAMP}.json"
    echo ""
    echo "Security summary:"
    bandit -r sentinel_backend/ -f csv 2>&1 | head -10 || true
else
    echo "${YELLOW}⚠${NC} bandit not installed. Run: pip install bandit"
fi

echo ""
if command -v safety &> /dev/null; then
    echo "${GREEN}✓${NC} safety found, checking dependencies..."
    safety check --json > "$REPORT_DIR/dependencies_${TIMESTAMP}.json" 2>&1 || true
    safety check > "$REPORT_DIR/dependencies_${TIMESTAMP}.txt" 2>&1 || true
    echo "${GREEN}✓${NC} Results saved to: $REPORT_DIR/dependencies_${TIMESTAMP}.json"
else
    echo "${YELLOW}⚠${NC} safety not installed. Run: pip install safety"
fi

echo ""
echo "================================================================================================"
echo "  🧪 3. TEST COVERAGE ANALYSIS"
echo "================================================================================================"
echo ""

if [ -d "sentinel_backend" ]; then
    echo "${GREEN}✓${NC} Running pytest with coverage..."
    cd sentinel_backend
    pytest --cov=. --cov-report=html --cov-report=term --cov-report=json -v \
        --html="$REPORT_DIR/test_results_${TIMESTAMP}.html" \
        --self-contained-html 2>&1 | tee "$REPORT_DIR/test_output_${TIMESTAMP}.txt" || true

    if [ -f "coverage.json" ]; then
        cp coverage.json "$REPORT_DIR/coverage_${TIMESTAMP}.json"
        echo "${GREEN}✓${NC} Coverage report saved to: $REPORT_DIR/coverage_${TIMESTAMP}.json"
    fi

    cd ..
else
    echo "${YELLOW}⚠${NC} sentinel_backend directory not found"
fi

echo ""
echo "================================================================================================"
echo "  ✨ 4. CODE QUALITY METRICS"
echo "================================================================================================"
echo ""

if command -v pylint &> /dev/null; then
    echo "${GREEN}✓${NC} pylint found, analyzing code quality..."
    pylint sentinel_backend/ --max-line-length=120 --output-format=json > "$REPORT_DIR/pylint_${TIMESTAMP}.json" 2>&1 || true
    pylint sentinel_backend/ --max-line-length=120 > "$REPORT_DIR/pylint_${TIMESTAMP}.txt" 2>&1 || true
    echo "${GREEN}✓${NC} Results saved to: $REPORT_DIR/pylint_${TIMESTAMP}.json"
    echo ""
    echo "Quality summary:"
    pylint sentinel_backend/ --max-line-length=120 2>&1 | tail -20 || true
else
    echo "${YELLOW}⚠${NC} pylint not installed. Run: pip install pylint"
fi

echo ""
if command -v mypy &> /dev/null; then
    echo "${GREEN}✓${NC} mypy found, checking type hints..."
    mypy sentinel_backend/ --ignore-missing-imports > "$REPORT_DIR/mypy_${TIMESTAMP}.txt" 2>&1 || true
    echo "${GREEN}✓${NC} Results saved to: $REPORT_DIR/mypy_${TIMESTAMP}.txt"
else
    echo "${YELLOW}⚠${NC} mypy not installed. Run: pip install mypy"
fi

echo ""
echo "================================================================================================"
echo "  📈 5. LINES OF CODE ANALYSIS"
echo "================================================================================================"
echo ""

if command -v cloc &> /dev/null; then
    echo "${GREEN}✓${NC} cloc found, counting lines of code..."
    cloc sentinel_backend/ --json > "$REPORT_DIR/loc_${TIMESTAMP}.json" 2>&1 || true
    cloc sentinel_backend/ > "$REPORT_DIR/loc_${TIMESTAMP}.txt" 2>&1 || true
    echo "${GREEN}✓${NC} Results saved to: $REPORT_DIR/loc_${TIMESTAMP}.json"
    cloc sentinel_backend/ --by-file | head -30 || true
else
    echo "${YELLOW}⚠${NC} cloc not installed. Run: sudo apt-get install cloc"
    echo "Fallback to basic wc count:"
    find sentinel_backend/ -name "*.py" -exec wc -l {} + | sort -rn | head -20
fi

echo ""
echo "================================================================================================"
echo "  📊 ANALYSIS COMPLETE - SUMMARY"
echo "================================================================================================"
echo ""
echo "All reports saved to: $REPORT_DIR"
echo ""
echo "Generated files:"
ls -lh "$REPORT_DIR"/*${TIMESTAMP}* 2>/dev/null || echo "No files generated"
echo ""
echo "================================================================================================"
echo "  💡 NEXT STEPS"
echo "================================================================================================"
echo ""
echo "1. Review complexity report: $REPORT_DIR/complexity_${TIMESTAMP}.txt"
echo "2. Address security findings: $REPORT_DIR/security_${TIMESTAMP}.json"
echo "3. Improve coverage gaps: $REPORT_DIR/coverage_${TIMESTAMP}.json"
echo "4. Fix quality issues: $REPORT_DIR/pylint_${TIMESTAMP}.txt"
echo ""
echo "To install missing tools:"
echo "  pip install radon bandit safety pylint mypy pytest pytest-cov"
echo "  sudo apt-get install cloc"
echo ""
echo "================================================================================================"
