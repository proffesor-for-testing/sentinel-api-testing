#!/bin/bash
# Observability Stack Validation Script
# Tests Prometheus and Jaeger configuration and connectivity

set -e

echo "=================================================="
echo "Sentinel Observability Stack Validation"
echo "=================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
check_mark() {
    echo -e "${GREEN}✓${NC} $1"
}

cross_mark() {
    echo -e "${RED}✗${NC} $1"
}

warning_mark() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check if Docker is running
echo "1. Checking Docker..."
if ! docker info > /dev/null 2>&1; then
    cross_mark "Docker is not running"
    exit 1
fi
check_mark "Docker is running"
echo ""

# Check if Prometheus container exists
echo "2. Checking Prometheus container..."
if docker ps -a | grep -q sentinel_prometheus; then
    if docker ps | grep -q sentinel_prometheus; then
        check_mark "Prometheus container is running"
    else
        warning_mark "Prometheus container exists but is not running"
        echo "   Try: docker-compose up -d prometheus"
    fi
else
    warning_mark "Prometheus container does not exist"
    echo "   Run: docker-compose up -d prometheus"
fi
echo ""

# Check if Jaeger container exists
echo "3. Checking Jaeger container..."
if docker ps -a | grep -q sentinel_jaeger; then
    if docker ps | grep -q sentinel_jaeger; then
        check_mark "Jaeger container is running"
    else
        warning_mark "Jaeger container exists but is not running"
        echo "   Try: docker-compose up -d jaeger"
    fi
else
    warning_mark "Jaeger container does not exist"
    echo "   Run: docker-compose up -d jaeger"
fi
echo ""

# Check Prometheus accessibility
echo "4. Checking Prometheus accessibility..."
if curl -s http://localhost:9090/-/healthy > /dev/null 2>&1; then
    check_mark "Prometheus is accessible at http://localhost:9090"
else
    cross_mark "Cannot reach Prometheus at http://localhost:9090"
    echo "   Check container logs: docker logs sentinel_prometheus"
fi
echo ""

# Check Jaeger accessibility
echo "5. Checking Jaeger accessibility..."
if curl -s http://localhost:16686/ > /dev/null 2>&1; then
    check_mark "Jaeger UI is accessible at http://localhost:16686"
else
    cross_mark "Cannot reach Jaeger at http://localhost:16686"
    echo "   Check container logs: docker logs sentinel_jaeger"
fi
echo ""

# Check Prometheus configuration
echo "6. Validating Prometheus configuration..."
if [ -f "/workspaces/api-testing-agents/prometheus.yml" ]; then
    check_mark "prometheus.yml exists"
else
    cross_mark "prometheus.yml not found"
fi

if [ -f "/workspaces/api-testing-agents/sentinel_backend/observability/prometheus/alerts.yml" ]; then
    check_mark "alerts.yml exists"
else
    cross_mark "alerts.yml not found"
fi

if [ -f "/workspaces/api-testing-agents/sentinel_backend/observability/prometheus/recording_rules.yml" ]; then
    check_mark "recording_rules.yml exists"
else
    cross_mark "recording_rules.yml not found"
fi
echo ""

# Check Prometheus targets
echo "7. Checking Prometheus scrape targets..."
if curl -s http://localhost:9090/-/healthy > /dev/null 2>&1; then
    TARGETS=$(curl -s http://localhost:9090/api/v1/targets 2>/dev/null | grep -o '"job":"[^"]*"' | wc -l)
    if [ "$TARGETS" -gt 0 ]; then
        check_mark "Found $TARGETS configured targets"

        # Check specific services
        SERVICES=("api_gateway" "auth_service" "spec_service" "orchestration_service" "execution_service" "data_service" "sentinel_rust_core")
        for service in "${SERVICES[@]}"; do
            if curl -s "http://localhost:9090/api/v1/targets" | grep -q "\"job\":\"$service\""; then
                check_mark "  - $service configured"
            else
                warning_mark "  - $service not configured"
            fi
        done
    else
        warning_mark "No targets configured yet"
    fi
else
    warning_mark "Prometheus not running, cannot check targets"
fi
echo ""

# Check if services expose metrics
echo "8. Checking service metrics endpoints..."
PORTS=(8000 8001 8002 8003 8004 8005 8088)
SERVICES=("api_gateway" "spec_service" "orchestration_service" "execution_service" "data_service" "auth_service" "rust_core")

for i in "${!PORTS[@]}"; do
    PORT="${PORTS[$i]}"
    SERVICE="${SERVICES[$i]}"

    if curl -s "http://localhost:$PORT/metrics" > /dev/null 2>&1; then
        METRIC_COUNT=$(curl -s "http://localhost:$PORT/metrics" | grep -c "^[a-z]" || true)
        check_mark "  - $SERVICE (port $PORT): $METRIC_COUNT metrics"
    else
        warning_mark "  - $SERVICE (port $PORT): not accessible"
    fi
done
echo ""

# Check custom metrics middleware
echo "9. Checking custom metrics middleware..."
if [ -f "/workspaces/api-testing-agents/sentinel_backend/observability/middleware/metrics.py" ]; then
    METRICS=$(grep -c "^[a-z_]*_[a-z_]* = " /workspaces/api-testing-agents/sentinel_backend/observability/middleware/metrics.py || true)
    check_mark "Custom metrics middleware exists ($METRICS metrics defined)"
else
    cross_mark "Custom metrics middleware not found"
fi
echo ""

# Check enhanced tracing config
echo "10. Checking enhanced tracing configuration..."
if [ -f "/workspaces/api-testing-agents/sentinel_backend/config/enhanced_tracing_config.py" ]; then
    check_mark "Enhanced tracing configuration exists"
else
    cross_mark "Enhanced tracing configuration not found"
fi
echo ""

# Check documentation
echo "11. Checking documentation..."
DOCS=(
    "/workspaces/api-testing-agents/sentinel_backend/observability/README.md"
    "/workspaces/api-testing-agents/sentinel_backend/observability/docs/QUICK_START.md"
    "/workspaces/api-testing-agents/sentinel_backend/observability/docs/OBSERVABILITY_GUIDE.md"
    "/workspaces/api-testing-agents/sentinel_backend/observability/docs/METRICS_CATALOG.md"
    "/workspaces/api-testing-agents/sentinel_backend/observability/docs/IMPLEMENTATION_SUMMARY.md"
)

for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        check_mark "  - $(basename $doc)"
    else
        cross_mark "  - $(basename $doc) missing"
    fi
done
echo ""

# Summary
echo "=================================================="
echo "Summary"
echo "=================================================="
echo ""
echo "Prometheus: http://localhost:9090"
echo "Jaeger UI:  http://localhost:16686"
echo ""
echo "Quick commands:"
echo "  - Start services:    docker-compose up -d prometheus jaeger"
echo "  - Check logs:        docker logs sentinel_prometheus"
echo "  - View targets:      curl http://localhost:9090/api/v1/targets"
echo "  - Test metrics:      curl http://localhost:8000/metrics"
echo ""
echo "Documentation:"
echo "  - Quick Start:       sentinel_backend/observability/docs/QUICK_START.md"
echo "  - Full Guide:        sentinel_backend/observability/docs/OBSERVABILITY_GUIDE.md"
echo "  - Metrics Catalog:   sentinel_backend/observability/docs/METRICS_CATALOG.md"
echo ""
echo "=================================================="
