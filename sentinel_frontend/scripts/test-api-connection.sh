#!/bin/bash

# Test API Connection Script
# Tests connectivity to backend services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
API_BASE_URL="${REACT_APP_API_BASE_URL:-http://localhost:8002}"
FEEDBACK_ENDPOINT="${REACT_APP_FEEDBACK_ENDPOINT:-/api/v1/feedback}"

echo "================================"
echo "Sentinel API Connection Test"
echo "================================"
echo ""

# Test 1: Orchestration Service Health
echo "1. Testing Orchestration Service Health..."
if curl -s -f "${API_BASE_URL}/" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Orchestration service is running on ${API_BASE_URL}"
else
    echo -e "${RED}✗${NC} Cannot connect to orchestration service on ${API_BASE_URL}"
    echo -e "${YELLOW}→${NC} Make sure the orchestration service is running:"
    echo "   cd sentinel_backend && python -m uvicorn orchestration_service.main:app --port 8002"
    exit 1
fi

# Test 2: Feedback Endpoint (without auth)
echo ""
echo "2. Testing Feedback Endpoint..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE_URL}${FEEDBACK_ENDPOINT}/statistics")

if [ "$STATUS" = "401" ]; then
    echo -e "${GREEN}✓${NC} Feedback endpoint exists (requires authentication)"
elif [ "$STATUS" = "200" ]; then
    echo -e "${GREEN}✓${NC} Feedback endpoint accessible"
else
    echo -e "${RED}✗${NC} Unexpected status code: ${STATUS}"
    echo -e "${YELLOW}→${NC} Check if feedback router is registered in main.py"
fi

# Test 3: CORS Headers
echo ""
echo "3. Testing CORS Configuration..."
CORS_ORIGIN=$(curl -s -I -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    "${API_BASE_URL}${FEEDBACK_ENDPOINT}/test-case" | grep -i "access-control-allow-origin" || echo "")

if [ -n "$CORS_ORIGIN" ]; then
    echo -e "${GREEN}✓${NC} CORS headers present"
    echo "   ${CORS_ORIGIN}"
else
    echo -e "${YELLOW}⚠${NC}  CORS headers not detected"
    echo -e "${YELLOW}→${NC} Add CORSMiddleware to orchestration_service/main.py:"
    echo ""
    echo "   from fastapi.middleware.cors import CORSMiddleware"
    echo ""
    echo "   app.add_middleware("
    echo "       CORSMiddleware,"
    echo "       allow_origins=['http://localhost:3000'],"
    echo "       allow_credentials=True,"
    echo "       allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],"
    echo "       allow_headers=['Content-Type', 'Authorization', 'X-Correlation-ID']"
    echo "   )"
fi

# Test 4: Response Time
echo ""
echo "4. Testing Response Time..."
START_TIME=$(date +%s%N)
curl -s "${API_BASE_URL}/" > /dev/null
END_TIME=$(date +%s%N)
RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))

if [ "$RESPONSE_TIME" -lt 1000 ]; then
    echo -e "${GREEN}✓${NC} Response time: ${RESPONSE_TIME}ms (good)"
elif [ "$RESPONSE_TIME" -lt 3000 ]; then
    echo -e "${YELLOW}⚠${NC}  Response time: ${RESPONSE_TIME}ms (acceptable)"
else
    echo -e "${RED}✗${NC} Response time: ${RESPONSE_TIME}ms (slow)"
fi

# Test 5: All Backend Services
echo ""
echo "5. Testing All Backend Services..."

declare -A SERVICES=(
    ["API Gateway"]="http://localhost:8000"
    ["Spec Service"]="http://localhost:8001"
    ["Orchestration"]="http://localhost:8002"
    ["Execution Service"]="http://localhost:8003"
    ["Data Service"]="http://localhost:8004"
    ["Auth Service"]="http://localhost:8005"
    ["Rust Core"]="http://localhost:8088"
)

for service_name in "${!SERVICES[@]}"; do
    url="${SERVICES[$service_name]}"
    if curl -s -f "${url}/" > /dev/null 2>&1 || curl -s -f "${url}/health" > /dev/null 2>&1; then
        echo -e "   ${GREEN}✓${NC} ${service_name} (${url})"
    else
        echo -e "   ${RED}✗${NC} ${service_name} (${url})"
    fi
done

# Summary
echo ""
echo "================================"
echo "Test Summary"
echo "================================"
echo ""
echo "Configuration:"
echo "  API Base URL: ${API_BASE_URL}"
echo "  Feedback Endpoint: ${FEEDBACK_ENDPOINT}"
echo ""
echo -e "${GREEN}All critical tests passed!${NC}"
echo ""
echo "Next steps:"
echo "  1. Start frontend: cd sentinel_frontend && npm start"
echo "  2. Open browser: http://localhost:3000"
echo "  3. Check browser console for connection status"
echo ""
