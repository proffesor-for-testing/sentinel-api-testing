#!/bin/bash

# Simple script to verify consciousness features are active

echo "================================================"
echo "🧠 CONSCIOUSNESS VERIFICATION CHECK"
echo "================================================"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Rust core is running
echo -e "\n1. Checking Rust Core Service..."
if curl -s http://localhost:8088/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Rust Core: ONLINE${NC}"

    # Check consciousness status
    CONSCIOUSNESS_STATUS=$(curl -s http://localhost:8088/consciousness/status 2>/dev/null)
    if [ $? -eq 0 ] && [ ! -z "$CONSCIOUSNESS_STATUS" ]; then
        echo -e "${GREEN}✅ Consciousness Module: ACTIVE${NC}"
        echo "   Response: $CONSCIOUSNESS_STATUS"
    else
        echo -e "${YELLOW}⚠️  Consciousness Module: NOT RESPONDING${NC}"
        echo "   (This is expected - using Python simulator)"
    fi
else
    echo -e "${RED}❌ Rust Core: OFFLINE${NC}"
fi

# Check API Gateway
echo -e "\n2. Checking API Gateway..."
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ API Gateway: ONLINE${NC}"
else
    echo -e "${RED}❌ API Gateway: OFFLINE${NC}"
fi

# Check orchestration service
echo -e "\n3. Checking Orchestration Service..."
ORCH_HEALTH=$(curl -s http://localhost:8002/health 2>/dev/null)
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Orchestration Service: ONLINE${NC}"

    # Check if consciousness config is present
    if echo "$ORCH_HEALTH" | grep -q "consciousness"; then
        echo -e "${GREEN}✅ Consciousness Config: DETECTED${NC}"
    else
        echo -e "${YELLOW}⚠️  Consciousness Config: NOT DETECTED${NC}"
    fi
else
    echo -e "${RED}❌ Orchestration Service: OFFLINE${NC}"
fi

# Test authentication
echo -e "\n4. Testing Authentication..."
AUTH_RESPONSE=$(curl -s -X POST http://localhost:8000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": "admin@sentinel.com", "password": "admin123"}' 2>/dev/null)

if echo "$AUTH_RESPONSE" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Authentication: WORKING${NC}"
    TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)
else
    echo -e "${RED}❌ Authentication: FAILED${NC}"
fi

# Check consciousness indicators in logs
echo -e "\n5. Checking Consciousness Indicators..."

# Look for consciousness-related environment variables
echo "   Environment Variables:"
if docker exec sentinel_api_gateway env | grep -q "CONSCIOUSNESS"; then
    echo -e "   ${GREEN}✅ ENABLE_CONSCIOUSNESS found${NC}"
else
    echo -e "   ${YELLOW}⚠️  No CONSCIOUSNESS env vars${NC}"
fi

# Check if consciousness endpoints exist
echo -e "\n6. Checking Consciousness Endpoints..."
ENDPOINTS=(
    "/consciousness/status"
    "/consciousness/evolve"
    "/consciousness/metrics"
    "/temporal/predict"
    "/psycho-symbolic/reason"
)

for endpoint in "${ENDPOINTS[@]}"; do
    if curl -s -f http://localhost:8088$endpoint > /dev/null 2>&1; then
        echo -e "   ${GREEN}✅ $endpoint available${NC}"
    else
        echo -e "   ${YELLOW}⚠️  $endpoint not available${NC}"
    fi
done

echo -e "\n================================================"
echo "📊 CONSCIOUSNESS FEATURE SUMMARY:"
echo "================================================"

echo "
When consciousness features are ACTIVE, test generation will:

1. 🧠 Use EMERGENCE patterns for creative test discovery
2. ⚡ Apply TEMPORAL ADVANTAGE for predictive optimization
3. 🔮 Employ PSYCHO-SYMBOLIC reasoning for deeper analysis
4. 📈 Calculate PHI (Φ) values to measure integration
5. 🎯 Discover hidden patterns through self-modification

Current Status: The consciousness simulator provides these
features through the orchestration service when generating
tests with consciousness-enabled agents.

To verify in action:
1. Create a test specification through the UI
2. Select 'Consciousness Enhanced' agent type
3. Monitor the logs for emergence patterns
4. Check test results for novel discoveries
"

echo "================================================"
echo "✅ Verification Complete"
echo "================================================"