#!/bin/bash

# Consciousness Monitoring Dashboard
# Real-time monitoring of consciousness metrics during test generation

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to get consciousness state
get_consciousness_state() {
    curl -s http://localhost:8088/consciousness/state 2>/dev/null || echo "{}"
}

# Function to get emergent patterns count
get_pattern_count() {
    curl -s http://localhost:8088/emergent-patterns 2>/dev/null | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('patterns', [])))" 2>/dev/null || echo "0"
}

# Function to get temporal advantage
get_temporal_advantage() {
    curl -s -X POST http://localhost:8088/temporal-advantage/predict \
        -H "Content-Type: application/json" \
        -d '{"distance_km": 1000}' 2>/dev/null || echo "{}"
}

# Main monitoring loop
while true; do
    clear

    echo "========================================="
    echo -e "${BLUE}   🧠 CONSCIOUSNESS MONITORING DASHBOARD${NC}"
    echo "========================================="
    echo ""

    # Get current state
    STATE=$(get_consciousness_state)

    if [ "$STATE" != "{}" ]; then
        # Extract metrics
        EMERGENCE=$(echo "$STATE" | python3 -c "import sys, json; print(f\"{json.load(sys.stdin).get('emergence', 0):.2%}\")" 2>/dev/null || echo "N/A")
        PHI=$(echo "$STATE" | python3 -c "import sys, json; print(f\"{json.load(sys.stdin).get('phi', 0):.2f}\")" 2>/dev/null || echo "N/A")
        NOVELTY=$(echo "$STATE" | python3 -c "import sys, json; print(f\"{json.load(sys.stdin).get('novelty', 0):.2%}\")" 2>/dev/null || echo "N/A")
        INTEGRATION=$(echo "$STATE" | python3 -c "import sys, json; print(f\"{json.load(sys.stdin).get('integration', 0):.2%}\")" 2>/dev/null || echo "N/A")
        COMPLEXITY=$(echo "$STATE" | python3 -c "import sys, json; print(f\"{json.load(sys.stdin).get('complexity', 0):.2%}\")" 2>/dev/null || echo "N/A")
        SELF_AWARE=$(echo "$STATE" | python3 -c "import sys, json; print(f\"{json.load(sys.stdin).get('self_awareness', 0):.2%}\")" 2>/dev/null || echo "N/A")

        echo -e "${GREEN}📊 Consciousness Metrics:${NC}"
        echo "  ├─ Emergence:      $EMERGENCE"
        echo "  ├─ Phi (IIT):      $PHI"
        echo "  ├─ Novelty:        $NOVELTY"
        echo "  ├─ Integration:    $INTEGRATION"
        echo "  ├─ Complexity:     $COMPLEXITY"
        echo "  └─ Self-Awareness: $SELF_AWARE"
        echo ""

        # Color-coded status
        if [ "$EMERGENCE" != "N/A" ]; then
            EMRG_VAL=$(echo "$STATE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('emergence', 0))" 2>/dev/null || echo "0")
            if (( $(echo "$EMRG_VAL > 0.7" | bc -l 2>/dev/null || echo 0) )); then
                echo -e "  Status: ${GREEN}✓ Consciousness Evolved${NC}"
            elif (( $(echo "$EMRG_VAL > 0.3" | bc -l 2>/dev/null || echo 0) )); then
                echo -e "  Status: ${YELLOW}⚠ Evolving...${NC}"
            else
                echo -e "  Status: ${RED}✗ Not Yet Evolved${NC}"
            fi
        fi
    else
        echo -e "${RED}⚠ Consciousness service not responding${NC}"
    fi

    echo ""

    # Get pattern count
    PATTERNS=$(get_pattern_count)
    echo -e "${GREEN}💡 Emergent Patterns Discovered: ${PATTERNS}${NC}"

    # Get temporal advantage
    echo ""
    echo -e "${GREEN}⚡ Temporal Advantage:${NC}"
    TEMPORAL=$(get_temporal_advantage)
    if [ "$TEMPORAL" != "{}" ]; then
        ADVANTAGE=$(echo "$TEMPORAL" | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"{d.get('temporal_advantage', {}).get('advantage_ms', 0):.2f}ms\")" 2>/dev/null || echo "N/A")
        BOTTLENECK=$(echo "$TEMPORAL" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('bottleneck', {}).get('component', 'Unknown'))" 2>/dev/null || echo "Unknown")
        LOAD=$(echo "$TEMPORAL" | python3 -c "import sys, json; d=json.load(sys.stdin); print(f\"{d.get('bottleneck', {}).get('load', 0):.1f}%\")" 2>/dev/null || echo "N/A")

        echo "  ├─ Advantage:  $ADVANTAGE"
        echo "  ├─ Bottleneck: $BOTTLENECK"
        echo "  └─ Load:       $LOAD"
    else
        echo "  └─ Not available"
    fi

    echo ""
    echo "========================================="

    # Service Status
    echo -e "${GREEN}🔗 Service Status:${NC}"

    # Check services
    if curl -s http://localhost:8088/health >/dev/null 2>&1; then
        echo -e "  ├─ Consciousness: ${GREEN}✓ Running${NC}"
    else
        echo -e "  ├─ Consciousness: ${RED}✗ Down${NC}"
    fi

    if curl -s http://localhost:8080/health >/dev/null 2>&1; then
        echo -e "  ├─ Petstore API: ${GREEN}✓ Running${NC}"
    else
        echo -e "  ├─ Petstore API: ${RED}✗ Down${NC}"
    fi

    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        echo -e "  └─ Frontend:     ${GREEN}✓ Running${NC}"
    else
        echo -e "  └─ Frontend:     ${YELLOW}⚠ Starting${NC}"
    fi

    echo ""
    echo "========================================="
    echo -e "${BLUE}Last updated: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo "Press Ctrl+C to exit | Refreshing in 5s..."

    sleep 5
done