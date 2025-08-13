#!/bin/bash

# Script to start Docker services with LLM support
# This script reads your SENTINEL_APP_ANTHROPIC_API_KEY from your environment

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Sentinel Platform with LLM Support${NC}"

# Check if API key is set in environment
if [ -z "$SENTINEL_APP_ANTHROPIC_API_KEY" ]; then
    echo -e "${YELLOW}Warning: SENTINEL_APP_ANTHROPIC_API_KEY not found in environment${NC}"
    echo "Please set it in your .zshrc or .bashrc:"
    echo "  export SENTINEL_APP_ANTHROPIC_API_KEY='your-api-key-here'"
    echo ""
    echo "Or run this command with the key:"
    echo "  SENTINEL_APP_ANTHROPIC_API_KEY='your-key' ./start-with-llm.sh"
    exit 1
fi

# Export the API key so Docker Compose can use it
export SENTINEL_APP_ANTHROPIC_API_KEY="$SENTINEL_APP_ANTHROPIC_API_KEY"

echo -e "${GREEN}✓ Anthropic API key found${NC}"

# Update .env.docker with the actual API key (temporary for this session)
# Create a temporary env file with the actual key
cp sentinel_backend/.env.docker sentinel_backend/.env.docker.tmp
sed -i '' "s|\${SENTINEL_APP_ANTHROPIC_API_KEY:-your-api-key-here}|$SENTINEL_APP_ANTHROPIC_API_KEY|" sentinel_backend/.env.docker.tmp

# Start Docker services with the temporary env file
echo -e "${GREEN}Starting Docker services...${NC}"
docker-compose --env-file sentinel_backend/.env.docker.tmp up -d --build

# Clean up temporary file
rm -f sentinel_backend/.env.docker.tmp

echo -e "${GREEN}✓ Services started successfully!${NC}"
echo ""
echo "You can now access:"
echo "  - Frontend: http://localhost:3000"
echo "  - API Gateway: http://localhost:8000"
echo "  - RabbitMQ: http://localhost:15672 (guest/guest)"
echo ""
echo -e "${GREEN}LLM Support is ENABLED with Anthropic Claude${NC}"