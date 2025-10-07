#!/bin/bash
# Test LLM Enhancement via API

echo "=================================================================================================="
echo "🧪 TESTING LLM-ENHANCED TEST GENERATION"
echo "=================================================================================================="

# Sample OpenAPI spec for Pet Store
SPEC_DATA=$(cat <<'EOF'
{
  "openapi": "3.0.0",
  "info": {
    "title": "Pet Store API",
    "version": "1.0.0"
  },
  "paths": {
    "/pets": {
      "get": {
        "summary": "List all pets",
        "operationId": "listPets",
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "description": "How many items to return",
            "required": false,
            "schema": {
              "type": "integer",
              "format": "int32"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "A list of pets"
          }
        }
      },
      "post": {
        "summary": "Create a pet",
        "operationId": "createPet",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                  "name": {"type": "string"},
                  "tag": {"type": "string"}
                }
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Pet created"
          }
        }
      }
    }
  }
}
EOF
)

echo ""
echo "📋 Step 1: Uploading API Specification..."
echo ""

SPEC_RESPONSE=$(curl -s -X POST http://localhost:8002/specs \
  -H "Content-Type: application/json" \
  -d "{\"spec_name\": \"Pet Store LLM Test\", \"spec_content\": $SPEC_DATA}")

echo "Response: $SPEC_RESPONSE"

SPEC_ID=$(echo $SPEC_RESPONSE | grep -o '"spec_id":[0-9]*' | grep -o '[0-9]*')

if [ -z "$SPEC_ID" ]; then
  echo "❌ Failed to create spec"
  exit 1
fi

echo "✅ Spec created with ID: $SPEC_ID"

echo ""
echo "=================================================================================================="
echo "🤖 Step 2: Generating LLM-Enhanced Test Cases"
echo "=================================================================================================="
echo ""

TEST_RESPONSE=$(curl -s -X POST http://localhost:8002/tasks \
  -H "Content-Type: application/json" \
  -d "{
    \"spec_id\": $SPEC_ID,
    \"agent_type\": \"functional_positive\",
    \"parameters\": {}
  }")

echo "Test Generation Response:"
echo "$TEST_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$TEST_RESPONSE"

echo ""
echo "=================================================================================================="
echo "✅ LLM Enhancement Test Complete!"
echo "=================================================================================================="
echo ""
echo "📊 Check the Docker logs to see LLM enhancement in action:"
echo "   docker logs sentinel_orchestration_service | grep -i 'llm\\|anthropic\\|claude'"
echo ""
