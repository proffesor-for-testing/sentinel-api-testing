#!/bin/bash
# Demonstrate LLM-Enhanced Test Generation

set -e

echo "=================================================================================================="
echo "🤖 SENTINEL LLM-ENHANCED TEST GENERATION DEMO"
echo "=================================================================================================="

# Pet Store OpenAPI Spec
SPEC_JSON=$(cat <<'SPECEOF'
{
  "openapi": "3.0.0",
  "info": {
    "title": "Pet Store API",
    "version": "1.0.0",
    "description": "A simple pet store API for demonstration"
  },
  "paths": {
    "/pets": {
      "get": {
        "summary": "List all pets",
        "description": "Returns a list of all pets in the store",
        "operationId": "listPets",
        "tags": ["pets"],
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of pets to return",
            "required": false,
            "schema": {
              "type": "integer",
              "format": "int32",
              "minimum": 1,
              "maximum": 100,
              "default": 20
            }
          },
          {
            "name": "species",
            "in": "query",
            "description": "Filter by species",
            "required": false,
            "schema": {
              "type": "string",
              "enum": ["dog", "cat", "bird", "fish"]
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Successful response",
            "content": {
              "application/json": {
                "schema": {
                  "type": "array",
                  "items": {
                    "$ref": "#/components/schemas/Pet"
                  }
                }
              }
            }
          }
        }
      },
      "post": {
        "summary": "Create a new pet",
        "description": "Add a new pet to the store",
        "operationId": "createPet",
        "tags": ["pets"],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/NewPet"
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Pet created successfully",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Pet"
                }
              }
            }
          },
          "400": {
            "description": "Invalid input"
          }
        }
      }
    },
    "/pets/{petId}": {
      "get": {
        "summary": "Get pet by ID",
        "description": "Returns a single pet",
        "operationId": "getPetById",
        "tags": ["pets"],
        "parameters": [
          {
            "name": "petId",
            "in": "path",
            "required": true,
            "description": "ID of pet to return",
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Successful response",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/Pet"
                }
              }
            }
          },
          "404": {
            "description": "Pet not found"
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "Pet": {
        "type": "object",
        "required": ["id", "name"],
        "properties": {
          "id": {
            "type": "integer",
            "format": "int64",
            "description": "Unique identifier"
          },
          "name": {
            "type": "string",
            "description": "Pet name",
            "minLength": 1,
            "maxLength": 100
          },
          "species": {
            "type": "string",
            "enum": ["dog", "cat", "bird", "fish"]
          },
          "age": {
            "type": "integer",
            "minimum": 0,
            "maximum": 50
          },
          "vaccinated": {
            "type": "boolean",
            "default": false
          }
        }
      },
      "NewPet": {
        "type": "object",
        "required": ["name", "species"],
        "properties": {
          "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100
          },
          "species": {
            "type": "string",
            "enum": ["dog", "cat", "bird", "fish"]
          },
          "age": {
            "type": "integer",
            "minimum": 0
          }
        }
      }
    }
  }
}
SPECEOF
)

echo ""
echo "📋 Step 1: Creating API Specification..."
echo "----------------------------------------"

SPEC_RESPONSE=$(curl -s -X POST http://localhost:8001/api/v1/specifications \
  -H "Content-Type: application/json" \
  -d "{
    \"spec_name\": \"Pet Store LLM Demo\",
    \"spec_content\": $SPEC_JSON,
    \"spec_type\": \"openapi\",
    \"spec_version\": \"3.0.0\"
  }")

echo "$SPEC_RESPONSE" | python3 -m json.tool

SPEC_ID=$(echo "$SPEC_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('spec_id', ''))" 2>/dev/null || echo "")

if [ -z "$SPEC_ID" ]; then
  echo "❌ Failed to create specification"
  exit 1
fi

echo ""
echo "✅ Specification created successfully!"
echo "   Spec ID: $SPEC_ID"

echo ""
echo "=================================================================================================="
echo "🧪 Step 2: Generating Test Cases with LLM Enhancement"
echo "=================================================================================================="
echo ""

# Generate tests using functional_positive agent
echo "⏳ Generating positive test cases..."
echo ""

TASK_RESPONSE=$(curl -s -X POST http://localhost:8002/api/v1/tasks \
  -H "Content-Type: application/json" \
  -d "{
    \"spec_id\": $SPEC_ID,
    \"agent_type\": \"functional_positive\",
    \"parameters\": {}
  }")

echo "📊 Test Generation Results:"
echo "$TASK_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$TASK_RESPONSE"

echo ""
echo "=================================================================================================="
echo "📈 Step 3: Checking LLM Activity in Logs"
echo "=================================================================================================="
echo ""

echo "🔍 LLM-related log entries:"
docker logs sentinel_orchestration_service 2>&1 | grep -i "llm\|anthropic\|claude\|provider" | tail -20 || echo "No LLM logs found yet"

echo ""
echo "=================================================================================================="
echo "✨ DEMO COMPLETE!"
echo "=================================================================================================="
echo ""
echo "📝 What happened:"
echo "   1. Created an OpenAPI specification for a Pet Store API"
echo "   2. Generated test cases using the functional_positive agent"
echo "   3. If LLM is properly configured, test cases were enhanced with Claude"
echo ""
echo "💡 To see detailed LLM enhancement:"
echo "   docker logs sentinel_orchestration_service -f"
echo ""
