"""
Learning Integration Test Fixtures

Provides comprehensive test data factories for learning system testing including:
- Sample API specifications (REST, GraphQL, gRPC)
- Feedback data (ratings, comments, quality indicators)
- Trajectories and reasoning patterns
- Q-Learning states and actions
- AgentDB vector data
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
import random


class FeedbackRating(str, Enum):
    """Feedback rating levels."""
    EXCELLENT = "excellent"  # 5 stars
    GOOD = "good"  # 4 stars
    AVERAGE = "average"  # 3 stars
    POOR = "poor"  # 2 stars
    VERY_POOR = "very_poor"  # 1 star


class APISpecType(str, Enum):
    """API specification types."""
    REST = "rest"
    GRAPHQL = "graphql"
    GRPC = "grpc"


# Sample REST API Specification
SAMPLE_REST_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "User Management API",
        "version": "1.0.0",
        "description": "API for managing users in the system"
    },
    "paths": {
        "/users": {
            "get": {
                "summary": "List all users",
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        }
                    }
                }
            },
            "post": {
                "summary": "Create a new user",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/UserCreate"}
                        }
                    }
                },
                "responses": {
                    "201": {"description": "User created"},
                    "400": {"description": "Invalid input"}
                }
            }
        },
        "/users/{userId}": {
            "get": {
                "summary": "Get user by ID",
                "parameters": [
                    {"name": "userId", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {
                    "200": {"description": "Success"},
                    "404": {"description": "User not found"}
                }
            }
        }
    },
    "components": {
        "schemas": {
            "User": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "email": {"type": "string"},
                    "name": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"}
                }
            },
            "UserCreate": {
                "type": "object",
                "required": ["email", "name"],
                "properties": {
                    "email": {"type": "string"},
                    "name": {"type": "string"}
                }
            }
        }
    }
}

# Sample GraphQL Schema
SAMPLE_GRAPHQL_SPEC = {
    "type": "graphql",
    "version": "1.0.0",
    "schema": """
    type User {
        id: ID!
        email: String!
        name: String!
        posts: [Post!]!
        createdAt: DateTime!
    }

    type Post {
        id: ID!
        title: String!
        content: String!
        author: User!
        publishedAt: DateTime
    }

    type Query {
        users(limit: Int, offset: Int): [User!]!
        user(id: ID!): User
        posts(authorId: ID): [Post!]!
    }

    type Mutation {
        createUser(email: String!, name: String!): User!
        updateUser(id: ID!, name: String): User!
        deleteUser(id: ID!): Boolean!
    }

    scalar DateTime
    """
}

# Sample gRPC Service Definition
SAMPLE_GRPC_SPEC = {
    "type": "grpc",
    "version": "1.0.0",
    "proto": """
    syntax = "proto3";

    package user.v1;

    service UserService {
        rpc ListUsers(ListUsersRequest) returns (ListUsersResponse);
        rpc GetUser(GetUserRequest) returns (User);
        rpc CreateUser(CreateUserRequest) returns (User);
        rpc UpdateUser(UpdateUserRequest) returns (User);
        rpc DeleteUser(DeleteUserRequest) returns (DeleteUserResponse);
    }

    message User {
        string id = 1;
        string email = 2;
        string name = 3;
        int64 created_at = 4;
    }

    message ListUsersRequest {
        int32 limit = 1;
        int32 offset = 2;
    }

    message ListUsersResponse {
        repeated User users = 1;
        int32 total = 2;
    }
    """
}


def create_sample_api_spec(spec_type: APISpecType = APISpecType.REST) -> Dict[str, Any]:
    """Create a sample API specification."""
    specs = {
        APISpecType.REST: SAMPLE_REST_SPEC,
        APISpecType.GRAPHQL: SAMPLE_GRAPHQL_SPEC,
        APISpecType.GRPC: SAMPLE_GRPC_SPEC
    }
    return specs[spec_type]


def create_sample_feedback(
    rating: FeedbackRating = FeedbackRating.GOOD,
    test_id: str = "test_123",
    agent_id: str = "functional-positive-agent",
    include_comment: bool = True,
    found_issue: bool = False
) -> Dict[str, Any]:
    """Create sample user feedback."""
    rating_map = {
        FeedbackRating.EXCELLENT: 5,
        FeedbackRating.GOOD: 4,
        FeedbackRating.AVERAGE: 3,
        FeedbackRating.POOR: 2,
        FeedbackRating.VERY_POOR: 1
    }

    comments = {
        FeedbackRating.EXCELLENT: "Perfect test case! Caught a critical bug.",
        FeedbackRating.GOOD: "Good test coverage, helpful assertions.",
        FeedbackRating.AVERAGE: "Decent test but could be more thorough.",
        FeedbackRating.POOR: "Missing important edge cases.",
        FeedbackRating.VERY_POOR: "Test doesn't validate the right behavior."
    }

    feedback = {
        "test_id": test_id,
        "agent_id": agent_id,
        "rating": rating_map[rating],
        "helpful": rating_map[rating] >= 4,
        "found_issue": found_issue,
        "timestamp": datetime.utcnow().isoformat()
    }

    if include_comment:
        feedback["comment"] = comments[rating]

    return feedback


def create_sample_trajectory(
    agent_id: str = "functional-positive-agent",
    api_spec_type: APISpecType = APISpecType.REST,
    success: bool = True
) -> Dict[str, Any]:
    """Create a sample ReasoningBank trajectory."""
    return {
        "trajectory_id": f"traj_{agent_id}_{datetime.utcnow().timestamp()}",
        "agent_id": agent_id,
        "task": {
            "type": "test_generation",
            "api_spec_type": api_spec_type.value,
            "endpoint": "/users",
            "method": "GET"
        },
        "reasoning_steps": [
            {
                "step": 1,
                "thought": "Analyze endpoint parameters and response schema",
                "action": "parse_openapi_spec",
                "observation": "Found GET /users with query params: limit, offset"
            },
            {
                "step": 2,
                "thought": "Identify positive test scenarios",
                "action": "generate_happy_path_tests",
                "observation": "Generated 3 positive test cases"
            },
            {
                "step": 3,
                "thought": "Add parameter validation tests",
                "action": "generate_boundary_tests",
                "observation": "Added tests for limit=0, limit=100, offset validation"
            }
        ],
        "result": {
            "success": success,
            "tests_generated": 5,
            "coverage_percentage": 85.0
        },
        "metadata": {
            "duration_ms": 1250,
            "tokens_used": 1500,
            "model": "claude-sonnet-4"
        }
    }


def create_sample_pattern(
    pattern_type: str = "positive_test_generation",
    frequency: int = 10
) -> Dict[str, Any]:
    """Create a sample learned pattern for AgentDB."""
    patterns = {
        "positive_test_generation": {
            "pattern_id": "pattern_positive_001",
            "type": "positive_test_generation",
            "context": "GET endpoint with pagination",
            "successful_approach": "Test default params, boundary values, and typical ranges",
            "key_insights": [
                "Always test limit=0 case",
                "Verify response schema matches OpenAPI spec",
                "Check pagination links in response"
            ],
            "embedding": [0.1] * 384  # Mock embedding vector
        },
        "boundary_analysis": {
            "pattern_id": "pattern_boundary_001",
            "type": "boundary_analysis",
            "context": "Integer parameter validation",
            "successful_approach": "Test min-1, min, typical, max, max+1",
            "key_insights": [
                "Check for integer overflow",
                "Verify error messages for out-of-range",
                "Test zero and negative values"
            ],
            "embedding": [0.2] * 384
        },
        "auth_testing": {
            "pattern_id": "pattern_auth_001",
            "type": "auth_testing",
            "context": "Protected API endpoints",
            "successful_approach": "Test no token, invalid token, expired token, valid token",
            "key_insights": [
                "Verify 401 for missing auth",
                "Check token expiration handling",
                "Test different permission levels"
            ],
            "embedding": [0.3] * 384
        }
    }

    pattern = patterns.get(pattern_type, patterns["positive_test_generation"])
    pattern["frequency"] = frequency
    pattern["last_used"] = datetime.utcnow().isoformat()
    return pattern


def create_sample_q_state(
    agent_id: str = "functional-positive-agent"
) -> Dict[str, Any]:
    """Create a sample Q-Learning state."""
    return {
        "agent_id": agent_id,
        "state": {
            "api_type": "rest",
            "endpoint_type": "crud",
            "has_auth": True,
            "has_pagination": True,
            "complexity": "medium"
        },
        "q_values": {
            "generate_happy_path": 0.85,
            "generate_boundary_tests": 0.78,
            "generate_auth_tests": 0.92,
            "generate_error_tests": 0.65
        },
        "visit_count": 25,
        "last_reward": 0.9,
        "updated_at": datetime.utcnow().isoformat()
    }


def create_batch_feedback(
    count: int = 100,
    good_ratio: float = 0.7
) -> List[Dict[str, Any]]:
    """Create a batch of feedback data for performance testing."""
    feedback_batch = []

    for i in range(count):
        if random.random() < good_ratio:
            rating = random.choice([FeedbackRating.EXCELLENT, FeedbackRating.GOOD])
        else:
            rating = random.choice([FeedbackRating.AVERAGE, FeedbackRating.POOR, FeedbackRating.VERY_POOR])

        feedback = create_sample_feedback(
            rating=rating,
            test_id=f"test_{i:04d}",
            agent_id=random.choice([
                "functional-positive-agent",
                "functional-negative-agent",
                "security-auth-agent",
                "performance-planner-agent"
            ]),
            include_comment=random.random() < 0.6,
            found_issue=random.random() < 0.3
        )
        feedback_batch.append(feedback)

    return feedback_batch


def create_complex_api_spec() -> Dict[str, Any]:
    """Create a complex API spec for advanced testing."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "E-Commerce API",
            "version": "2.0.0"
        },
        "paths": {
            "/products": {
                "get": {
                    "summary": "List products",
                    "parameters": [
                        {"name": "category", "in": "query", "schema": {"type": "string"}},
                        {"name": "minPrice", "in": "query", "schema": {"type": "number"}},
                        {"name": "maxPrice", "in": "query", "schema": {"type": "number"}},
                        {"name": "sortBy", "in": "query", "schema": {"type": "string", "enum": ["price", "name", "rating"]}}
                    ]
                }
            },
            "/products/{productId}": {
                "get": {"summary": "Get product"},
                "put": {
                    "summary": "Update product",
                    "security": [{"bearerAuth": []}]
                },
                "delete": {
                    "summary": "Delete product",
                    "security": [{"bearerAuth": []}]
                }
            },
            "/orders": {
                "post": {
                    "summary": "Create order",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["items", "shippingAddress"],
                                    "properties": {
                                        "items": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "productId": {"type": "string"},
                                                    "quantity": {"type": "integer", "minimum": 1}
                                                }
                                            }
                                        },
                                        "shippingAddress": {"type": "object"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        }
    }


# Export fixtures for easy import
__all__ = [
    'FeedbackRating',
    'APISpecType',
    'SAMPLE_REST_SPEC',
    'SAMPLE_GRAPHQL_SPEC',
    'SAMPLE_GRPC_SPEC',
    'create_sample_api_spec',
    'create_sample_feedback',
    'create_sample_trajectory',
    'create_sample_pattern',
    'create_sample_q_state',
    'create_batch_feedback',
    'create_complex_api_spec'
]
