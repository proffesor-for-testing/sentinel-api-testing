//! Tests for the Functional-Stateful-Agent
//! 
//! These tests validate the stateful test generation capabilities of the agent.

use std::collections::HashMap;
use serde_json::json;
use sentinel_rust_core::agents::{Agent, AgentOrchestrator};
use sentinel_rust_core::types::AgentTask;

#[tokio::test]
async fn test_functional_stateful_agent_basic() {
    // Create a simple OpenAPI spec with CRUD operations
    let api_spec = json!({
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "paths": {
            "/users": {
                "get": {
                    "operationId": "getUsers",
                    "responses": {
                        "200": {
                            "description": "List of users",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/User"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/CreateUser"
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created user",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/User"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "operationId": "getUserById",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User details",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/User"
                                    }
                                }
                            }
                        }
                    }
                },
                "put": {
                    "operationId": "updateUser",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/UpdateUser"
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Updated user",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/User"
                                    }
                                }
                            }
                        }
                    }
                },
                "delete": {
                    "operationId": "deleteUser",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "204": {
                            "description": "User deleted"
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string"
                        },
                        "name": {
                            "type": "string"
                        },
                        "email": {
                            "type": "string"
                        }
                    },
                    "required": ["id", "name", "email"]
                },
                "CreateUser": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string"
                        },
                        "email": {
                            "type": "string"
                        }
                    },
                    "required": ["name", "email"]
                },
                "UpdateUser": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string"
                        },
                        "email": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    });

    // Create agent task
    let task = AgentTask {
        task_id: "test-stateful-001".to_string(),
        spec_id: "test-spec".to_string(),
        agent_type: "Functional-Stateful-Agent".to_string(),
        parameters: HashMap::new(),
        target_environment: None,
    };

    // Create orchestrator and execute task
    let orchestrator = AgentOrchestrator::new();
    let result = orchestrator.execute_task(task, api_spec).await;

    // Verify results
    assert_eq!(result.status, "success");
    assert_eq!(result.agent_type, "Functional-Stateful-Agent");
    assert!(!result.test_cases.is_empty());

    // Check that at least one test case was generated
    let test_case = &result.test_cases[0];
    assert_eq!(test_case.test_type, "Functional-Stateful-Agent");
    assert_eq!(test_case.method, "STATEFUL");
    assert_eq!(test_case.path, "multi-step");

    // Verify metadata
    assert!(result.metadata.contains_key("total_operations"));
    assert!(result.metadata.contains_key("workflow_patterns"));
    assert!(result.metadata.contains_key("total_scenarios"));
    assert!(result.metadata.contains_key("total_test_cases"));
    assert!(result.metadata.contains_key("generation_strategy"));

    // Check that generation strategy is correct
    assert_eq!(
        result.metadata.get("generation_strategy").unwrap().as_str().unwrap(),
        "sodg_based_stateful_workflows"
    );

    println!("✅ Functional-Stateful-Agent test passed!");
    println!("Generated {} test cases", result.test_cases.len());
    println!("Identified {} workflow patterns", result.metadata.get("workflow_patterns").unwrap().as_i64().unwrap());
    println!("Found {} operations in SODG", result.metadata.get("total_operations").unwrap().as_i64().unwrap());
}

#[tokio::test]
async fn test_functional_stateful_agent_parent_child() {
    // Create an API spec with parent-child relationship
    let api_spec = json!({
        "openapi": "3.0.0",
        "info": {
            "title": "Blog API",
            "version": "1.0.0"
        },
        "paths": {
            "/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created user",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{userId}/posts": {
                "post": {
                    "operationId": "createPost",
                    "parameters": [
                        {
                            "name": "userId",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"}
                        }
                    ],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "content": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Created post",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "title": {"type": "string"},
                                            "content": {"type": "string"},
                                            "userId": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let task = AgentTask {
        task_id: "test-parent-child-001".to_string(),
        spec_id: "test-spec".to_string(),
        agent_type: "Functional-Stateful-Agent".to_string(),
        parameters: HashMap::new(),
        target_environment: None,
    };

    let orchestrator = AgentOrchestrator::new();
    let result = orchestrator.execute_task(task, api_spec).await;

    // Verify results
    assert_eq!(result.status, "success");
    assert!(!result.test_cases.is_empty());

    // Check that parent-child patterns were identified
    if let Some(supported_patterns) = result.metadata.get("supported_patterns") {
        let patterns = supported_patterns.as_array().unwrap();
        let pattern_strings: Vec<&str> = patterns.iter()
            .filter_map(|p| p.as_str())
            .collect();
        
        // We should have at least some pattern detected
        assert!(!pattern_strings.is_empty());
        println!("✅ Parent-child test passed!");
        println!("Detected patterns: {:?}", pattern_strings);
    }
}