//! Tests for the Performance-Planner-Agent
//! 
//! This file contains comprehensive tests for performance test generation functionality.

use serde_json::json;
use std::collections::HashMap;
use sentinel_rust_core::agents::{Agent, AgentOrchestrator};
use sentinel_rust_core::types::{AgentTask};

#[tokio::test]
async fn test_performance_planner_agent_basic() {
    let orchestrator = AgentOrchestrator::new();
    
    // Create a simple API specification for testing
    let api_spec = json!({
        "openapi": "3.0.0",
        "info": {
            "title": "Test API",
            "version": "1.0.0"
        },
        "paths": {
            "/users": {
                "get": {
                    "summary": "Get users",
                    "description": "Retrieve a list of users",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100
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
                                            "type": "object",
                                            "properties": {
                                                "id": { "type": "integer" },
                                                "name": { "type": "string" },
                                                "email": { "type": "string" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user by ID",
                    "description": "Retrieve a specific user",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "integer"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "User found",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": { "type": "integer" },
                                            "name": { "type": "string" },
                                            "email": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/auth/login": {
                "post": {
                    "summary": "User login",
                    "description": "Authenticate user credentials",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email", "password"],
                                    "properties": {
                                        "email": { "type": "string" },
                                        "password": { "type": "string" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Login successful"
                        },
                        "401": {
                            "description": "Invalid credentials"
                        }
                    }
                }
            }
        }
    });
    
    // Create task for Performance-Planner-Agent
    let task = AgentTask {
        task_id: "perf-test-001".to_string(),
        agent_type: "Performance-Planner-Agent".to_string(),
        spec_id: "test-spec-001".to_string(),
        target_environment: Some("test".to_string()),
        parameters: HashMap::new(),
    };
    
    // Execute the task
    let result = orchestrator.execute_task(task, api_spec).await;
    
    // Verify the result
    assert_eq!(result.status, "success");
    assert_eq!(result.agent_type, "Performance-Planner-Agent");
    assert!(!result.test_cases.is_empty(), "Should generate performance test cases");
    
    // Check that different types of performance tests are generated
    let test_names: Vec<&str> = result.test_cases.iter()
        .map(|tc| tc.test_name.as_str())
        .collect();
    
    // Should have generated multiple test types
    assert!(test_names.iter().any(|name| name.contains("Load Test")), 
           "Should generate load tests");
    assert!(test_names.iter().any(|name| name.contains("Stress Test")), 
           "Should generate stress tests");
    assert!(test_names.iter().any(|name| name.contains("Spike Test")), 
           "Should generate spike tests");
    
    // Check that critical path (auth) gets special treatment
    assert!(test_names.iter().any(|name| name.contains("/auth/login")), 
           "Should generate tests for auth endpoint");
    
    // Verify metadata
    assert!(result.metadata.contains_key("total_test_cases"));
    assert!(result.metadata.contains_key("test_types"));
    assert!(result.metadata.contains_key("performance_frameworks"));
    
    println!("✅ Performance-Planner-Agent generated {} test cases", result.test_cases.len());
    
    // Print some example test cases
    for (i, test_case) in result.test_cases.iter().take(3).enumerate() {
        println!("📊 Test Case {}: {} - {} {}", 
                i + 1, 
                test_case.test_name, 
                test_case.method, 
                test_case.path);
        println!("   Tags: {:?}", test_case.tags);
        println!("   Assertions: {}", test_case.assertions.len());
    }
}

#[tokio::test]
async fn test_performance_planner_agent_critical_paths() {
    let orchestrator = AgentOrchestrator::new();
    
    // API spec with critical paths (auth, payment, search)
    let api_spec = json!({
        "openapi": "3.0.0",
        "info": {
            "title": "E-commerce API",
            "version": "1.0.0"
        },
        "paths": {
            "/auth/login": {
                "post": {
                    "summary": "User authentication",
                    "responses": { "200": { "description": "Success" } }
                }
            },
            "/payment/process": {
                "post": {
                    "summary": "Process payment",
                    "responses": { "200": { "description": "Success" } }
                }
            },
            "/search/products": {
                "get": {
                    "summary": "Search products",
                    "responses": { "200": { "description": "Success" } }
                }
            },
            "/admin/settings": {
                "get": {
                    "summary": "Admin settings",
                    "responses": { "200": { "description": "Success" } }
                }
            }
        }
    });
    
    let task = AgentTask {
        task_id: "critical-perf-test".to_string(),
        agent_type: "Performance-Planner-Agent".to_string(),
        spec_id: "critical-spec-001".to_string(),
        target_environment: Some("test".to_string()),
        parameters: HashMap::new(),
    };
    
    let result = orchestrator.execute_task(task, api_spec).await;
    
    assert_eq!(result.status, "success");
    
    // Should generate performance tests for critical paths
    let critical_tests: Vec<_> = result.test_cases.iter()
        .filter(|tc| tc.path.contains("/auth/login") || 
                    tc.path.contains("/payment/process") || 
                    tc.path.contains("/search/products"))
        .collect();
    
    assert!(!critical_tests.is_empty(), "Should generate tests for critical paths");
    
    println!("✅ Generated {} critical path performance tests", critical_tests.len());
}

#[tokio::test]
async fn test_performance_planner_agent_data_intensive() {
    let orchestrator = AgentOrchestrator::new();
    
    // API spec with data-intensive operations
    let api_spec = json!({
        "openapi": "3.0.0",
        "info": {
            "title": "File API",
            "version": "1.0.0"
        },
        "paths": {
            "/files/upload": {
                "post": {
                    "summary": "Upload file",
                    "requestBody": {
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {
                                            "type": "string",
                                            "format": "binary"
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "responses": { "200": { "description": "Success" } }
                }
            },
            "/reports/export": {
                "get": {
                    "summary": "Export large report",
                    "responses": { "200": { "description": "Success" } }
                }
            }
        }
    });
    
    let task = AgentTask {
        task_id: "data-intensive-perf-test".to_string(),
        agent_type: "Performance-Planner-Agent".to_string(),
        spec_id: "data-spec-001".to_string(),
        target_environment: Some("test".to_string()),
        parameters: HashMap::new(),
    };
    
    let result = orchestrator.execute_task(task, api_spec).await;
    
    assert_eq!(result.status, "success");
    
    // Should generate appropriate tests for data-intensive operations
    let data_intensive_tests: Vec<_> = result.test_cases.iter()
        .filter(|tc| tc.path.contains("/files/upload") || tc.path.contains("/reports/export"))
        .collect();
    
    assert!(!data_intensive_tests.is_empty(), "Should generate tests for data-intensive operations");
    
    println!("✅ Generated {} data-intensive performance tests", data_intensive_tests.len());
}

#[tokio::test]
async fn test_performance_planner_system_wide_tests() {
    let orchestrator = AgentOrchestrator::new();
    
    // Simple API spec to trigger system-wide test generation
    let api_spec = json!({
        "openapi": "3.0.0",
        "info": {
            "title": "System API",
            "version": "1.0.0"
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                    "responses": { "200": { "description": "Success" } }
                }
            }
        }
    });
    
    let task = AgentTask {
        task_id: "system-wide-perf-test".to_string(),
        agent_type: "Performance-Planner-Agent".to_string(),
        spec_id: "system-spec-001".to_string(),
        target_environment: Some("test".to_string()),
        parameters: HashMap::new(),
    };
    
    let result = orchestrator.execute_task(task, api_spec).await;
    
    assert_eq!(result.status, "success");
    
    // Should generate system-wide workflow tests
    let workflow_tests: Vec<_> = result.test_cases.iter()
        .filter(|tc| tc.tags.contains(&"workflow".to_string()))
        .collect();
    
    assert!(!workflow_tests.is_empty(), "Should generate workflow-based performance tests");
    
    println!("✅ Generated {} system-wide workflow tests", workflow_tests.len());
}

#[test]
fn test_performance_planner_agent_creation() {
    use sentinel_rust_core::agents::performance_planner::PerformancePlannerAgent;
    
    let agent = PerformancePlannerAgent::new();
    assert_eq!(agent.agent_type(), "Performance-Planner-Agent");
}