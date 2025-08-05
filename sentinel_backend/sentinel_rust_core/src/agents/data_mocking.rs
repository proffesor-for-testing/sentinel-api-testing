//! Intelligent Data Mocking Agent
//! 
//! This agent generates realistic, contextually appropriate test data for API testing.
//! It analyzes API specifications to understand data requirements and generates
//! mock data that respects constraints, relationships, and business logic.

use async_trait::async_trait;
use rand::prelude::*;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use crate::agents::{Agent, BaseAgent};
use crate::agents::utils::*;
use crate::types::{AgentTask, AgentResult, DataGenConfig};

/// Intelligent Data Mocking Agent
pub struct DataMockingAgent {
    base: BaseAgent,
    config: DataGenConfig,
}

impl DataMockingAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("data-mocking".to_string()),
            config: DataGenConfig::default(),
        }
    }
    
    /// Generate mock data based on API specification
    async fn generate_mock_data(
        &self,
        specification: &Value,
        config: &DataGenConfig,
    ) -> Result<Value, String> {
        // Analyze specification
        let analysis = self.analyze_specification(specification);
        
        // Generate mock data for each endpoint
        let mut mock_data = serde_json::Map::new();
        
        if let Some(paths) = specification.get("paths").and_then(|p| p.as_object()) {
            for (path, methods) in paths {
                let mut path_data = serde_json::Map::new();
                
                if let Some(methods_obj) = methods.as_object() {
                    for (method, operation) in methods_obj {
                        if ["get", "post", "put", "patch", "delete"].contains(&method.to_lowercase().as_str()) {
                            let operation_data = self.generate_operation_data(
                                operation,
                                &analysis,
                                &config.strategy,
                                config.count,
                            ).await;
                            path_data.insert(method.clone(), operation_data);
                        }
                    }
                }
                
                mock_data.insert(path.clone(), Value::Object(path_data));
            }
        }
        
        // Generate global mock data
        let global_data = self.generate_global_data(specification, &analysis, &config.strategy, config.count).await;
        
        let mut result = serde_json::Map::new();
        result.insert("agent_type".to_string(), Value::String(self.base.agent_type.clone()));
        result.insert("strategy".to_string(), Value::String(config.strategy.clone()));
        result.insert("mock_data".to_string(), Value::Object(mock_data));
        result.insert("global_data".to_string(), global_data);
        result.insert("analysis".to_string(), analysis);
        
        let mut metadata = serde_json::Map::new();
        metadata.insert("generation_timestamp".to_string(), 
                       Value::String(chrono::Utc::now().to_rfc3339()));
        result.insert("metadata".to_string(), Value::Object(metadata));
        
        Ok(Value::Object(result))
    }
    
    /// Analyze API specification to understand data requirements
    fn analyze_specification(&self, specification: &Value) -> Value {
        let mut analysis = serde_json::Map::new();
        let mut schemas = serde_json::Map::new();
        let mut relationships = Vec::new();
        let mut patterns = serde_json::Map::new();
        let mut constraints = serde_json::Map::new();
        let mut enums = serde_json::Map::new();
        
        // Analyze schemas
        if let Some(components) = specification.get("components") {
            if let Some(spec_schemas) = components.get("schemas").and_then(|s| s.as_object()) {
                for (schema_name, schema_def) in spec_schemas {
                    schemas.insert(schema_name.clone(), self.analyze_schema(schema_def));
                    
                    // Extract patterns, constraints, and enums
                    self.extract_schema_info(schema_name, schema_def, &mut patterns, &mut constraints, &mut enums);
                    
                    // Find relationships
                    let schema_relationships = self.find_schema_relationships(schema_name, schema_def, spec_schemas);
                    relationships.extend(schema_relationships);
                }
            }
        }
        
        analysis.insert("schemas".to_string(), Value::Object(schemas));
        analysis.insert("relationships".to_string(), Value::Array(relationships));
        analysis.insert("patterns".to_string(), Value::Object(patterns));
        analysis.insert("constraints".to_string(), Value::Object(constraints));
        analysis.insert("enums".to_string(), Value::Object(enums));
        
        Value::Object(analysis)
    }
    
    /// Analyze individual schema definition
    fn analyze_schema(&self, schema: &Value) -> Value {
        let mut analysis = serde_json::Map::new();
        
        analysis.insert("type".to_string(), 
                       schema.get("type").unwrap_or(&Value::String("object".to_string())).clone());
        analysis.insert("properties".to_string(), 
                       schema.get("properties").unwrap_or(&Value::Object(serde_json::Map::new())).clone());
        analysis.insert("required".to_string(), 
                       schema.get("required").unwrap_or(&Value::Array(Vec::new())).clone());
        
        let mut constraints = serde_json::Map::new();
        if let Some(min_length) = schema.get("minLength") {
            constraints.insert("minLength".to_string(), min_length.clone());
        }
        if let Some(max_length) = schema.get("maxLength") {
            constraints.insert("maxLength".to_string(), max_length.clone());
        }
        if let Some(minimum) = schema.get("minimum") {
            constraints.insert("minimum".to_string(), minimum.clone());
        }
        if let Some(maximum) = schema.get("maximum") {
            constraints.insert("maximum".to_string(), maximum.clone());
        }
        if let Some(pattern) = schema.get("pattern") {
            constraints.insert("pattern".to_string(), pattern.clone());
        }
        if let Some(format) = schema.get("format") {
            constraints.insert("format".to_string(), format.clone());
        }
        
        analysis.insert("constraints".to_string(), Value::Object(constraints));
        
        Value::Object(analysis)
    }
    
    /// Extract schema information for patterns, constraints, and enums
    fn extract_schema_info(
        &self,
        schema_name: &str,
        schema_def: &Value,
        patterns: &mut serde_json::Map<String, Value>,
        constraints: &mut serde_json::Map<String, Value>,
        enums: &mut serde_json::Map<String, Value>,
    ) {
        if let Some(properties) = schema_def.get("properties").and_then(|p| p.as_object()) {
            for (prop_name, prop_def) in properties {
                let field_key = format!("{}.{}", schema_name, prop_name);
                
                // Extract patterns
                for pattern in &["email", "phone", "name", "address", "url", "date", "time"] {
                    if prop_name.to_lowercase().contains(pattern) {
                        patterns.insert(field_key.clone(), Value::String(pattern.to_string()));
                        break;
                    }
                }
                
                // Extract constraints
                let mut field_constraints = serde_json::Map::new();
                if let Some(prop_type) = prop_def.get("type") {
                    field_constraints.insert("type".to_string(), prop_type.clone());
                }
                if let Some(format) = prop_def.get("format") {
                    field_constraints.insert("format".to_string(), format.clone());
                }
                if let Some(min_length) = prop_def.get("minLength") {
                    field_constraints.insert("minLength".to_string(), min_length.clone());
                }
                if let Some(max_length) = prop_def.get("maxLength") {
                    field_constraints.insert("maxLength".to_string(), max_length.clone());
                }
                if let Some(minimum) = prop_def.get("minimum") {
                    field_constraints.insert("minimum".to_string(), minimum.clone());
                }
                if let Some(maximum) = prop_def.get("maximum") {
                    field_constraints.insert("maximum".to_string(), maximum.clone());
                }
                
                let required = schema_def.get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some(prop_name)))
                    .unwrap_or(false);
                field_constraints.insert("required".to_string(), Value::Bool(required));
                
                constraints.insert(field_key.clone(), Value::Object(field_constraints));
                
                // Extract enums
                if let Some(enum_values) = prop_def.get("enum") {
                    enums.insert(field_key, enum_values.clone());
                }
            }
        }
    }
    
    /// Find relationships between schemas
    fn find_schema_relationships(
        &self,
        schema_name: &str,
        schema_def: &Value,
        all_schemas: &serde_json::Map<String, Value>,
    ) -> Vec<Value> {
        let mut relationships = Vec::new();
        
        if let Some(properties) = schema_def.get("properties").and_then(|p| p.as_object()) {
            for (prop_name, prop_def) in properties {
                // Check for references to other schemas
                if let Some(ref_path) = prop_def.get("$ref").and_then(|r| r.as_str()) {
                    if let Some(ref_schema) = ref_path.split('/').last() {
                        let mut relationship = serde_json::Map::new();
                        relationship.insert("from".to_string(), Value::String(schema_name.to_string()));
                        relationship.insert("to".to_string(), Value::String(ref_schema.to_string()));
                        relationship.insert("field".to_string(), Value::String(prop_name.clone()));
                        relationship.insert("type".to_string(), Value::String("reference".to_string()));
                        relationships.push(Value::Object(relationship));
                    }
                }
                
                // Check for foreign key patterns
                if prop_name.ends_with("_id") || prop_name.ends_with("Id") {
                    let potential_ref = prop_name.replace("_id", "").replace("Id", "");
                    let capitalized_ref = format!("{}{}", 
                        potential_ref.chars().next().unwrap().to_uppercase(),
                        potential_ref.chars().skip(1).collect::<String>()
                    );
                    
                    if all_schemas.contains_key(&capitalized_ref) {
                        let mut relationship = serde_json::Map::new();
                        relationship.insert("from".to_string(), Value::String(schema_name.to_string()));
                        relationship.insert("to".to_string(), Value::String(capitalized_ref));
                        relationship.insert("field".to_string(), Value::String(prop_name.clone()));
                        relationship.insert("type".to_string(), Value::String("foreign_key".to_string()));
                        relationships.push(Value::Object(relationship));
                    }
                }
            }
        }
        
        relationships
    }
    
    /// Generate mock data for a specific operation
    async fn generate_operation_data(
        &self,
        operation: &Value,
        _analysis: &Value,
        strategy: &str,
        count: usize,
    ) -> Value {
        let mut operation_data = serde_json::Map::new();
        let mut request_bodies = Vec::new();
        let mut responses = serde_json::Map::new();
        let mut parameters = Vec::new();
        
        // Generate request body data
        if let Some(request_body) = operation.get("requestBody") {
            if let Some(content) = request_body.get("content").and_then(|c| c.as_object()) {
                for (media_type, media_def) in content {
                    if let Some(schema) = media_def.get("schema") {
                        for i in 0..count {
                            let mock_body = self.generate_from_schema(schema, strategy);
                            let mut body_data = serde_json::Map::new();
                            body_data.insert("media_type".to_string(), Value::String(media_type.clone()));
                            body_data.insert("data".to_string(), mock_body);
                            body_data.insert("variation".to_string(), Value::Number(serde_json::Number::from(i)));
                            request_bodies.push(Value::Object(body_data));
                        }
                    }
                }
            }
        }
        
        // Generate response data
        if let Some(op_responses) = operation.get("responses").and_then(|r| r.as_object()) {
            for (status_code, response_def) in op_responses {
                let mut status_responses = Vec::new();
                
                if let Some(content) = response_def.get("content").and_then(|c| c.as_object()) {
                    for (media_type, media_def) in content {
                        if let Some(schema) = media_def.get("schema") {
                            for i in 0..std::cmp::min(count, 5) { // Limit response variations
                                let mock_response = self.generate_from_schema(schema, strategy);
                                let mut response_data = serde_json::Map::new();
                                response_data.insert("media_type".to_string(), Value::String(media_type.clone()));
                                response_data.insert("data".to_string(), mock_response);
                                response_data.insert("variation".to_string(), Value::Number(serde_json::Number::from(i)));
                                status_responses.push(Value::Object(response_data));
                            }
                        }
                    }
                }
                
                responses.insert(status_code.clone(), Value::Array(status_responses));
            }
        }
        
        // Generate parameter data
        if let Some(op_parameters) = operation.get("parameters").and_then(|p| p.as_array()) {
            for param in op_parameters {
                if let Some(param_schema) = param.get("schema") {
                    for i in 0..std::cmp::min(count, 3) { // Limit parameter variations
                        let mock_param = self.generate_from_schema(param_schema, strategy);
                        let mut param_data = serde_json::Map::new();
                        param_data.insert("name".to_string(), 
                                         param.get("name").unwrap_or(&Value::String("unknown".to_string())).clone());
                        param_data.insert("in".to_string(), 
                                         param.get("in").unwrap_or(&Value::String("query".to_string())).clone());
                        param_data.insert("value".to_string(), mock_param);
                        param_data.insert("variation".to_string(), Value::Number(serde_json::Number::from(i)));
                        parameters.push(Value::Object(param_data));
                    }
                }
            }
        }
        
        operation_data.insert("request_bodies".to_string(), Value::Array(request_bodies));
        operation_data.insert("responses".to_string(), Value::Object(responses));
        operation_data.insert("parameters".to_string(), Value::Array(parameters));
        
        Value::Object(operation_data)
    }
    
    /// Generate global mock data (users, auth tokens, etc.)
    async fn generate_global_data(
        &self,
        _specification: &Value,
        analysis: &Value,
        _strategy: &str,
        count: usize,
    ) -> Value {
        let mut global_data = serde_json::Map::new();
        let mut users = Vec::new();
        let mut auth_tokens = Vec::new();
        let mut api_keys = Vec::new();
        let mut test_entities = serde_json::Map::new();
        
        let mut rng = thread_rng();
        
        // Generate test users
        for i in 0..count {
            let mut user = serde_json::Map::new();
            user.insert("id".to_string(), Value::String(format!("user_{}", Uuid::new_v4().simple())));
            user.insert("username".to_string(), Value::String(format!("testuser{}", i + 1)));
            user.insert("email".to_string(), Value::String(format!("user{}@example.com", i + 1)));
            user.insert("first_name".to_string(), Value::String(["John", "Jane", "Alice", "Bob", "Charlie"].choose(&mut rng).unwrap().to_string()));
            user.insert("last_name".to_string(), Value::String(["Smith", "Johnson", "Williams", "Brown", "Jones"].choose(&mut rng).unwrap().to_string()));
            user.insert("role".to_string(), Value::String(["admin", "user", "moderator"].choose(&mut rng).unwrap().to_string()));
            user.insert("created_at".to_string(), Value::String(chrono::Utc::now().to_rfc3339()));
            user.insert("active".to_string(), Value::Bool(rng.gen_bool(0.8)));
            users.push(Value::Object(user));
        }
        
        // Generate auth tokens
        for i in 0..count {
            let mut token = serde_json::Map::new();
            token.insert("token".to_string(), Value::String(self.generate_jwt_token()));
            token.insert("user_id".to_string(), users[i % users.len()].get("id").unwrap().clone());
            token.insert("expires_at".to_string(), 
                        Value::String((chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339()));
            token.insert("scopes".to_string(), 
                        Value::Array(vec![Value::String("read".to_string()), Value::String("write".to_string())]));
            auth_tokens.push(Value::Object(token));
        }
        
        // Generate API keys
        for i in 0..std::cmp::min(count, 5) {
            let mut api_key = serde_json::Map::new();
            api_key.insert("key".to_string(), Value::String(self.generate_api_key()));
            api_key.insert("name".to_string(), Value::String(format!("Test Key {}", i + 1)));
            api_key.insert("user_id".to_string(), users[i % users.len()].get("id").unwrap().clone());
            api_key.insert("created_at".to_string(), Value::String(chrono::Utc::now().to_rfc3339()));
            api_key.insert("last_used".to_string(), 
                          if rng.gen_bool(0.5) { 
                              Value::String(chrono::Utc::now().to_rfc3339()) 
                          } else { 
                              Value::Null 
                          });
            api_keys.push(Value::Object(api_key));
        }
        
        // Generate test entities for each schema
        if let Some(schemas) = analysis.get("schemas").and_then(|s| s.as_object()) {
            for schema_name in schemas.keys() {
                let mut entities = Vec::new();
                for _i in 0..std::cmp::min(count, 5) {
                    // This would generate entities based on the schema
                    // For now, we'll create a placeholder
                    let mut entity = serde_json::Map::new();
                    entity.insert("id".to_string(), Value::String(generate_realistic_id()));
                    entity.insert("name".to_string(), Value::String(format!("Test {}", schema_name)));
                    entities.push(Value::Object(entity));
                }
                test_entities.insert(schema_name.clone(), Value::Array(entities));
            }
        }
        
        global_data.insert("users".to_string(), Value::Array(users));
        global_data.insert("auth_tokens".to_string(), Value::Array(auth_tokens));
        global_data.insert("api_keys".to_string(), Value::Array(api_keys));
        global_data.insert("test_entities".to_string(), Value::Object(test_entities));
        
        Value::Object(global_data)
    }
    
    /// Generate data from a schema definition
    fn generate_from_schema(&self, schema: &Value, strategy: &str) -> Value {
        let schema_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("object");
        
        match schema_type {
            "object" => self.generate_object(schema, strategy),
            "array" => self.generate_array(schema, strategy),
            "string" => self.generate_string(schema, strategy),
            "integer" => self.generate_integer(schema, strategy),
            "number" => self.generate_number(schema, strategy),
            "boolean" => self.generate_boolean(schema, strategy),
            _ => Value::Null,
        }
    }
    
    /// Generate object data
    fn generate_object(&self, schema: &Value, strategy: &str) -> Value {
        let mut obj = serde_json::Map::new();
        let mut rng = thread_rng();
        
        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            let required = schema.get("required")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            
            for (prop_name, prop_schema) in properties {
                // Always generate required fields
                if required.contains(&prop_name.as_str()) || rng.gen_bool(0.7) {
                    obj.insert(prop_name.clone(), self.generate_from_schema(prop_schema, strategy));
                }
            }
        }
        
        Value::Object(obj)
    }
    
    /// Generate array data
    fn generate_array(&self, schema: &Value, strategy: &str) -> Value {
        let default_schema = Value::Object(serde_json::Map::new());
        let items_schema = schema.get("items").unwrap_or(&default_schema);
        let min_items = schema.get("minItems").and_then(|m| m.as_u64()).unwrap_or(1) as usize;
        let max_items = schema.get("maxItems").and_then(|m| m.as_u64()).unwrap_or(5) as usize;
        
        let mut rng = thread_rng();
        let length = rng.gen_range(min_items..=max_items);
        
        let items: Vec<Value> = (0..length)
            .map(|_| self.generate_from_schema(items_schema, strategy))
            .collect();
        
        Value::Array(items)
    }
    
    /// Generate string data
    fn generate_string(&self, schema: &Value, strategy: &str) -> Value {
        let mut rng = thread_rng();
        
        if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
            return enum_values.choose(&mut rng).unwrap_or(&Value::String("default".to_string())).clone();
        }
        
        if let Some(format) = schema.get("format").and_then(|f| f.as_str()) {
            return match format {
                "email" => Value::String(format!("user{}@example.com", rng.gen_range(1..=999))),
                "uri" => Value::String("https://example.com/test".to_string()),
                "date" => Value::String(chrono::Utc::now().format("%Y-%m-%d").to_string()),
                "date-time" => Value::String(chrono::Utc::now().to_rfc3339()),
                "uuid" => Value::String(Uuid::new_v4().to_string()),
                _ => Value::String("example_string".to_string()),
            };
        }
        
        let min_length = schema.get("minLength").and_then(|m| m.as_u64()).unwrap_or(1) as usize;
        let max_length = schema.get("maxLength").and_then(|m| m.as_u64()).unwrap_or(50) as usize;
        
        if strategy == "edge_cases" {
            if rng.gen_bool(0.5) {
                Value::String("a".repeat(min_length))
            } else {
                Value::String("a".repeat(max_length))
            }
        } else {
            let length = rng.gen_range(min_length..=std::cmp::min(max_length, 20));
            let chars: String = (0..length)
                .map(|_| {
                    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
                    chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                })
                .collect();
            Value::String(chars.trim().to_string())
        }
    }
    
    /// Generate integer data
    fn generate_integer(&self, schema: &Value, strategy: &str) -> Value {
        let minimum = schema.get("minimum").and_then(|m| m.as_i64()).unwrap_or(0);
        let maximum = schema.get("maximum").and_then(|m| m.as_i64()).unwrap_or(1000);
        
        let mut rng = thread_rng();
        
        let value = match strategy {
            "edge_cases" => *[minimum, maximum, minimum + 1, maximum - 1].choose(&mut rng).unwrap(),
            "boundary" => *[minimum, maximum].choose(&mut rng).unwrap(),
            _ => rng.gen_range(minimum..=maximum),
        };
        
        Value::Number(serde_json::Number::from(value))
    }
    
    /// Generate number data
    fn generate_number(&self, schema: &Value, strategy: &str) -> Value {
        let minimum = schema.get("minimum").and_then(|m| m.as_f64()).unwrap_or(0.0);
        let maximum = schema.get("maximum").and_then(|m| m.as_f64()).unwrap_or(1000.0);
        
        let mut rng = thread_rng();
        
        let value = match strategy {
            "edge_cases" => *[minimum, maximum, minimum + 0.1, maximum - 0.1].choose(&mut rng).unwrap(),
            "boundary" => *[minimum, maximum].choose(&mut rng).unwrap(),
            _ => rng.gen_range(minimum..=maximum),
        };
        
        Value::Number(serde_json::Number::from_f64((value * 100.0).round() / 100.0).unwrap())
    }
    
    /// Generate boolean data
    fn generate_boolean(&self, _schema: &Value, _strategy: &str) -> Value {
        let mut rng = thread_rng();
        Value::Bool(rng.gen_bool(0.5))
    }
    
    /// Generate a JWT token
    fn generate_jwt_token(&self) -> String {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        let mut rng = thread_rng();
        let signature: String = (0..43)
            .map(|_| {
                let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
                chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
            })
            .collect();
        
        format!("{}.{}.{}", header, payload, signature)
    }
    
    /// Generate an API key
    fn generate_api_key(&self) -> String {
        let mut rng = thread_rng();
        let prefix = ["test", "dev", "prod"].choose(&mut rng).unwrap();
        let key: String = (0..32)
            .map(|_| {
                let chars = "abcdefghijklmnopqrstuvwxyz0123456789";
                chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
            })
            .collect();
        
        format!("sk-{}-{}", prefix, key)
    }
}

#[async_trait]
impl Agent for DataMockingAgent {
    fn agent_type(&self) -> &str {
        &self.base.agent_type
    }
    
    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        let config = DataGenConfig {
            strategy: task.parameters.get("strategy")
                .and_then(|s| s.as_str())
                .unwrap_or("realistic")
                .to_string(),
            count: task.parameters.get("count")
                .and_then(|c| c.as_u64())
                .unwrap_or(10) as usize,
            seed: task.parameters.get("seed")
                .and_then(|s| s.as_u64()),
            realistic_bias: task.parameters.get("realistic_bias")
                .and_then(|b| b.as_f64())
                .unwrap_or(0.8),
        };
        
        match self.generate_mock_data(&api_spec, &config).await {
            Ok(_mock_data) => {
                let mut metadata = HashMap::new();
                metadata.insert("strategy".to_string(), Value::String(config.strategy));
                metadata.insert("count".to_string(), Value::Number(serde_json::Number::from(config.count)));
                
                AgentResult {
                    task_id: task.task_id,
                    agent_type: self.agent_type().to_string(),
                    status: "success".to_string(),
                    test_cases: vec![], // Data mocking doesn't generate test cases
                    metadata,
                    error_message: None,
                }
            }
            Err(e) => AgentResult {
                task_id: task.task_id,
                agent_type: self.agent_type().to_string(),
                status: "failed".to_string(),
                test_cases: vec![],
                metadata: HashMap::new(),
                error_message: Some(e),
            },
        }
    }
}