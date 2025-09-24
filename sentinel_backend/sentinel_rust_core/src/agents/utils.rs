//! Utility functions for agent implementations
//! 
//! This module provides common utility functions used across different agent implementations.

use rand::prelude::*;
use serde_json::Value;
use std::collections::HashMap;

/// Generate a realistic ID value (type-aware)
pub fn generate_realistic_id(is_integer: bool) -> Value {
    let mut rng = thread_rng();

    if is_integer {
        // For integer IDs, always return a valid integer
        Value::Number(serde_json::Number::from(rng.gen_range(1..=10000)))
    } else {
        // For string IDs, generate realistic string formats
        let formats: Vec<Box<dyn Fn(&mut ThreadRng) -> String>> = vec![
            Box::new(|rng| rng.gen_range(1..=10000).to_string()),
            Box::new(|rng| {
                let chars: String = (0..8)
                    .map(|_| {
                        let chars = "abcdefghijklmnopqrstuvwxyz0123456789";
                        chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                    })
                    .collect();
                chars
            }),
            Box::new(|rng| format!("usr_{}", rng.gen_range(1000..=9999))),
            Box::new(|rng| {
                let chars: String = (0..12)
                    .map(|_| {
                        let chars = "abcdefghijklmnopqrstuvwxyz0123456789";
                        chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                    })
                    .collect();
                chars
            }),
        ];

        let format_fn = formats.choose(&mut rng).unwrap();
        Value::String(format_fn(&mut rng))
    }
}

/// Generate a realistic parameter value based on parameter name and schema
pub fn generate_parameter_value(param_name: &str, schema: &Value) -> Value {
    // Use example if provided
    if let Some(example) = schema.get("example") {
        return example.clone();
    }
    
    let param_name_lower = param_name.to_lowercase();
    let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
    
    // Generate realistic values based on common parameter names
    if param_name_lower.contains("id") {
        // Check if the schema type is integer
        let is_integer = param_type == "integer" || param_type == "number";
        return generate_realistic_id(is_integer);
    } else if param_name_lower.contains("email") {
        return Value::String("test@example.com".to_string());
    } else if param_name_lower.contains("name") {
        return Value::String("Test Name".to_string());
    } else if param_name_lower.contains("date") {
        return Value::String(chrono::Utc::now().to_rfc3339());
    } else if param_name_lower.contains("limit") || param_name_lower.contains("size") {
        return Value::Number(serde_json::Number::from(10));
    } else if param_name_lower.contains("offset") || param_name_lower.contains("page") {
        return Value::Number(serde_json::Number::from(0));
    }
    
    // Fall back to schema-based generation
    generate_schema_example(schema)
}

/// Generate example value from JSON schema
pub fn generate_schema_example(schema: &Value) -> Value {
    if let Some(example) = schema.get("example") {
        return example.clone();
    }
    
    let schema_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
    
    match schema_type {
        "string" => {
            // First priority: Check for enum values
            if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
                if !enum_values.is_empty() {
                    // Pick a random enum value for more variety in positive tests
                    let mut rng = thread_rng();
                    let index = rng.gen_range(0..enum_values.len());
                    return enum_values[index].clone();
                }
            }

            // Second priority: Check for format hints
            if let Some(format) = schema.get("format").and_then(|f| f.as_str()) {
                return match format {
                    "email" => Value::String("test@example.com".to_string()),
                    "uri" | "url" => Value::String("https://example.com".to_string()),
                    "date" => Value::String("2024-01-01".to_string()),
                    "date-time" => Value::String(chrono::Utc::now().to_rfc3339()),
                    "uuid" => Value::String("550e8400-e29b-41d4-a716-446655440000".to_string()),
                    _ => Value::String("Test User".to_string())
                };
            }

            // Third priority: Check for min/max length constraints
            let min_length = schema.get("minLength").and_then(|m| m.as_u64()).unwrap_or(1) as usize;
            let max_length = schema.get("maxLength").and_then(|m| m.as_u64()).unwrap_or(50) as usize;

            // Generate a string that respects length constraints
            let base_string = "Test User";
            if base_string.len() < min_length {
                // Pad string to meet minimum length
                let padding = "x".repeat(min_length - base_string.len());
                Value::String(format!("{}{}", base_string, padding))
            } else if base_string.len() > max_length {
                // Truncate to max length
                Value::String(base_string[..max_length].to_string())
            } else {
                Value::String(base_string.to_string())
            }
        }
        "integer" => {
            let mut rng = thread_rng();
            let min = schema.get("minimum").and_then(|m| m.as_i64()).unwrap_or(1);
            let max = schema.get("maximum").and_then(|m| m.as_i64()).unwrap_or(1000);
            // Generate a random value within the constraints
            let value = if min < max {
                rng.gen_range(min..=max)
            } else {
                min
            };
            Value::Number(serde_json::Number::from(value))
        }
        "number" => {
            let mut rng = thread_rng();
            let min = schema.get("minimum").and_then(|m| m.as_f64()).unwrap_or(1.0);
            let max = schema.get("maximum").and_then(|m| m.as_f64()).unwrap_or(1000.0);
            // Generate a random value within the constraints
            let value = if min < max {
                rng.gen_range(min..=max)
            } else {
                min
            };
            Value::Number(serde_json::Number::from_f64(value).unwrap_or(serde_json::Number::from(1)))
        }
        "boolean" => Value::Bool(true),
        "array" => {
            if let Some(items) = schema.get("items") {
                Value::Array(vec![generate_schema_example(items)])
            } else {
                Value::Array(vec![])
            }
        }
        "object" => {
            let mut obj = serde_json::Map::new();
            if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                let required = schema
                    .get("required")
                    .and_then(|r| r.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                
                for (prop_name, prop_schema) in properties {
                    if required.contains(&prop_name.as_str()) || properties.len() <= 3 {
                        obj.insert(prop_name.clone(), generate_schema_example(prop_schema));
                    }
                }
            }
            Value::Object(obj)
        }
        _ => Value::Null,
    }
}

/// Generate realistic property value based on property name
pub fn generate_realistic_property_value(prop_name: &str, schema: &Value) -> Value {
    generate_realistic_property_value_with_spec(prop_name, schema, None)
}

/// Generate realistic property value with API spec for reference resolution
pub fn generate_realistic_property_value_with_spec(prop_name: &str, schema: &Value, api_spec: Option<&Value>) -> Value {
    let prop_name_lower = prop_name.to_lowercase();

    // Use existing example if available
    if let Some(example) = schema.get("example") {
        return example.clone();
    }

    // Check if this is a reference to an enum (e.g., for category)
    // The schema might have an anyOf with a $ref to an enum
    if let Some(any_of) = schema.get("anyOf").and_then(|a| a.as_array()) {
        for item in any_of {
            // Skip null type
            if item.get("type").and_then(|t| t.as_str()) == Some("null") {
                continue;
            }

            // If there's a $ref, resolve it first
            let resolved_item = if let Some(api_spec) = api_spec {
                if item.get("$ref").is_some() {
                    resolve_schema_ref(item, api_spec)
                } else {
                    item.clone()
                }
            } else {
                item.clone()
            };

            // If there's an enum in the resolved item, use it
            if let Some(enum_values) = resolved_item.get("enum").and_then(|e| e.as_array()) {
                if !enum_values.is_empty() {
                    let mut rng = thread_rng();
                    let index = rng.gen_range(0..enum_values.len());
                    return enum_values[index].clone();
                }
            }

            // If we have a resolved type that's not null, recursively generate for it
            if resolved_item.get("type").is_some() {
                return generate_realistic_property_value_with_spec(prop_name, &resolved_item, api_spec);
            }
        }
    }
    
    let mut rng = thread_rng();
    
    // First check for enum values in the schema itself
    if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
        if !enum_values.is_empty() {
            let index = rng.gen_range(0..enum_values.len());
            return enum_values[index].clone();
        }
    }

    // Handle specific properties with known enum values (common in APIs)
    if prop_name_lower == "status" {
        // Common status values in APIs
        let status_values = vec!["available", "pending", "sold", "active", "inactive"];
        return Value::String(status_values.choose(&mut rng).unwrap().to_string());
    } else if prop_name_lower == "category" {
        // Common category values (adapted for Petstore)
        let category_values = vec!["dog", "cat", "bird", "fish", "other"];
        return Value::String(category_values.choose(&mut rng).unwrap().to_string());
    } else if prop_name_lower.contains("type") && !prop_name_lower.contains("content") {
        // Common type values
        let type_values = vec!["standard", "premium", "basic", "advanced"];
        return Value::String(type_values.choose(&mut rng).unwrap().to_string());
    }

    // Generate realistic values based on property names
    if prop_name_lower.contains("email") {
        let user_num = rng.gen_range(1..=999);
        return Value::String(format!("user{}@example.com", user_num));
    } else if prop_name_lower.contains("name") {
        if prop_name_lower.contains("first") {
            let names = vec!["John", "Jane", "Alice", "Bob", "Charlie"];
            return Value::String(names.choose(&mut rng).unwrap().to_string());
        } else if prop_name_lower.contains("last") {
            let names = vec!["Smith", "Johnson", "Williams", "Brown", "Jones"];
            return Value::String(names.choose(&mut rng).unwrap().to_string());
        } else {
            return Value::String("Test Pet".to_string());  // Changed to "Test Pet" for pet APIs
        }
    } else if prop_name_lower.contains("phone") {
        let area = rng.gen_range(100..=999);
        let exchange = rng.gen_range(1000..=9999);
        return Value::String(format!("+1-555-{}-{}", area, exchange));
    } else if prop_name_lower.contains("address") {
        return Value::String("123 Test Street, Test City, TC 12345".to_string());
    } else if prop_name_lower.contains("age") {
        return Value::Number(serde_json::Number::from(rng.gen_range(18..=80)));
    } else if prop_name_lower.contains("price") || prop_name_lower.contains("amount") {
        let price = (rng.gen_range(1000..=100000) as f64) / 100.0; // 10.00 to 1000.00
        return Value::Number(serde_json::Number::from_f64(price).unwrap());
    } else if prop_name_lower.contains("date") {
        let days_offset = rng.gen_range(-30..=30);
        let date = chrono::Utc::now() + chrono::Duration::days(days_offset);
        return Value::String(date.to_rfc3339());
    } else if prop_name_lower.contains("url") {
        return Value::String("https://example.com/test".to_string());
    } else if prop_name_lower.contains("description") {
        return Value::String("This is a test description for the API endpoint.".to_string());
    }
    
    // Fall back to schema-based generation
    generate_schema_example(schema)
}

/// Substitute path parameters in URL
pub fn substitute_path_parameters(path: &str, path_params: &HashMap<String, Value>) -> String {
    let mut actual_path = path.to_string();
    for (param_name, param_value) in path_params {
        let placeholder = format!("{{{}}}", param_name);
        let value_str = match param_value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => "unknown".to_string(),
        };
        actual_path = actual_path.replace(&placeholder, &value_str);
    }
    actual_path
}

/// Get expected success status code for a method
pub fn get_expected_success_status(responses: &HashMap<String, Value>, method: &str) -> u16 {
    // Look for success responses (2xx)
    for code in responses.keys() {
        if code.starts_with('2') {
            if let Ok(status_code) = code.parse::<u16>() {
                return status_code;
            }
        }
    }
    
    // Default success codes by method
    match method.to_uppercase().as_str() {
        "GET" => 200,
        "POST" => 201,
        "PUT" => 200,
        "PATCH" => 200,
        "DELETE" => 204,
        _ => 200,
    }
}

/// Resolve schema references
pub fn resolve_schema_ref(schema: &Value, api_spec: &Value) -> Value {
    if let Some(ref_path) = schema.get("$ref").and_then(|r| r.as_str()) {
        if ref_path.starts_with("#/") {
            // Navigate to the referenced schema
            let parts: Vec<&str> = ref_path[2..].split('/').collect();
            let mut resolved = api_spec;
            for part in parts {
                if let Some(next) = resolved.get(part) {
                    resolved = next;
                } else {
                    return schema.clone(); // Return original if reference not found
                }
            }
            return resolved.clone();
        }
    }
    schema.clone()
}