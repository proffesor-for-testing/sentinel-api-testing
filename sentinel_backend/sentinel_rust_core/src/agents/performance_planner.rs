//! Performance-Planner-Agent: Generates comprehensive performance test plans and scripts.
//! 
//! This agent specializes in creating performance test configurations for various testing
//! frameworks like k6, JMeter, and Locust. It generates realistic load patterns, stress
//! tests, spike tests, and system-wide performance scenarios.

use async_trait::async_trait;
// use rand::prelude::*;
use serde_json::{Value, Map, Number};
use std::collections::HashMap;

use crate::agents::{Agent, BaseAgent};
use crate::agents::utils::*;
use crate::types::{AgentTask, AgentResult, TestCase, EndpointInfo, Assertion};

/// Agent responsible for generating performance test plans and configurations
pub struct PerformancePlannerAgent {
    base: BaseAgent,
    /// Default number of virtual users for performance tests
    default_users: u32,
    /// Maximum number of virtual users
    max_users: u32,
    /// Test duration in seconds
    test_duration: u32,
    /// Ramp-up time in seconds
    ramp_up_time: u32,
    /// Think time between requests in seconds
    think_time: u32,
}

#[derive(Debug, Clone)]
struct LoadProfile {
    name: String,
    category: String,
    duration: String,
    virtual_users: u32,
    ramp_up_time: String,
    ramp_down_time: String,
    think_time: String,
    expected_response_time: String,
    expected_throughput: String,
    success_criteria: SuccessCriteria,
}

#[derive(Debug, Clone)]
struct StressProfile {
    name: String,
    duration: String,
    max_virtual_users: u32,
    ramp_up_strategy: String,
    breaking_point_detection: BreakingPointDetection,
    recovery_validation: bool,
    success_criteria: StressSuccessCriteria,
}

#[derive(Debug, Clone)]
struct SpikeProfile {
    name: String,
    baseline_users: u32,
    spike_users: u32,
    spike_duration: String,
    spike_pattern: String,
    recovery_time: String,
    success_criteria: SpikeSuccessCriteria,
}

#[derive(Debug, Clone)]
struct SuccessCriteria {
    response_time_p95: String,
    error_rate: String,
    throughput_min: String,
}

#[derive(Debug, Clone)]
struct StressSuccessCriteria {
    breaking_point_identified: bool,
    recovery_time: String,
    post_recovery_performance: String,
}

#[derive(Debug, Clone)]
struct SpikeSuccessCriteria {
    spike_handling: String,
    recovery_time: String,
    error_rate_during_spike: String,
}

#[derive(Debug, Clone)]
struct BreakingPointDetection {
    response_time_threshold: String,
    error_rate_threshold: String,
    throughput_degradation: String,
}

#[derive(Debug, Clone)]
struct ApiAnalysis {
    total_endpoints: usize,
    read_endpoints: usize,
    write_endpoints: usize,
    critical_paths: Vec<CriticalPath>,
    data_intensive_operations: Vec<DataIntensiveOperation>,
    authentication_required: bool,
    estimated_complexity: String,
    recommended_load_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
struct CriticalPath {
    path: String,
    method: String,
    reason: String,
}

#[derive(Debug, Clone)]
struct DataIntensiveOperation {
    path: String,
    method: String,
    operation_type: String,
}

#[derive(Debug, Clone)]
struct WorkflowStep {
    action: String,
    weight: f64,
}

#[derive(Debug, Clone)]
struct PerformanceWorkflow {
    name: String,
    category: String,
    concurrent_workflows: u32,
    duration: String,
    steps: Vec<WorkflowStep>,
    success_criteria: WorkflowSuccessCriteria,
}

#[derive(Debug, Clone)]
struct WorkflowSuccessCriteria {
    workflow_completion_rate: String,
    average_workflow_time: String,
    error_rate: String,
}

impl PerformancePlannerAgent {
    pub fn new() -> Self {
        Self {
            base: BaseAgent::new("Performance-Planner-Agent".to_string()),
            default_users: 10,
            max_users: 1000,
            test_duration: 60,
            ramp_up_time: 30,
            think_time: 1,
        }
    }
    
    /// Generate performance test cases for all endpoints
    async fn generate_performance_tests(&self, api_spec: &Value) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        
        // Extract endpoints and analyze API characteristics
        let endpoints = self.base.extract_endpoints(api_spec);
        let api_analysis = self.analyze_api_performance_characteristics(&endpoints);
        
        // Generate different types of performance tests
        for endpoint in &endpoints {
            // Generate load test scenarios
            test_cases.extend(
                self.generate_load_test_scenarios(endpoint, &api_analysis)
            );
            
            // Generate stress test scenarios
            test_cases.extend(
                self.generate_stress_test_scenarios(endpoint, &api_analysis)
            );
            
            // Generate spike test scenarios
            test_cases.extend(
                self.generate_spike_test_scenarios(endpoint, &api_analysis)
            );
        }
        
        // Generate system-wide performance tests
        test_cases.extend(self.generate_system_wide_tests(&api_analysis));
        
        test_cases
    }
    
    /// Analyze API specification to understand performance characteristics
    fn analyze_api_performance_characteristics(&self, endpoints: &[EndpointInfo]) -> ApiAnalysis {
        let mut analysis = ApiAnalysis {
            total_endpoints: endpoints.len(),
            read_endpoints: 0,
            write_endpoints: 0,
            critical_paths: Vec::new(),
            data_intensive_operations: Vec::new(),
            authentication_required: false,
            estimated_complexity: "medium".to_string(),
            recommended_load_patterns: Vec::new(),
        };
        
        for endpoint in endpoints {
            // Categorize operations
            if endpoint.method == "GET" {
                analysis.read_endpoints += 1;
            } else {
                analysis.write_endpoints += 1;
            }
            
            // Identify critical paths
            if self.is_critical_path(&endpoint.path, &endpoint.method, &endpoint.operation) {
                analysis.critical_paths.push(CriticalPath {
                    path: endpoint.path.clone(),
                    method: endpoint.method.clone(),
                    reason: self.get_criticality_reason(&endpoint.path, &endpoint.method, &endpoint.operation),
                });
            }
            
            // Identify data-intensive operations
            if self.is_data_intensive(&endpoint.path, &endpoint.method, &endpoint.operation) {
                analysis.data_intensive_operations.push(DataIntensiveOperation {
                    path: endpoint.path.clone(),
                    method: endpoint.method.clone(),
                    operation_type: self.get_data_intensity_type(&endpoint.path, &endpoint.method, &endpoint.operation),
                });
            }
            
            // Check for authentication requirements
            if self.requires_authentication(&endpoint.operation) {
                analysis.authentication_required = true;
            }
        }
        
        // Determine overall complexity
        analysis.estimated_complexity = self.estimate_api_complexity(&analysis);
        
        // Generate recommended load patterns
        analysis.recommended_load_patterns = self.generate_load_patterns(&analysis);
        
        analysis
    }
    
    /// Generate load testing scenarios for an endpoint
    fn generate_load_test_scenarios(&self, endpoint: &EndpointInfo, api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let profiles = self.get_load_profiles_for_operation(&endpoint.path, &endpoint.method, &endpoint.operation, api_analysis);
        
        for profile in profiles {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("Accept".to_string(), "application/json".to_string());
            headers.insert("User-Agent".to_string(), "Sentinel-Performance-Test/1.0".to_string());
            
            // Generate query parameters optimized for performance testing
            let query_params = self.generate_performance_query_params(&endpoint.parameters);
            
            // Generate request body if needed
            let body = if ["POST", "PUT", "PATCH"].contains(&endpoint.method.as_str()) {
                endpoint.request_body.as_ref().map(|rb| {
                    self.generate_minimal_request_body(rb)
                })
            } else {
                None
            };
            
            // Create performance configuration
            let mut performance_config = Map::new();
            performance_config.insert("test_type".to_string(), Value::String("load".to_string()));
            performance_config.insert("duration".to_string(), Value::String(profile.duration.clone()));
            performance_config.insert("virtual_users".to_string(), Value::Number(Number::from(profile.virtual_users)));
            performance_config.insert("ramp_up_time".to_string(), Value::String(profile.ramp_up_time.clone()));
            performance_config.insert("ramp_down_time".to_string(), Value::String(profile.ramp_down_time.clone()));
            performance_config.insert("think_time".to_string(), Value::String(profile.think_time.clone()));
            performance_config.insert("expected_response_time".to_string(), Value::String(profile.expected_response_time.clone()));
            performance_config.insert("expected_throughput".to_string(), Value::String(profile.expected_throughput.clone()));
            
            // Generate k6 script
            let k6_script = self.generate_k6_script(&endpoint.path, &endpoint.method, &profile);
            
            // Generate JMeter configuration
            let jmeter_config = self.generate_jmeter_config(&endpoint.path, &endpoint.method, &profile);
            
            // Generate Locust script
            let locust_script = self.generate_locust_script(&endpoint.path, &endpoint.method, &profile);
            
            // Create assertions for performance validation
            let assertions = vec![
                Assertion {
                    assertion_type: "response_time_p95".to_string(),
                    expected: Value::String(profile.success_criteria.response_time_p95.clone()),
                    path: None,
                },
                Assertion {
                    assertion_type: "error_rate".to_string(),
                    expected: Value::String(profile.success_criteria.error_rate.clone()),
                    path: None,
                },
                Assertion {
                    assertion_type: "throughput_min".to_string(),
                    expected: Value::String(profile.success_criteria.throughput_min.clone()),
                    path: None,
                },
            ];
            
            let mut test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                format!("Load Test: {} {} - {}", endpoint.method, endpoint.path, profile.name),
                Some(headers),
                Some(query_params),
                body,
                200,
                Some(assertions),
            );
            
            // Add performance-specific metadata
            test_case.test_type = "performance-planner".to_string();
            test_case.tags = vec![
                "performance".to_string(),
                "load-test".to_string(),
                format!("{}-method", endpoint.method.to_lowercase()),
                profile.category.clone(),
            ];
            
            // Store performance configuration as metadata
            let mut metadata = Map::new();
            metadata.insert("performance_config".to_string(), Value::Object(performance_config));
            metadata.insert("k6_script".to_string(), Value::String(k6_script));
            metadata.insert("jmeter_config".to_string(), jmeter_config);
            metadata.insert("locust_script".to_string(), Value::String(locust_script));
            
            // Convert metadata to test case (this would need to be stored appropriately in actual implementation)
            test_cases.push(test_case);
        }
        
        test_cases
    }
    
    /// Generate stress testing scenarios for an endpoint
    fn generate_stress_test_scenarios(&self, endpoint: &EndpointInfo, api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let profiles = self.get_stress_profiles_for_operation(&endpoint.path, &endpoint.method, &endpoint.operation, api_analysis);
        
        for profile in profiles {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("Accept".to_string(), "application/json".to_string());
            headers.insert("User-Agent".to_string(), "Sentinel-Stress-Test/1.0".to_string());
            
            // Generate k6 stress script
            let _k6_script = self.generate_k6_stress_script(&endpoint.path, &endpoint.method, &profile);
            
            // Create assertions for stress testing
            let assertions = vec![
                Assertion {
                    assertion_type: "breaking_point_identified".to_string(),
                    expected: Value::Bool(profile.success_criteria.breaking_point_identified),
                    path: None,
                },
                Assertion {
                    assertion_type: "recovery_time".to_string(),
                    expected: Value::String(profile.success_criteria.recovery_time.clone()),
                    path: None,
                },
            ];
            
            let mut test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                format!("Stress Test: {} {} - {}", endpoint.method, endpoint.path, profile.name),
                Some(headers),
                Some(HashMap::new()),
                None,
                200,
                Some(assertions),
            );
            
            test_case.test_type = "performance-planner".to_string();
            test_case.tags = vec![
                "performance".to_string(),
                "stress-test".to_string(),
                format!("{}-method", endpoint.method.to_lowercase()),
                "breaking-point".to_string(),
            ];
            
            test_cases.push(test_case);
        }
        
        test_cases
    }
    
    /// Generate spike testing scenarios for an endpoint
    fn generate_spike_test_scenarios(&self, endpoint: &EndpointInfo, api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let profiles = self.get_spike_profiles_for_operation(&endpoint.path, &endpoint.method, &endpoint.operation, api_analysis);
        
        for profile in profiles {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("Accept".to_string(), "application/json".to_string());
            headers.insert("User-Agent".to_string(), "Sentinel-Spike-Test/1.0".to_string());
            
            // Generate k6 spike script
            let _k6_script = self.generate_k6_spike_script(&endpoint.path, &endpoint.method, &profile);
            
            // Create assertions for spike testing
            let assertions = vec![
                Assertion {
                    assertion_type: "spike_handling".to_string(),
                    expected: Value::String(profile.success_criteria.spike_handling.clone()),
                    path: None,
                },
                Assertion {
                    assertion_type: "error_rate_during_spike".to_string(),
                    expected: Value::String(profile.success_criteria.error_rate_during_spike.clone()),
                    path: None,
                },
            ];
            
            let mut test_case = self.base.create_test_case(
                endpoint.path.clone(),
                endpoint.method.clone(),
                format!("Spike Test: {} {} - {}", endpoint.method, endpoint.path, profile.name),
                Some(headers),
                Some(HashMap::new()),
                None,
                200,
                Some(assertions),
            );
            
            test_case.test_type = "performance-planner".to_string();
            test_case.tags = vec![
                "performance".to_string(),
                "spike-test".to_string(),
                format!("{}-method", endpoint.method.to_lowercase()),
                "traffic-spike".to_string(),
            ];
            
            test_cases.push(test_case);
        }
        
        test_cases
    }
    
    /// Generate system-wide performance tests
    fn generate_system_wide_tests(&self, api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let workflows = self.identify_performance_workflows(api_analysis);
        
        for workflow in workflows {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("Accept".to_string(), "application/json".to_string());
            headers.insert("User-Agent".to_string(), "Sentinel-Workflow-Test/1.0".to_string());
            
            // Generate k6 workflow script
            let _k6_script = self.generate_k6_workflow_script(&workflow);
            
            // Create assertions for workflow testing
            let assertions = vec![
                Assertion {
                    assertion_type: "workflow_completion_rate".to_string(),
                    expected: Value::String(workflow.success_criteria.workflow_completion_rate.clone()),
                    path: None,
                },
                Assertion {
                    assertion_type: "average_workflow_time".to_string(),
                    expected: Value::String(workflow.success_criteria.average_workflow_time.clone()),
                    path: None,
                },
            ];
            
            let mut test_case = self.base.create_test_case(
                "/workflow".to_string(),
                "GET".to_string(),
                format!("System Performance Test: {}", workflow.name),
                Some(headers),
                Some(HashMap::new()),
                None,
                200,
                Some(assertions),
            );
            
            test_case.test_type = "performance-planner".to_string();
            test_case.tags = vec![
                "performance".to_string(),
                "system-wide".to_string(),
                "workflow".to_string(),
                workflow.category.clone(),
            ];
            
            test_cases.push(test_case);
        }
        
        test_cases
    }
    
    /// Check if endpoint is a critical path
    fn is_critical_path(&self, path: &str, _method: &str, operation: &Value) -> bool {
        let critical_indicators = [
            "login", "auth", "payment", "checkout", "order", "search",
            "dashboard", "home", "index", "list", "feed"
        ];
        
        let path_lower = path.to_lowercase();
        let summary_lower = operation
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_lowercase();
        
        critical_indicators.iter().any(|&indicator| {
            path_lower.contains(indicator) || summary_lower.contains(indicator)
        })
    }
    
    /// Get reason for criticality
    fn get_criticality_reason(&self, path: &str, method: &str, _operation: &Value) -> String {
        let path_lower = path.to_lowercase();
        
        if path_lower.contains("auth") || path_lower.contains("login") {
            "Authentication endpoint - critical for user access".to_string()
        } else if path_lower.contains("payment") || path_lower.contains("checkout") {
            "Payment processing - critical for business operations".to_string()
        } else if path_lower.contains("search") {
            "Search functionality - high user interaction".to_string()
        } else if method == "GET" && (path_lower.contains("list") || path_lower.contains("index")) {
            "Data listing endpoint - potentially high traffic".to_string()
        } else {
            "High-impact user-facing functionality".to_string()
        }
    }
    
    /// Check if operation is data-intensive
    fn is_data_intensive(&self, path: &str, _method: &str, operation: &Value) -> bool {
        let data_indicators = [
            "upload", "download", "export", "import", "bulk", "batch",
            "file", "image", "video", "document", "report"
        ];
        
        let path_lower = path.to_lowercase();
        let summary_lower = operation
            .get("summary")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_lowercase();
        
        // Check request body for file uploads
        if let Some(request_body) = operation.get("requestBody") {
            if let Some(content) = request_body.get("content") {
                if content.get("multipart/form-data").is_some() || 
                   content.get("application/octet-stream").is_some() {
                    return true;
                }
            }
        }
        
        data_indicators.iter().any(|&indicator| {
            path_lower.contains(indicator) || summary_lower.contains(indicator)
        })
    }
    
    /// Get data intensity type
    fn get_data_intensity_type(&self, path: &str, _method: &str, _operation: &Value) -> String {
        let path_lower = path.to_lowercase();
        
        if path_lower.contains("upload") || path_lower.contains("file") {
            "file_upload".to_string()
        } else if path_lower.contains("download") {
            "file_download".to_string()
        } else if path_lower.contains("export") || path_lower.contains("report") {
            "data_export".to_string()
        } else if path_lower.contains("bulk") || path_lower.contains("batch") {
            "bulk_operation".to_string()
        } else {
            "large_payload".to_string()
        }
    }
    
    /// Check if operation requires authentication
    fn requires_authentication(&self, operation: &Value) -> bool {
        // Check security field
        if operation.get("security").is_some() {
            return true;
        }
        
        // Check for auth-related status codes in responses
        if let Some(responses) = operation.get("responses").and_then(|r| r.as_object()) {
            if responses.contains_key("401") || responses.contains_key("403") {
                return true;
            }
        }
        
        false
    }
    
    /// Estimate API complexity
    fn estimate_api_complexity(&self, analysis: &ApiAnalysis) -> String {
        let complexity_score = analysis.total_endpoints + 
                              (analysis.critical_paths.len() * 2) + 
                              (analysis.data_intensive_operations.len() * 3);
        
        if complexity_score < 10 {
            "low".to_string()
        } else if complexity_score < 25 {
            "medium".to_string()
        } else {
            "high".to_string()
        }
    }
    
    /// Generate recommended load patterns
    fn generate_load_patterns(&self, analysis: &ApiAnalysis) -> Vec<String> {
        let mut patterns = Vec::new();
        
        let read_ratio = if analysis.total_endpoints > 0 {
            analysis.read_endpoints as f64 / analysis.total_endpoints as f64
        } else {
            0.0
        };
        
        if read_ratio > 0.7 {
            patterns.push("read_heavy".to_string());
        } else if read_ratio < 0.3 {
            patterns.push("write_heavy".to_string());
        } else {
            patterns.push("balanced".to_string());
        }
        
        if !analysis.critical_paths.is_empty() {
            patterns.push("critical_path_focused".to_string());
        }
        
        if !analysis.data_intensive_operations.is_empty() {
            patterns.push("data_intensive".to_string());
        }
        
        if analysis.authentication_required {
            patterns.push("authenticated_sessions".to_string());
        }
        
        patterns
    }
    
    /// Get load profiles for a specific operation
    fn get_load_profiles_for_operation(
        &self, 
        path: &str, 
        method: &str, 
        operation: &Value, 
        _api_analysis: &ApiAnalysis
    ) -> Vec<LoadProfile> {
        let mut profiles = Vec::new();
        
        // Base profile
        let base_profile = LoadProfile {
            name: "Standard Load".to_string(),
            category: "standard".to_string(),
            duration: format!("{}s", self.test_duration),
            virtual_users: self.default_users,
            ramp_up_time: format!("{}s", self.ramp_up_time),
            ramp_down_time: format!("{}s", self.ramp_up_time),
            think_time: format!("{}s", self.think_time),
            expected_response_time: "500ms".to_string(),
            expected_throughput: format!("{} rps", self.default_users * 2),
            success_criteria: SuccessCriteria {
                response_time_p95: "1s".to_string(),
                error_rate: "1%".to_string(),
                throughput_min: format!("{} rps", (self.default_users as f64 * 1.5) as u32),
            },
        };
        
        // Adjust for critical paths
        if self.is_critical_path(path, method, operation) {
            let mut critical_profile = base_profile.clone();
            critical_profile.name = "Critical Path Load".to_string();
            critical_profile.category = "critical".to_string();
            critical_profile.virtual_users = (self.default_users * 2).min(self.max_users / 10);
            critical_profile.expected_response_time = "200ms".to_string();
            critical_profile.expected_throughput = format!("{} rps", (self.default_users * 5).min(self.max_users / 5));
            critical_profile.success_criteria = SuccessCriteria {
                response_time_p95: "500ms".to_string(),
                error_rate: "0.5%".to_string(),
                throughput_min: format!("{} rps", (self.default_users * 4).min(self.max_users / 6)),
            };
            profiles.push(critical_profile);
        }
        
        // Adjust for data-intensive operations
        if self.is_data_intensive(path, method, operation) {
            let mut data_profile = base_profile.clone();
            data_profile.name = "Data Intensive Load".to_string();
            data_profile.category = "data_intensive".to_string();
            data_profile.virtual_users = (self.default_users / 2).max(2);
            data_profile.think_time = format!("{}s", self.think_time * 3);
            data_profile.expected_response_time = "2s".to_string();
            data_profile.expected_throughput = format!("{} rps", (self.default_users / 2).max(2));
            data_profile.success_criteria = SuccessCriteria {
                response_time_p95: "5s".to_string(),
                error_rate: "2%".to_string(),
                throughput_min: format!("{} rps", (self.default_users / 3).max(1)),
            };
            profiles.push(data_profile);
        }
        
        if profiles.is_empty() {
            profiles.push(base_profile);
        }
        
        profiles
    }
    
    /// Get stress profiles for a specific operation
    fn get_stress_profiles_for_operation(
        &self,
        _path: &str,
        _method: &str,
        _operation: &Value,
        _api_analysis: &ApiAnalysis,
    ) -> Vec<StressProfile> {
        vec![StressProfile {
            name: "Breaking Point Stress".to_string(),
            duration: format!("{}s", self.test_duration * 10),
            max_virtual_users: (self.max_users).min(self.default_users * 10),
            ramp_up_strategy: "gradual_increase".to_string(),
            breaking_point_detection: BreakingPointDetection {
                response_time_threshold: "5s".to_string(),
                error_rate_threshold: "10%".to_string(),
                throughput_degradation: "50%".to_string(),
            },
            recovery_validation: true,
            success_criteria: StressSuccessCriteria {
                breaking_point_identified: true,
                recovery_time: format!("{}s", self.ramp_up_time * 4),
                post_recovery_performance: "90% of baseline".to_string(),
            },
        }]
    }
    
    /// Get spike profiles for a specific operation
    fn get_spike_profiles_for_operation(
        &self,
        _path: &str,
        _method: &str,
        _operation: &Value,
        _api_analysis: &ApiAnalysis,
    ) -> Vec<SpikeProfile> {
        vec![SpikeProfile {
            name: "Traffic Spike".to_string(),
            baseline_users: self.default_users,
            spike_users: (self.default_users * 5).min(self.max_users / 2),
            spike_duration: format!("{}s", self.test_duration * 2),
            spike_pattern: "instant".to_string(),
            recovery_time: format!("{}s", self.test_duration * 3),
            success_criteria: SpikeSuccessCriteria {
                spike_handling: "graceful_degradation".to_string(),
                recovery_time: format!("{}s", self.ramp_up_time * 2),
                error_rate_during_spike: "5%".to_string(),
            },
        }]
    }
    
    /// Identify performance workflows for system-wide testing
    fn identify_performance_workflows(&self, _api_analysis: &ApiAnalysis) -> Vec<PerformanceWorkflow> {
        vec![
            PerformanceWorkflow {
                name: "User Authentication Workflow".to_string(),
                category: "authentication".to_string(),
                concurrent_workflows: 5,
                duration: "10m".to_string(),
                steps: vec![
                    WorkflowStep { action: "register".to_string(), weight: 0.1 },
                    WorkflowStep { action: "login".to_string(), weight: 0.8 },
                    WorkflowStep { action: "access_protected_resource".to_string(), weight: 0.1 },
                ],
                success_criteria: WorkflowSuccessCriteria {
                    workflow_completion_rate: "95%".to_string(),
                    average_workflow_time: "10s".to_string(),
                    error_rate: "2%".to_string(),
                },
            },
            PerformanceWorkflow {
                name: "CRUD Operations Workflow".to_string(),
                category: "crud".to_string(),
                concurrent_workflows: 10,
                duration: "15m".to_string(),
                steps: vec![
                    WorkflowStep { action: "create_resource".to_string(), weight: 0.2 },
                    WorkflowStep { action: "read_resource".to_string(), weight: 0.5 },
                    WorkflowStep { action: "update_resource".to_string(), weight: 0.2 },
                    WorkflowStep { action: "delete_resource".to_string(), weight: 0.1 },
                ],
                success_criteria: WorkflowSuccessCriteria {
                    workflow_completion_rate: "98%".to_string(),
                    average_workflow_time: "5s".to_string(),
                    error_rate: "1%".to_string(),
                },
            },
        ]
    }
    
    /// Generate performance-optimized query parameters
    fn generate_performance_query_params(&self, parameters: &[Value]) -> HashMap<String, Value> {
        let mut query_params = HashMap::new();
        
        for param in parameters {
            if let (Some(param_in), Some(param_name)) = (
                param.get("in").and_then(|i| i.as_str()),
                param.get("name").and_then(|n| n.as_str()),
            ) {
                if param_in == "query" {
                    let param_type = param.get("schema")
                        .and_then(|s| s.get("type"))
                        .and_then(|t| t.as_str())
                        .unwrap_or("string");
                    
                    // Use performance-friendly values
                    if param_type == "integer" {
                        query_params.insert(param_name.to_string(), Value::Number(Number::from(1)));
                    } else if param_name.to_lowercase().contains("limit") || 
                             param_name.to_lowercase().contains("size") || 
                             param_name.to_lowercase().contains("count") {
                        query_params.insert(param_name.to_string(), Value::Number(Number::from(10)));
                    } else {
                        query_params.insert(param_name.to_string(), Value::String("test".to_string()));
                    }
                }
            }
        }
        
        query_params
    }
    
    /// Generate minimal request body for performance testing
    fn generate_minimal_request_body(&self, request_body: &Value) -> Value {
        if let Some(content) = request_body.get("content") {
            if let Some(json_content) = content.get("application/json") {
                if let Some(schema) = json_content.get("schema") {
                    return self.generate_minimal_object_from_schema(schema);
                }
            }
        }
        
        serde_json::json!({"test": "data"})
    }
    
    /// Generate minimal object from schema (only required fields)
    fn generate_minimal_object_from_schema(&self, schema: &Value) -> Value {
        if schema.get("type").and_then(|t| t.as_str()) == Some("object") {
            let mut obj = Map::new();
            
            if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
                if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
                    for req_field in required {
                        if let Some(field_name) = req_field.as_str() {
                            if let Some(field_schema) = properties.get(field_name) {
                                obj.insert(field_name.to_string(), generate_schema_example(field_schema));
                            }
                        }
                    }
                }
            }
            
            Value::Object(obj)
        } else {
            generate_schema_example(schema)
        }
    }
    
    /// Generate k6 JavaScript test script
    fn generate_k6_script(&self, path: &str, method: &str, profile: &LoadProfile) -> String {
        format!(r#"
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    stages: [
        {{ duration: '{}', target: {} }},
        {{ duration: '{}', target: {} }},
        {{ duration: '{}', target: 0 }},
    ],
    thresholds: {{
        http_req_duration: ['p(95)<{}'],
        http_req_failed: ['rate<{}'],
    }},
}};

export default function () {{
    let response = http.{}('${{__ENV.BASE_URL}}{}');
    
    check(response, {{
        'status is 200': (r) => r.status === 200,
        'response time < {}': (r) => r.timings.duration < {},
    }});
    
    sleep({});
}}
"#,
            profile.ramp_up_time,
            profile.virtual_users,
            profile.duration,
            profile.virtual_users,
            profile.ramp_down_time,
            profile.success_criteria.response_time_p95.replace("s", "000"),
            profile.success_criteria.error_rate.replace("%", "").parse::<f64>().unwrap_or(0.01) / 100.0,
            method.to_lowercase(),
            path,
            profile.expected_response_time,
            profile.expected_response_time.replace("ms", ""),
            profile.think_time.replace("s", "")
        ).trim().to_string()
    }
    
    /// Generate k6 stress test script
    fn generate_k6_stress_script(&self, path: &str, method: &str, profile: &StressProfile) -> String {
        format!(r#"
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    stages: [
        {{ duration: '2m', target: 10 }},
        {{ duration: '5m', target: {} }},
        {{ duration: '2m', target: {} }},
        {{ duration: '1m', target: 0 }},
    ],
    thresholds: {{
        http_req_duration: ['p(95)<{}'],
        http_req_failed: ['rate<{}'],
    }},
}};

export default function () {{
    let response = http.{}('${{__ENV.BASE_URL}}{}');
    
    check(response, {{
        'status is not 5xx': (r) => r.status < 500,
        'response time acceptable': (r) => r.timings.duration < 10000,
    }});
    
    sleep(1);
}}
"#,
            profile.max_virtual_users,
            profile.max_virtual_users,
            profile.breaking_point_detection.response_time_threshold.replace("s", "000"),
            profile.breaking_point_detection.error_rate_threshold.replace("%", "").parse::<f64>().unwrap_or(0.10) / 100.0,
            method.to_lowercase(),
            path
        ).trim().to_string()
    }
    
    /// Generate k6 spike test script
    fn generate_k6_spike_script(&self, path: &str, method: &str, profile: &SpikeProfile) -> String {
        format!(r#"
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    stages: [
        {{ duration: '1m', target: {} }},
        {{ duration: '10s', target: {} }},
        {{ duration: '{}', target: {} }},
        {{ duration: '10s', target: {} }},
        {{ duration: '{}', target: {} }},
    ],
    thresholds: {{
        http_req_duration: ['p(95)<2000'],
        http_req_failed: ['rate<{}'],
    }},
}};

export default function () {{
    let response = http.{}('${{__ENV.BASE_URL}}{}');
    
    check(response, {{
        'status is successful': (r) => r.status >= 200 && r.status < 400,
        'spike handling': (r) => r.timings.duration < 5000,
    }});
    
    sleep(1);
}}
"#,
            profile.baseline_users,
            profile.spike_users,
            profile.spike_duration,
            profile.spike_users,
            profile.baseline_users,
            profile.recovery_time,
            profile.baseline_users,
            profile.success_criteria.error_rate_during_spike.replace("%", "").parse::<f64>().unwrap_or(0.05) / 100.0,
            method.to_lowercase(),
            path
        ).trim().to_string()
    }
    
    /// Generate k6 workflow script
    fn generate_k6_workflow_script(&self, workflow: &PerformanceWorkflow) -> String {
        let mut script = format!(r#"
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    vus: {},
    duration: '{}',
    thresholds: {{
        http_req_duration: ['p(95)<5000'],
        http_req_failed: ['rate<{}'],
    }},
}};

export default function () {{
    // {} workflow
"#,
            workflow.concurrent_workflows,
            workflow.duration,
            workflow.success_criteria.error_rate.replace("%", "").parse::<f64>().unwrap_or(0.02) / 100.0,
            workflow.name
        );
        
        for step in &workflow.steps {
            script.push_str(&format!(r#"
    // {} (weight: {})
    if (Math.random() < {}) {{
        let response = http.get('${{__ENV.BASE_URL}}/{}');
        check(response, {{
            '{} successful': (r) => r.status < 400,
        }});
    }}
"#,
                step.action,
                step.weight,
                step.weight,
                step.action,
                step.action
            ));
        }
        
        script.push_str(r#"
    sleep(1);
}
"#);
        
        script.trim().to_string()
    }
    
    /// Generate JMeter test configuration
    fn generate_jmeter_config(&self, path: &str, method: &str, profile: &LoadProfile) -> Value {
        serde_json::json!({
            "test_plan": {
                "name": format!("Performance Test - {} {}", method.to_uppercase(), path),
                "thread_group": {
                    "threads": profile.virtual_users,
                    "ramp_up": profile.ramp_up_time,
                    "duration": profile.duration
                },
                "http_request": {
                    "method": method.to_uppercase(),
                    "path": path,
                    "headers": {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "User-Agent": "Sentinel-Performance-Test/1.0"
                    }
                },
                "assertions": [
                    {
                        "type": "response_time",
                        "value": profile.expected_response_time
                    },
                    {
                        "type": "response_code",
                        "value": "200"
                    }
                ]
            }
        })
    }
    
    /// Generate Locust Python script
    fn generate_locust_script(&self, path: &str, method: &str, profile: &LoadProfile) -> String {
        format!(r#"
from locust import HttpUser, task, between

class PerformanceUser(HttpUser):
    wait_time = between(1, {})
    
    @task
    def {}_{}_test(self):
        response = self.client.{}('{}')
        if response.status_code != 200:
            response.failure(f"Got status code {{response.status_code}}")
        
        # Check response time
        if response.elapsed.total_seconds() > {}:
            response.failure(f"Response time too slow: {{response.elapsed.total_seconds()}}s")

# Run with: locust -f locustfile.py --users {} --spawn-rate {} --run-time {}
"#,
            self.think_time + 2,
            method.to_lowercase(),
            path.replace("/", "").replace("{", "").replace("}", ""),
            method.to_lowercase(),
            path,
            profile.expected_response_time.replace("ms", "").parse::<f64>().unwrap_or(500.0) / 1000.0,
            profile.virtual_users,
            profile.virtual_users / self.ramp_up_time.max(1),
            profile.duration
        ).trim().to_string()
    }
}

#[async_trait]
impl Agent for PerformancePlannerAgent {
    fn agent_type(&self) -> &str {
        &self.base.agent_type
    }
    
    async fn execute(&self, task: AgentTask, api_spec: Value) -> AgentResult {
        let start_time = std::time::Instant::now();
        
        match self.execute_internal(task.clone(), api_spec).await {
            Ok(mut result) => {
                let processing_time = start_time.elapsed().as_millis() as u64;
                result.metadata.insert(
                    "processing_time_ms".to_string(),
                    Value::Number(Number::from(processing_time)),
                );
                result
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

impl PerformancePlannerAgent {
    async fn execute_internal(&self, task: AgentTask, api_spec: Value) -> Result<AgentResult, String> {
        // Generate performance test cases
        let test_cases = self.generate_performance_tests(&api_spec).await;
        
        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert(
            "total_test_cases".to_string(),
            Value::Number(Number::from(test_cases.len())),
        );
        metadata.insert(
            "test_types".to_string(),
            Value::Array(vec![
                Value::String("Load".to_string()),
                Value::String("Stress".to_string()),
                Value::String("Spike".to_string()),
                Value::String("System-wide".to_string()),
                Value::String("Benchmark".to_string()),
            ]),
        );
        metadata.insert(
            "performance_frameworks".to_string(),
            Value::Array(vec![
                Value::String("k6".to_string()),
                Value::String("JMeter".to_string()),
                Value::String("Locust".to_string()),
            ]),
        );
        
        Ok(AgentResult {
            task_id: task.task_id,
            agent_type: self.agent_type().to_string(),
            status: "success".to_string(),
            test_cases,
            metadata,
            error_message: None,
        })
    }
}