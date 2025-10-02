//! Performance-Planner-Agent: Generates comprehensive performance test plans and scripts.
//! 
//! This agent specializes in creating performance test configurations for various testing
//! frameworks like k6, JMeter, and Locust. It generates realistic load patterns, stress
//! tests, spike tests, and system-wide performance scenarios.

use async_trait::async_trait;
use rand::prelude::*;
use serde_json::{Value, Map, Number};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};

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

#[derive(Debug, Clone)]
struct AdvancedLoadPattern {
    pattern_name: String,
    pattern_type: LoadPatternType,
    stages: Vec<LoadStage>,
    user_behavior: UserBehaviorModel,
    geographic_distribution: Vec<GeographicLocation>,
    device_profiles: Vec<DeviceProfile>,
    think_time_distribution: ThinkTimeDistribution,
}

#[derive(Debug, Clone)]
enum LoadPatternType {
    GradualRampUp,
    SteppedLoad,
    SpikeAndRecover,
    SoakTest,
    VolumeTest,
    CapacityPlanning,
    RealUserSimulation,
    BusinessHourSimulation,
}

#[derive(Debug, Clone)]
struct LoadStage {
    duration: String,
    target_users: u32,
    ramp_rate: String,
    hold_duration: Option<String>,
}

#[derive(Debug, Clone)]
struct UserBehaviorModel {
    session_duration: String,
    pages_per_session: u32,
    bounce_rate: f64,
    conversion_rate: f64,
    return_user_percentage: f64,
}

#[derive(Debug, Clone)]
struct GeographicLocation {
    region: String,
    percentage: f64,
    latency_overhead: u32, // ms
}

#[derive(Debug, Clone)]
struct DeviceProfile {
    device_type: String,
    percentage: f64,
    performance_multiplier: f64,
}

#[derive(Debug, Clone)]
struct ThinkTimeDistribution {
    min_think_time: u32, // seconds
    max_think_time: u32,
    distribution_type: String, // normal, exponential, uniform
    mean: f64,
    std_deviation: f64,
}

#[derive(Debug, Clone)]
struct ComprehensiveMetrics {
    response_time_metrics: ResponseTimeMetrics,
    throughput_metrics: ThroughputMetrics,
    error_metrics: ErrorMetrics,
    resource_metrics: ResourceMetrics,
    business_metrics: BusinessMetrics,
    custom_slos: Vec<ServiceLevelObjective>,
}

#[derive(Debug, Clone)]
struct ResponseTimeMetrics {
    percentiles: Vec<Percentile>,
    mean_response_time: String,
    min_response_time: String,
    max_response_time: String,
    response_time_distribution: String,
}

#[derive(Debug, Clone)]
struct Percentile {
    percentile: f64,
    threshold: String,
}

#[derive(Debug, Clone)]
struct ThroughputMetrics {
    requests_per_second: String,
    transactions_per_minute: String,
    data_transfer_rate: String,
    concurrent_users: String,
}

#[derive(Debug, Clone)]
struct ErrorMetrics {
    error_rate: String,
    error_types: Vec<ErrorType>,
    timeout_rate: String,
    retry_rate: String,
}

#[derive(Debug, Clone)]
struct ErrorType {
    status_code: u16,
    percentage: f64,
    acceptable_threshold: f64,
}

#[derive(Debug, Clone)]
struct ResourceMetrics {
    cpu_utilization: String,
    memory_utilization: String,
    network_bandwidth: String,
    disk_io: String,
    connection_pool_usage: String,
}

#[derive(Debug, Clone)]
struct BusinessMetrics {
    conversion_rate: String,
    revenue_per_hour: String,
    user_satisfaction_score: String,
    abandonment_rate: String,
}

#[derive(Debug, Clone)]
struct ServiceLevelObjective {
    name: String,
    metric: String,
    threshold: String,
    measurement_window: String,
    priority: String,
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

        // Generate advanced load pattern tests
        test_cases.extend(self.generate_advanced_load_pattern_tests(&endpoints, &api_analysis).await);

        // Generate volume and capacity tests
        test_cases.extend(self.generate_volume_capacity_tests(&endpoints, &api_analysis).await);

        // Generate endurance/soak tests
        test_cases.extend(self.generate_endurance_tests(&endpoints, &api_analysis).await);

        // Generate real user simulation tests
        test_cases.extend(self.generate_real_user_simulation_tests(&endpoints, &api_analysis).await);

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

    /// Generate advanced load pattern tests
    async fn generate_advanced_load_pattern_tests(&self, endpoints: &[EndpointInfo], api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let patterns = self.generate_advanced_load_patterns(api_analysis);

        for pattern in patterns {
            for endpoint in endpoints {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());
                headers.insert("X-Load-Pattern".to_string(), pattern.pattern_name.clone());

                // Create comprehensive metrics configuration
                let metrics = self.create_comprehensive_metrics_config(&pattern, endpoint);

                // Generate pattern-specific test script
                let k6_script = self.generate_advanced_k6_script(&pattern, endpoint);

                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Advanced Load Pattern: {} - {} {}", pattern.pattern_name, endpoint.method, endpoint.path),
                    Some(headers),
                    None,
                    None,
                    200,
                    Some(self.create_advanced_assertions(&metrics)),
                );

                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate volume and capacity planning tests
    async fn generate_volume_capacity_tests(&self, endpoints: &[EndpointInfo], _api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Volume test configurations
        let volume_configs = vec![
            ("High Volume", 1000, "30m"),
            ("Peak Volume", 5000, "15m"),
            ("Max Capacity", 10000, "10m"),
        ];

        for (config_name, users, duration) in volume_configs {
            for endpoint in endpoints {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());
                headers.insert("X-Test-Type".to_string(), "volume".to_string());

                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Volume Test: {} - {} users for {} - {} {}", config_name, users, duration, endpoint.method, endpoint.path),
                    Some(headers),
                    None,
                    None,
                    200,
                    Some(vec![
                        Assertion {
                            assertion_type: "response_time_p99_lt".to_string(),
                            expected: Value::String("5000ms".to_string()), path: None },
                        Assertion {
                            assertion_type: "throughput_gt".to_string(),
                            expected: Value::Number(Number::from(users / 10)), path: None },
                    ]),
                );

                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate endurance/soak tests
    async fn generate_endurance_tests(&self, endpoints: &[EndpointInfo], _api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();

        // Endurance test configurations
        let endurance_configs = vec![
            ("Short Endurance", 50, "2h"),
            ("Long Endurance", 100, "8h"),
            ("Weekend Soak", 200, "72h"),
        ];

        for (config_name, users, duration) in endurance_configs {
            for endpoint in endpoints {
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());
                headers.insert("X-Test-Type".to_string(), "endurance".to_string());

                let test_case = self.base.create_test_case(
                    endpoint.path.clone(),
                    endpoint.method.clone(),
                    format!("Endurance Test: {} - {} users for {} - {} {}", config_name, users, duration, endpoint.method, endpoint.path),
                    Some(headers),
                    None,
                    None,
                    200,
                    Some(vec![
                        Assertion {
                            assertion_type: "memory_leak_detection_eq".to_string(),
                            expected: Value::Bool(false), path: None },
                        Assertion {
                            assertion_type: "performance_degradation_lt".to_string(),
                            expected: Value::String("10%".to_string()), path: None },
                    ]),
                );

                test_cases.push(test_case);
            }
        }

        test_cases
    }

    /// Generate real user simulation tests
    async fn generate_real_user_simulation_tests(&self, endpoints: &[EndpointInfo], api_analysis: &ApiAnalysis) -> Vec<TestCase> {
        let mut test_cases = Vec::new();
        let user_journeys = self.create_realistic_user_journeys(endpoints, api_analysis);

        for journey in user_journeys {
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            headers.insert("X-Test-Type".to_string(), "real-user-simulation".to_string());
            headers.insert("X-User-Journey".to_string(), journey.name.clone());

            let test_case = self.base.create_test_case(
                "/user-journey".to_string(),
                "GET".to_string(),
                format!("Real User Simulation: {}", journey.name),
                Some(headers),
                None,
                None,
                200,
                Some(vec![
                    Assertion {
                        assertion_type: "user_experience_score_gt".to_string(),
                        expected: Value::Number(Number::from(85)), // 85% satisfaction
                        path: None,
                    },
                    Assertion {
                        assertion_type: "journey_completion_rate_gt".to_string(),
                        expected: Value::String("95%".to_string()),
                        path: None,
                    },
                ]),
            );

            test_cases.push(test_case);
        }

        test_cases
    }

    /// Generate advanced load patterns
    fn generate_advanced_load_patterns(&self, api_analysis: &ApiAnalysis) -> Vec<AdvancedLoadPattern> {
        let mut patterns = Vec::new();

        // Gradual Ramp-Up Pattern
        patterns.push(AdvancedLoadPattern {
            pattern_name: "Gradual Ramp-Up".to_string(),
            pattern_type: LoadPatternType::GradualRampUp,
            stages: vec![
                LoadStage { duration: "2m".to_string(), target_users: 10, ramp_rate: "5 users/min".to_string(), hold_duration: None },
                LoadStage { duration: "5m".to_string(), target_users: 50, ramp_rate: "8 users/min".to_string(), hold_duration: Some("2m".to_string()) },
                LoadStage { duration: "10m".to_string(), target_users: 100, ramp_rate: "5 users/min".to_string(), hold_duration: Some("5m".to_string()) },
                LoadStage { duration: "3m".to_string(), target_users: 0, ramp_rate: "33 users/min down".to_string(), hold_duration: None },
            ],
            user_behavior: UserBehaviorModel {
                session_duration: "15m".to_string(),
                pages_per_session: 8,
                bounce_rate: 0.35,
                conversion_rate: 0.12,
                return_user_percentage: 0.65,
            },
            geographic_distribution: vec![
                GeographicLocation { region: "US-East".to_string(), percentage: 40.0, latency_overhead: 20 },
                GeographicLocation { region: "US-West".to_string(), percentage: 30.0, latency_overhead: 50 },
                GeographicLocation { region: "Europe".to_string(), percentage: 20.0, latency_overhead: 100 },
                GeographicLocation { region: "Asia".to_string(), percentage: 10.0, latency_overhead: 200 },
            ],
            device_profiles: vec![
                DeviceProfile { device_type: "Desktop".to_string(), percentage: 60.0, performance_multiplier: 1.0 },
                DeviceProfile { device_type: "Mobile".to_string(), percentage: 35.0, performance_multiplier: 0.7 },
                DeviceProfile { device_type: "Tablet".to_string(), percentage: 5.0, performance_multiplier: 0.85 },
            ],
            think_time_distribution: ThinkTimeDistribution {
                min_think_time: 1,
                max_think_time: 30,
                distribution_type: "normal".to_string(),
                mean: 5.0,
                std_deviation: 2.0,
            },
        });

        // Stepped Load Pattern
        patterns.push(AdvancedLoadPattern {
            pattern_name: "Stepped Load".to_string(),
            pattern_type: LoadPatternType::SteppedLoad,
            stages: vec![
                LoadStage { duration: "5m".to_string(), target_users: 25, ramp_rate: "instant".to_string(), hold_duration: Some("3m".to_string()) },
                LoadStage { duration: "5m".to_string(), target_users: 50, ramp_rate: "instant".to_string(), hold_duration: Some("3m".to_string()) },
                LoadStage { duration: "5m".to_string(), target_users: 100, ramp_rate: "instant".to_string(), hold_duration: Some("3m".to_string()) },
                LoadStage { duration: "5m".to_string(), target_users: 200, ramp_rate: "instant".to_string(), hold_duration: Some("3m".to_string()) },
            ],
            user_behavior: UserBehaviorModel {
                session_duration: "10m".to_string(),
                pages_per_session: 5,
                bounce_rate: 0.25,
                conversion_rate: 0.15,
                return_user_percentage: 0.70,
            },
            geographic_distribution: vec![
                GeographicLocation { region: "Local".to_string(), percentage: 100.0, latency_overhead: 10 },
            ],
            device_profiles: vec![
                DeviceProfile { device_type: "Desktop".to_string(), percentage: 100.0, performance_multiplier: 1.0 },
            ],
            think_time_distribution: ThinkTimeDistribution {
                min_think_time: 2,
                max_think_time: 10,
                distribution_type: "uniform".to_string(),
                mean: 5.0,
                std_deviation: 1.5,
            },
        });

        // Business Hours Simulation
        if api_analysis.authentication_required {
            patterns.push(AdvancedLoadPattern {
                pattern_name: "Business Hours Simulation".to_string(),
                pattern_type: LoadPatternType::BusinessHourSimulation,
                stages: vec![
                    LoadStage { duration: "1h".to_string(), target_users: 20, ramp_rate: "gradual".to_string(), hold_duration: None }, // 9 AM
                    LoadStage { duration: "2h".to_string(), target_users: 80, ramp_rate: "gradual".to_string(), hold_duration: Some("30m".to_string()) }, // 10-12 PM
                    LoadStage { duration: "1h".to_string(), target_users: 40, ramp_rate: "gradual".to_string(), hold_duration: None }, // Lunch
                    LoadStage { duration: "3h".to_string(), target_users: 100, ramp_rate: "gradual".to_string(), hold_duration: Some("1h".to_string()) }, // 1-4 PM
                    LoadStage { duration: "1h".to_string(), target_users: 60, ramp_rate: "gradual".to_string(), hold_duration: None }, // 4-5 PM
                    LoadStage { duration: "1h".to_string(), target_users: 10, ramp_rate: "gradual".to_string(), hold_duration: None }, // After hours
                ],
                user_behavior: UserBehaviorModel {
                    session_duration: "45m".to_string(),
                    pages_per_session: 12,
                    bounce_rate: 0.20,
                    conversion_rate: 0.25,
                    return_user_percentage: 0.85,
                },
                geographic_distribution: vec![
                    GeographicLocation { region: "Corporate-Network".to_string(), percentage: 80.0, latency_overhead: 5 },
                    GeographicLocation { region: "Remote-Workers".to_string(), percentage: 20.0, latency_overhead: 30 },
                ],
                device_profiles: vec![
                    DeviceProfile { device_type: "Desktop".to_string(), percentage: 80.0, performance_multiplier: 1.0 },
                    DeviceProfile { device_type: "Laptop".to_string(), percentage: 15.0, performance_multiplier: 0.9 },
                    DeviceProfile { device_type: "Mobile".to_string(), percentage: 5.0, performance_multiplier: 0.6 },
                ],
                think_time_distribution: ThinkTimeDistribution {
                    min_think_time: 5,
                    max_think_time: 120,
                    distribution_type: "exponential".to_string(),
                    mean: 30.0,
                    std_deviation: 15.0,
                },
            });
        }

        patterns
    }

    /// Create comprehensive metrics configuration
    fn create_comprehensive_metrics_config(&self, pattern: &AdvancedLoadPattern, endpoint: &EndpointInfo) -> ComprehensiveMetrics {
        ComprehensiveMetrics {
            response_time_metrics: ResponseTimeMetrics {
                percentiles: vec![
                    Percentile { percentile: 50.0, threshold: "200ms".to_string() },
                    Percentile { percentile: 75.0, threshold: "500ms".to_string() },
                    Percentile { percentile: 90.0, threshold: "1000ms".to_string() },
                    Percentile { percentile: 95.0, threshold: "2000ms".to_string() },
                    Percentile { percentile: 99.0, threshold: "5000ms".to_string() },
                    Percentile { percentile: 99.9, threshold: "10000ms".to_string() },
                ],
                mean_response_time: "<300ms".to_string(),
                min_response_time: ">50ms".to_string(),
                max_response_time: "<15000ms".to_string(),
                response_time_distribution: "normal".to_string(),
            },
            throughput_metrics: ThroughputMetrics {
                requests_per_second: ">100 RPS".to_string(),
                transactions_per_minute: ">6000 TPM".to_string(),
                data_transfer_rate: "<10 MB/s".to_string(),
                concurrent_users: format!("{} users", pattern.stages.iter().map(|s| s.target_users).max().unwrap_or(100)),
            },
            error_metrics: ErrorMetrics {
                error_rate: "<1%".to_string(),
                error_types: vec![
                    ErrorType { status_code: 400, percentage: 0.1, acceptable_threshold: 0.5 },
                    ErrorType { status_code: 401, percentage: 0.05, acceptable_threshold: 0.1 },
                    ErrorType { status_code: 403, percentage: 0.02, acceptable_threshold: 0.1 },
                    ErrorType { status_code: 404, percentage: 0.1, acceptable_threshold: 0.2 },
                    ErrorType { status_code: 429, percentage: 0.2, acceptable_threshold: 1.0 },
                    ErrorType { status_code: 500, percentage: 0.05, acceptable_threshold: 0.1 },
                    ErrorType { status_code: 502, percentage: 0.02, acceptable_threshold: 0.05 },
                    ErrorType { status_code: 503, percentage: 0.03, acceptable_threshold: 0.1 },
                ],
                timeout_rate: "<0.5%".to_string(),
                retry_rate: "<2%".to_string(),
            },
            resource_metrics: ResourceMetrics {
                cpu_utilization: "<80%".to_string(),
                memory_utilization: "<85%".to_string(),
                network_bandwidth: "<70%".to_string(),
                disk_io: "<60%".to_string(),
                connection_pool_usage: "<90%".to_string(),
            },
            business_metrics: BusinessMetrics {
                conversion_rate: format!(">{}%", pattern.user_behavior.conversion_rate * 100.0),
                revenue_per_hour: ">$1000".to_string(),
                user_satisfaction_score: ">4.5/5".to_string(),
                abandonment_rate: format!("<{}%", pattern.user_behavior.bounce_rate * 100.0),
            },
            custom_slos: vec![
                ServiceLevelObjective {
                    name: "Page Load Time".to_string(),
                    metric: "response_time_p95".to_string(),
                    threshold: "<2s".to_string(),
                    measurement_window: "5m".to_string(),
                    priority: "high".to_string(),
                },
                ServiceLevelObjective {
                    name: "API Availability".to_string(),
                    metric: "success_rate".to_string(),
                    threshold: ">99.5%".to_string(),
                    measurement_window: "1h".to_string(),
                    priority: "critical".to_string(),
                },
            ],
        }
    }

    /// Create advanced assertions from metrics
    fn create_advanced_assertions(&self, metrics: &ComprehensiveMetrics) -> Vec<Assertion> {
        let mut assertions = Vec::new();

        // Response time assertions
        for percentile in &metrics.response_time_metrics.percentiles {
            assertions.push(Assertion {
                assertion_type: format!("response_time_p{}_lt", percentile.percentile),
                expected: Value::String(percentile.threshold.clone()),
                path: None,
            });
        }

        // Throughput assertions
        assertions.push(Assertion {
            assertion_type: "throughput_rps_gt".to_string(),
            expected: Value::String(metrics.throughput_metrics.requests_per_second.clone()),
            path: None,
        });

        // Error rate assertions
        assertions.push(Assertion {
            assertion_type: "error_rate_lt".to_string(),
            expected: Value::String(metrics.error_metrics.error_rate.clone()),
            path: None,
        });

        // Business metric assertions
        assertions.push(Assertion {
            assertion_type: "user_satisfaction_gt".to_string(),
            expected: Value::String(metrics.business_metrics.user_satisfaction_score.clone()),
            path: None,
        });

        // SLO assertions
        for slo in &metrics.custom_slos {
            assertions.push(Assertion {
                assertion_type: if slo.threshold.starts_with('>') { format!("{}_gt", slo.metric) } else { format!("{}_lt", slo.metric) },
                expected: Value::String(slo.threshold.clone()),
                path: None,
            });
        }

        assertions
    }

    /// Generate advanced k6 script with comprehensive monitoring
    fn generate_advanced_k6_script(&self, pattern: &AdvancedLoadPattern, endpoint: &EndpointInfo) -> String {
        let mut script = format!(r#"
import http from 'k6/http';
import {{ check, sleep, group }} from 'k6';
import {{ Rate, Trend, Counter }} from 'k6/metrics';
import {{ randomIntBetween, randomItem }} from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
let errorRate = new Rate('errors');
let responseTimeTrend = new Trend('response_time');
let userSatisfactionScore = new Trend('user_satisfaction');
let businessTransactions = new Counter('business_transactions');

export let options = {{
    scenarios: {{
        '{}': {{
            executor: 'ramping-vus',
            stages: [
"#, pattern.pattern_name.replace(" ", "_").to_lowercase());

        // Add stages
        for stage in &pattern.stages {
            script.push_str(&format!(
                "                {{ duration: '{}', target: {} }},\n",
                stage.duration, stage.target_users
            ));
        }

        script.push_str(&format!(r#"
            ],
            gracefulRampDown: '30s',
        }},
    }},
    thresholds: {{
        'http_req_duration': ['p(95)<2000', 'p(99)<5000'],
        'http_req_failed': ['rate<0.01'],
        'errors': ['rate<0.01'],
        'user_satisfaction': ['avg>4.0'],
        'response_time': ['p(95)<1500'],
    }},
    ext: {{
        loadimpact: {{
            distribution: {{
"#));

        // Add geographic distribution
        for location in &pattern.geographic_distribution {
            script.push_str(&format!(
                "                '{}': {},\n",
                location.region.to_lowercase().replace("-", "_"),
                location.percentage / 100.0
            ));
        }

        script.push_str(&format!(r#"
            }},
        }},
    }},
}};

let deviceProfiles = {};
let thinkTimeConfig = {};

export function setup() {{
    console.log('Starting {} load test');
    console.log('Expected user behavior: {} pages per session, {} conversion rate');
    return {{
        baseUrl: __ENV.BASE_URL || 'http://localhost:3000',
        testStartTime: new Date().toISOString(),
    }};
}}

export default function (data) {{
    // Simulate device performance
    let deviceProfile = randomItem(deviceProfiles);
    let performanceMultiplier = deviceProfile.performance_multiplier;

    group('User Session Simulation', function() {{
        group('Authentication', function() {{
            if (Math.random() < {}) {{
                // Returning user
                let response = http.get(data.baseUrl + '/login');
                check(response, {{
                    'login successful': (r) => r.status === 200,
                }});
            }}
        }});

        group('Main Interaction', function() {{
            for (let i = 0; i < {}; i++) {{
                let startTime = new Date();

                let response = http.{}(data.baseUrl + '{}');

                let endTime = new Date();
                let responseTime = endTime - startTime;

                // Apply device performance multiplier
                let adjustedResponseTime = responseTime * performanceMultiplier;
                responseTimeTrend.add(adjustedResponseTime);

                let success = check(response, {{
                    'status is 2xx': (r) => r.status >= 200 && r.status < 300,
                    'response time acceptable': (r) => adjustedResponseTime < 2000,
                }});

                if (!success) {{
                    errorRate.add(1);
                }} else {{
                    errorRate.add(0);
                    businessTransactions.add(1);

                    // Calculate user satisfaction based on response time
                    let satisfaction = 5.0;
                    if (adjustedResponseTime > 1000) satisfaction -= 1.0;
                    if (adjustedResponseTime > 3000) satisfaction -= 1.5;
                    if (adjustedResponseTime > 5000) satisfaction -= 2.0;
                    userSatisfactionScore.add(Math.max(1.0, satisfaction));
                }}

                // Simulate conversion
                if (Math.random() < {}) {{
                    businessTransactions.add(10); // Higher weight for conversions
                }}

                // Dynamic think time based on distribution
                let thinkTime = calculateThinkTime(thinkTimeConfig);
                sleep(thinkTime / 1000); // Convert to seconds
            }}
        }});

        // Simulate bounce rate
        if (Math.random() < {}) {{
            // User bounces - exit early
            return;
        }}
    }});
}}

function calculateThinkTime(config) {{
    // Simple normal distribution approximation
    let u1 = Math.random();
    let u2 = Math.random();
    let z0 = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    let result = config.mean + (z0 * config.std_deviation);
    return Math.max(config.min_think_time * 1000, Math.min(config.max_think_time * 1000, result * 1000));
}}

export function teardown(data) {{
    console.log('Load test completed');
    console.log('Test duration: ' + (new Date() - new Date(data.testStartTime)) + 'ms');
}}
"#,
            format!("[{}]", pattern.device_profiles.iter().map(|d| format!("{{device_type: '{}', performance_multiplier: {}}}", d.device_type, d.performance_multiplier)).collect::<Vec<_>>().join(", ")),
            format!("{{min_think_time: {}, max_think_time: {}, mean: {}, std_deviation: {}}}",
                pattern.think_time_distribution.min_think_time,
                pattern.think_time_distribution.max_think_time,
                pattern.think_time_distribution.mean,
                pattern.think_time_distribution.std_deviation),
            pattern.pattern_name,
            pattern.user_behavior.pages_per_session,
            pattern.user_behavior.conversion_rate,
            pattern.user_behavior.return_user_percentage,
            pattern.user_behavior.pages_per_session,
            endpoint.method.to_lowercase(),
            endpoint.path,
            pattern.user_behavior.conversion_rate,
            pattern.user_behavior.bounce_rate
        ));

        script
    }

    /// Create realistic user journeys
    fn create_realistic_user_journeys(&self, endpoints: &[EndpointInfo], api_analysis: &ApiAnalysis) -> Vec<PerformanceWorkflow> {
        let mut journeys = Vec::new();

        // E-commerce user journey
        if endpoints.iter().any(|e| e.path.contains("product") || e.path.contains("cart")) {
            journeys.push(PerformanceWorkflow {
                name: "E-commerce Purchase Journey".to_string(),
                category: "ecommerce".to_string(),
                concurrent_workflows: 25,
                duration: "30m".to_string(),
                steps: vec![
                    WorkflowStep { action: "browse_products".to_string(), weight: 0.8 },
                    WorkflowStep { action: "view_product_details".to_string(), weight: 0.6 },
                    WorkflowStep { action: "add_to_cart".to_string(), weight: 0.3 },
                    WorkflowStep { action: "checkout".to_string(), weight: 0.15 },
                    WorkflowStep { action: "payment".to_string(), weight: 0.12 },
                ],
                success_criteria: WorkflowSuccessCriteria {
                    workflow_completion_rate: "92%".to_string(),
                    average_workflow_time: "8m".to_string(),
                    error_rate: "1.5%".to_string(),
                },
            });
        }

        // API exploration journey
        journeys.push(PerformanceWorkflow {
            name: "API Explorer Journey".to_string(),
            category: "api_usage".to_string(),
            concurrent_workflows: 15,
            duration: "20m".to_string(),
            steps: vec![
                WorkflowStep { action: "authenticate".to_string(), weight: 0.9 },
                WorkflowStep { action: "list_resources".to_string(), weight: 0.8 },
                WorkflowStep { action: "read_resource".to_string(), weight: 0.7 },
                WorkflowStep { action: "create_resource".to_string(), weight: 0.3 },
                WorkflowStep { action: "update_resource".to_string(), weight: 0.2 },
            ],
            success_criteria: WorkflowSuccessCriteria {
                workflow_completion_rate: "95%".to_string(),
                average_workflow_time: "5m".to_string(),
                error_rate: "1%".to_string(),
            },
        });

        // Heavy data processing journey
        if !api_analysis.data_intensive_operations.is_empty() {
            journeys.push(PerformanceWorkflow {
                name: "Data Processing Journey".to_string(),
                category: "data_intensive".to_string(),
                concurrent_workflows: 5,
                duration: "45m".to_string(),
                steps: vec![
                    WorkflowStep { action: "upload_data".to_string(), weight: 0.8 },
                    WorkflowStep { action: "process_data".to_string(), weight: 0.9 },
                    WorkflowStep { action: "generate_report".to_string(), weight: 0.7 },
                    WorkflowStep { action: "download_results".to_string(), weight: 0.6 },
                ],
                success_criteria: WorkflowSuccessCriteria {
                    workflow_completion_rate: "88%".to_string(),
                    average_workflow_time: "25m".to_string(),
                    error_rate: "3%".to_string(),
                },
            });
        }

        journeys
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