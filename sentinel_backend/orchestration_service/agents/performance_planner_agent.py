"""
Performance Planner Agent for Sentinel Platform

This agent specializes in generating comprehensive performance test plans
and configurations from API specifications, including load testing scenarios
and performance benchmarking strategies.
"""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
import re
import math
from .base_agent import BaseAgent
from sentinel_backend.config.settings import get_application_settings

# Get configuration
app_settings = get_application_settings()
logger = logging.getLogger(__name__)

class PerformancePlannerAgent(BaseAgent):
    """
    Agent specialized in generating performance test plans and configurations.
    
    Primary focus areas:
    - Load testing scenario generation
    - Performance benchmarking strategies
    - Stress testing configurations
    - Capacity planning recommendations
    - Performance test script generation (k6/JMeter compatible)
    """
    
    def __init__(self):
        super().__init__()
        self.agent_type = "performance-planner"
        self.description = "Performance agent focused on generating comprehensive test plans and load scenarios"
        
        # Configuration-driven settings
        self.default_users = getattr(app_settings, 'performance_default_users', 10)
        self.max_users = getattr(app_settings, 'performance_max_users', 1000)
        self.test_duration = getattr(app_settings, 'performance_test_duration', 60)
        self.ramp_up_time = getattr(app_settings, 'performance_ramp_up_time', 30)
        self.think_time = getattr(app_settings, 'performance_think_time', 1)
    
    def generate_test_cases(self, spec_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate performance test cases and configurations.
        
        Args:
            spec_data: Parsed OpenAPI specification
            
        Returns:
            List of performance test configurations and scenarios
        """
        test_cases = []
        
        try:
            # Extract paths and operations from spec
            paths = spec_data.get('paths', {})
            
            # Analyze API structure for performance characteristics
            api_analysis = self._analyze_api_performance_characteristics(spec_data)
            
            for path, operations in paths.items():
                for method, operation_spec in operations.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        # Generate load testing scenarios
                        test_cases.extend(self._generate_load_test_scenarios(path, method, operation_spec, api_analysis))
                        
                        # Generate stress testing scenarios
                        test_cases.extend(self._generate_stress_test_scenarios(path, method, operation_spec, api_analysis))
                        
                        # Generate spike testing scenarios
                        test_cases.extend(self._generate_spike_test_scenarios(path, method, operation_spec, api_analysis))
            
            # Generate system-wide performance tests
            test_cases.extend(self._generate_system_wide_tests(spec_data, api_analysis))
            
            logger.info(f"Generated {len(test_cases)} performance test scenarios")
            return test_cases
            
        except Exception as e:
            logger.error(f"Error generating performance test cases: {str(e)}")
            return []
    
    def _analyze_api_performance_characteristics(self, spec_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the API specification to understand performance characteristics.
        """
        analysis = {
            'total_endpoints': 0,
            'read_endpoints': 0,
            'write_endpoints': 0,
            'critical_paths': [],
            'data_intensive_operations': [],
            'authentication_required': False,
            'estimated_complexity': 'medium',
            'recommended_load_patterns': []
        }
        
        paths = spec_data.get('paths', {})
        
        for path, operations in paths.items():
            for method, operation_spec in operations.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    analysis['total_endpoints'] += 1
                    
                    # Categorize operations
                    if method.upper() == 'GET':
                        analysis['read_endpoints'] += 1
                    else:
                        analysis['write_endpoints'] += 1
                    
                    # Identify critical paths
                    if self._is_critical_path(path, method, operation_spec):
                        analysis['critical_paths'].append({
                            'path': path,
                            'method': method.upper(),
                            'reason': self._get_criticality_reason(path, method, operation_spec)
                        })
                    
                    # Identify data-intensive operations
                    if self._is_data_intensive(path, method, operation_spec):
                        analysis['data_intensive_operations'].append({
                            'path': path,
                            'method': method.upper(),
                            'type': self._get_data_intensity_type(path, method, operation_spec)
                        })
                    
                    # Check for authentication requirements
                    if self._requires_authentication(operation_spec):
                        analysis['authentication_required'] = True
        
        # Determine overall complexity
        analysis['estimated_complexity'] = self._estimate_api_complexity(analysis)
        
        # Generate recommended load patterns
        analysis['recommended_load_patterns'] = self._generate_load_patterns(analysis)
        
        return analysis
    
    def _generate_load_test_scenarios(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                    api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate load testing scenarios for normal expected traffic.
        """
        test_cases = []
        
        # Determine load characteristics based on operation type
        load_profiles = self._get_load_profiles_for_operation(path, method, operation_spec, api_analysis)
        
        for profile in load_profiles:
            test_case = {
                'test_name': f"Load Test: {method.upper()} {path} - {profile['name']}",
                'test_type': 'performance-planner',
                'test_subtype': 'load-test',
                'method': method.upper(),
                'path': path,
                'headers': self._generate_performance_headers(),
                'path_params': self._generate_valid_path_params(path, operation_spec),
                'query_params': self._generate_performance_query_params(operation_spec),
                'body': self._generate_request_body(operation_spec) if method.upper() in ['POST', 'PUT', 'PATCH'] else None,
                'performance_config': {
                    'test_type': 'load',
                    'duration': profile['duration'],
                    'virtual_users': profile['virtual_users'],
                    'ramp_up_time': profile['ramp_up_time'],
                    'ramp_down_time': profile['ramp_down_time'],
                    'think_time': profile['think_time'],
                    'expected_response_time': profile['expected_response_time'],
                    'expected_throughput': profile['expected_throughput'],
                    'success_criteria': profile['success_criteria']
                },
                'k6_script': self._generate_k6_script(path, method, operation_spec, profile),
                'jmeter_config': self._generate_jmeter_config(path, method, operation_spec, profile),
                'tags': ['performance', 'load-test', f'{method.lower()}-method', profile['category']]
            }
            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_stress_test_scenarios(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                      api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate stress testing scenarios to find breaking points.
        """
        test_cases = []
        
        # Generate stress test profiles
        stress_profiles = self._get_stress_profiles_for_operation(path, method, operation_spec, api_analysis)
        
        for profile in stress_profiles:
            test_case = {
                'test_name': f"Stress Test: {method.upper()} {path} - {profile['name']}",
                'test_type': 'performance-planner',
                'test_subtype': 'stress-test',
                'method': method.upper(),
                'path': path,
                'headers': self._generate_performance_headers(),
                'path_params': self._generate_valid_path_params(path, operation_spec),
                'query_params': self._generate_performance_query_params(operation_spec),
                'body': self._generate_request_body(operation_spec) if method.upper() in ['POST', 'PUT', 'PATCH'] else None,
                'performance_config': {
                    'test_type': 'stress',
                    'duration': profile['duration'],
                    'max_virtual_users': profile['max_virtual_users'],
                    'ramp_up_strategy': profile['ramp_up_strategy'],
                    'breaking_point_detection': profile['breaking_point_detection'],
                    'recovery_validation': profile['recovery_validation'],
                    'success_criteria': profile['success_criteria']
                },
                'k6_script': self._generate_k6_stress_script(path, method, operation_spec, profile),
                'tags': ['performance', 'stress-test', f'{method.lower()}-method', 'breaking-point']
            }
            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_spike_test_scenarios(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                     api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate spike testing scenarios for sudden traffic increases.
        """
        test_cases = []
        
        # Generate spike test profiles
        spike_profiles = self._get_spike_profiles_for_operation(path, method, operation_spec, api_analysis)
        
        for profile in spike_profiles:
            test_case = {
                'test_name': f"Spike Test: {method.upper()} {path} - {profile['name']}",
                'test_type': 'performance-planner',
                'test_subtype': 'spike-test',
                'method': method.upper(),
                'path': path,
                'headers': self._generate_performance_headers(),
                'path_params': self._generate_valid_path_params(path, operation_spec),
                'query_params': self._generate_performance_query_params(operation_spec),
                'body': self._generate_request_body(operation_spec) if method.upper() in ['POST', 'PUT', 'PATCH'] else None,
                'performance_config': {
                    'test_type': 'spike',
                    'baseline_users': profile['baseline_users'],
                    'spike_users': profile['spike_users'],
                    'spike_duration': profile['spike_duration'],
                    'spike_pattern': profile['spike_pattern'],
                    'recovery_time': profile['recovery_time'],
                    'success_criteria': profile['success_criteria']
                },
                'k6_script': self._generate_k6_spike_script(path, method, operation_spec, profile),
                'tags': ['performance', 'spike-test', f'{method.lower()}-method', 'traffic-spike']
            }
            test_cases.append(test_case)
        
        return test_cases
    
    def _generate_system_wide_tests(self, spec_data: Dict[str, Any], api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate system-wide performance tests that exercise multiple endpoints.
        """
        test_cases = []
        
        # Generate workflow-based performance tests
        workflows = self._identify_performance_workflows(spec_data, api_analysis)
        
        for workflow in workflows:
            test_case = {
                'test_name': f"System Performance Test: {workflow['name']}",
                'test_type': 'performance-planner',
                'test_subtype': 'system-wide',
                'workflow': workflow['steps'],
                'performance_config': {
                    'test_type': 'system-wide',
                    'workflow_name': workflow['name'],
                    'concurrent_workflows': workflow['concurrent_workflows'],
                    'duration': workflow['duration'],
                    'success_criteria': workflow['success_criteria']
                },
                'k6_script': self._generate_k6_workflow_script(workflow),
                'tags': ['performance', 'system-wide', 'workflow', workflow['category']]
            }
            test_cases.append(test_case)
        
        return test_cases
    
    def _is_critical_path(self, path: str, method: str, operation_spec: Dict[str, Any]) -> bool:
        """Determine if this is a critical path for performance."""
        # Check for critical path indicators
        critical_indicators = [
            'login', 'auth', 'payment', 'checkout', 'order', 'search',
            'dashboard', 'home', 'index', 'list', 'feed'
        ]
        
        path_lower = path.lower()
        summary_lower = operation_spec.get('summary', '').lower()
        
        return any(indicator in path_lower or indicator in summary_lower 
                  for indicator in critical_indicators)
    
    def _get_criticality_reason(self, path: str, method: str, operation_spec: Dict[str, Any]) -> str:
        """Get the reason why this path is considered critical."""
        if 'auth' in path.lower() or 'login' in path.lower():
            return 'Authentication endpoint - critical for user access'
        elif 'payment' in path.lower() or 'checkout' in path.lower():
            return 'Payment processing - critical for business operations'
        elif 'search' in path.lower():
            return 'Search functionality - high user interaction'
        elif method.upper() == 'GET' and ('list' in path.lower() or 'index' in path.lower()):
            return 'Data listing endpoint - potentially high traffic'
        else:
            return 'High-impact user-facing functionality'
    
    def _is_data_intensive(self, path: str, method: str, operation_spec: Dict[str, Any]) -> bool:
        """Determine if this operation is data-intensive."""
        # Check for data-intensive indicators
        data_indicators = [
            'upload', 'download', 'export', 'import', 'bulk', 'batch',
            'file', 'image', 'video', 'document', 'report'
        ]
        
        path_lower = path.lower()
        summary_lower = operation_spec.get('summary', '').lower()
        
        # Check request body size indicators
        request_body = operation_spec.get('requestBody', {})
        if request_body:
            content = request_body.get('content', {})
            if 'multipart/form-data' in content or 'application/octet-stream' in content:
                return True
        
        return any(indicator in path_lower or indicator in summary_lower 
                  for indicator in data_indicators)
    
    def _get_data_intensity_type(self, path: str, method: str, operation_spec: Dict[str, Any]) -> str:
        """Get the type of data intensity."""
        path_lower = path.lower()
        
        if 'upload' in path_lower or 'file' in path_lower:
            return 'file_upload'
        elif 'download' in path_lower:
            return 'file_download'
        elif 'export' in path_lower or 'report' in path_lower:
            return 'data_export'
        elif 'bulk' in path_lower or 'batch' in path_lower:
            return 'bulk_operation'
        else:
            return 'large_payload'
    
    def _requires_authentication(self, operation_spec: Dict[str, Any]) -> bool:
        """Determine if an operation requires authentication."""
        security = operation_spec.get('security', [])
        if security:
            return True
        
        responses = operation_spec.get('responses', {})
        auth_status_codes = ['401', '403']
        
        return any(code in responses for code in auth_status_codes)
    
    def _estimate_api_complexity(self, analysis: Dict[str, Any]) -> str:
        """Estimate the overall complexity of the API."""
        total_endpoints = analysis['total_endpoints']
        critical_paths = len(analysis['critical_paths'])
        data_intensive = len(analysis['data_intensive_operations'])
        
        complexity_score = total_endpoints + (critical_paths * 2) + (data_intensive * 3)
        
        if complexity_score < 10:
            return 'low'
        elif complexity_score < 25:
            return 'medium'
        else:
            return 'high'
    
    def _generate_load_patterns(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommended load patterns based on API analysis."""
        patterns = []
        
        read_ratio = analysis['read_endpoints'] / max(analysis['total_endpoints'], 1)
        
        if read_ratio > 0.7:
            patterns.append('read_heavy')
        elif read_ratio < 0.3:
            patterns.append('write_heavy')
        else:
            patterns.append('balanced')
        
        if analysis['critical_paths']:
            patterns.append('critical_path_focused')
        
        if analysis['data_intensive_operations']:
            patterns.append('data_intensive')
        
        if analysis['authentication_required']:
            patterns.append('authenticated_sessions')
        
        return patterns
    
    def _get_load_profiles_for_operation(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                       api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get load testing profiles for a specific operation."""
        profiles = []
        
        # Base profile using configuration
        base_profile = {
            'name': 'Standard Load',
            'category': 'standard',
            'duration': f'{self.test_duration}s',
            'virtual_users': self.default_users,
            'ramp_up_time': f'{self.ramp_up_time}s',
            'ramp_down_time': f'{self.ramp_up_time}s',
            'think_time': f'{self.think_time}s',
            'expected_response_time': '500ms',
            'expected_throughput': f'{self.default_users * 2} rps',
            'success_criteria': {
                'response_time_p95': '1s',
                'error_rate': '1%',
                'throughput_min': f'{int(self.default_users * 1.5)} rps'
            }
        }
        
        # Adjust based on operation characteristics
        if self._is_critical_path(path, method, operation_spec):
            critical_profile = base_profile.copy()
            critical_profile.update({
                'name': 'Critical Path Load',
                'category': 'critical',
                'virtual_users': min(self.default_users * 2, self.max_users // 10),
                'expected_response_time': '200ms',
                'expected_throughput': f'{min(self.default_users * 5, self.max_users // 5)} rps',
                'success_criteria': {
                    'response_time_p95': '500ms',
                    'error_rate': '0.5%',
                    'throughput_min': f'{min(self.default_users * 4, self.max_users // 6)} rps'
                }
            })
            profiles.append(critical_profile)
        
        if self._is_data_intensive(path, method, operation_spec):
            data_profile = base_profile.copy()
            data_profile.update({
                'name': 'Data Intensive Load',
                'category': 'data_intensive',
                'virtual_users': max(self.default_users // 2, 2),
                'think_time': f'{self.think_time * 3}s',
                'expected_response_time': '2s',
                'expected_throughput': f'{max(self.default_users // 2, 2)} rps',
                'success_criteria': {
                    'response_time_p95': '5s',
                    'error_rate': '2%',
                    'throughput_min': f'{max(self.default_users // 3, 1)} rps'
                }
            })
            profiles.append(data_profile)
        
        if not profiles:  # Add base profile if no specific profiles were added
            profiles.append(base_profile)
        
        return profiles
    
    def _get_stress_profiles_for_operation(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                         api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get stress testing profiles for a specific operation."""
        profiles = []
        
        base_stress_profile = {
            'name': 'Breaking Point Stress',
            'duration': f'{self.test_duration * 10}s',
            'max_virtual_users': min(self.max_users, self.default_users * 10),
            'ramp_up_strategy': 'gradual_increase',
            'breaking_point_detection': {
                'response_time_threshold': '5s',
                'error_rate_threshold': '10%',
                'throughput_degradation': '50%'
            },
            'recovery_validation': True,
            'success_criteria': {
                'breaking_point_identified': True,
                'recovery_time': f'{self.ramp_up_time * 4}s',
                'post_recovery_performance': '90% of baseline'
            }
        }
        
        profiles.append(base_stress_profile)
        
        return profiles
    
    def _get_spike_profiles_for_operation(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                        api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get spike testing profiles for a specific operation."""
        profiles = []
        
        base_spike_profile = {
            'name': 'Traffic Spike',
            'baseline_users': self.default_users,
            'spike_users': min(self.default_users * 5, self.max_users // 2),
            'spike_duration': f'{self.test_duration * 2}s',
            'spike_pattern': 'instant',
            'recovery_time': f'{self.test_duration * 3}s',
            'success_criteria': {
                'spike_handling': 'graceful_degradation',
                'recovery_time': f'{self.ramp_up_time * 2}s',
                'error_rate_during_spike': '5%'
            }
        }
        
        profiles.append(base_spike_profile)
        
        return profiles
    
    def _identify_performance_workflows(self, spec_data: Dict[str, Any], api_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify common workflows for system-wide performance testing."""
        workflows = []
        
        # Example: User registration and authentication workflow
        auth_workflow = {
            'name': 'User Authentication Workflow',
            'category': 'authentication',
            'concurrent_workflows': 5,
            'duration': '10m',
            'steps': [
                {'action': 'register', 'weight': 0.1},
                {'action': 'login', 'weight': 0.8},
                {'action': 'access_protected_resource', 'weight': 0.1}
            ],
            'success_criteria': {
                'workflow_completion_rate': '95%',
                'average_workflow_time': '10s',
                'error_rate': '2%'
            }
        }
        workflows.append(auth_workflow)
        
        # Example: CRUD operations workflow
        crud_workflow = {
            'name': 'CRUD Operations Workflow',
            'category': 'crud',
            'concurrent_workflows': 10,
            'duration': '15m',
            'steps': [
                {'action': 'create_resource', 'weight': 0.2},
                {'action': 'read_resource', 'weight': 0.5},
                {'action': 'update_resource', 'weight': 0.2},
                {'action': 'delete_resource', 'weight': 0.1}
            ],
            'success_criteria': {
                'workflow_completion_rate': '98%',
                'average_workflow_time': '5s',
                'error_rate': '1%'
            }
        }
        workflows.append(crud_workflow)
        
        return workflows
    
    def _generate_performance_headers(self) -> Dict[str, str]:
        """Generate headers for performance testing."""
        return {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': 'Sentinel-Performance-Test/1.0'
        }
    
    def _generate_performance_query_params(self, operation_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Generate query parameters optimized for performance testing."""
        query_params = {}
        parameters = operation_spec.get('parameters', [])
        
        for param in parameters:
            if param.get('in') == 'query':
                param_name = param.get('name')
                param_type = param.get('schema', {}).get('type', 'string')
                
                # Use performance-friendly values
                if param_type == 'integer':
                    query_params[param_name] = 1
                elif param_name.lower() in ['limit', 'size', 'count']:
                    query_params[param_name] = 10  # Small result sets for performance
                else:
                    query_params[param_name] = 'test'
        
        return query_params
    
    def _generate_k6_script(self, path: str, method: str, operation_spec: Dict[str, Any], 
                          profile: Dict[str, Any]) -> str:
        """Generate a k6 performance test script."""
        script = f"""
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    stages: [
        {{ duration: '{profile['ramp_up_time']}', target: {profile['virtual_users']} }},
        {{ duration: '{profile['duration']}', target: {profile['virtual_users']} }},
        {{ duration: '{profile['ramp_down_time']}', target: 0 }},
    ],
    thresholds: {{
        http_req_duration: ['p(95)<{profile['success_criteria']['response_time_p95']}'],
        http_req_failed: ['rate<{profile['success_criteria']['error_rate']}'],
    }},
}};

export default function () {{
    let response = http.{method.lower()}('${{__ENV.BASE_URL}}{path}');
    
    check(response, {{
        'status is 200': (r) => r.status === 200,
        'response time < {profile['expected_response_time']}': (r) => r.timings.duration < {profile['expected_response_time'].replace('ms', '')},
    }});
    
    sleep({profile['think_time'].replace('s', '')});
}}
"""
        return script.strip()
    
    def _generate_k6_stress_script(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                 profile: Dict[str, Any]) -> str:
        """Generate a k6 stress test script."""
        script = f"""
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    stages: [
        {{ duration: '2m', target: 10 }},
        {{ duration: '5m', target: {profile['max_virtual_users']} }},
        {{ duration: '2m', target: {profile['max_virtual_users']} }},
        {{ duration: '1m', target: 0 }},
    ],
    thresholds: {{
        http_req_duration: ['p(95)<{profile['breaking_point_detection']['response_time_threshold']}'],
        http_req_failed: ['rate<{profile['breaking_point_detection']['error_rate_threshold']}'],
    }},
}};

export default function () {{
    let response = http.{method.lower()}('${{__ENV.BASE_URL}}{path}');
    
    check(response, {{
        'status is not 5xx': (r) => r.status < 500,
        'response time acceptable': (r) => r.timings.duration < 10000,
    }});
    
    sleep(1);
}}
"""
        return script.strip()
    
    def _generate_k6_spike_script(self, path: str, method: str, operation_spec: Dict[str, Any], 
                                profile: Dict[str, Any]) -> str:
        """Generate a k6 spike test script."""
        script = f"""
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    stages: [
        {{ duration: '1m', target: {profile['baseline_users']} }},
        {{ duration: '10s', target: {profile['spike_users']} }},
        {{ duration: '{profile['spike_duration']}', target: {profile['spike_users']} }},
        {{ duration: '10s', target: {profile['baseline_users']} }},
        {{ duration: '{profile['recovery_time']}', target: {profile['baseline_users']} }},
    ],
    thresholds: {{
        http_req_duration: ['p(95)<2000'],
        http_req_failed: ['rate<{profile['success_criteria']['error_rate_during_spike']}'],
    }},
}};

export default function () {{
    let response = http.{method.lower()}('${{__ENV.BASE_URL}}{path}');
    
    check(response, {{
        'status is successful': (r) => r.status >= 200 && r.status < 400,
        'spike handling': (r) => r.timings.duration < 5000,
    }});
    
    sleep(1);
}}
"""
        return script.strip()
    
    def _generate_k6_workflow_script(self, workflow: Dict[str, Any]) -> str:
        """Generate a k6 script for workflow-based testing."""
        script = f"""
import http from 'k6/http';
import {{ check, sleep }} from 'k6';

export let options = {{
    vus: {workflow['concurrent_workflows']},
    duration: '{workflow['duration']}',
    thresholds: {{
        http_req_duration: ['p(95)<5000'],
        http_req_failed: ['rate<{workflow['success_criteria']['error_rate']}'],
    }},
}};

export default function () {{
    // {workflow['name']} workflow
"""
        
        for step in workflow['steps']:
            script += f"""
    // {step['action']} (weight: {step['weight']})
    if (Math.random() < {step['weight']}) {{
        let response = http.get('${{__ENV.BASE_URL}}/{step['action']}');
        check(response, {{
            '{step['action']} successful': (r) => r.status < 400,
        }});
    }}
"""
        
        script += """
    sleep(1);
}
"""
        return script.strip()
    
    def _generate_jmeter_config(self, path: str, method: str, operation_spec: Dict[str, Any], 
                              profile: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JMeter test configuration."""
        return {
            'test_plan': {
                'name': f"Performance Test - {method.upper()} {path}",
                'thread_group': {
                    'threads': profile['virtual_users'],
                    'ramp_up': profile['ramp_up_time'],
                    'duration': profile['duration']
                },
                'http_request': {
                    'method': method.upper(),
                    'path': path,
                    'headers': self._generate_performance_headers()
                },
                'assertions': [
                    {
                        'type': 'response_time',
                        'value': profile['expected_response_time']
                    },
                    {
                        'type': 'response_code',
                        'value': '200'
                    }
                ]
            }
        }
    
    def _generate_valid_path_params(self, path: str, operation_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Generate valid path parameters for testing."""
        path_params = {}
        parameters = operation_spec.get('parameters', [])
        
        for param in parameters:
            if param.get('in') == 'path':
                param_name = param.get('name')
                param_type = param.get('schema', {}).get('type', 'string')
                
                if param_type == 'integer':
                    path_params[param_name] = 123
                else:
                    path_params[param_name] = 'test-id-123'
        
        # Extract from path pattern
        path_param_names = re.findall(r'\{([^}]+)\}', path)
        for param_name in path_param_names:
            if param_name not in path_params:
                path_params[param_name] = 'test-value'
        
        return path_params
    
    def _generate_request_body(self, operation_spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate a basic request body for testing."""
        request_body = operation_spec.get('requestBody', {})
        if not request_body:
            return None
        
        content = request_body.get('content', {})
        json_content = content.get('application/json', {})
        schema = json_content.get('schema', {})
        
        if not schema:
            return {'test': 'data'}
        
        return self._generate_data_from_schema(schema)
    
    def _generate_data_from_schema(self, schema: Dict[str, Any]) -> Any:
        """Generate test data from a JSON schema."""
        schema_type = schema.get('type', 'object')
        
        if schema_type == 'object':
            properties = schema.get('properties', {})
            required = schema.get('required', [])
            
            data = {}
            for prop_name, prop_schema in properties.items():
                if prop_name in required:
                    data[prop_name] = self._generate_data_from_schema(prop_schema)
            
            return data
        elif schema_type == 'string':
            return 'test-string'
        elif schema_type == 'integer':
            return 123
        elif schema_type == 'number':
            return 123.45
        elif schema_type == 'boolean':
            return True
        elif schema_type == 'array':
            items_schema = schema.get('items', {'type': 'string'})
            return [self._generate_data_from_schema(items_schema)]
        else:
            return 'test-value'
