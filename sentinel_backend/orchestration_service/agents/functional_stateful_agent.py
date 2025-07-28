"""
Functional-Stateful-Agent: Generates complex, multi-step test scenarios.

This agent focuses on creating test cases that validate complex business workflows
spanning multiple API calls, using a Semantic Operation Dependency Graph (SODG)
to manage state between operations and create realistic end-to-end test scenarios.
"""

from typing import Dict, List, Any, Optional, Tuple, Set
import json
import re
from dataclasses import dataclass
from enum import Enum

from .base_agent import BaseAgent, AgentTask, AgentResult
from config.settings import get_application_settings


class DependencyType(Enum):
    """Types of dependencies between operations."""
    RESOURCE_ID = "resource_id"  # POST /users -> GET /users/{id}
    PARENT_CHILD = "parent_child"  # POST /users -> POST /users/{id}/posts
    FILTER_REFERENCE = "filter_reference"  # POST /users -> GET /posts?userId={id}
    UPDATE_REFERENCE = "update_reference"  # POST /users -> PUT /users/{id}
    DELETE_REFERENCE = "delete_reference"  # POST /users -> DELETE /users/{id}


@dataclass
class ExtractRule:
    """Rule for extracting data from a response."""
    source_field: str  # JSON path to extract from (e.g., "id", "data.userId")
    target_variable: str  # Variable name to store the extracted value
    description: str


@dataclass
class InjectRule:
    """Rule for injecting extracted data into a request."""
    target_location: str  # Where to inject: "path", "query", "body", "header"
    target_field: str  # Field name or path parameter name
    source_variable: str  # Variable name containing the value to inject
    description: str


@dataclass
class OperationNode:
    """Represents an operation in the SODG."""
    operation_id: str
    path: str
    method: str
    operation_spec: Dict[str, Any]
    dependencies: List['OperationEdge']
    dependents: List['OperationEdge']


@dataclass
class OperationEdge:
    """Represents a dependency edge between operations."""
    from_operation: str
    to_operation: str
    dependency_type: DependencyType
    extract_rules: List[ExtractRule]
    inject_rules: List[InjectRule]
    description: str


@dataclass
class StatefulTestScenario:
    """Represents a complete stateful test scenario."""
    scenario_id: str
    description: str
    operations: List[Dict[str, Any]]  # Ordered list of operations to execute
    state_variables: Dict[str, Any]  # Initial state variables
    cleanup_operations: List[Dict[str, Any]]  # Operations to clean up after test


class FunctionalStatefulAgent(BaseAgent):
    """
    Agent responsible for generating stateful functional test cases.
    
    This agent creates test cases that:
    - Span multiple API operations in sequence
    - Manage state between operations using extract/inject rules
    - Validate complex business workflows and resource lifecycles
    - Support resource creation, retrieval, update, and deletion flows
    """
    
    def __init__(self):
        super().__init__("Functional-Stateful-Agent")
        self.sodg: Dict[str, OperationNode] = {}
    
    async def execute(self, task: AgentTask, api_spec: Dict[str, Any]) -> AgentResult:
        """
        Generate stateful test cases for the given API specification.
        
        Args:
            task: The agent task containing parameters and context
            api_spec: The parsed OpenAPI specification
            
        Returns:
            AgentResult with generated stateful test scenarios
        """
        try:
            self.logger.info(f"Starting stateful test generation for spec_id: {task.spec_id}")
            
            # Step 1: Build the Semantic Operation Dependency Graph
            self.sodg = self._build_sodg(api_spec)
            self.logger.info(f"Built SODG with {len(self.sodg)} operations")
            
            # Step 2: Identify workflow patterns
            workflow_patterns = self._identify_workflow_patterns()
            self.logger.info(f"Identified {len(workflow_patterns)} workflow patterns")
            
            # Step 3: Generate test scenarios for each pattern
            test_scenarios = []
            for pattern in workflow_patterns:
                scenarios = await self._generate_scenarios_for_pattern(pattern, api_spec)
                test_scenarios.extend(scenarios)
            
            # Step 4: Convert scenarios to test cases
            test_cases = []
            for scenario in test_scenarios:
                test_case = self._convert_scenario_to_test_case(scenario)
                test_cases.append(test_case)
            
            self.logger.info(f"Generated {len(test_cases)} stateful test cases")
            
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="success",
                test_cases=test_cases,
                metadata={
                    "total_operations": len(self.sodg),
                    "workflow_patterns": len(workflow_patterns),
                    "total_scenarios": len(test_scenarios),
                    "total_test_cases": len(test_cases),
                    "generation_strategy": "sodg_based_stateful_workflows",
                    "supported_patterns": [p["type"] for p in workflow_patterns]
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error generating stateful test cases: {str(e)}")
            return AgentResult(
                task_id=task.task_id,
                agent_type=self.agent_type,
                status="failed",
                error_message=str(e)
            )
    
    def _build_sodg(self, api_spec: Dict[str, Any]) -> Dict[str, OperationNode]:
        """
        Build the Semantic Operation Dependency Graph from the API specification.
        
        Args:
            api_spec: The parsed OpenAPI specification
            
        Returns:
            Dictionary mapping operation IDs to OperationNode objects
        """
        sodg = {}
        
        # Step 1: Create nodes for all operations
        endpoints = self._extract_endpoints(api_spec)
        for endpoint in endpoints:
            operation_id = self._generate_operation_id(endpoint)
            node = OperationNode(
                operation_id=operation_id,
                path=endpoint["path"],
                method=endpoint["method"],
                operation_spec=endpoint["operation"],
                dependencies=[],
                dependents=[]
            )
            sodg[operation_id] = node
        
        # Step 2: Identify and create edges between operations
        for from_op_id, from_node in sodg.items():
            for to_op_id, to_node in sodg.items():
                if from_op_id != to_op_id:
                    edge = self._identify_dependency(from_node, to_node)
                    if edge:
                        from_node.dependents.append(edge)
                        to_node.dependencies.append(edge)
        
        return sodg
    
    def _generate_operation_id(self, endpoint: Dict[str, Any]) -> str:
        """Generate a unique operation ID for an endpoint."""
        method = endpoint["method"].lower()
        path = endpoint["path"]
        
        # Use operationId if available, otherwise generate from method and path
        operation_spec = endpoint.get("operation", {})
        if "operationId" in operation_spec:
            return operation_spec["operationId"]
        
        # Generate ID from method and path
        path_parts = [part for part in path.split("/") if part and not part.startswith("{")]
        if path_parts:
            resource = path_parts[-1]
            return f"{method}_{resource}"
        else:
            return f"{method}_root"
    
    def _identify_dependency(self, from_node: OperationNode, to_node: OperationNode) -> Optional[OperationEdge]:
        """
        Identify if there's a dependency relationship between two operations.
        
        Args:
            from_node: The source operation node
            to_node: The target operation node
            
        Returns:
            OperationEdge if dependency exists, None otherwise
        """
        from_path = from_node.path
        from_method = from_node.method.upper()
        to_path = to_node.path
        to_method = to_node.method.upper()
        
        # Pattern 1: Resource creation -> Resource access
        # POST /users -> GET /users/{id}
        if (from_method == "POST" and to_method == "GET" and
            self._is_resource_access_pattern(from_path, to_path)):
            
            extract_rules = [ExtractRule(
                source_field="id",
                target_variable="resource_id",
                description=f"Extract resource ID from {from_method} {from_path}"
            )]
            
            inject_rules = [InjectRule(
                target_location="path",
                target_field="id",
                source_variable="resource_id",
                description=f"Inject resource ID into {to_method} {to_path}"
            )]
            
            return OperationEdge(
                from_operation=from_node.operation_id,
                to_operation=to_node.operation_id,
                dependency_type=DependencyType.RESOURCE_ID,
                extract_rules=extract_rules,
                inject_rules=inject_rules,
                description=f"Resource creation to access: {from_path} -> {to_path}"
            )
        
        # Pattern 2: Resource creation -> Resource update
        # POST /users -> PUT /users/{id}
        if (from_method == "POST" and to_method in ["PUT", "PATCH"] and
            self._is_resource_access_pattern(from_path, to_path)):
            
            extract_rules = [ExtractRule(
                source_field="id",
                target_variable="resource_id",
                description=f"Extract resource ID from {from_method} {from_path}"
            )]
            
            inject_rules = [InjectRule(
                target_location="path",
                target_field="id",
                source_variable="resource_id",
                description=f"Inject resource ID into {to_method} {to_path}"
            )]
            
            return OperationEdge(
                from_operation=from_node.operation_id,
                to_operation=to_node.operation_id,
                dependency_type=DependencyType.UPDATE_REFERENCE,
                extract_rules=extract_rules,
                inject_rules=inject_rules,
                description=f"Resource creation to update: {from_path} -> {to_path}"
            )
        
        # Pattern 3: Resource creation -> Resource deletion
        # POST /users -> DELETE /users/{id}
        if (from_method == "POST" and to_method == "DELETE" and
            self._is_resource_access_pattern(from_path, to_path)):
            
            extract_rules = [ExtractRule(
                source_field="id",
                target_variable="resource_id",
                description=f"Extract resource ID from {from_method} {from_path}"
            )]
            
            inject_rules = [InjectRule(
                target_location="path",
                target_field="id",
                source_variable="resource_id",
                description=f"Inject resource ID into {to_method} {to_path}"
            )]
            
            return OperationEdge(
                from_operation=from_node.operation_id,
                to_operation=to_node.operation_id,
                dependency_type=DependencyType.DELETE_REFERENCE,
                extract_rules=extract_rules,
                inject_rules=inject_rules,
                description=f"Resource creation to deletion: {from_path} -> {to_path}"
            )
        
        # Pattern 4: Parent resource -> Child resource
        # POST /users -> POST /users/{userId}/posts
        if (from_method == "POST" and to_method == "POST" and
            self._is_parent_child_pattern(from_path, to_path)):
            
            parent_resource = self._extract_resource_name(from_path)
            parent_id_param = f"{parent_resource[:-1]}Id" if parent_resource.endswith('s') else f"{parent_resource}Id"
            
            extract_rules = [ExtractRule(
                source_field="id",
                target_variable=parent_id_param,
                description=f"Extract parent resource ID from {from_method} {from_path}"
            )]
            
            inject_rules = [InjectRule(
                target_location="path",
                target_field=parent_id_param,
                source_variable=parent_id_param,
                description=f"Inject parent resource ID into {to_method} {to_path}"
            )]
            
            return OperationEdge(
                from_operation=from_node.operation_id,
                to_operation=to_node.operation_id,
                dependency_type=DependencyType.PARENT_CHILD,
                extract_rules=extract_rules,
                inject_rules=inject_rules,
                description=f"Parent-child resource creation: {from_path} -> {to_path}"
            )
        
        # Pattern 5: Resource creation -> Filter by resource
        # POST /users -> GET /posts?userId={id}
        if (from_method == "POST" and to_method == "GET" and
            self._is_filter_reference_pattern(from_node, to_node)):
            
            resource_name = self._extract_resource_name(from_path)
            filter_param = f"{resource_name[:-1]}Id" if resource_name.endswith('s') else f"{resource_name}Id"
            
            extract_rules = [ExtractRule(
                source_field="id",
                target_variable=filter_param,
                description=f"Extract resource ID from {from_method} {from_path}"
            )]
            
            inject_rules = [InjectRule(
                target_location="query",
                target_field=filter_param,
                source_variable=filter_param,
                description=f"Inject resource ID as filter in {to_method} {to_path}"
            )]
            
            return OperationEdge(
                from_operation=from_node.operation_id,
                to_operation=to_node.operation_id,
                dependency_type=DependencyType.FILTER_REFERENCE,
                extract_rules=extract_rules,
                inject_rules=inject_rules,
                description=f"Resource creation to filtered query: {from_path} -> {to_path}"
            )
        
        return None
    
    def _is_resource_access_pattern(self, from_path: str, to_path: str) -> bool:
        """Check if paths follow resource creation -> resource access pattern."""
        # Remove trailing slashes and split paths
        from_parts = [p for p in from_path.strip('/').split('/') if p]
        to_parts = [p for p in to_path.strip('/').split('/') if p]
        
        # Basic pattern: /users -> /users/{id}
        if len(to_parts) == len(from_parts) + 1:
            # Check if all parts except the last match
            for i in range(len(from_parts)):
                if from_parts[i] != to_parts[i]:
                    return False
            # Check if the last part is a path parameter
            return to_parts[-1].startswith('{') and to_parts[-1].endswith('}')
        
        return False
    
    def _is_parent_child_pattern(self, from_path: str, to_path: str) -> bool:
        """Check if paths follow parent -> child resource pattern."""
        # Example: /users -> /users/{userId}/posts
        from_parts = [p for p in from_path.strip('/').split('/') if p]
        to_parts = [p for p in to_path.strip('/').split('/') if p]
        
        if len(to_parts) >= len(from_parts) + 2:
            # Check if from_path is a prefix of to_path
            for i in range(len(from_parts)):
                if from_parts[i] != to_parts[i]:
                    return False
            
            # Check if there's a path parameter after the parent resource
            if len(to_parts) > len(from_parts):
                param_part = to_parts[len(from_parts)]
                return param_part.startswith('{') and param_part.endswith('}')
        
        return False
    
    def _is_filter_reference_pattern(self, from_node: OperationNode, to_node: OperationNode) -> bool:
        """Check if operations follow resource creation -> filtered query pattern."""
        # Check if the target operation has query parameters that could reference the source resource
        to_params = to_node.operation_spec.get("parameters", [])
        from_resource = self._extract_resource_name(from_node.path)
        
        if not from_resource:
            return False
        
        # Look for query parameters that might reference the source resource
        expected_param_names = [
            f"{from_resource[:-1]}Id" if from_resource.endswith('s') else f"{from_resource}Id",
            f"{from_resource}_id",
            from_resource.lower() + "_id"
        ]
        
        for param in to_params:
            if (param.get("in") == "query" and 
                param.get("name", "").lower() in [name.lower() for name in expected_param_names]):
                return True
        
        return False
    
    def _extract_resource_name(self, path: str) -> Optional[str]:
        """Extract the main resource name from a path."""
        parts = [p for p in path.strip('/').split('/') if p and not p.startswith('{')]
        return parts[-1] if parts else None
    
    def _identify_workflow_patterns(self) -> List[Dict[str, Any]]:
        """
        Identify common workflow patterns in the SODG.
        
        Returns:
            List of workflow pattern descriptions
        """
        patterns = []
        
        # Pattern 1: CRUD lifecycle patterns
        crud_patterns = self._find_crud_patterns()
        patterns.extend(crud_patterns)
        
        # Pattern 2: Parent-child resource patterns
        parent_child_patterns = self._find_parent_child_patterns()
        patterns.extend(parent_child_patterns)
        
        # Pattern 3: Resource filtering patterns
        filter_patterns = self._find_filter_patterns()
        patterns.extend(filter_patterns)
        
        return patterns
    
    def _find_crud_patterns(self) -> List[Dict[str, Any]]:
        """Find Create-Read-Update-Delete workflow patterns."""
        patterns = []
        
        # Group operations by resource
        resource_operations = {}
        for op_id, node in self.sodg.items():
            resource = self._extract_resource_name(node.path)
            if resource:
                if resource not in resource_operations:
                    resource_operations[resource] = []
                resource_operations[resource].append(node)
        
        # For each resource, identify CRUD patterns
        for resource, operations in resource_operations.items():
            crud_ops = {
                "create": None,
                "read": None,
                "update": None,
                "delete": None
            }
            
            for op in operations:
                method = op.method.upper()
                if method == "POST" and not self._has_path_parameters(op.path):
                    crud_ops["create"] = op
                elif method == "GET" and self._has_path_parameters(op.path):
                    crud_ops["read"] = op
                elif method in ["PUT", "PATCH"] and self._has_path_parameters(op.path):
                    crud_ops["update"] = op
                elif method == "DELETE" and self._has_path_parameters(op.path):
                    crud_ops["delete"] = op
            
            # Create patterns based on available operations
            if crud_ops["create"] and crud_ops["read"]:
                patterns.append({
                    "type": "create_read",
                    "resource": resource,
                    "operations": [crud_ops["create"], crud_ops["read"]],
                    "description": f"Create and read {resource} workflow"
                })
            
            if crud_ops["create"] and crud_ops["update"]:
                patterns.append({
                    "type": "create_update",
                    "resource": resource,
                    "operations": [crud_ops["create"], crud_ops["update"]],
                    "description": f"Create and update {resource} workflow"
                })
            
            if crud_ops["create"] and crud_ops["delete"]:
                patterns.append({
                    "type": "create_delete",
                    "resource": resource,
                    "operations": [crud_ops["create"], crud_ops["delete"]],
                    "description": f"Create and delete {resource} workflow"
                })
            
            if crud_ops["create"] and crud_ops["read"] and crud_ops["update"]:
                patterns.append({
                    "type": "full_crud",
                    "resource": resource,
                    "operations": [crud_ops["create"], crud_ops["read"], crud_ops["update"]],
                    "description": f"Full CRUD workflow for {resource}"
                })
        
        return patterns
    
    def _find_parent_child_patterns(self) -> List[Dict[str, Any]]:
        """Find parent-child resource workflow patterns."""
        patterns = []
        
        # Find parent-child relationships
        for op_id, node in self.sodg.items():
            for edge in node.dependents:
                if edge.dependency_type == DependencyType.PARENT_CHILD:
                    parent_node = self.sodg[edge.from_operation]
                    child_node = self.sodg[edge.to_operation]
                    
                    patterns.append({
                        "type": "parent_child",
                        "parent_resource": self._extract_resource_name(parent_node.path),
                        "child_resource": self._extract_resource_name(child_node.path),
                        "operations": [parent_node, child_node],
                        "description": f"Create parent {parent_node.path} then child {child_node.path}"
                    })
        
        return patterns
    
    def _find_filter_patterns(self) -> List[Dict[str, Any]]:
        """Find resource filtering workflow patterns."""
        patterns = []
        
        # Find filter relationships
        for op_id, node in self.sodg.items():
            for edge in node.dependents:
                if edge.dependency_type == DependencyType.FILTER_REFERENCE:
                    source_node = self.sodg[edge.from_operation]
                    filter_node = self.sodg[edge.to_operation]
                    
                    patterns.append({
                        "type": "create_filter",
                        "source_resource": self._extract_resource_name(source_node.path),
                        "filter_resource": self._extract_resource_name(filter_node.path),
                        "operations": [source_node, filter_node],
                        "description": f"Create {source_node.path} then filter {filter_node.path}"
                    })
        
        return patterns
    
    def _has_path_parameters(self, path: str) -> bool:
        """Check if a path contains path parameters."""
        return '{' in path and '}' in path
    
    async def _generate_scenarios_for_pattern(
        self, 
        pattern: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> List[StatefulTestScenario]:
        """
        Generate test scenarios for a specific workflow pattern.
        
        Args:
            pattern: The workflow pattern description
            api_spec: The API specification
            
        Returns:
            List of StatefulTestScenario objects
        """
        scenarios = []
        pattern_type = pattern["type"]
        operations = pattern["operations"]
        
        if pattern_type in ["create_read", "create_update", "create_delete", "full_crud"]:
            scenario = await self._generate_crud_scenario(pattern, api_spec)
            if scenario:
                scenarios.append(scenario)
        
        elif pattern_type == "parent_child":
            scenario = await self._generate_parent_child_scenario(pattern, api_spec)
            if scenario:
                scenarios.append(scenario)
        
        elif pattern_type == "create_filter":
            scenario = await self._generate_filter_scenario(pattern, api_spec)
            if scenario:
                scenarios.append(scenario)
        
        return scenarios
    
    async def _generate_crud_scenario(
        self, 
        pattern: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[StatefulTestScenario]:
        """Generate a CRUD workflow scenario."""
        operations = pattern["operations"]
        resource = pattern["resource"]
        pattern_type = pattern["type"]
        
        scenario_operations = []
        cleanup_operations = []
        
        # Build the operation sequence
        for i, op_node in enumerate(operations):
            # Find the dependency edge to this operation (if any)
            extract_rules = []
            inject_rules = []
            
            if i > 0:  # Not the first operation
                # Find the edge from previous operation to this one
                prev_op = operations[i-1]
                for edge in prev_op.dependents:
                    if edge.to_operation == op_node.operation_id:
                        extract_rules = edge.extract_rules
                        inject_rules = edge.inject_rules
                        break
            
            # Generate operation definition
            operation_def = {
                "operation_id": op_node.operation_id,
                "method": op_node.method,
                "path": op_node.path,
                "description": f"Step {i+1}: {op_node.method} {op_node.path}",
                "extract_rules": [self._extract_rule_to_dict(rule) for rule in extract_rules],
                "inject_rules": [self._inject_rule_to_dict(rule) for rule in inject_rules],
                "request_body": self._generate_request_body_for_operation(op_node, api_spec),
                "expected_status": self._get_expected_status_for_operation(op_node),
                "assertions": self._generate_assertions_for_operation(op_node)
            }
            
            scenario_operations.append(operation_def)
        
        # Add cleanup if we created resources
        create_op = operations[0] if operations and operations[0].method.upper() == "POST" else None
        if create_op:
            # Look for a corresponding DELETE operation
            for op_id, node in self.sodg.items():
                if (node.method.upper() == "DELETE" and 
                    self._is_resource_access_pattern(create_op.path, node.path)):
                    
                    cleanup_op = {
                        "operation_id": node.operation_id,
                        "method": node.method,
                        "path": node.path,
                        "description": f"Cleanup: Delete created {resource}",
                        "inject_rules": [{
                            "target_location": "path",
                            "target_field": "id",
                            "source_variable": "resource_id",
                            "description": "Inject resource ID for cleanup"
                        }],
                        "expected_status": 204
                    }
                    cleanup_operations.append(cleanup_op)
                    break
        
        scenario_id = f"{pattern_type}_{resource}_{len(scenario_operations)}_steps"
        
        return StatefulTestScenario(
            scenario_id=scenario_id,
            description=pattern["description"],
            operations=scenario_operations,
            state_variables={},
            cleanup_operations=cleanup_operations
        )
    
    async def _generate_parent_child_scenario(
        self, 
        pattern: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[StatefulTestScenario]:
        """Generate a parent-child resource scenario."""
        operations = pattern["operations"]
        parent_resource = pattern["parent_resource"]
        child_resource = pattern["child_resource"]
        
        scenario_operations = []
        
        for i, op_node in enumerate(operations):
            extract_rules = []
            inject_rules = []
            
            if i > 0:  # Child operation
                # Find the edge from parent to child
                parent_op = operations[0]
                for edge in parent_op.dependents:
                    if edge.to_operation == op_node.operation_id:
                        extract_rules = edge.extract_rules
                        inject_rules = edge.inject_rules
                        break
            
            operation_def = {
                "operation_id": op_node.operation_id,
                "method": op_node.method,
                "path": op_node.path,
                "description": f"Step {i+1}: Create {'parent' if i == 0 else 'child'} resource",
                "extract_rules": [self._extract_rule_to_dict(rule) for rule in extract_rules],
                "inject_rules": [self._inject_rule_to_dict(rule) for rule in inject_rules],
                "request_body": self._generate_request_body_for_operation(op_node, api_spec),
                "expected_status": self._get_expected_status_for_operation(op_node),
                "assertions": self._generate_assertions_for_operation(op_node)
            }
            
            scenario_operations.append(operation_def)
        
        scenario_id = f"parent_child_{parent_resource}_{child_resource}"
        
        return StatefulTestScenario(
            scenario_id=scenario_id,
            description=pattern["description"],
            operations=scenario_operations,
            state_variables={},
            cleanup_operations=[]
        )
    
    async def _generate_filter_scenario(
        self, 
        pattern: Dict[str, Any], 
        api_spec: Dict[str, Any]
    ) -> Optional[StatefulTestScenario]:
        """Generate a create-then-filter scenario."""
        operations = pattern["operations"]
        source_resource = pattern["source_resource"]
        filter_resource = pattern["filter_resource"]
        
        scenario_operations = []
        
        for i, op_node in enumerate(operations):
            extract_rules = []
            inject_rules = []
            
            if i > 0:  # Filter operation
                # Find the edge from source to filter
                source_op = operations[0]
                for edge in source_op.dependents:
                    if edge.to_operation == op_node.operation_id:
                        extract_rules = edge.extract_rules
                        inject_rules = edge.inject_rules
                        break
            
            operation_def = {
                "operation_id": op_node.operation_id,
                "method": op_node.method,
                "path": op_node.path,
                "description": f"Step {i+1}: {'Create' if i == 0 else 'Filter'} {op_node.path}",
                "extract_rules": [self._extract_rule_to_dict(rule) for rule in extract_rules],
                "inject_rules": [self._inject_rule_to_dict(rule) for rule in inject_rules],
                "request_body": self._generate_request_body_for_operation(op_node, api_spec) if i == 0 else None,
                "expected_status": self._get_expected_status_for_operation(op_node),
                "assertions": self._generate_assertions_for_operation(op_node)
            }
            
            scenario_operations.append(operation_def)
        
        scenario_id = f"create_filter_{source_resource}_{filter_resource}"
        
        return StatefulTestScenario(
            scenario_id=scenario_id,
            description=pattern["description"],
            operations=scenario_operations,
            state_variables={},
            cleanup_operations=[]
        )
    
    def _convert_scenario_to_test_case(self, scenario: StatefulTestScenario) -> Dict[str, Any]:
        """
        Convert a StatefulTestScenario to a test case format.
        
        Args:
            scenario: The stateful test scenario
            
        Returns:
            Test case dictionary compatible with the test execution engine
        """
        return self._create_test_case(
            endpoint="multi-step",  # Special marker for stateful tests
            method="STATEFUL",
            description=scenario.description,
            expected_status=200,  # Will be overridden by individual operations
            assertions=[{
                "type": "stateful_workflow",
                "scenario": {
                    "scenario_id": scenario.scenario_id,
                    "operations": scenario.operations,
                    "state_variables": scenario.state_variables,
                    "cleanup_operations": scenario.cleanup_operations
                }
            }]
        )
    
    def _extract_rule_to_dict(self, rule: ExtractRule) -> Dict[str, Any]:
        """Convert ExtractRule to dictionary format."""
        return {
            "source_field": rule.source_field,
            "target_variable": rule.target_variable,
            "description": rule.description
        }
    
    def _inject_rule_to_dict(self, rule: InjectRule) -> Dict[str, Any]:
        """Convert InjectRule to dictionary format."""
        return {
            "target_location": rule.target_location,
            "target_field": rule.target_field,
            "source_variable": rule.source_variable,
            "description": rule.description
        }
    
    def _generate_request_body_for_operation(
        self, 
        op_node: OperationNode, 
        api_spec: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Generate a request body for an operation if needed."""
        if op_node.method.upper() not in ["POST", "PUT", "PATCH"]:
            return None
        
        request_body = op_node.operation_spec.get("requestBody", {})
        if not request_body:
            return None
        
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        if not json_content:
            return None
        
        schema = json_content.get("schema", {})
        resolved_schema = self._resolve_schema_ref(schema, api_spec)
        
        return self._generate_realistic_object(resolved_schema)
    
    def _resolve_schema_ref(self, schema: Dict[str, Any], api_spec: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve $ref references in schemas."""
        if "$ref" in schema:
            ref_path = schema["$ref"]
            if ref_path.startswith("#/"):
                # Navigate to the referenced schema
                parts = ref_path[2:].split("/")
                resolved = api_spec
                for part in parts:
                    resolved = resolved.get(part, {})
                return resolved
        return schema
    
    def _generate_realistic_object(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a realistic object based on schema."""
        if schema.get("type") != "object":
            return self._get_schema_example(schema)
        
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        
        obj = {}
        
        for prop_name, prop_schema in properties.items():
            # Always include required properties, sometimes include optional ones
            if prop_name in required or len(properties) <= 5:  # Include all if few properties
                obj[prop_name] = self._generate_realistic_property_value(prop_name, prop_schema)
        
        return obj
    
    def _generate_realistic_property_value(self, prop_name: str, schema: Dict[str, Any]) -> Any:
        """Generate realistic values based on property names and schemas."""
        prop_name_lower = prop_name.lower()
        
        # Use existing example if available
        if "example" in schema:
            return schema["example"]
        
        # Generate realistic values based on property names
        if "email" in prop_name_lower:
            return "stateful.test@example.com"
        elif "name" in prop_name_lower:
            if "first" in prop_name_lower:
                return "Stateful"
            elif "last" in prop_name_lower:
                return "Tester"
            else:
                return "Stateful Test Resource"
        elif "title" in prop_name_lower:
            return "Test Resource for Stateful Workflow"
        elif "description" in prop_name_lower or "body" in prop_name_lower:
            return "This resource was created as part of a stateful test workflow to validate multi-step API operations."
        elif "phone" in prop_name_lower:
            return "+1-555-STATEFUL"
        elif "age" in prop_name_lower:
            return 25
        elif "price" in prop_name_lower or "amount" in prop_name_lower:
            return 99.99
        elif "date" in prop_name_lower:
            return "2024-01-01T00:00:00Z"
        elif "url" in prop_name_lower:
            return "https://example.com/stateful-test"
        
        # Fall back to schema-based generation
        return self._get_schema_example(schema)
    
    def _get_expected_status_for_operation(self, op_node: OperationNode) -> int:
        """Determine the expected success status code for an operation."""
        responses = op_node.operation_spec.get("responses", {})
        
        # Look for success responses (2xx)
        success_codes = [code for code in responses.keys() if code.startswith('2')]
        
        if success_codes:
            return int(success_codes[0])
        
        # Default success codes by method
        method_defaults = {
            "GET": 200,
            "POST": 201,
            "PUT": 200,
            "PATCH": 200,
            "DELETE": 204
        }
        
        return method_defaults.get(op_node.method.upper(), 200)
    
    def _generate_assertions_for_operation(self, op_node: OperationNode) -> List[Dict[str, Any]]:
        """Generate assertions for validating an operation's response."""
        assertions = []
        
        # Basic status code assertion
        expected_status = self._get_expected_status_for_operation(op_node)
        assertions.append({
            "type": "status_code",
            "expected": expected_status
        })
        
        # Response schema assertion if available
        responses = op_node.operation_spec.get("responses", {})
        success_response = responses.get(str(expected_status), {})
        content = success_response.get("content", {})
        
        if content:
            json_content = content.get("application/json", {})
            if json_content and "schema" in json_content:
                assertions.append({
                    "type": "response_schema",
                    "schema": json_content["schema"]
                })
        
        # For POST operations, assert that an ID is returned
        if op_node.method.upper() == "POST":
            assertions.append({
                "type": "response_field_exists",
                "field": "id",
                "description": "Verify that created resource has an ID"
            })
        
        return assertions
    
    def _create_test_case(
        self,
        endpoint: str,
        method: str,
        description: str,
        expected_status: int,
        assertions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Create a standardized test case with configuration-based settings."""
        app_settings = get_application_settings()
        test_timeout = getattr(app_settings, 'test_execution_timeout', 600)
        
        return {
            'test_name': description,
            'test_type': 'functional-stateful',
            'method': method.upper(),
            'path': endpoint,
            'timeout': test_timeout,
            'expected_status_codes': [expected_status],
            'assertions': assertions,
            'tags': ['functional', 'stateful', 'multi-step', 'workflow']
        }
