"""
Assertion Type Registry and Validation

This module provides centralized validation and documentation for all supported
assertion types used across Sentinel's Python and Rust agent implementations.

Usage:
    from sentinel_backend.common.assertion_registry import (
        AssertionRegistry,
        validate_assertion_type
    )

    # Validate assertion type
    if AssertionRegistry.validate_assertion_type('response_time_p95_lt'):
        print("Valid assertion type!")

    # Get operator for assertion type
    operator = AssertionRegistry.get_operator('status_code_in')  # Returns 'in'

    # List all supported types
    all_types = AssertionRegistry.list_all()
"""

import re
from typing import Dict, List, Optional, Literal


class AssertionRegistry:
    """Centralized registry of all supported assertion types

    This registry defines all valid assertion types used in test case generation
    across both Python and Rust agent implementations. Each assertion type includes:
    - operator: The comparison operator used
    - type: The data type expected for the value
    - description: Human-readable explanation of the assertion

    Attributes:
        SUPPORTED_PATTERNS: Dictionary mapping assertion type names to their metadata
    """

    SUPPORTED_PATTERNS: Dict[str, Dict[str, str]] = {
        # Status Code Assertions
        'status_code_in': {
            'operator': 'in',
            'type': 'array',
            'description': 'Status code in list of accepted codes',
            'example': '[200, 201, 204]'
        },
        'status_code_eq': {
            'operator': '==',
            'type': 'integer',
            'description': 'Status code equals specific value',
            'example': '200'
        },
        'status_code_ne': {
            'operator': '!=',
            'type': 'integer',
            'description': 'Status code not equal to value',
            'example': '500'
        },
        'status_code_gt': {
            'operator': '>',
            'type': 'integer',
            'description': 'Status code greater than value',
            'example': '199'
        },
        'status_code_lt': {
            'operator': '<',
            'type': 'integer',
            'description': 'Status code less than value',
            'example': '400'
        },

        # Response Time Assertions (Basic)
        'response_time_lt': {
            'operator': '<',
            'type': 'duration',
            'description': 'Response time less than threshold (ms)',
            'example': '500ms'
        },
        'response_time_gt': {
            'operator': '>',
            'type': 'duration',
            'description': 'Response time greater than threshold (ms)',
            'example': '100ms'
        },
        'response_time_eq': {
            'operator': '==',
            'type': 'duration',
            'description': 'Response time equals threshold (ms)',
            'example': '250ms'
        },

        # Response Time Assertions (Percentiles)
        'response_time_p50_lt': {
            'operator': '<',
            'type': 'duration',
            'description': 'P50 (median) response time less than threshold',
            'example': '200ms'
        },
        'response_time_p75_lt': {
            'operator': '<',
            'type': 'duration',
            'description': 'P75 response time less than threshold',
            'example': '300ms'
        },
        'response_time_p90_lt': {
            'operator': '<',
            'type': 'duration',
            'description': 'P90 response time less than threshold',
            'example': '500ms'
        },
        'response_time_p95_lt': {
            'operator': '<',
            'type': 'duration',
            'description': 'P95 response time less than threshold',
            'example': '750ms'
        },
        'response_time_p99_lt': {
            'operator': '<',
            'type': 'duration',
            'description': 'P99 response time less than threshold',
            'example': '1000ms'
        },
        'response_time_p99_9_lt': {
            'operator': '<',
            'type': 'duration',
            'description': 'P99.9 response time less than threshold',
            'example': '2000ms'
        },

        # Throughput Assertions
        'throughput_gt': {
            'operator': '>',
            'type': 'number',
            'description': 'Throughput greater than threshold (req/sec)',
            'example': '1000'
        },
        'throughput_lt': {
            'operator': '<',
            'type': 'number',
            'description': 'Throughput less than threshold (req/sec)',
            'example': '10000'
        },
        'throughput_min': {
            'operator': '>=',
            'type': 'number',
            'description': 'Minimum throughput threshold (req/sec)',
            'example': '500'
        },
        'throughput_rps_gt': {
            'operator': '>',
            'type': 'number',
            'description': 'Requests per second greater than threshold',
            'example': '2000'
        },

        # Error Rate Assertions
        'error_rate_lt': {
            'operator': '<',
            'type': 'percentage',
            'description': 'Error rate less than threshold (percentage)',
            'example': '0.01'
        },
        'error_rate': {
            'operator': '<=',
            'type': 'percentage',
            'description': 'Error rate within threshold (percentage)',
            'example': '0.05'
        },
        'error_rate_during_spike': {
            'operator': '<',
            'type': 'percentage',
            'description': 'Error rate during spike test (percentage)',
            'example': '0.10'
        },

        # Performance Degradation Assertions
        'memory_leak_detection_eq': {
            'operator': '==',
            'type': 'boolean',
            'description': 'Memory leak detected (true/false)',
            'example': 'false'
        },
        'performance_degradation_lt': {
            'operator': '<',
            'type': 'percentage',
            'description': 'Performance degradation less than threshold',
            'example': '0.10'
        },

        # User Experience Assertions
        'user_experience_score_gt': {
            'operator': '>',
            'type': 'number',
            'description': 'User experience score greater than threshold (0-100)',
            'example': '75'
        },
        'user_satisfaction_gt': {
            'operator': '>',
            'type': 'number',
            'description': 'User satisfaction score greater than threshold',
            'example': '80'
        },

        # Stress Test Assertions
        'breaking_point_identified': {
            'operator': '==',
            'type': 'boolean',
            'description': 'Breaking point successfully identified',
            'example': 'true'
        },
        'recovery_time': {
            'operator': '<',
            'type': 'duration',
            'description': 'System recovery time after stress',
            'example': '60s'
        },

        # Spike Test Assertions
        'spike_handling': {
            'operator': '==',
            'type': 'string',
            'description': 'Spike handling result',
            'example': 'graceful'
        },

        # Workflow Assertions
        'workflow_completion_rate': {
            'operator': '>',
            'type': 'percentage',
            'description': 'Workflow completion rate threshold',
            'example': '0.95'
        },
        'average_workflow_time': {
            'operator': '<',
            'type': 'duration',
            'description': 'Average workflow completion time',
            'example': '5000ms'
        },
        'journey_completion_rate_gt': {
            'operator': '>',
            'type': 'percentage',
            'description': 'User journey completion rate',
            'example': '0.90'
        },
    }

    @classmethod
    def validate_assertion_type(cls, assertion_type: str) -> bool:
        """Validate assertion_type is supported

        Args:
            assertion_type: The assertion type string to validate

        Returns:
            True if the assertion type is supported, False otherwise

        Examples:
            >>> AssertionRegistry.validate_assertion_type('response_time_p95_lt')
            True
            >>> AssertionRegistry.validate_assertion_type('invalid_assertion')
            False
        """
        return assertion_type in cls.SUPPORTED_PATTERNS

    @classmethod
    def get_operator(cls, assertion_type: str) -> Optional[str]:
        """Extract operator from assertion_type

        Args:
            assertion_type: The assertion type string

        Returns:
            The operator string if found, None if assertion type is invalid

        Examples:
            >>> AssertionRegistry.get_operator('status_code_in')
            'in'
            >>> AssertionRegistry.get_operator('response_time_lt')
            '<'
        """
        if assertion_type in cls.SUPPORTED_PATTERNS:
            return cls.SUPPORTED_PATTERNS[assertion_type]['operator']
        return None

    @classmethod
    def get_type(cls, assertion_type: str) -> Optional[str]:
        """Get expected data type for assertion_type

        Args:
            assertion_type: The assertion type string

        Returns:
            The expected type string if found, None if assertion type is invalid

        Examples:
            >>> AssertionRegistry.get_type('status_code_in')
            'array'
            >>> AssertionRegistry.get_type('response_time_lt')
            'duration'
        """
        if assertion_type in cls.SUPPORTED_PATTERNS:
            return cls.SUPPORTED_PATTERNS[assertion_type]['type']
        return None

    @classmethod
    def get_description(cls, assertion_type: str) -> Optional[str]:
        """Get human-readable description for assertion_type

        Args:
            assertion_type: The assertion type string

        Returns:
            Description string if found, None if assertion type is invalid
        """
        if assertion_type in cls.SUPPORTED_PATTERNS:
            return cls.SUPPORTED_PATTERNS[assertion_type]['description']
        return None

    @classmethod
    def get_example(cls, assertion_type: str) -> Optional[str]:
        """Get example value for assertion_type

        Args:
            assertion_type: The assertion type string

        Returns:
            Example value string if found, None if assertion type is invalid
        """
        if assertion_type in cls.SUPPORTED_PATTERNS:
            return cls.SUPPORTED_PATTERNS[assertion_type]['example']
        return None

    @classmethod
    def list_all(cls) -> List[str]:
        """List all supported assertion types

        Returns:
            List of all supported assertion type names

        Examples:
            >>> types = AssertionRegistry.list_all()
            >>> 'response_time_p95_lt' in types
            True
        """
        return list(cls.SUPPORTED_PATTERNS.keys())

    @classmethod
    def list_by_category(cls) -> Dict[str, List[str]]:
        """List assertion types grouped by category

        Returns:
            Dictionary mapping category names to lists of assertion types
        """
        categories = {
            'status_code': [],
            'response_time': [],
            'throughput': [],
            'error_rate': [],
            'performance': [],
            'user_experience': [],
            'stress_test': [],
            'spike_test': [],
            'workflow': [],
        }

        for assertion_type in cls.SUPPORTED_PATTERNS.keys():
            if assertion_type.startswith('status_code'):
                categories['status_code'].append(assertion_type)
            elif assertion_type.startswith('response_time'):
                categories['response_time'].append(assertion_type)
            elif assertion_type.startswith('throughput'):
                categories['throughput'].append(assertion_type)
            elif 'error_rate' in assertion_type:
                categories['error_rate'].append(assertion_type)
            elif assertion_type in ['memory_leak_detection_eq', 'performance_degradation_lt']:
                categories['performance'].append(assertion_type)
            elif 'user_' in assertion_type or 'satisfaction' in assertion_type:
                categories['user_experience'].append(assertion_type)
            elif assertion_type in ['breaking_point_identified', 'recovery_time']:
                categories['stress_test'].append(assertion_type)
            elif assertion_type == 'spike_handling':
                categories['spike_test'].append(assertion_type)
            elif 'workflow' in assertion_type or 'journey' in assertion_type:
                categories['workflow'].append(assertion_type)

        return categories


def validate_assertion_type(assertion_type: str) -> bool:
    """Validate assertion_type string is supported (from regression analysis line 825)

    This function provides backward compatibility and supports both exact matches
    and regex pattern matching for assertion types.

    Args:
        assertion_type: The assertion type string to validate

    Returns:
        True if the assertion type is supported (exact match or pattern match)

    Examples:
        >>> validate_assertion_type('response_time_p95_lt')
        True
        >>> validate_assertion_type('response_time_p50_lt')
        True
        >>> validate_assertion_type('invalid_type')
        False

    Note:
        This function supports dynamic percentile assertions like:
        - response_time_p50_lt, response_time_p75_lt, response_time_p90_lt
        - response_time_p95_lt, response_time_p99_lt, response_time_p99_9_lt
    """
    # First check exact match in registry
    if AssertionRegistry.validate_assertion_type(assertion_type):
        return True

    # Then check regex patterns for dynamic assertions
    supported_patterns = [
        r"^status_code_(in|eq|ne|gt|lt)$",
        r"^response_time_(p\d+(_\d+)?_)?(lt|gt|eq)$",
        r"^throughput_(gt|lt|min|rps_gt)$",
        r"^error_rate(_lt|_during_spike)?$",
        r"^memory_leak_detection_eq$",
        r"^performance_degradation_lt$",
        r"^user_(experience_score|satisfaction)_gt$",
        r"^(breaking_point_identified|recovery_time|spike_handling)$",
        r"^(workflow_completion_rate|average_workflow_time|journey_completion_rate_gt)$",
    ]

    return any(re.match(pattern, assertion_type) for pattern in supported_patterns)


def get_assertion_info(assertion_type: str) -> Optional[Dict[str, str]]:
    """Get complete information about an assertion type

    Args:
        assertion_type: The assertion type string

    Returns:
        Dictionary with operator, type, description, and example, or None if invalid

    Examples:
        >>> info = get_assertion_info('response_time_p95_lt')
        >>> info['operator']
        '<'
        >>> info['type']
        'duration'
    """
    if assertion_type in AssertionRegistry.SUPPORTED_PATTERNS:
        return AssertionRegistry.SUPPORTED_PATTERNS[assertion_type].copy()
    return None


def suggest_similar_assertions(partial_type: str) -> List[str]:
    """Suggest similar assertion types based on partial match

    Args:
        partial_type: Partial assertion type string to match

    Returns:
        List of similar assertion type names

    Examples:
        >>> suggest_similar_assertions('response_time')
        ['response_time_lt', 'response_time_gt', 'response_time_eq', ...]
    """
    all_types = AssertionRegistry.list_all()
    return [t for t in all_types if partial_type.lower() in t.lower()]
