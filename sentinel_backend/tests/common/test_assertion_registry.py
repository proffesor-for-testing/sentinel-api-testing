"""
Unit tests for AssertionRegistry and assertion validation

Tests cover:
1. Exact assertion type validation
2. Regex pattern matching for dynamic assertions
3. Operator extraction
4. Type and description retrieval
5. Category grouping
6. Suggestion functionality
7. Edge cases and error handling
"""

import pytest
from sentinel_backend.common.assertion_registry import (
    AssertionRegistry,
    validate_assertion_type,
    get_assertion_info,
    suggest_similar_assertions,
)


class TestAssertionRegistry:
    """Test suite for AssertionRegistry class"""

    def test_validate_exact_match_assertions(self):
        """Test validation of exact match assertion types"""
        # Valid exact matches
        assert AssertionRegistry.validate_assertion_type("status_code_in") is True
        assert AssertionRegistry.validate_assertion_type("response_time_p95_lt") is True
        assert AssertionRegistry.validate_assertion_type("throughput_gt") is True
        assert AssertionRegistry.validate_assertion_type("error_rate_lt") is True
        assert AssertionRegistry.validate_assertion_type("memory_leak_detection_eq") is True

        # Invalid assertions
        assert AssertionRegistry.validate_assertion_type("invalid_assertion") is False
        assert AssertionRegistry.validate_assertion_type("") is False
        assert AssertionRegistry.validate_assertion_type("random_type") is False

    def test_get_operator(self):
        """Test operator extraction from assertion types"""
        assert AssertionRegistry.get_operator("status_code_in") == "in"
        assert AssertionRegistry.get_operator("status_code_eq") == "=="
        assert AssertionRegistry.get_operator("response_time_lt") == "<"
        assert AssertionRegistry.get_operator("throughput_gt") == ">"
        assert AssertionRegistry.get_operator("error_rate_lt") == "<"

        # Invalid assertion type
        assert AssertionRegistry.get_operator("invalid_type") is None

    def test_get_type(self):
        """Test data type retrieval for assertion types"""
        assert AssertionRegistry.get_type("status_code_in") == "array"
        assert AssertionRegistry.get_type("status_code_eq") == "integer"
        assert AssertionRegistry.get_type("response_time_lt") == "duration"
        assert AssertionRegistry.get_type("throughput_gt") == "number"
        assert AssertionRegistry.get_type("error_rate_lt") == "percentage"
        assert AssertionRegistry.get_type("memory_leak_detection_eq") == "boolean"

        # Invalid assertion type
        assert AssertionRegistry.get_type("invalid_type") is None

    def test_get_description(self):
        """Test description retrieval for assertion types"""
        desc = AssertionRegistry.get_description("status_code_in")
        assert desc == "Status code in list of accepted codes"

        desc = AssertionRegistry.get_description("response_time_p95_lt")
        assert desc == "P95 response time less than threshold"

        # Invalid assertion type
        assert AssertionRegistry.get_description("invalid_type") is None

    def test_get_example(self):
        """Test example value retrieval for assertion types"""
        example = AssertionRegistry.get_example("status_code_in")
        assert example == "[200, 201, 204]"

        example = AssertionRegistry.get_example("response_time_lt")
        assert example == "500ms"

        # Invalid assertion type
        assert AssertionRegistry.get_example("invalid_type") is None

    def test_list_all(self):
        """Test listing all supported assertion types"""
        all_types = AssertionRegistry.list_all()

        # Should return a list
        assert isinstance(all_types, list)

        # Should contain expected assertion types
        assert "status_code_in" in all_types
        assert "response_time_p95_lt" in all_types
        assert "throughput_gt" in all_types
        assert "error_rate_lt" in all_types

        # Should have reasonable number of assertions (at least 30+)
        assert len(all_types) >= 30

    def test_list_by_category(self):
        """Test grouping assertion types by category"""
        by_category = AssertionRegistry.list_by_category()

        # Should have all expected categories
        assert "status_code" in by_category
        assert "response_time" in by_category
        assert "throughput" in by_category
        assert "error_rate" in by_category
        assert "performance" in by_category
        assert "user_experience" in by_category
        assert "stress_test" in by_category
        assert "spike_test" in by_category
        assert "workflow" in by_category

        # Check status code category
        status_codes = by_category["status_code"]
        assert "status_code_in" in status_codes
        assert "status_code_eq" in status_codes
        assert "status_code_ne" in status_codes
        assert "status_code_gt" in status_codes
        assert "status_code_lt" in status_codes

        # Check response time category
        response_times = by_category["response_time"]
        assert "response_time_lt" in response_times
        assert "response_time_p50_lt" in response_times
        assert "response_time_p95_lt" in response_times
        assert "response_time_p99_lt" in response_times

        # Check throughput category
        throughput = by_category["throughput"]
        assert "throughput_gt" in throughput
        assert "throughput_lt" in throughput

        # Check performance category
        performance = by_category["performance"]
        assert "memory_leak_detection_eq" in performance
        assert "performance_degradation_lt" in performance


class TestValidateAssertionType:
    """Test suite for validate_assertion_type function"""

    def test_exact_match_validation(self):
        """Test exact match validation"""
        # Exact matches from registry
        assert validate_assertion_type("status_code_in") is True
        assert validate_assertion_type("response_time_p95_lt") is True
        assert validate_assertion_type("throughput_gt") is True

    def test_status_code_pattern_matching(self):
        """Test status code assertion pattern matching"""
        assert validate_assertion_type("status_code_in") is True
        assert validate_assertion_type("status_code_eq") is True
        assert validate_assertion_type("status_code_ne") is True
        assert validate_assertion_type("status_code_gt") is True
        assert validate_assertion_type("status_code_lt") is True

        # Invalid status code patterns
        assert validate_assertion_type("status_code_xyz") is False
        assert validate_assertion_type("status_code_") is False

    def test_response_time_pattern_matching(self):
        """Test response time assertion pattern matching"""
        # Basic response time
        assert validate_assertion_type("response_time_lt") is True
        assert validate_assertion_type("response_time_gt") is True
        assert validate_assertion_type("response_time_eq") is True

        # Percentile response time (single digit)
        assert validate_assertion_type("response_time_p50_lt") is True
        assert validate_assertion_type("response_time_p75_lt") is True
        assert validate_assertion_type("response_time_p90_lt") is True
        assert validate_assertion_type("response_time_p95_lt") is True
        assert validate_assertion_type("response_time_p99_lt") is True

        # Decimal percentiles
        assert validate_assertion_type("response_time_p99_9_lt") is True

        # Dynamic percentiles (should match pattern)
        assert validate_assertion_type("response_time_p85_lt") is True
        assert validate_assertion_type("response_time_p99_5_lt") is True

        # Invalid patterns
        assert validate_assertion_type("response_time_xyz") is False
        assert validate_assertion_type("response_time_p_lt") is False

    def test_throughput_pattern_matching(self):
        """Test throughput assertion pattern matching"""
        assert validate_assertion_type("throughput_gt") is True
        assert validate_assertion_type("throughput_lt") is True
        assert validate_assertion_type("throughput_min") is True
        assert validate_assertion_type("throughput_rps_gt") is True

        # Invalid patterns
        assert validate_assertion_type("throughput_xyz") is False

    def test_error_rate_pattern_matching(self):
        """Test error rate assertion pattern matching"""
        assert validate_assertion_type("error_rate_lt") is True
        assert validate_assertion_type("error_rate") is True
        assert validate_assertion_type("error_rate_during_spike") is True

        # Invalid patterns
        assert validate_assertion_type("error_rate_xyz") is False

    def test_performance_pattern_matching(self):
        """Test performance-related assertion pattern matching"""
        assert validate_assertion_type("memory_leak_detection_eq") is True
        assert validate_assertion_type("performance_degradation_lt") is True

    def test_user_experience_pattern_matching(self):
        """Test user experience assertion pattern matching"""
        assert validate_assertion_type("user_experience_score_gt") is True
        assert validate_assertion_type("user_satisfaction_gt") is True

    def test_stress_and_spike_pattern_matching(self):
        """Test stress and spike test assertion pattern matching"""
        assert validate_assertion_type("breaking_point_identified") is True
        assert validate_assertion_type("recovery_time") is True
        assert validate_assertion_type("spike_handling") is True

    def test_workflow_pattern_matching(self):
        """Test workflow assertion pattern matching"""
        assert validate_assertion_type("workflow_completion_rate") is True
        assert validate_assertion_type("average_workflow_time") is True
        assert validate_assertion_type("journey_completion_rate_gt") is True

    def test_invalid_assertions(self):
        """Test that invalid assertion types return False"""
        assert validate_assertion_type("") is False
        assert validate_assertion_type("invalid") is False
        assert validate_assertion_type("random_assertion_type") is False
        assert validate_assertion_type("status_code_invalid") is False
        assert validate_assertion_type("response_time_invalid_lt") is False


class TestGetAssertionInfo:
    """Test suite for get_assertion_info function"""

    def test_get_valid_assertion_info(self):
        """Test retrieval of assertion info for valid types"""
        info = get_assertion_info("status_code_in")
        assert info is not None
        assert info["operator"] == "in"
        assert info["type"] == "array"
        assert info["description"] == "Status code in list of accepted codes"
        assert info["example"] == "[200, 201, 204]"

    def test_get_response_time_assertion_info(self):
        """Test retrieval of response time assertion info"""
        info = get_assertion_info("response_time_p95_lt")
        assert info is not None
        assert info["operator"] == "<"
        assert info["type"] == "duration"
        assert "P95" in info["description"]

    def test_get_invalid_assertion_info(self):
        """Test retrieval of info for invalid assertion types"""
        info = get_assertion_info("invalid_type")
        assert info is None

    def test_info_dictionary_copy(self):
        """Test that returned info is a copy, not reference"""
        info1 = get_assertion_info("status_code_in")
        info2 = get_assertion_info("status_code_in")

        # Modify one
        info1["operator"] = "modified"

        # Other should remain unchanged
        assert info2["operator"] == "in"


class TestSuggestSimilarAssertions:
    """Test suite for suggest_similar_assertions function"""

    def test_suggest_status_code_assertions(self):
        """Test suggestions for status code assertions"""
        suggestions = suggest_similar_assertions("status_code")
        assert len(suggestions) >= 5
        assert "status_code_in" in suggestions
        assert "status_code_eq" in suggestions
        assert "status_code_ne" in suggestions

    def test_suggest_response_time_assertions(self):
        """Test suggestions for response time assertions"""
        suggestions = suggest_similar_assertions("response_time")
        assert len(suggestions) >= 9
        assert "response_time_lt" in suggestions
        assert "response_time_p95_lt" in suggestions
        assert "response_time_p99_lt" in suggestions

    def test_suggest_throughput_assertions(self):
        """Test suggestions for throughput assertions"""
        suggestions = suggest_similar_assertions("throughput")
        assert len(suggestions) >= 3
        assert "throughput_gt" in suggestions
        assert "throughput_lt" in suggestions

    def test_suggest_error_rate_assertions(self):
        """Test suggestions for error rate assertions"""
        suggestions = suggest_similar_assertions("error_rate")
        assert len(suggestions) >= 2
        assert "error_rate_lt" in suggestions

    def test_suggest_partial_match(self):
        """Test suggestions with partial matches"""
        suggestions = suggest_similar_assertions("p95")
        assert "response_time_p95_lt" in suggestions

    def test_suggest_case_insensitive(self):
        """Test that suggestions are case-insensitive"""
        suggestions_lower = suggest_similar_assertions("status")
        suggestions_upper = suggest_similar_assertions("STATUS")
        suggestions_mixed = suggest_similar_assertions("StAtUs")

        assert suggestions_lower == suggestions_upper == suggestions_mixed

    def test_suggest_no_matches(self):
        """Test suggestions when no matches found"""
        suggestions = suggest_similar_assertions("xyz_nonexistent")
        assert len(suggestions) == 0


class TestRealWorldUsageFromPerformancePlanner:
    """Test real-world assertion types used in performance_planner.rs"""

    def test_performance_planner_assertions(self):
        """Test all assertion types found in performance_planner.rs"""
        # From line 438, 443, 448
        assert validate_assertion_type("response_time_p95_lt") is True  # Fixed: added _lt suffix to match registry
        assert validate_assertion_type("error_rate") is True
        assert validate_assertion_type("throughput_min") is True

        # From line 505, 510
        assert validate_assertion_type("breaking_point_identified") is True
        assert validate_assertion_type("recovery_time") is True

        # From line 558, 563
        assert validate_assertion_type("spike_handling") is True
        assert validate_assertion_type("error_rate_during_spike") is True

        # From line 611, 616
        assert validate_assertion_type("workflow_completion_rate") is True
        assert validate_assertion_type("average_workflow_time") is True

        # From line 1258, 1261
        assert validate_assertion_type("response_time_p99_lt") is True
        assert validate_assertion_type("throughput_gt") is True

        # From line 1300, 1303
        assert validate_assertion_type("memory_leak_detection_eq") is True
        assert validate_assertion_type("performance_degradation_lt") is True

        # From line 1336, 1341
        assert validate_assertion_type("user_experience_score_gt") is True
        assert validate_assertion_type("journey_completion_rate_gt") is True

        # From line 1554, 1561, 1568
        assert validate_assertion_type("throughput_rps_gt") is True
        assert validate_assertion_type("error_rate_lt") is True
        assert validate_assertion_type("user_satisfaction_gt") is True

    def test_dynamic_percentile_assertions(self):
        """Test dynamic percentile assertions from line 1546"""
        # Dynamic percentiles generated in performance_planner.rs
        for percentile in [50, 75, 90, 95, 99]:
            assertion_type = f"response_time_p{percentile}_lt"
            assert validate_assertion_type(assertion_type) is True, \
                f"Failed for {assertion_type}"


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_string_validation(self):
        """Test validation with empty string"""
        assert validate_assertion_type("") is False
        assert AssertionRegistry.validate_assertion_type("") is False

    def test_none_handling(self):
        """Test that None inputs are handled gracefully"""
        # These should not raise exceptions
        try:
            AssertionRegistry.get_operator(None)
            AssertionRegistry.get_type(None)
            AssertionRegistry.get_description(None)
        except (TypeError, AttributeError):
            # Expected behavior - None is not a valid input
            pass

    def test_whitespace_assertions(self):
        """Test assertions with whitespace"""
        assert validate_assertion_type("  status_code_in  ") is False  # Should not trim
        assert validate_assertion_type("status code in") is False  # Should not allow spaces

    def test_case_sensitivity(self):
        """Test that assertion types are case-sensitive"""
        assert validate_assertion_type("status_code_in") is True
        assert validate_assertion_type("STATUS_CODE_IN") is False
        assert validate_assertion_type("Status_Code_In") is False

    def test_special_characters(self):
        """Test assertions with special characters"""
        assert validate_assertion_type("status_code_in!") is False
        assert validate_assertion_type("@status_code_in") is False
        assert validate_assertion_type("status-code-in") is False  # Hyphens not underscores


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple functions"""

    def test_validate_then_get_info(self):
        """Test validating then retrieving info for assertion"""
        assertion_type = "response_time_p95_lt"

        # First validate
        assert validate_assertion_type(assertion_type) is True

        # Then get info
        info = get_assertion_info(assertion_type)
        assert info is not None
        assert info["operator"] == "<"
        assert info["type"] == "duration"

    def test_suggest_then_validate(self):
        """Test suggesting assertions then validating them"""
        suggestions = suggest_similar_assertions("throughput")

        # All suggestions should be valid
        for suggestion in suggestions:
            assert validate_assertion_type(suggestion) is True

    def test_list_all_then_validate(self):
        """Test that all listed assertions are valid"""
        all_types = AssertionRegistry.list_all()

        # Every assertion in the registry should validate
        for assertion_type in all_types:
            assert validate_assertion_type(assertion_type) is True
            assert AssertionRegistry.validate_assertion_type(assertion_type) is True

    def test_category_grouping_completeness(self):
        """Test that category grouping includes all assertions"""
        all_types = set(AssertionRegistry.list_all())
        by_category = AssertionRegistry.list_by_category()

        # Collect all assertions from categories
        categorized = set()
        for assertions in by_category.values():
            categorized.update(assertions)

        # All assertions should be categorized
        assert categorized == all_types


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
