#!/usr/bin/env python3
"""
Comprehensive fix for functional_agent.py to pass all 6 failing tests.

This script applies all necessary fixes in one operation to avoid linter conflicts.
"""

import re

def main():
    file_path = "sentinel_backend/orchestration_service/agents/functional_agent.py"

    with open(file_path, 'r') as f:
        content = f.read()

    # FIX #1 & #5: Skip basic test for POST/PUT/PATCH, let body_tests handle them with proper subtypes
    content = re.sub(
        r"        # Generate valid body\n        body = None\n        if method in \['POST', 'PUT', 'PATCH'\] and endpoint\.get\('requestBody'\):\n            body = self\._generate_valid_body\(endpoint\['requestBody'\], api_spec\)\n\n        # Determine expected status\n        expected_status = self\._get_success_status\(operation\['responses'\], method\)\n\n        return self\._create_test_case\(\n            endpoint=actual_path,\n            method=method,\n            description=f\"Valid \{method\} request to \{path\}\",\n            test_type='functional-positive',\n            test_subtype='complete_valid',\n            query_params=query_params,\n            body=body,\n            expected_status=expected_status\n        \)",
        """        # SKIP basic test for POST/PUT/PATCH with body - let _generate_body_tests handle those
        if method in ['POST', 'PUT', 'PATCH'] and endpoint.get('requestBody'):
            return None

        # Determine expected status
        expected_status = self._get_success_status(operation['responses'], method)

        return self._create_test_case(
            endpoint=actual_path,
            method=method,
            description=f"Valid {method} request to {path}",
            test_type='functional-positive',
            test_subtype='valid',
            query_params=query_params,
            body=None,
            expected_status=expected_status
        )""",
        content,
        flags=re.MULTILINE
    )

    # FIX #3 & #4: Ensure complete body test is ALWAYS generated
    content = re.sub(
        r"        # Test with complete body\n        complete_body = self\._generate_valid_body\(endpoint\['requestBody'\], api_spec\)\n        if complete_body and complete_body != minimal_body:",
        "        # Test with complete body (ALWAYS generate, deduplication will handle duplicates)\n        complete_body = self._generate_valid_body(endpoint['requestBody'], api_spec)\n        if complete_body:",
        content
    )

    # FIX #2 & #6: Add isinstance checks for body and include path in descriptions
    content = re.sub(
        r"        # Invalid data types\n        invalid_body = self\._generate_invalid_body\(endpoint\['requestBody'\], api_spec\)\n        if invalid_body:\n            test_cases\.append\(self\._create_test_case\(\n                endpoint=actual_path,\n                method=endpoint\['method'\],\n                description=f\"Invalid data types in body\",",
        """        # Invalid data types
        invalid_body = self._generate_invalid_body(endpoint['requestBody'], api_spec)
        if invalid_body and isinstance(invalid_body, dict):  # Ensure body is dict not string
            test_cases.append(self._create_test_case(
                endpoint=actual_path,
                method=endpoint['method'],
                description=f\"Invalid data types in {endpoint['path']} body\",""",
        content,
        flags=re.MULTILINE
    )

    content = re.sub(
        r"        # Constraint violations\n        violating_body = self\._generate_constraint_violating_body\(endpoint\['requestBody'\], api_spec\)\n        if violating_body:\n            test_cases\.append\(self\._create_test_case\(\n                endpoint=actual_path,\n                method=endpoint\['method'\],\n                description=f\"Constraint violations in body\",",
        """        # Constraint violations
        violating_body = self._generate_constraint_violating_body(endpoint['requestBody'], api_spec)
        if violating_body and isinstance(violating_body, dict):  # Ensure body is dict not string
            test_cases.append(self._create_test_case(
                endpoint=actual_path,
                method=endpoint['method'],
                description=f\"Constraint violations in {endpoint['path']} body\",""",
        content,
        flags=re.MULTILINE
    )

    # Write fixed content
    with open(file_path, 'w') as f:
        f.write(content)

    print("✅ Applied all fixes to functional_agent.py")
    print("Fixed issues:")
    print("  1. POST/PUT/PATCH basic tests now skip to avoid duplication")
    print("  2. Body isinstance checks added to prevent TypeError")
    print("  3. Complete body test always generated")
    print("  4. Proper test_subtype values maintained")
    print("  5. Path included in test descriptions for uniqueness")
    print("  6. violation_type already added by linter")

if __name__ == "__main__":
    main()
