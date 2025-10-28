# Test Generation Gap Analysis: FunctionalAgent vs Old Agents

## Executive Summary

The new consolidated `FunctionalAgent` generates **92% fewer tests** (25 tests vs 320 tests) compared to the combined old `FunctionalPositiveAgent` and `FunctionalNegativeAgent`. This is due to aggressive slicing limits, missing test strategies, and incomplete negative test coverage.

## Quantitative Comparison

| Metric | Old Positive Agent | Old Negative Agent | New Functional Agent | Gap |
|--------|-------------------|-------------------|---------------------|-----|
| **Generation Methods** | 5 | 34 | 12 | -27 methods (-79%) |
| **Tests per Endpoint** | ~100 | ~200+ | ~25 | -275 tests (-92%) |
| **Parameter Variations** | 10-15 per param | 5-10 per param | 3 per param | -12 tests (-80%) |
| **Negative Test Stages** | N/A | 15 stages | 4 basic tests | -11 stages (-73%) |
| **Array Slicing Limits** | None (unlimited) | 21 locations | 5 locations | -16 limits (-76%) |

---

## Root Cause Analysis

### 1. **Over-Aggressive Array Slicing** ⚠️
**Location**: Lines 161, 237, 375, 790, 818

**Issue**: Every iteration is limited to 2-3 items maximum:

```python
# Line 161 - Parameter variation tests
for value in values[:3]:  # ❌ LIMIT: Only 3 values per param
    test_cases.append(...)

# Line 375 - Invalid parameter tests
for value, violation_type in invalid_values[:2]:  # ❌ LIMIT: Only 2 per param
    test_cases.append(...)

# Line 790 - Unicode tests
for unicode_str, case_type in unicode_cases[:2]:  # ❌ LIMIT: Only 2 unicode tests
    test_cases.append(...)
```

**Old Positive Agent** (no limits):
```python
# Lines 321-341 - Generates 8+ values per integer parameter
test_values = [
    minimum,                    # Min boundary
    minimum + 1,               # Just above min
    (minimum + maximum) // 2,  # Middle value
    maximum - 1,               # Just below max
    maximum,                   # Max boundary
    5, 10, 20, 50             # Common values
]
values = list(set(v for v in test_values if minimum <= v <= maximum))
# Result: 8-12 tests per integer param
```

**Impact**:
- Old: 10-15 tests per parameter
- New: 3 tests per parameter
- **Lost: 7-12 tests per parameter (70-80% reduction)**

---

### 2. **Missing Parameter Combination Tests** ❌
**Location**: Not implemented in new agent

**Missing Logic**:
```python
# Old Positive Agent (lines 248-260) - MISSING IN NEW AGENT
if len(optional_params) >= 2:
    # Test pairs of parameters
    for i, param1 in enumerate(optional_params):
        for param2 in optional_params[i+1:]:
            test = await self._create_parameter_combination_test(
                endpoint, api_spec, [param1, param2]
            )
            test_cases.append(test)

# Test with all parameters
if optional_params:
    all_params_test = await self._create_all_parameters_test(
        endpoint, api_spec, optional_params
    )
    test_cases.append(all_params_test)
```

**Example**: For endpoint with 5 optional parameters
- Old: 10 pair combinations + 1 all parameters = **11 tests**
- New: **0 tests** (not implemented)
- **Lost: 100% of combination tests**

---

### 3. **Incomplete Negative Test Coverage** 🚨
**Location**: Lines 309-333 (NegativeStrategy)

**Old Negative Agent** had **15 comprehensive stages** (lines 102-180):

| Stage | Old Agent | New Agent | Status |
|-------|-----------|-----------|--------|
| 1. Format-Specific Tests | ✅ Lines 1108-1195 | ❌ Missing | Lost 100+ format tests |
| 2. Comprehensive BVA | ✅ Lines 1196-1600 | ⚠️ Basic only | Lost 80% boundary tests |
| 3. Type Mismatch | ✅ Lines 1601-1667 | ⚠️ Limited | Lost type matrix tests |
| 4. Required Fields | ✅ Lines 1669-1795 | ✅ Basic | 50% coverage |
| 5. Constraint Violations | ✅ Lines 1796-1969 | ⚠️ Limited | Lost nested constraints |
| 6. Null/Undefined | ✅ Lines 1970-2035 | ❌ Missing | Lost null variations |
| 7. Array Constraints | ✅ Lines 2036-2152 | ⚠️ Basic | Lost uniqueItems tests |
| 8. Enum Invalid | ✅ Lines 2153-2274 | ❌ Missing | Lost case/whitespace tests |
| 9. Nested Objects | ✅ Lines 2275-2365 | ❌ Missing | Lost deep nesting tests |
| 10. Multiple Failures | ✅ Lines 2366-2526 | ❌ Missing | Lost combined violations |
| 11. Content-Type | ✅ Lines 2527-2580 | ❌ Missing | Lost header tests |
| 12. Injection Tests | ✅ Lines 2581-2703 | ❌ Missing | Lost security tests |
| 13. PATCH-specific | ✅ Lines 2704-2805 | ❌ Missing | Lost partial update tests |
| 14. Collection Tests | ✅ Lines 2806-2941 | ❌ Missing | Lost pagination tests |
| 15. Structural Malform | ✅ Lines 2942-3210 | ❌ Missing | Lost JSON corruption tests |

**New Agent** implements only **4 basic negative tests** (lines 318-436):
```python
# 1. Missing required parameters (line 335)
# 2. Invalid parameter values (line 364) - LIMITED TO 2 PER PARAM
# 3. Invalid body - empty (line 401)
# 4. Invalid body - type/constraint (lines 412-435)
```

**Impact**: Lost 11 out of 15 test categories = **73% reduction**

---

### 4. **Missing Format-Specific Validators** 🔍
**Location**: Old Negative Agent lines 560-691

**Old Agent** had comprehensive invalid format generators:

```python
# Email formats (18 variants) - MISSING IN NEW AGENT
def _generate_invalid_email(self):
    return [
        "invalid-email", "@example.com", "user@", "user@.com",
        "user.@example.com", "user..user@example.com",
        "user@example.", "user@.example.com",
        "user name@example.com", "user@exam ple.com",
        "user@example..com", "user@", "@",
        "", "user@-example.com", "user@example-.com",
        "a" * 320 + "@example.com",  # too long
        "user@" + "a" * 255 + ".com",  # domain too long
    ]

# URL formats (14 variants) - MISSING IN NEW AGENT
# UUID formats (10 variants) - MISSING IN NEW AGENT
# Date formats (18 variants) - MISSING IN NEW AGENT
# Phone formats (14 variants) - MISSING IN NEW AGENT
# IP address (12 variants) - MISSING IN NEW AGENT
# Credit card (12 variants) - MISSING IN NEW AGENT
```

**New Agent**: Uses only `self.data_service.generate_realistic_data(strategy="invalid")`
- Generic type mismatch only
- No format-specific validation
- **Lost: 100+ format-specific invalid tests**

---

### 5. **Missing Body Variation Tests** 📦
**Location**: Old Positive Agent lines 264-284

**Old Agent** generated:
```python
# 1. Minimal body (only required fields)
minimal_body = self._generate_minimal_body(...)
test_cases.append(minimal_test)

# 2. Complete body (all fields)
complete_body = self._generate_valid_body(...)
if complete_body != minimal_body:
    test_cases.append(complete_test)
```

**New Agent** (line 184-210):
```python
# Only generates minimal and complete
# BUT: Missing variations between minimal and complete
# Missing: optional field combinations
```

**Impact**:
- Old: 2-5 body variations per endpoint
- New: 2 body variations maximum
- **Lost: 0-3 variation tests per endpoint**

---

## Missing Test Patterns

### ❌ 1. HTTP Method Coverage
**Issue**: New agent doesn't test all HTTP methods systematically

**Old Agents**: Tested GET, POST, PUT, PATCH, DELETE with method-specific logic
**New Agent**: Basic coverage only, missing method-specific edge cases

**Example Missing**:
- HEAD requests (same as GET but no body)
- OPTIONS requests (CORS preflight)
- Method not allowed tests

---

### ❌ 2. Parameter Location Variations
**Issue**: Incomplete coverage of parameter locations

**Old Coverage**:
- Query parameters: ✅ Comprehensive
- Path parameters: ✅ Substitution + invalid values
- Header parameters: ✅ Missing/invalid headers
- Cookie parameters: ❌ Not implemented in either

**New Coverage**:
- Query parameters: ⚠️ Limited (3 values max)
- Path parameters: ⚠️ Basic substitution only
- Header parameters: ❌ Missing

---

### ❌ 3. Body Content Variations
**Issue**: Missing comprehensive body test patterns

**Old Negative Agent** tested:
- Empty body: `{}`
- Null values in fields: `{"name": null}`
- Undefined vs null: `{"name": undefined}` vs `{"name": null}`
- Missing vs empty string: `{}` vs `{"name": ""}`
- Type mismatches per field
- Constraint violations per field
- Nested object errors
- Array constraint violations
- Multiple simultaneous errors

**New Agent** tests only:
- Empty body: `{}`
- Invalid types (generic)
- Constraint violations (basic)

**Lost**: 80% of body variation tests

---

### ❌ 4. Injection Attack Patterns
**Location**: Old Negative Agent lines 2581-2703

**Missing Security Tests**:
```python
# SQL Injection variants (MISSING)
["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT * FROM users--"]

# XSS variants (MISSING)
["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]

# NoSQL Injection (MISSING)
[{"$gt": ""}, {"$ne": null}]

# Command Injection (MISSING)
["; ls -la", "| cat /etc/passwd", "$(whoami)"]

# Path Traversal (MISSING)
["../../etc/passwd", "..\\..\\windows\\system32\\config\\sam"]

# LDAP Injection (MISSING)
["*)(uid=*))(|(uid=*", "admin*)(|(password=*)"]
```

**Impact**: **0% security testing coverage** in new agent

---

## Recommended Fixes

### Fix 1: Remove Array Slicing Limits ⚡
**File**: `functional_agent.py`
**Lines**: 161, 237, 375, 790, 818

```python
# BEFORE (line 161):
for value in values[:3]:  # ❌ Limit to 3 values per param
    test_cases.append(...)

# AFTER:
for value in values:  # ✅ Test all values
    test_cases.append(...)
```

**Impact**: +200% parameter variation tests

---

### Fix 2: Restore Parameter Combinations 🔄
**File**: `functional_agent.py`
**Location**: Add to PositiveStrategy class after line 173

```python
async def _generate_parameter_combination_tests(
    self,
    endpoint: Dict[str, Any],
    api_spec: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Generate tests with parameter combinations"""
    test_cases = []
    query_params = [p for p in endpoint.get('parameters', [])
                   if p.get('in') == 'query']
    optional_params = [p for p in query_params if not p.get('required', False)]

    # Test pairs
    if len(optional_params) >= 2:
        for i, param1 in enumerate(optional_params):
            for param2 in optional_params[i+1:]:
                combo = {
                    param1['name']: self._generate_valid_param_value(param1),
                    param2['name']: self._generate_valid_param_value(param2)
                }
                actual_path = self._substitute_path_params(endpoint)
                test_cases.append(self._create_test_case(
                    endpoint=actual_path,
                    method=endpoint['method'],
                    description=f"Test {param1['name']} + {param2['name']} combination",
                    test_type='functional-positive',
                    test_subtype='combination',
                    query_params=combo,
                    expected_status=200
                ))

    # Test all parameters
    if optional_params:
        all_params = {p['name']: self._generate_valid_param_value(p)
                     for p in optional_params}
        actual_path = self._substitute_path_params(endpoint)
        test_cases.append(self._create_test_case(
            endpoint=actual_path,
            method=endpoint['method'],
            description="Test all optional parameters",
            test_type='functional-positive',
            test_subtype='all_params',
            query_params=all_params,
            expected_status=200
        ))

    return test_cases

# Add to generate_tests method (line 98):
# Parameter combinations
combo_tests = await self._generate_parameter_combination_tests(endpoint, api_spec)
test_cases.extend(combo_tests)
```

**Impact**: +50-100 combination tests

---

### Fix 3: Add Format Validation Strategy 📋
**File**: `functional_agent.py`
**Location**: Add new strategy class after line 862

```python
class FormatValidationStrategy(TestStrategy):
    """Generate format-specific invalid value tests"""

    INVALID_FORMATS = {
        'email': [
            "invalid-email", "@example.com", "user@", "user@.com",
            "user.@example.com", "user..user@example.com",
            "user@example.", "user name@example.com", ""
        ],
        'uuid': [
            "not-a-uuid", "123e4567-e89b-12d3-a456-42661417400",
            "123e4567-e89b-12d3-a456-4266141740000",
            "123e4567-e89b-12d3-a456-42661417400g", ""
        ],
        'uri': [
            "not-a-url", "http://", "://example.com",
            "http://exam ple.com", "javascript:alert(1)", ""
        ],
        'date': [
            "not-a-date", "2023-13-01", "2023-02-30",
            "2023-00-01", "2023/01/01", ""
        ],
        'date-time': [
            "not-a-datetime", "2023-01-01T25:00:00Z",
            "2023-01-01T12:60:00Z", "2023-01-01 12:00:00", ""
        ]
    }

    async def generate_tests(
        self,
        endpoints: List[Dict[str, Any]],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate format validation tests"""
        test_cases = []

        for endpoint in endpoints:
            # Test parameters
            for param in endpoint.get('parameters', []):
                schema = param.get('schema', {})
                format_type = schema.get('format')

                if format_type in self.INVALID_FORMATS:
                    for invalid_value in self.INVALID_FORMATS[format_type]:
                        actual_path = self._substitute_path_params(endpoint)
                        test_cases.append(self._create_test_case(
                            endpoint=actual_path,
                            method=endpoint['method'],
                            description=f"Invalid {format_type} format: {param['name']}",
                            test_type='functional-negative',
                            test_subtype='format_invalid',
                            query_params={param['name']: invalid_value},
                            expected_status=400
                        ))

            # Test body formats
            if endpoint['method'] in ['POST', 'PUT', 'PATCH'] and endpoint.get('requestBody'):
                body_tests = await self._generate_body_format_tests(endpoint, api_spec)
                test_cases.extend(body_tests)

        return test_cases

    async def _generate_body_format_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate format tests for body properties"""
        test_cases = []
        content = endpoint['requestBody'].get('content', {})
        json_content = content.get('application/json', {})
        schema = json_content.get('schema', {})

        if not schema:
            return test_cases

        resolved_schema = self.agent._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get('type') == 'object':
            properties = resolved_schema.get('properties', {})

            for prop_name, prop_schema in properties.items():
                format_type = prop_schema.get('format')

                if format_type in self.INVALID_FORMATS:
                    base_body = self._generate_base_body(endpoint, api_spec)

                    for invalid_value in self.INVALID_FORMATS[format_type]:
                        body = base_body.copy()
                        body[prop_name] = invalid_value

                        actual_path = self._substitute_path_params(endpoint)
                        test_cases.append(self._create_test_case(
                            endpoint=actual_path,
                            method=endpoint['method'],
                            description=f"Invalid {format_type} in {prop_name}",
                            test_type='functional-negative',
                            test_subtype='format_invalid',
                            body=body,
                            expected_status=400
                        ))

        return test_cases

    def _generate_base_body(self, endpoint, api_spec):
        """Generate valid base body"""
        from sentinel_backend.orchestration_service.services.data_generation_service import DataGenerationService
        service = DataGenerationService()
        content = endpoint['requestBody'].get('content', {})
        json_content = content.get('application/json', {})
        schema = json_content.get('schema', {})
        resolved = self.agent._resolve_schema_ref(schema, api_spec)
        return service.generate_realistic_data(resolved, strategy="realistic")

    def _substitute_path_params(self, endpoint):
        """Substitute path parameters"""
        path = endpoint['path']
        for param in endpoint.get('parameters', []):
            if param.get('in') == 'path':
                schema = param.get('schema', {})
                value = 123 if schema.get('type') == 'integer' else 'test_id'
                path = path.replace(f"{{{param['name']}}}", str(value))
        return path

# Update __init__ to include format strategy (line 881):
self.strategies = {
    'positive': PositiveStrategy(self),
    'negative': NegativeStrategy(self),
    'boundary': BoundaryStrategy(self),
    'edge_case': EdgeCaseStrategy(self),
    'format': FormatValidationStrategy(self)  # ADD THIS
}
```

**Impact**: +100-200 format validation tests

---

### Fix 4: Add Injection Test Strategy 🛡️
**File**: `functional_agent.py`
**Location**: Add after FormatValidationStrategy

```python
class InjectionTestStrategy(TestStrategy):
    """Generate security injection tests"""

    INJECTION_PAYLOADS = {
        'sql': [
            "' OR '1'='1", "1; DROP TABLE users--",
            "' UNION SELECT * FROM users--", "admin'--",
            "1' AND '1'='1", "' OR 1=1--"
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ],
        'nosql': [
            '{"$gt": ""}', '{"$ne": null}',
            '{"$where": "1==1"}', '{"$regex": ".*"}'
        ],
        'command': [
            "; ls -la", "| cat /etc/passwd",
            "$(whoami)", "`whoami`",
            "&& echo vulnerable"
        ],
        'path_traversal': [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "....//....//etc/passwd"
        ],
        'ldap': [
            "*)(uid=*))(|(uid=*",
            "admin*)(|(password=*)",
            "*))%00"
        ]
    }

    async def generate_tests(
        self,
        endpoints: List[Dict[str, Any]],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate injection tests"""
        test_cases = []

        for endpoint in endpoints:
            # Test parameters
            for param in endpoint.get('parameters', []):
                if param.get('schema', {}).get('type') == 'string':
                    for category, payloads in self.INJECTION_PAYLOADS.items():
                        for payload in payloads[:2]:  # Limit to 2 per category
                            actual_path = self._substitute_path_params(endpoint)
                            test_cases.append(self._create_test_case(
                                endpoint=actual_path,
                                method=endpoint['method'],
                                description=f"{category.upper()} injection in {param['name']}",
                                test_type='functional-security',
                                test_subtype=f'{category}_injection',
                                query_params={param['name']: payload},
                                expected_status=400
                            ))

            # Test body injections
            if endpoint['method'] in ['POST', 'PUT', 'PATCH'] and endpoint.get('requestBody'):
                body_tests = await self._generate_body_injection_tests(endpoint, api_spec)
                test_cases.extend(body_tests)

        return test_cases

    async def _generate_body_injection_tests(
        self,
        endpoint: Dict[str, Any],
        api_spec: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate injection tests for body"""
        test_cases = []
        content = endpoint['requestBody'].get('content', {})
        json_content = content.get('application/json', {})
        schema = json_content.get('schema', {})

        if not schema:
            return test_cases

        resolved_schema = self.agent._resolve_schema_ref(schema, api_spec)

        if resolved_schema.get('type') == 'object':
            properties = resolved_schema.get('properties', {})

            for prop_name, prop_schema in properties.items():
                if prop_schema.get('type') == 'string':
                    base_body = self._generate_base_body(endpoint, api_spec)

                    for category, payloads in self.INJECTION_PAYLOADS.items():
                        payload = payloads[0]  # Use first payload
                        body = base_body.copy()
                        body[prop_name] = payload

                        actual_path = self._substitute_path_params(endpoint)
                        test_cases.append(self._create_test_case(
                            endpoint=actual_path,
                            method=endpoint['method'],
                            description=f"{category.upper()} injection in body.{prop_name}",
                            test_type='functional-security',
                            test_subtype=f'{category}_injection',
                            body=body,
                            expected_status=400
                        ))

        return test_cases

    def _generate_base_body(self, endpoint, api_spec):
        from sentinel_backend.orchestration_service.services.data_generation_service import DataGenerationService
        service = DataGenerationService()
        content = endpoint['requestBody'].get('content', {})
        json_content = content.get('application/json', {})
        schema = json_content.get('schema', {})
        resolved = self.agent._resolve_schema_ref(schema, api_spec)
        return service.generate_realistic_data(resolved, strategy="realistic")

    def _substitute_path_params(self, endpoint):
        path = endpoint['path']
        for param in endpoint.get('parameters', []):
            if param.get('in') == 'path':
                schema = param.get('schema', {})
                value = 123 if schema.get('type') == 'integer' else 'test_id'
                path = path.replace(f"{{{param['name']}}}", str(value))
        return path

# Update strategies (line 881):
self.strategies = {
    'positive': PositiveStrategy(self),
    'negative': NegativeStrategy(self),
    'boundary': BoundaryStrategy(self),
    'edge_case': EdgeCaseStrategy(self),
    'format': FormatValidationStrategy(self),
    'injection': InjectionTestStrategy(self)  # ADD THIS
}
```

**Impact**: +100-150 security tests

---

### Fix 5: Expand Parameter Value Generation 📈
**File**: `functional_agent.py`
**Location**: Line 231-247 (_generate_valid_param_values)

```python
# BEFORE:
def _generate_valid_param_values(self, param: Dict[str, Any]) -> List[Any]:
    schema = param.get('schema', {})
    param_type = schema.get('type', 'string')

    if 'enum' in schema:
        return schema['enum'][:3]  # ❌ Limited
    elif param_type == 'integer':
        minimum = schema.get('minimum', 1)
        maximum = schema.get('maximum', 100)
        return [minimum, (minimum + maximum) // 2, maximum]  # ❌ Only 3 values
    # ...

# AFTER:
def _generate_valid_param_values(self, param: Dict[str, Any]) -> List[Any]:
    schema = param.get('schema', {})
    param_type = schema.get('type', 'string')

    if 'enum' in schema:
        return schema['enum']  # ✅ All enum values
    elif param_type == 'integer':
        minimum = schema.get('minimum', 1)
        maximum = schema.get('maximum', 100)
        # Generate comprehensive boundary + common values
        values = [
            minimum,                    # Min boundary
            minimum + 1,               # Just above min
            (minimum + maximum) // 2,  # Middle value
            maximum - 1,               # Just below max
            maximum,                   # Max boundary
        ]
        # Add common test values within range
        common = [1, 5, 10, 20, 50, 100]
        values.extend([v for v in common if minimum <= v <= maximum])
        return list(set(values))  # ✅ Remove duplicates
    elif param_type == 'string':
        return ['test', 'value', 'sample', 'data', 'example']  # ✅ More variations
    elif param_type == 'boolean':
        return [True, False]
    else:
        return ['default', 'test', 'value']
```

**Impact**: +100-150 parameter variation tests

---

## Summary of Fixes

| Fix | Lines to Change | Tests Added | Effort |
|-----|----------------|-------------|--------|
| 1. Remove slicing limits | 161, 237, 375, 790, 818 | +150 | 5 min |
| 2. Add parameter combinations | After line 173 | +50-100 | 30 min |
| 3. Add format validation | After line 862 | +100-200 | 1 hour |
| 4. Add injection tests | After FormatValidationStrategy | +100-150 | 1 hour |
| 5. Expand param generation | Lines 231-247 | +100-150 | 15 min |
| **TOTAL** | **~15 locations** | **+500-750 tests** | **~3 hours** |

---

## Expected Results After Fixes

| Metric | Current | After Fixes | Improvement |
|--------|---------|-------------|-------------|
| Tests per endpoint | 25 | 300+ | +1100% |
| Parameter variations | 3 | 12-15 | +400% |
| Negative test coverage | 27% | 90%+ | +233% |
| Security test coverage | 0% | 100% | +∞ |
| Format validation | 0% | 100% | +∞ |
| Total test count | ~25 | ~320 | +1180% |

---

## Implementation Priority

### 🔥 Critical (Fix Immediately):
1. **Remove array slicing limits** - 5 minutes, +150 tests
2. **Expand parameter value generation** - 15 minutes, +100 tests

### ⚠️ High Priority (Fix This Week):
3. **Add parameter combination tests** - 30 minutes, +50 tests
4. **Add format validation strategy** - 1 hour, +150 tests

### 📋 Medium Priority (Fix This Sprint):
5. **Add injection test strategy** - 1 hour, +100 tests

---

## Conclusion

The new `FunctionalAgent` sacrificed **92% test coverage** for code consolidation. While the strategy pattern is elegant, the implementation is incomplete. The root causes are:

1. **Over-aggressive slicing** ([:2], [:3] everywhere)
2. **Missing test strategies** (11 out of 15 negative stages)
3. **Incomplete positive coverage** (no parameter combinations)
4. **No security testing** (0 injection tests)
5. **No format validation** (0 format-specific tests)

**Total effort to fix: ~3 hours**
**Test coverage increase: 25 → 320 tests (+1180%)**

The fixes are straightforward and can be implemented incrementally without breaking existing functionality.
