# Psycho-Symbolic Analysis: Test Generation Agent Failures

## Executive Summary

Our Rust-based test generation agents exhibit **cognitive symbolic failures** rooted in **incomplete schema understanding** and **type-blind data generation**. This analysis applies psycho-symbolic reasoning to identify root causes and propose novel solutions.

---

## 1. Root Cognitive Failures: A Psycho-Symbolic Diagnosis

### 1.1 The "Placeholder Fallacy" - Symbolic Disconnection

**Location**: `sentinel_backend/sentinel_rust_core/src/agents/utils.rs:94`

```rust
"string" => {
    if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
        if !enum_values.is_empty() {
            let mut rng = thread_rng();
            let index = rng.gen_range(0..enum_values.len());
            return enum_values[index].clone();
        }
    }
    Value::String("example_string".to_string())  // ❌ COGNITIVE FAILURE
}
```

**Psychological Pattern**: **Default Response Bias**
- Like a student who writes "example" on a test when they don't know the answer
- The agent exhibits **learned helplessness** when schema constraints are ambiguous
- Falls back to generic placeholder instead of extracting actual valid values

**Symbolic Failure**: **Loss of Semantic Connection**
- The symbolic chain breaks: `Schema → Constraints → Valid Values`
- Agent generates `"example_string"` completely divorced from domain semantics
- No attempt to **infer** from context (endpoint name, property name, API patterns)

### 1.2 The "Type Confusion Syndrome" - Category Error

**Location**: `sentinel_backend/sentinel_rust_core/src/agents/utils.rs:23, 50-59`

```rust
if param_name_lower.contains("id") {
    if param_type == "integer" || param_type == "number" {
        return Value::Number(serde_json::Number::from(rng.gen_range(1..=100)));
    } else {
        return Value::String(generate_realistic_id());  // Generates "usr_6655"
    }
}
```

**Psychological Pattern**: **Category Confusion**
- Agent makes *implicit assumptions* about ID format without schema validation
- `generate_realistic_id()` can return `"usr_6655"` even when schema demands integer
- Cognitive bias toward "realistic looking" data over **schema compliance**

**Symbolic Failure**: **Type System Blindness**
- The symbolic type hierarchy is ignored: `Integer ≠ String`
- Agent prioritizes **surface realism** (looks like an ID) over **structural validity** (matches type)
- No meta-cognitive check: "Does my generated value satisfy the schema constraints?"

### 1.3 The "Enumeration Blindness" - Constraint Ignorance

**Critical Issue**: When enum values exist in schema but aren't extracted properly

```json
{
  "status": {
    "type": "string",
    "enum": ["available", "pending", "sold"]
  }
}
```

**Agent Generates**: `"status": "example_string"` ❌

**Should Generate**: `"status": "available"` or randomly from `["available", "pending", "sold"]` ✅

**Psychological Pattern**: **Constraint Neglect**
- Agent sees the schema structure but doesn't **internalize the constraints**
- Like reading instructions but not following them
- No mental model of "these are the ONLY valid values"

**Symbolic Failure**: **Finite Set Comprehension**
- Enums define a **closed symbolic universe**: `∀x ∈ status : x ∈ {available, pending, sold}`
- Agent fails to understand the **exclusivity** of enumerated values
- Generates values outside the allowed set

---

## 2. Symbolic Framework for Schema-Aware Generation

### 2.1 The "Schema Internalization" Architecture

**Core Principle**: Agents must build an **internal symbolic model** of the API schema before generation.

```rust
pub struct SchemaKnowledge {
    // Symbolic representation of constraints
    type_mappings: HashMap<String, SchemaType>,
    enum_constraints: HashMap<String, Vec<Value>>,
    numeric_bounds: HashMap<String, (Option<f64>, Option<f64>)>,
    string_patterns: HashMap<String, Regex>,

    // Semantic understanding
    property_semantics: HashMap<String, PropertySemantic>,
    domain_vocabulary: DomainVocabulary,
}

pub struct PropertySemantic {
    name: String,
    inferred_domain: Domain,  // email, id, status, category, etc.
    constraints: Constraints,
    examples: Vec<Value>,
}
```

**Psycho-Symbolic Reasoning Process**:

1. **Schema Parsing** (Symbolic Extraction)
   - Extract ALL constraints: type, enum, min/max, pattern, format
   - Build constraint graph: property → constraints → valid values

2. **Semantic Inference** (Cognitive Enrichment)
   - Infer domain from property names: `status` → likely enum, `id` → likely integer/string
   - Cross-reference with OpenAPI examples, descriptions

3. **Validation Projection** (Forward Symbolic Reasoning)
   - Before generating value: "What constraints must this satisfy?"
   - Generate → Validate → Adjust loop until valid

### 2.2 Enhanced Data Generation Algorithm

```rust
pub fn generate_schema_aware_value(
    prop_name: &str,
    schema: &Value,
    schema_knowledge: &SchemaKnowledge
) -> Result<Value, GenerationError> {

    // Step 1: Extract ALL constraints (symbolic grounding)
    let constraints = extract_all_constraints(schema)?;

    // Step 2: Check for enum first (highest priority)
    if let Some(enum_values) = constraints.enum_values {
        if enum_values.is_empty() {
            return Err(GenerationError::EmptyEnum);
        }
        return Ok(select_random_enum_value(&enum_values));
    }

    // Step 3: Type-aware generation with constraint checking
    let value = match constraints.schema_type {
        SchemaType::String => {
            if let Some(pattern) = constraints.pattern {
                generate_pattern_matching_string(pattern)?
            } else if let Some((min, max)) = constraints.length_bounds {
                generate_bounded_string(prop_name, min, max)?
            } else {
                generate_semantic_string(prop_name, &schema_knowledge.domain_vocabulary)?
            }
        },
        SchemaType::Integer => {
            generate_bounded_integer(
                constraints.numeric_bounds.0,
                constraints.numeric_bounds.1
            )?
        },
        SchemaType::Number => {
            generate_bounded_number(
                constraints.numeric_bounds.0,
                constraints.numeric_bounds.1
            )?
        },
        _ => generate_default_for_type(&constraints.schema_type)?
    };

    // Step 4: Validate before returning (meta-cognitive check)
    if !validate_against_schema(&value, schema) {
        return Err(GenerationError::ValidationFailed {
            value: value.clone(),
            schema: schema.clone(),
        });
    }

    Ok(value)
}
```

### 2.3 Enum-First Strategy

**Principle**: Enums are **the most specific constraints** and should take absolute priority.

```rust
pub fn extract_enum_values(schema: &Value, api_spec: &Value) -> Option<Vec<Value>> {
    // Direct enum
    if let Some(enum_array) = schema.get("enum").and_then(|e| e.as_array()) {
        if !enum_array.is_empty() {
            return Some(enum_array.clone());
        }
    }

    // anyOf with enum (for nullable enums)
    if let Some(any_of) = schema.get("anyOf").and_then(|a| a.as_array()) {
        for variant in any_of {
            if variant.get("type").and_then(|t| t.as_str()) == Some("null") {
                continue;  // Skip null option
            }
            if let Some(enum_array) = variant.get("enum").and_then(|e| e.as_array()) {
                if !enum_array.is_empty() {
                    return Some(enum_array.clone());
                }
            }
        }
    }

    // $ref to enum definition
    if let Some(ref_path) = schema.get("$ref").and_then(|r| r.as_str()) {
        let resolved = resolve_schema_ref(schema, api_spec);
        if let Some(enum_array) = resolved.get("enum").and_then(|e| e.as_array()) {
            if !enum_array.is_empty() {
                return Some(enum_array.clone());
            }
        }
    }

    None
}
```

---

## 3. Meta-Cognitive Self-Evaluation System

### 3.1 The "Test Quality Oracle" - Agent Self-Awareness

**Principle**: Agents must **evaluate their own test cases** before submission.

```rust
pub struct TestQualityEvaluator {
    schema_validator: SchemaValidator,
    semantic_analyzer: SemanticAnalyzer,
    quality_metrics: QualityMetrics,
}

impl TestQualityEvaluator {
    pub fn evaluate_test_case(
        &self,
        test_case: &TestCase,
        schema: &Value
    ) -> TestQualityReport {

        let mut report = TestQualityReport::new();

        // 1. Schema Compliance Check
        if let Some(body) = &test_case.body {
            report.schema_valid = self.schema_validator.validate(body, schema);
            if !report.schema_valid {
                report.add_error("Test body violates schema constraints");
            }
        }

        // 2. Type Consistency Check
        for (param_name, param_value) in &test_case.query_params {
            let expected_type = self.get_param_expected_type(param_name, schema);
            let actual_type = self.infer_value_type(param_value);

            if expected_type != actual_type {
                report.add_error(format!(
                    "Type mismatch for {}: expected {:?}, got {:?}",
                    param_name, expected_type, actual_type
                ));
            }
        }

        // 3. Enum Compliance Check
        for (prop_name, value) in self.extract_all_properties(&test_case) {
            if let Some(enum_values) = self.get_enum_constraints(prop_name, schema) {
                if !enum_values.contains(value) {
                    report.add_error(format!(
                        "Property {} has value {:?} not in enum {:?}",
                        prop_name, value, enum_values
                    ));
                }
            }
        }

        // 4. Semantic Coherence Check
        let semantic_score = self.semantic_analyzer.analyze_coherence(&test_case);
        report.semantic_quality = semantic_score;

        if semantic_score < 0.7 {
            report.add_warning("Test data lacks semantic coherence");
        }

        report
    }
}
```

### 3.2 Learning from Execution Results

**Principle**: Agents learn from actual API responses to improve generation.

```rust
pub struct ExecutionFeedbackLoop {
    execution_history: Vec<TestExecution>,
    pattern_learner: PatternLearner,
}

impl ExecutionFeedbackLoop {
    pub fn learn_from_execution(&mut self, execution: TestExecution) {
        self.execution_history.push(execution.clone());

        match execution.result {
            ExecutionResult::ValidationError(ref err) => {
                // Extract constraint violation pattern
                if err.contains("422") || err.contains("validation") {
                    self.pattern_learner.record_constraint_violation(
                        &execution.test_case,
                        err
                    );

                    // Update schema knowledge
                    if let Some(extracted_constraint) = self.extract_constraint_from_error(err) {
                        self.update_schema_knowledge(extracted_constraint);
                    }
                }
            },
            ExecutionResult::Success => {
                // Learn successful patterns
                self.pattern_learner.record_success(&execution.test_case);
            },
            _ => {}
        }
    }

    fn extract_constraint_from_error(&self, error: &str) -> Option<LearnedConstraint> {
        // Parse error messages like:
        // "status must be one of: available, pending, sold"
        // "id must be an integer"

        if let Some(enum_pattern) = self.parse_enum_error(error) {
            return Some(LearnedConstraint::Enum(enum_pattern));
        }

        if let Some(type_pattern) = self.parse_type_error(error) {
            return Some(LearnedConstraint::Type(type_pattern));
        }

        None
    }
}
```

---

## 4. Concrete Rust Implementation Strategy

### 4.1 Immediate Fixes (High Priority)

#### Fix 1: Enhanced Enum Extraction

**File**: `sentinel_backend/sentinel_rust_core/src/agents/utils.rs`

```rust
/// Generate example value from JSON schema with proper enum handling
pub fn generate_schema_example(schema: &Value) -> Value {
    // Priority 1: Check for example
    if let Some(example) = schema.get("example") {
        return example.clone();
    }

    let schema_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

    match schema_type {
        "string" => {
            // Priority 2: Extract enum values (CRITICAL FIX)
            if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
                if !enum_values.is_empty() {
                    let mut rng = thread_rng();
                    let index = rng.gen_range(0..enum_values.len());
                    return enum_values[index].clone();
                }
                // If enum array exists but is empty, this is a schema error
                // Fall through to default with warning
                eprintln!("WARNING: Empty enum array in schema");
            }

            // Priority 3: Check anyOf for nullable enums
            if let Some(any_of) = schema.get("anyOf").and_then(|a| a.as_array()) {
                for variant in any_of {
                    // Skip null type
                    if variant.get("type").and_then(|t| t.as_str()) == Some("null") {
                        continue;
                    }
                    // Check for enum in variant
                    if let Some(enum_values) = variant.get("enum").and_then(|e| e.as_array()) {
                        if !enum_values.is_empty() {
                            let mut rng = thread_rng();
                            let index = rng.gen_range(0..enum_values.len());
                            return enum_values[index].clone();
                        }
                    }
                }
            }

            // Only use fallback if no enum constraints exist
            Value::String("valid_test_string".to_string())
        }
        // ... rest of types
    }
}
```

#### Fix 2: Type-Aware ID Generation

```rust
/// Generate a realistic ID value respecting schema type
pub fn generate_realistic_id(schema: &Value) -> Value {
    let id_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");

    match id_type {
        "integer" => {
            let mut rng = thread_rng();
            let min = schema.get("minimum").and_then(|m| m.as_i64()).unwrap_or(1);
            let max = schema.get("maximum").and_then(|m| m.as_i64()).unwrap_or(10000);
            Value::Number(serde_json::Number::from(rng.gen_range(min..=max)))
        }
        "number" => {
            let mut rng = thread_rng();
            let min = schema.get("minimum").and_then(|m| m.as_f64()).unwrap_or(1.0);
            let max = schema.get("maximum").and_then(|m| m.as_f64()).unwrap_or(10000.0);
            let value = rng.gen_range(min..=max);
            Value::Number(serde_json::Number::from_f64(value).unwrap())
        }
        "string" => {
            // String ID formats: uuid, alphanumeric, prefixed
            if let Some(format) = schema.get("format").and_then(|f| f.as_str()) {
                match format {
                    "uuid" => Value::String(uuid::Uuid::new_v4().to_string()),
                    _ => generate_string_id()
                }
            } else {
                generate_string_id()
            }
        }
        _ => generate_string_id()
    }
}

fn generate_string_id() -> Value {
    let mut rng = thread_rng();
    let formats = vec![
        || rng.gen_range(1..=10000).to_string(),  // Numeric string
        || format!("usr_{}", rng.gen_range(1000..=9999)),  // Prefixed
        || {
            (0..12)
                .map(|_| {
                    let chars = "abcdefghijklmnopqrstuvwxyz0123456789";
                    chars.chars().nth(rng.gen_range(0..chars.len())).unwrap()
                })
                .collect::<String>()
        },  // Alphanumeric
    ];

    let selected = formats.choose(&mut rng).unwrap();
    Value::String(selected())
}
```

#### Fix 3: Parameter Generation with Schema Priority

```rust
/// Generate a realistic parameter value based on parameter name and schema
pub fn generate_parameter_value(param_name: &str, schema: &Value) -> Value {
    // Priority 1: Use example if provided
    if let Some(example) = schema.get("example") {
        return example.clone();
    }

    // Priority 2: Check for enum (CRITICAL)
    if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
        if !enum_values.is_empty() {
            let mut rng = thread_rng();
            return enum_values[rng.gen_range(0..enum_values.len())].clone();
        }
    }

    // Priority 3: Type-specific generation
    let param_type = schema.get("type").and_then(|t| t.as_str()).unwrap_or("string");
    let param_name_lower = param_name.to_lowercase();

    // Generate based on name semantics + type constraints
    if param_name_lower.contains("id") || param_name_lower.ends_with("_id") {
        return generate_realistic_id(schema);
    } else if param_name_lower.contains("email") {
        return Value::String("test@example.com".to_string());
    } else if param_name_lower.contains("status") || param_name_lower.contains("category") {
        // These are likely enums, but fallback gracefully
        return generate_schema_example(schema);
    }

    // Fallback to schema-based generation
    generate_schema_example(schema)
}
```

### 4.2 Advanced Enhancements (Medium Priority)

#### Enhancement 1: SchemaAnalyzer Module

Create new file: `sentinel_backend/sentinel_rust_core/src/agents/schema_analyzer.rs`

```rust
use serde_json::Value;
use std::collections::HashMap;

pub struct SchemaAnalyzer {
    api_spec: Value,
    constraint_cache: HashMap<String, ExtractedConstraints>,
}

#[derive(Clone)]
pub struct ExtractedConstraints {
    pub schema_type: String,
    pub enum_values: Option<Vec<Value>>,
    pub numeric_bounds: Option<(Option<f64>, Option<f64>)>,
    pub string_constraints: Option<StringConstraints>,
    pub nullable: bool,
}

#[derive(Clone)]
pub struct StringConstraints {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub format: Option<String>,
}

impl SchemaAnalyzer {
    pub fn new(api_spec: Value) -> Self {
        Self {
            api_spec,
            constraint_cache: HashMap::new(),
        }
    }

    pub fn extract_constraints(&mut self, schema: &Value) -> ExtractedConstraints {
        // Resolve $ref first
        let resolved = self.resolve_ref(schema);

        ExtractedConstraints {
            schema_type: self.extract_type(&resolved),
            enum_values: self.extract_enums(&resolved),
            numeric_bounds: self.extract_numeric_bounds(&resolved),
            string_constraints: self.extract_string_constraints(&resolved),
            nullable: self.is_nullable(&resolved),
        }
    }

    fn extract_enums(&self, schema: &Value) -> Option<Vec<Value>> {
        // Direct enum
        if let Some(arr) = schema.get("enum").and_then(|e| e.as_array()) {
            if !arr.is_empty() {
                return Some(arr.clone());
            }
        }

        // anyOf/oneOf patterns
        if let Some(variants) = schema.get("anyOf").and_then(|a| a.as_array()) {
            for variant in variants {
                if variant.get("type") != Some(&Value::String("null".to_string())) {
                    if let Some(arr) = variant.get("enum").and_then(|e| e.as_array()) {
                        if !arr.is_empty() {
                            return Some(arr.clone());
                        }
                    }
                }
            }
        }

        None
    }

    fn resolve_ref(&self, schema: &Value) -> Value {
        if let Some(ref_path) = schema.get("$ref").and_then(|r| r.as_str()) {
            // Navigate reference
            let parts: Vec<&str> = ref_path.trim_start_matches("#/").split('/').collect();
            let mut current = &self.api_spec;

            for part in parts {
                if let Some(next) = current.get(part) {
                    current = next;
                } else {
                    return schema.clone();
                }
            }

            return current.clone();
        }

        schema.clone()
    }
}
```

---

## 5. Continuous Improvement Framework

### 5.1 Feedback Loop Architecture

```rust
pub struct AgentImprovementSystem {
    test_executor: TestExecutor,
    result_analyzer: ResultAnalyzer,
    knowledge_base: SharedKnowledgeBase,
    improvement_engine: ImprovementEngine,
}

impl AgentImprovementSystem {
    pub async fn improve_from_execution(&mut self, test_results: Vec<TestResult>) {
        for result in test_results {
            // Analyze failures
            if let TestOutcome::Failed(error) = &result.outcome {
                let analysis = self.result_analyzer.analyze_failure(error);

                match analysis.failure_category {
                    FailureCategory::SchemaViolation => {
                        // Extract the actual constraint from error
                        if let Some(constraint) = analysis.extracted_constraint {
                            self.knowledge_base.add_learned_constraint(
                                &result.endpoint,
                                &result.property,
                                constraint
                            );
                        }
                    }
                    FailureCategory::TypeMismatch => {
                        self.knowledge_base.record_type_correction(
                            &result.property,
                            &analysis.expected_type,
                            &analysis.actual_type
                        );
                    }
                    _ => {}
                }
            }
        }

        // Update generation strategies
        self.improvement_engine.update_strategies(&self.knowledge_base);
    }
}
```

### 5.2 Pattern Learning System

```rust
pub struct PatternLearner {
    successful_patterns: HashMap<String, Vec<Value>>,
    failed_patterns: HashMap<String, Vec<(Value, String)>>,
    constraint_patterns: Vec<ConstraintPattern>,
}

impl PatternLearner {
    pub fn learn_from_success(&mut self, test_case: &TestCase) {
        // Record successful value patterns
        if let Some(body) = &test_case.body {
            self.extract_and_record_patterns(body, &test_case.path);
        }
    }

    pub fn learn_from_failure(&mut self, test_case: &TestCase, error: &str) {
        // Parse error to extract constraint information
        if let Some(constraint) = self.parse_constraint_from_error(error) {
            self.constraint_patterns.push(constraint);
        }
    }

    pub fn suggest_value(&self, property: &str, schema: &Value) -> Option<Value> {
        // Use learned patterns to suggest values
        if let Some(patterns) = self.successful_patterns.get(property) {
            // Return a random successful pattern
            let mut rng = rand::thread_rng();
            return patterns.choose(&mut rng).cloned();
        }
        None
    }
}
```

---

## 6. Summary: From Cognitive Failure to Intelligent Generation

### Current State (Cognitive Failures):
1. **Placeholder Fallacy**: Falls back to "example_string" without extracting enums
2. **Type Confusion**: Generates "usr_6655" when schema expects integers
3. **Constraint Neglect**: Ignores enum constraints and generates invalid values

### Proposed Solution (Intelligent Generation):
1. **Schema Internalization**: Build complete symbolic model of constraints
2. **Enum-First Strategy**: Prioritize enum extraction over fallbacks
3. **Type-Aware Generation**: Respect type system strictly
4. **Meta-Cognitive Validation**: Self-evaluate before submission
5. **Continuous Learning**: Learn from execution results

### Implementation Priorities:
1. **Immediate** (Days 1-2): Fix enum extraction and type-aware ID generation
2. **Short-term** (Week 1): Add SchemaAnalyzer and TestQualityEvaluator
3. **Medium-term** (Weeks 2-3): Implement feedback loop and pattern learning
4. **Long-term** (Month 1+): Advanced semantic inference and cross-agent learning

### Expected Outcomes:
- ✅ 100% schema-compliant positive tests
- ✅ Diverse, meaningful negative tests without duplication
- ✅ Self-improving agents that learn from failures
- ✅ Human-level QA expertise in test generation

---

**The key insight**: Test generation agents fail not because they lack data, but because they lack **symbolic understanding**. By building proper mental models of API schemas and enabling meta-cognitive self-evaluation, we transform blind generation into intelligent, adaptive testing.