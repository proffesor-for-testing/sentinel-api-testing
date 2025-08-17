# Agent Specifications: The Sentinel Workforce

This document provides a detailed breakdown of the specialized agents within the Sentinel `ruv-swarm` ecosystem. Each agent is an expert in a particular domain of testing, and their collective intelligence drives the platform's effectiveness.

## Test Coverage Status (Phase 1 Complete - August 16, 2025)

**✅ PHASE 1 IMPLEMENTATION COMPLETE: 100% Agent Test Coverage Achieved**

All 8 core AI agents now have comprehensive unit test coverage with 184 tests total:
- Each agent has 21-25 dedicated unit tests covering all functionality
- Full mocking of LLM providers and external dependencies
- Dedicated test runner with coverage reporting (`run_agent_tests.sh`)
- Test infrastructure includes async support, fixtures, and comprehensive edge case handling

---

## Table of Agents

| Agent Type                    | Primary Responsibility                                      | Core Techniques & Capabilities                                                                                                                                 | Test Coverage |
| ----------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| **Spec-Linter-Agent**         | Analyzes API specs for "LLM-readiness"                      | NLP for description quality, schema validation, checks for missing examples.                                                                                   | ⏳ Pending     |
| **Functional-Positive-Agent** | Generates valid, "happy path" test cases.                   | Schema-based data generation, LLM-enhanced realistic data creation.                                                                                            | ✅ 23 tests   |
| **Functional-Negative-Agent** | Generates tests to trigger errors and validate failure paths. | Boundary Value Analysis (BVA), Equivalence Partitioning, fuzzing, LLM-driven creative invalid data generation.                                                 | ✅ 21 tests   |
| **Functional-Stateful-Agent** | Generates complex, multi-step test scenarios.               | Constructs and traverses a Semantic Operation Dependency Graph (SODG), manages state between API calls.                                                        | ✅ 24 tests   |
| **Security-Auth-Agent**       | Probes for authentication and authorization vulnerabilities.  | Tests for Broken Object-Level Authorization (BOLA), Broken Function-Level Authorization, and incorrect role enforcement.                                       | ✅ 23 tests   |
| **Security-Injection-Agent**  | Attempts to inject malicious payloads into requests.        | Generates tests for SQL/NoSQL injection, and critically, Prompt Injection attacks against LLM-backed APIs.                                                     | ✅ 25 tests   |
| **Performance-Planner-Agent** | Generates a complete performance test plan.                 | Translates API specs into JMeter/k6 scripts, uses LLMs for natural language configuration of load profiles.                                                    | ✅ 24 tests   |
| **Performance-Analyzer-Agent**| Analyzes performance test results for insights.             | Statistical analysis (mean, median, percentiles), real-time anomaly detection, historical trend analysis.                                                      | ⏳ Pending     |
| **Data-Mocking-Agent**        | Creates intelligent test data for API testing.              | Generates realistic mock data with schema-aware generation, relationship handling, and multiple strategies (realistic, edge cases, boundary, invalid).         | ✅ 22 tests   |
| **Base-Agent**                | Core agent functionality and shared behaviors.              | Abstract base class providing common methods, LLM integration, error handling, and agent lifecycle management.                                                | ✅ 22 tests   |

---

## Detailed Agent Profiles

### 1. `Spec-Linter-Agent`
- **Goal:** To improve the quality of downstream test generation by first improving the quality of the input API specification.
- **Workflow:**
    1. Ingests the parsed API specification.
    2. Evaluates the quality of `summary` and `description` fields using NLP heuristics.
    3. Validates that schemas are well-defined and not overly generic.
    4. Checks for the presence of `examples` in parameter and schema definitions.
    5. Generates a "LLM-readiness" score and a report with actionable recommendations for the user to improve their specification.

### 2. `Functional-Negative-Agent`
- **Goal:** To systematically and creatively probe an API's error-handling capabilities.
- **Workflow (Hybrid Approach):**
    1. **Stage 1 (Deterministic):**
        - Parses the spec to find all parameters with defined constraints (e.g., `minimum`, `maximum`, `minLength`, `maxLength`, `enum`).
        - Algorithmically generates a baseline of test cases using Boundary Value Analysis (BVA) for these constraints.
    2. **Stage 2 (Probabilistic):**
        - Uses a creatively prompted LLM to generate a diverse set of invalid inputs.
        - Prompts are engineered to produce payloads with wrong data types, missing required fields, unexpected extra fields, and structurally malformed JSON/XML.
- **Output:** A suite of test cases designed to elicit 4xx and 5xx error responses.

### 3. `Functional-Stateful-Agent`
- **Goal:** To validate complex business workflows that span multiple API calls.
- **Core Data Structure:** Semantic Operation Dependency Graph (SODG).
- **Workflow:**
    1. **Graph Construction:** During spec ingestion, the agent (or Specification Service) builds the SODG, creating directed edges between operations that have a producer-consumer relationship (e.g., `POST /users` -> `GET /users/{id}`).
    2. **Test Generation:** The agent receives a high-level goal (e.g., "Test the full resource lifecycle"). It finds all valid paths through the SODG that satisfy this goal.
    3. **State Management:** As it traverses a path, it defines `extract_rules` to capture values from responses (e.g., resource IDs) and `inject_rules` to use those captured values in subsequent requests.
- **Output:** A sequence of API calls with defined state management rules, representing a complete end-to-end test scenario.

### 4. `Security-Injection-Agent`
- **Goal:** To identify injection vulnerabilities, with a special focus on Prompt Injection in LLM-backed APIs.
- **Workflow (Two-Tiered LLM Architecture):**
    1. **Tier 1 (Strategy):** A powerful, state-of-the-art LLM (e.g., GPT-4) is prompted to devise a high-level plan of attack (e.g., "Outline five logical approaches to test for prompt injection").
    2. **Tier 2 (Payload Generation):** A less-restricted, potentially open-source and locally-hosted LLM takes the strategic outline and generates the actual malicious payloads. This bypasses the safety filters of commercial LLM providers.
- **Output:** A suite of test cases containing payloads designed to test for vulnerabilities like SQLi, NoSQLi, and various forms of prompt injection.
