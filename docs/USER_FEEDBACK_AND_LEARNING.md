# User Feedback and Learning System

**Version:** 1.0.0
**Last Updated:** 2025-10-29

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Learning Loop](#learning-loop)
4. [User Workflows](#user-workflows)
5. [API Reference](#api-reference)
6. [Metrics & Analytics](#metrics--analytics)
7. [Integration Guide](#integration-guide)
8. [Advanced Topics](#advanced-topics)

---

## Overview

The Sentinel platform implements a **continuous learning system** that improves test generation quality over time through user feedback and reinforcement learning. The system combines three complementary learning mechanisms:

### Learning Components

1. **ReasoningBank** - Trajectory-based learning from execution history
2. **Q-Learning** - Reinforcement learning with reward mapping from feedback
3. **Pattern Recognition** - Semantic pattern extraction and reuse with AgentDB

### Key Benefits

- **30-50% reduction** in duplicate test generation through pattern reuse
- **Continuous improvement** of test quality based on user feedback
- **Automated learning** from both successes and failures
- **Semantic search** for intelligent pattern matching (150x faster with AgentDB)

---

## Architecture

### System Components Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INTERACTION                          │
│  ┌────────────┐  ┌─────────────┐  ┌──────────────┐            │
│  │ Test Case  │  │ Test Suite  │  │  Statistics  │            │
│  │  Feedback  │  │  Feedback   │  │   Dashboard  │            │
│  └─────┬──────┘  └──────┬──────┘  └──────┬───────┘            │
└────────┼─────────────────┼─────────────────┼───────────────────┘
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FEEDBACK API LAYER                             │
│  POST /api/v1/feedback/test-case                                │
│  POST /api/v1/feedback/test-suite                               │
│  GET  /api/v1/feedback/statistics                               │
│  GET  /api/v1/feedback/test-case/{id}                           │
│  GET  /api/v1/feedback/patterns/{id}                            │
└────────┬───────────────────────┬────────────────────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────────┐   ┌─────────────────────┐
│  FeedbackLearning   │   │   Database Models   │
│      Queue          │   │                     │
│  ┌───────────────┐  │   │ • TestCaseFeedback │
│  │   Pending     │  │   │ • TestSuiteFeedback│
│  │  Processing   │  │   │ • TestCasePattern  │
│  │  Completed    │  │   │                     │
│  └───────────────┘  │   └─────────────────────┘
└────────┬────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   LEARNING PROCESSING LAYER                      │
│                                                                   │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │  ReasoningBank   │  │   Q-Learning     │  │   Pattern    │  │
│  │                  │  │   (RL Service)   │  │  Learning    │  │
│  │  • Trajectories  │  │                  │  │  (AgentDB)   │  │
│  │  • Judgment      │  │ • Reward Mapping │  │              │  │
│  │  • Distillation  │  │ • Q-Table Update │  │ • Extraction │  │
│  │                  │  │ • Policy Update  │  │ • Storage    │  │
│  └────────┬─────────┘  └────────┬─────────┘  └──────┬───────┘  │
│           │                     │                    │           │
└───────────┼─────────────────────┼────────────────────┼───────────┘
            │                     │                    │
            ▼                     ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                      STORAGE LAYER                               │
│                                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │  PostgreSQL  │  │  Q-Learning  │  │  AgentDB Vector    │    │
│  │  (Task       │  │  Q-Tables    │  │  Store             │    │
│  │  Trajector.) │  │  (In-Memory/ │  │  (384-dim          │    │
│  │              │  │  Persistent) │  │  embeddings)       │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
            │                     │                    │
            ▼                     ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                     AGENT EXECUTION LAYER                        │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  BaseLearningAgent Mixin                                 │   │
│  │                                                           │   │
│  │  • start_trajectory()    → Track execution start         │   │
│  │  • log_action()          → Log intermediate steps        │   │
│  │  • complete_trajectory() → Record final results          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  Agents using learning:                                          │
│  • FunctionalPositiveAgent  • SecurityAuthAgent                  │
│  • FunctionalNegativeAgent  • SecurityInjectionAgent             │
│  • PerformancePlannerAgent  • DataMockingAgent                   │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Agent Execution** → Trajectory tracking via `BaseLearningAgent` mixin
2. **Trajectory Storage** → PostgreSQL `task_trajectories` table
3. **User Feedback** → REST API submission
4. **Queue Processing** → Asynchronous learning integration
5. **Learning Updates**:
   - **ReasoningBank**: LLM-as-judge verdict + pattern distillation
   - **Q-Learning**: Reward calculation + Q-table update
   - **Pattern Learning**: Embedding generation + AgentDB storage
6. **Future Test Generation** → Enhanced with learned patterns

---

## Learning Loop

### Complete Learning Cycle

```
┌──────────────────┐
│  1. AGENT        │
│  EXECUTION       │
│                  │
│  Agent starts    │
│  tracking via    │
│  start_          │
│  trajectory()    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  2. ACTION       │
│  LOGGING         │
│                  │
│  log_action()    │
│  at each step    │
│                  │
│  • API analysis  │
│  • Test gen.     │
│  • Validation    │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  3. TRAJECTORY   │
│  COMPLETION      │
│                  │
│  complete_       │
│  trajectory()    │
│                  │
│  Stores:         │
│  • Actions taken │
│  • Final output  │
│  • Metrics       │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  4. USER         │
│  FEEDBACK        │
│                  │
│  POST /feedback/ │
│  test-case       │
│                  │
│  • Rating (1-5)  │
│  • Helpful flag  │
│  • Found issue   │
│  • Comments      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  5. FEEDBACK     │
│  QUEUING         │
│                  │
│  FeedbackLearning│
│  Queue           │
│                  │
│  Status:         │
│  • pending       │
│  • processing    │
│  • completed     │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  6. PARALLEL LEARNING PROCESSING                     │
│                                                       │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │ ReasoningBank│  │  Q-Learning │  │  Pattern   │  │
│  │              │  │             │  │  Learning  │  │
│  │ • LLM judge  │  │ • Reward    │  │            │  │
│  │   verdict    │  │   calc.     │  │ • Extract  │  │
│  │              │  │             │  │   pattern  │  │
│  │ • Distill    │  │ • Q-table   │  │            │  │
│  │   patterns   │  │   update    │  │ • Generate │  │
│  │              │  │             │  │   embedding│  │
│  │ • Store      │  │ • Policy    │  │            │  │
│  │   outcome    │  │   optimize  │  │ • Store in │  │
│  │              │  │             │  │   AgentDB  │  │
│  └──────────────┘  └─────────────┘  └────────────┘  │
└─────────────────────────┬────────────────────────────┘
                          │
                          ▼
                ┌──────────────────┐
                │  7. LEARNING     │
                │  ARTIFACTS       │
                │                  │
                │  • Judged        │
                │    trajectories  │
                │  • Updated       │
                │    Q-values      │
                │  • Stored        │
                │    patterns      │
                │  • Improved      │
                │    policies      │
                └────────┬─────────┘
                         │
                         ▼
                ┌──────────────────┐
                │  8. FUTURE TEST  │
                │  GENERATION      │
                │                  │
                │  Agents use:     │
                │  • High-Q        │
                │    actions       │
                │  • Successful    │
                │    patterns      │
                │  • Learned       │
                │    strategies    │
                └──────────────────┘
```

### 1. Trajectory Tracking (BaseLearningAgent)

Every agent execution is tracked using the `BaseLearningAgent` mixin:

```python
class FunctionalPositiveAgent(BaseAgent, BaseLearningAgent):
    async def execute(self, task, api_spec):
        # Start trajectory tracking
        trajectory = await self.start_trajectory(
            task_type="test_generation",
            task_description=f"Generate positive tests for {task.endpoint}",
            context_data={
                "api_spec": api_spec.dict(),
                "endpoint": task.endpoint,
                "method": task.method
            },
            db_session=db_session
        )

        # Log actions during execution
        await self.log_action(
            "Analyzing API specification",
            metadata={"endpoint_count": len(endpoints)}
        )

        await self.log_action(
            "Generating test cases",
            metadata={"tests_generated": len(test_cases)}
        )

        # Complete trajectory with results
        await self.complete_trajectory(
            final_output={
                "test_cases": [tc.dict() for tc in test_cases],
                "total_tests": len(test_cases)
            },
            execution_time_ms=execution_time,
            test_success_rate=0.95,
            coverage_score=0.87
        )

        return test_cases
```

**Key Methods:**

- `start_trajectory()` - Begins tracking with task description and context
- `log_action()` - Records each step during execution
- `complete_trajectory()` - Saves final output and metrics
- `abort_trajectory()` - Handles error cases

### 2. LLM-as-Judge Verdict (ReasoningBank)

After trajectory completion, Claude Sonnet 4.5 evaluates the outcome:

**Judgment Process:**

```python
# JudgmentService uses Claude Sonnet 4.5 at temperature=0
judgment_service = JudgmentService(anthropic_client)

# Evaluate trajectory
outcome, confidence, reasoning, metadata = await judgment_service.judge_trajectory(
    trajectory
)

# Outcome: SUCCESS, FAILURE, or PARTIAL
# Confidence: 0.0-1.0
# Reasoning: 2-3 sentence explanation
```

**Judgment Criteria:**

1. Task completion success
2. Test comprehensiveness and correctness
3. Error handling quality
4. Output fitness for purpose

### 3. Pattern Distillation

Successful trajectories are analyzed to extract reusable patterns:

```python
# Extract pattern from successful test
pattern = await pattern_learning_service.extract_pattern_from_test_case(
    test_case=test_case,
    execution_result=execution_result,
    api_spec=api_spec
)

# Generate 384-dim embedding
pattern.embedding = await embedding_service.embed_test_pattern(pattern)

# Store in AgentDB with deduplication
result = await pattern_learning_service.store_pattern(
    pattern,
    deduplicate=True  # Merge if 87%+ similar
)
```

**Pattern Components:**

- **Endpoint Pattern**: Normalized (e.g., `/api/users/{id}`)
- **Test Structure**: Generic template with assertions
- **API Characteristics**: Auth, pagination, filtering
- **Success Metrics**: Execution time, pass rate
- **Confidence Score**: Updated based on usage (0.0-1.0)

### 4. Reward Mapping (Q-Learning)

User feedback is converted to numerical rewards:

```python
# FeedbackRewardMapper calculates rewards
reward_mapper = FeedbackRewardMapper()

reward = reward_mapper.calculate_reward(
    rating=5,              # 1-5 stars
    is_helpful=True,       # +0.3 bonus
    found_issue=True,      # +0.3 bonus
    not_helpful=False,     # -0.3 penalty
    execution_result={
        "status": "passed",
        "execution_time_ms": 250
    }
)

# Result: reward = 1.0 (base) + 0.3 (helpful) + 0.3 (found_issue) + 0.1 (fast) = 1.7
# Clamped to [-1.0, 1.0] → 1.0
```

**Reward Formula:**

| Rating | Base Reward | Helpful | Found Issue | Fast (<1s) | Slow (>10s) |
|--------|-------------|---------|-------------|------------|-------------|
| 5 ⭐    | +1.0        | +0.3    | +0.3        | +0.05      | -0.05       |
| 4 ⭐    | +0.5        | +0.3    | +0.3        | +0.05      | -0.05       |
| 3 ⭐    | 0.0         | +0.3    | +0.3        | +0.05      | -0.05       |
| 2 ⭐    | -0.3        | +0.3    | +0.3        | +0.05      | -0.05       |
| 1 ⭐    | -0.5        | +0.3    | +0.3        | +0.05      | -0.05       |

**Final Reward:** Clamped to `[-1.0, 1.0]`

### 5. Q-Table Update

The reward updates agent Q-values using classical Q-Learning:

```python
# Q-Learning update rule
current_q = q_learning.get_q_value(state, action)
max_next_q = max(q_learning.get_q_values(next_state, available_actions).values())

td_target = reward + discount_factor * max_next_q
td_error = td_target - current_q
new_q = current_q + learning_rate * td_error

q_learning.set_q_value(state, action, new_q)
```

**Parameters:**

- **Learning Rate (α)**: 0.1 (default)
- **Discount Factor (γ)**: 0.95 (default)
- **Exploration (ε)**: Decays from 1.0 → 0.01

---

## User Workflows

### Workflow 1: Providing Test Case Feedback

**Scenario:** User reviews a generated test case and provides detailed feedback.

#### Step 1: Review Generated Test

```bash
# User receives test case from agent execution
Test Case ID: test_12345
Test Type: functional-positive
Endpoint: GET /api/users/123
Status Code: 200
Assertions:
  - Response time < 500ms
  - Status code = 200
  - Body contains "id", "name", "email"
```

#### Step 2: Submit Feedback via API

```bash
curl -X POST "http://localhost:8000/api/v1/feedback/test-case" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -H "X-Correlation-ID: feedback-12345" \
  -d '{
    "test_case_id": "test_12345",
    "rating": 5,
    "feedback_type": "quality",
    "is_helpful": true,
    "found_issue": false,
    "comment": "Excellent test! Covers all critical assertions and runs fast.",
    "execution_time_ms": 245.3
  }'
```

#### Step 3: API Response

```json
{
  "success": true,
  "feedback_id": "fb_a1b2c3d4e5f6",
  "test_case_id": "test_12345",
  "learning_status": "queued",
  "message": "Feedback submitted successfully. Thank you for helping improve test quality!",
  "queued_for_learning": true
}
```

#### Step 4: Learning Processing (Automatic)

```
1. FeedbackLearningQueue → Creates queue entry with status "pending"
2. ReasoningBank → Judges trajectory as SUCCESS (confidence: 0.92)
3. Q-Learning → Updates Q-value: 0.65 → 0.73 (reward: +1.0)
4. Pattern Learning → Extracts pattern, generates embedding, stores in AgentDB
5. Queue Status → Updates to "completed"
```

#### Step 5: View Learning Impact

```bash
curl -X GET "http://localhost:8000/api/v1/feedback/test-case/test_12345" \
  -H "Authorization: Bearer ${AUTH_TOKEN}"
```

**Response:**

```json
{
  "success": true,
  "test_case_id": "test_12345",
  "feedback_count": 3,
  "feedback": [
    {
      "feedback_id": "fb_a1b2c3d4e5f6",
      "rating": 5,
      "feedback_type": "quality",
      "is_helpful": true,
      "found_issue": false,
      "comment": "Excellent test! Covers all critical assertions and runs fast.",
      "created_at": "2025-10-29T14:30:00Z",
      "learning_applied": true,
      "pattern_updates": ["pattern_8f3a5b2c"]
    }
  ]
}
```

---

### Workflow 2: Providing Test Suite Feedback

**Scenario:** User evaluates an entire test suite for comprehensive coverage.

#### Step 1: Execute Test Suite

```bash
# Suite execution results
Suite ID: suite_67890
Total Tests: 45
Passed: 42
Failed: 2
Skipped: 1
Coverage: 87%
Execution Time: 12.3s
```

#### Step 2: Identify Coverage Gaps

```json
{
  "coverage_gaps": [
    {
      "category": "authentication",
      "description": "Missing tests for invalid token scenarios",
      "severity": "high",
      "suggested_tests": ["invalid_token", "expired_token", "missing_token"]
    },
    {
      "category": "error_handling",
      "description": "No tests for 500 Internal Server Error responses",
      "severity": "medium",
      "suggested_tests": ["server_error_handling"]
    }
  ]
}
```

#### Step 3: Submit Suite Feedback

```bash
curl -X POST "http://localhost:8000/api/v1/feedback/test-suite" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "suite_id": "suite_67890",
    "spec_id": "petstore_v1",
    "overall_rating": 4,
    "quality_score": 5,
    "coverage_score": 3,
    "accuracy_score": 4,
    "speed_score": 4,
    "coverage_gaps": [
      {
        "category": "authentication",
        "description": "Missing tests for invalid token scenarios",
        "severity": "high",
        "suggested_tests": ["invalid_token", "expired_token", "missing_token"]
      },
      {
        "category": "error_handling",
        "description": "No tests for 500 Internal Server Error responses",
        "severity": "medium",
        "suggested_tests": ["server_error_handling"]
      }
    ],
    "excellent_tests": ["test_12345", "test_12346", "test_12350"],
    "false_positives": ["test_12348"],
    "comment": "Good overall coverage but missing critical auth edge cases."
  }'
```

#### Step 4: API Response

```json
{
  "success": true,
  "feedback_id": "fb_suite_abc123",
  "suite_id": "suite_67890",
  "learning_status": "queued",
  "message": "Suite feedback submitted successfully. Coverage gaps will be analyzed for auto-generation.",
  "queued_for_learning": true,
  "gaps_queued_for_generation": 2
}
```

#### Step 5: Automatic Gap Resolution

```
1. Queue Processing:
   - Feedback stored in test_suite_feedback table
   - 2 coverage gaps queued for auto-generation

2. Gap Analysis:
   - Gap 1: "authentication" → Routes to SecurityAuthAgent
   - Gap 2: "error_handling" → Routes to FunctionalNegativeAgent

3. Test Generation:
   - SecurityAuthAgent generates 3 auth tests
   - FunctionalNegativeAgent generates 1 error test

4. Pattern Learning:
   - Excellent tests (3) → Patterns extracted and stored
   - False positive (1) → Pattern confidence reduced
```

---

### Workflow 3: Monitoring Learning Statistics

**Scenario:** View system-wide learning metrics and trends.

#### Step 1: Request Statistics

```bash
curl -X GET "http://localhost:8000/api/v1/feedback/statistics" \
  -H "Authorization: Bearer ${AUTH_TOKEN}"
```

#### Step 2: Statistics Response

```json
{
  "total_feedback_count": 1247,
  "average_rating": 4.2,
  "helpful_percentage": 82.5,
  "issue_found_percentage": 15.3,
  "coverage_gaps_identified": 47,
  "coverage_gaps_resolved": 35,
  "pattern_count": 128,
  "average_confidence": 0.78,
  "feedback_by_type": {
    "quality": 512,
    "accuracy": 298,
    "coverage": 187,
    "performance": 156,
    "false_positive": 94
  },
  "feedback_trend": [
    {
      "date": "2025-10-23",
      "count": 156,
      "avg_rating": 4.1
    },
    {
      "date": "2025-10-24",
      "count": 178,
      "avg_rating": 4.3
    },
    {
      "date": "2025-10-25",
      "count": 203,
      "avg_rating": 4.2
    },
    {
      "date": "2025-10-26",
      "count": 189,
      "avg_rating": 4.4
    },
    {
      "date": "2025-10-27",
      "count": 195,
      "avg_rating": 4.3
    },
    {
      "date": "2025-10-28",
      "count": 167,
      "avg_rating": 4.2
    },
    {
      "date": "2025-10-29",
      "count": 159,
      "avg_rating": 4.1
    }
  ]
}
```

#### Step 3: Analyze Trends

**Key Insights:**

- **82.5% helpful rate** → High user satisfaction
- **35/47 gaps resolved** → 74.5% gap resolution rate
- **128 patterns learned** → Rich pattern library
- **Average confidence 0.78** → Strong pattern reliability
- **Consistent feedback volume** → ~170-200 submissions/day

---

### Workflow 4: Pattern-Based Test Generation

**Scenario:** Agent uses learned patterns for faster test generation.

#### Step 1: Agent Receives Task

```python
task = TestGenerationTask(
    endpoint="/api/products/{id}",
    method="GET",
    test_type="functional-positive"
)
```

#### Step 2: Semantic Pattern Search

```python
# Generate query embedding
query_embedding = embedding_service.embed_test_pattern({
    "endpoint": "/api/products/{id}",
    "method": "GET",
    "type": "functional-positive"
})

# Search AgentDB (150x faster than pgvector)
similar_patterns = await agentdb.vector_search(
    collection="sentinel_test_patterns",
    query_vector=query_embedding,
    top_k=3,
    filters={
        "http_method": "GET",
        "confidence_score": {"$gte": 0.7}
    }
)
```

#### Step 3: Pattern Results

```json
{
  "patterns": [
    {
      "pattern_id": "8f3a5b2c",
      "endpoint_pattern": "/api/users/{id}",
      "http_method": "GET",
      "similarity": 0.92,
      "confidence_score": 0.85,
      "usage_count": 45,
      "success_rate": 0.93,
      "test_structure": {
        "assertions": [
          "status_code == 200",
          "response_time < 500",
          "body.id is not None",
          "body contains required_fields"
        ],
        "auth_required": true
      }
    }
  ]
}
```

#### Step 4: Pattern Application

```python
# Agent adapts pattern to new endpoint
test_case = agent.adapt_pattern_to_endpoint(
    pattern=similar_patterns[0],
    endpoint="/api/products/{id}",
    api_spec=api_spec
)

# Result: Test generated in <100ms (vs 2-5s without patterns)
```

#### Step 5: Update Pattern Confidence

```python
# After test execution
await pattern_learning_service.update_pattern_confidence(
    pattern_id="8f3a5b2c",
    success=True,
    execution_time_ms=287.5
)

# Confidence: 0.85 → 0.87 (incremental learning rate: 0.15)
```

---

## API Reference

### Base URL

```
http://localhost:8000/api/v1/feedback
```

### Authentication

All endpoints require JWT Bearer authentication:

```bash
Authorization: Bearer ${AUTH_TOKEN}
```

---

### POST /test-case

Submit feedback for a test case.

**Request:**

```json
{
  "test_case_id": "string",
  "rating": 1-5,
  "feedback_type": "quality" | "accuracy" | "coverage" | "performance" | "false_positive" | "false_negative",
  "is_helpful": boolean,
  "found_issue": boolean,
  "comment": "string (max 2000 chars, optional)",
  "execution_time_ms": number (optional)
}
```

**Response:**

```json
{
  "success": true,
  "feedback_id": "string",
  "test_case_id": "string",
  "learning_status": "queued" | "pending",
  "message": "string",
  "queued_for_learning": boolean
}
```

**Rate Limit:** 10 requests/minute per user

**Error Codes:**

- `400` - Invalid input (missing required fields, invalid rating range)
- `429` - Rate limit exceeded
- `401` - Unauthorized (invalid/missing token)
- `500` - Server error

**Example:**

```bash
curl -X POST "http://localhost:8000/api/v1/feedback/test-case" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "test_case_id": "test_12345",
    "rating": 5,
    "feedback_type": "quality",
    "is_helpful": true,
    "found_issue": false,
    "comment": "Excellent test coverage"
  }'
```

---

### POST /test-suite

Submit feedback for a test suite.

**Request:**

```json
{
  "suite_id": "string",
  "spec_id": "string",
  "overall_rating": 1-5,
  "quality_score": 1-5,
  "coverage_score": 1-5,
  "accuracy_score": 1-5,
  "speed_score": 1-5,
  "coverage_gaps": [
    {
      "category": "authentication" | "error_handling" | "edge_cases" | "performance" | "security" | "custom",
      "description": "string",
      "severity": "high" | "medium" | "low",
      "suggested_tests": ["string"]
    }
  ],
  "excellent_tests": ["string"],
  "false_positives": ["string"],
  "comment": "string (max 2000 chars, optional)"
}
```

**Response:**

```json
{
  "success": true,
  "feedback_id": "string",
  "suite_id": "string",
  "learning_status": "queued" | "pending",
  "message": "string",
  "queued_for_learning": boolean,
  "gaps_queued_for_generation": number
}
```

**Example:**

```bash
curl -X POST "http://localhost:8000/api/v1/feedback/test-suite" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${AUTH_TOKEN}" \
  -d '{
    "suite_id": "suite_67890",
    "spec_id": "petstore_v1",
    "overall_rating": 4,
    "quality_score": 5,
    "coverage_score": 3,
    "accuracy_score": 4,
    "speed_score": 4,
    "coverage_gaps": [
      {
        "category": "authentication",
        "description": "Missing invalid token tests",
        "severity": "high",
        "suggested_tests": ["invalid_token", "expired_token"]
      }
    ],
    "excellent_tests": ["test_12345", "test_12346"],
    "false_positives": ["test_12348"]
  }'
```

---

### GET /statistics

Get comprehensive learning and feedback statistics.

**Response:**

```json
{
  "total_feedback_count": number,
  "average_rating": number,
  "helpful_percentage": number,
  "issue_found_percentage": number,
  "coverage_gaps_identified": number,
  "coverage_gaps_resolved": number,
  "pattern_count": number,
  "average_confidence": number,
  "feedback_by_type": {
    "quality": number,
    "accuracy": number,
    "coverage": number,
    "performance": number,
    "false_positive": number
  },
  "feedback_trend": [
    {
      "date": "YYYY-MM-DD",
      "count": number,
      "avg_rating": number
    }
  ]
}
```

**Example:**

```bash
curl -X GET "http://localhost:8000/api/v1/feedback/statistics" \
  -H "Authorization: Bearer ${AUTH_TOKEN}"
```

---

### GET /test-case/{test_id}

Get all feedback for a specific test case.

**Response:**

```json
{
  "success": true,
  "test_case_id": "string",
  "feedback_count": number,
  "feedback": [
    {
      "feedback_id": "string",
      "test_case_id": "string",
      "rating": number,
      "feedback_type": "string",
      "is_helpful": boolean,
      "found_issue": boolean,
      "comment": "string",
      "created_at": "ISO 8601 datetime",
      "learning_applied": boolean,
      "pattern_updates": ["string"]
    }
  ]
}
```

**Example:**

```bash
curl -X GET "http://localhost:8000/api/v1/feedback/test-case/test_12345" \
  -H "Authorization: Bearer ${AUTH_TOKEN}"
```

---

### GET /patterns/{pattern_id}

Get feedback summary for a learned pattern.

**Response:**

```json
{
  "success": true,
  "pattern_feedback": {
    "pattern_id": "string",
    "usage_count": number,
    "success_count": number,
    "failure_count": number,
    "average_rating": number,
    "confidence": number,
    "last_updated": "ISO 8601 datetime",
    "feedback_count": number,
    "recent_feedback": [
      {
        "rating": number,
        "comment": "string",
        "created_at": "ISO 8601 datetime"
      }
    ]
  }
}
```

**Example:**

```bash
curl -X GET "http://localhost:8000/api/v1/feedback/patterns/8f3a5b2c" \
  -H "Authorization: Bearer ${AUTH_TOKEN}"
```

---

## Metrics & Analytics

### Key Performance Indicators

| Metric | Description | Target | Current |
|--------|-------------|--------|---------|
| **Helpful Rate** | % of tests marked helpful | >80% | 82.5% |
| **Average Rating** | Average user rating (1-5) | >4.0 | 4.2 |
| **Gap Resolution** | % of gaps auto-resolved | >70% | 74.5% |
| **Pattern Confidence** | Average pattern reliability | >0.75 | 0.78 |
| **Issue Detection** | % of tests finding real bugs | >10% | 15.3% |
| **Learning Queue** | Avg. processing time | <5min | 3.2min |

### Trajectory Statistics

Available via `TrajectoryService.get_trajectory_statistics()`:

```python
{
  "total_trajectories": 5432,
  "success_count": 4987,
  "failure_count": 289,
  "partial_count": 156,
  "unjudged_count": 0,
  "distilled_count": 4523,
  "success_rate": 0.918,
  "distillation_rate": 0.833
}
```

### Q-Learning Metrics

Available via `QLearning.get_statistics()`:

```python
{
  "q_table_size": 12847,
  "total_updates": 54392,
  "avg_q_value": 0.673,
  "max_q_value": 0.987,
  "min_q_value": -0.432,
  "std_q_value": 0.215,
  "total_visits": 89432,
  "avg_visits_per_state_action": 6.96,
  "max_visits": 234
}
```

### Pattern Statistics

Available via `PatternLearningService.get_pattern_statistics()`:

```python
{
  "total_patterns": 128,
  "collection": "sentinel_test_patterns",
  "embedding_dimension": 384,
  "index_type": "HNSW",
  "memory_mb": 4.7
}
```

### Reward Trends

Track agent improvement over time:

```python
trend = reward_mapper.get_reward_trend(
    agent_id="functional-positive",
    window_size=10
)

# Result:
{
  "trend": "improving",        # "improving" | "declining" | "stable"
  "slope": 0.023,              # Positive = improving
  "recent_avg": 0.745,         # Last 10 rewards
  "overall_avg": 0.682,        # All-time average
  "total_feedback_count": 234
}
```

---

## Integration Guide

### For Frontend Developers

#### 1. Test Case Feedback Form

```typescript
interface TestCaseFeedback {
  test_case_id: string;
  rating: 1 | 2 | 3 | 4 | 5;
  feedback_type: 'quality' | 'accuracy' | 'coverage' | 'performance' | 'false_positive' | 'false_negative';
  is_helpful: boolean;
  found_issue: boolean;
  comment?: string;
  execution_time_ms?: number;
}

async function submitTestFeedback(feedback: TestCaseFeedback): Promise<void> {
  const response = await fetch('http://localhost:8000/api/v1/feedback/test-case', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${authToken}`,
      'X-Correlation-ID': crypto.randomUUID()
    },
    body: JSON.stringify(feedback)
  });

  if (!response.ok) {
    throw new Error(`Feedback submission failed: ${response.statusText}`);
  }

  const result = await response.json();
  console.log('Feedback submitted:', result.feedback_id);
}
```

#### 2. Statistics Dashboard

```typescript
interface FeedbackStatistics {
  total_feedback_count: number;
  average_rating: number;
  helpful_percentage: number;
  issue_found_percentage: number;
  coverage_gaps_identified: number;
  coverage_gaps_resolved: number;
  pattern_count: number;
  average_confidence: number;
  feedback_by_type: Record<string, number>;
  feedback_trend: Array<{
    date: string;
    count: number;
    avg_rating: number;
  }>;
}

async function fetchStatistics(): Promise<FeedbackStatistics> {
  const response = await fetch('http://localhost:8000/api/v1/feedback/statistics', {
    headers: {
      'Authorization': `Bearer ${authToken}`
    }
  });

  return response.json();
}

// React component example
function StatisticsDashboard() {
  const [stats, setStats] = useState<FeedbackStatistics | null>(null);

  useEffect(() => {
    fetchStatistics().then(setStats);
  }, []);

  if (!stats) return <Loading />;

  return (
    <div className="statistics-dashboard">
      <MetricCard
        title="Helpful Rate"
        value={`${stats.helpful_percentage}%`}
        target={80}
      />
      <MetricCard
        title="Average Rating"
        value={stats.average_rating.toFixed(1)}
        target={4.0}
      />
      <TrendChart data={stats.feedback_trend} />
    </div>
  );
}
```

### For Backend Developers

#### 1. Agent Integration

```python
from sentinel_backend.orchestration_service.agents.base_learning_agent import BaseLearningAgent

class MyCustomAgent(BaseAgent, BaseLearningAgent):
    def __init__(self, agent_type: str):
        BaseAgent.__init__(self, agent_type)
        BaseLearningAgent.__init__(self)

    async def execute(self, task, api_spec, db_session):
        # Start trajectory
        trajectory = await self.start_trajectory(
            task_type="custom_task",
            task_description=f"Custom task for {task.id}",
            context_data={"task": task.dict()},
            db_session=db_session
        )

        try:
            # Log actions
            await self.log_action(
                "Step 1: Analyzing input",
                metadata={"input_size": len(task.data)}
            )

            # Perform work
            result = await self.do_work(task)

            await self.log_action(
                "Step 2: Generating output",
                metadata={"output_size": len(result)}
            )

            # Complete trajectory
            await self.complete_trajectory(
                final_output={"result": result},
                execution_time_ms=int(elapsed_ms),
                test_success_rate=1.0
            )

            return result

        except Exception as e:
            # Abort on error
            await self.abort_trajectory(str(e))
            raise
```

#### 2. Feedback Processing

```python
from sentinel_backend.rl_service.services.feedback_reward_mapper import FeedbackRewardMapper
from sentinel_backend.rl_service.algorithms.q_learning import QLearning

# Initialize services
reward_mapper = FeedbackRewardMapper()
q_learning = QLearning()

async def process_feedback(feedback: TestCaseFeedback, trajectory: TaskTrajectory):
    # Calculate reward
    reward = reward_mapper.calculate_reward(
        rating=feedback.rating,
        is_helpful=feedback.helpful,
        found_issue=feedback.issue_found,
        execution_result={"status": "passed"}
    )

    # Update Q-learning
    state = extract_state_from_trajectory(trajectory)
    action = extract_action_from_trajectory(trajectory)
    next_state = extract_next_state_from_trajectory(trajectory)

    metrics = q_learning.update(
        state=state,
        action=action,
        reward=reward,
        next_state=next_state,
        done=True
    )

    logger.info(f"Q-learning updated: Q={metrics['new_q']:.3f}, TD_error={metrics['td_error']:.3f}")
```

---

## Advanced Topics

### 1. Custom Reward Functions

Create domain-specific reward functions:

```python
class CustomRewardMapper(FeedbackRewardMapper):
    def _calculate_execution_reward(self, execution_result: Dict[str, Any]) -> float:
        reward = 0.0

        # Custom logic: Reward comprehensive assertions
        assertion_count = execution_result.get("assertion_count", 0)
        if assertion_count >= 5:
            reward += 0.2
        elif assertion_count >= 3:
            reward += 0.1

        # Custom logic: Penalize long execution
        execution_time = execution_result.get("execution_time_ms", 0)
        if execution_time > 5000:  # 5 seconds
            reward -= 0.2

        return reward
```

### 2. Pattern Similarity Tuning

Adjust similarity threshold for pattern deduplication:

```python
# Default: 0.87 (87% similarity)
pattern_learning_service.store_pattern(
    pattern,
    deduplicate=True
)

# More aggressive deduplication (fewer patterns, more merging)
similar = await pattern_learning_service._find_similar_patterns(
    pattern.embedding,
    similarity_threshold=0.75  # 75% similarity
)

# Less aggressive (more unique patterns)
similar = await pattern_learning_service._find_similar_patterns(
    pattern.embedding,
    similarity_threshold=0.95  # 95% similarity
)
```

### 3. Multi-Objective Learning

Optimize for multiple objectives simultaneously:

```python
# Weighted reward function
def calculate_multi_objective_reward(
    quality_score: float,
    speed_score: float,
    coverage_score: float,
    weights=(0.5, 0.3, 0.2)
) -> float:
    """
    Optimize for quality, speed, and coverage.

    Default weights:
    - Quality: 50%
    - Speed: 30%
    - Coverage: 20%
    """
    return (
        weights[0] * quality_score +
        weights[1] * speed_score +
        weights[2] * coverage_score
    )
```

### 4. Batch Judgment

Process multiple trajectories efficiently:

```python
from sentinel_backend.reasoningbank.services.judgment_service import JudgmentService

judgment_service = JudgmentService(anthropic_client)

# Batch judge 10 trajectories
trajectories = await trajectory_service.get_unjudged_trajectories(limit=10)

results = await judgment_service.batch_judge_trajectories(trajectories)

for trajectory, outcome, confidence, reasoning, metadata in results:
    await trajectory_service.update_judgment(
        trajectory.trajectory_id,
        outcome,
        confidence,
        reasoning
    )

    logger.info(
        f"Judged {trajectory.trajectory_id}: {outcome.value} "
        f"(confidence: {confidence:.2f})"
    )
```

### 5. Learning Rate Schedules

Implement adaptive learning rates:

```python
class AdaptiveLearningRate:
    def __init__(self, initial_lr=0.1, decay_rate=0.995, min_lr=0.01):
        self.initial_lr = initial_lr
        self.decay_rate = decay_rate
        self.min_lr = min_lr
        self.current_lr = initial_lr
        self.update_count = 0

    def get_lr(self) -> float:
        return self.current_lr

    def step(self):
        self.update_count += 1
        self.current_lr = max(
            self.min_lr,
            self.initial_lr * (self.decay_rate ** self.update_count)
        )

# Use in Q-learning
adaptive_lr = AdaptiveLearningRate()
q_learning = QLearning(learning_rate=adaptive_lr.get_lr())

# After each update
q_learning.update(...)
adaptive_lr.step()
q_learning.learning_rate = adaptive_lr.get_lr()
```

---

## Troubleshooting

### Common Issues

#### 1. Feedback Not Being Processed

**Symptom:** Feedback submitted but `learning_status` stays "pending"

**Diagnosis:**

```bash
# Check queue status
curl -X GET "http://localhost:8000/api/v1/feedback/test-case/test_12345" \
  -H "Authorization: Bearer ${AUTH_TOKEN}"
```

**Solution:**

1. Verify database connection
2. Check `feedback_learning_queue` table for errors
3. Review processing logs for exceptions
4. Retry failed entries manually

#### 2. Pattern Not Found During Search

**Symptom:** AgentDB returns empty results

**Diagnosis:**

```python
# Check collection stats
stats = await agentdb.get_stats("sentinel_test_patterns")
print(f"Total patterns: {stats.get('vector_count', 0)}")
```

**Solution:**

1. Verify patterns are being stored
2. Check embedding dimension (must be 384)
3. Validate query embedding generation
4. Adjust similarity threshold

#### 3. Q-Learning Not Improving

**Symptom:** Q-values stagnate or decrease

**Diagnosis:**

```python
stats = q_learning.get_statistics()
print(f"Updates: {stats['total_updates']}")
print(f"Avg Q: {stats['avg_q_value']:.3f}")
print(f"Epsilon: {q_learning.epsilon:.3f}")
```

**Solution:**

1. Increase learning rate (0.1 → 0.2)
2. Reduce exploration (epsilon decay faster)
3. Verify reward calculations are correct
4. Check for reward sparsity (add intermediate rewards)

---

## Best Practices

### 1. Feedback Collection

- **Be Specific**: Provide detailed comments explaining ratings
- **Timely**: Submit feedback shortly after test execution
- **Balanced**: Include both positive and negative feedback
- **Actionable**: Suggest specific improvements for poor tests

### 2. Coverage Gap Reporting

- **Prioritize**: Mark severity (high/medium/low) accurately
- **Detailed**: Describe what's missing, not just categories
- **Suggestive**: Provide concrete test case suggestions
- **Realistic**: Focus on achievable coverage improvements

### 3. Pattern Learning

- **Quality Over Quantity**: Extract patterns from high-quality tests only
- **Deduplication**: Enable to prevent pattern explosion
- **Confidence Tracking**: Monitor and prune low-confidence patterns
- **Regular Review**: Periodically audit pattern effectiveness

### 4. Q-Learning Optimization

- **Hyperparameter Tuning**: Adjust based on domain characteristics
- **State Representation**: Design meaningful state features
- **Reward Shaping**: Add intermediate rewards for sparse environments
- **Exploration Strategy**: Balance exploration vs. exploitation

---

## Future Enhancements

### Planned Features (v2.0)

1. **Multi-Agent Reinforcement Learning**
   - Cooperative Q-learning across agent types
   - Shared experience replay buffers
   - Policy gradient methods (PPO, A3C)

2. **Advanced Pattern Matching**
   - Graph neural networks for structural similarity
   - Attention mechanisms for endpoint matching
   - Multi-modal embeddings (code + docs + tests)

3. **Automated Gap Detection**
   - LLM-powered coverage analysis
   - Proactive gap identification before user feedback
   - Intelligent test prioritization

4. **Real-Time Learning**
   - Streaming trajectory processing
   - Online Q-learning updates
   - Live pattern extraction during execution

5. **Explainable AI**
   - SHAP values for Q-value attribution
   - Pattern contribution analysis
   - Judgment reasoning transparency

---

## References

### Academic Papers

1. **ReasoningBank**: [Paper](https://arxiv.org/abs/2406.13891) - Trajectory-based learning with LLM judgment
2. **Q-Learning**: Watkins & Dayan (1992) - "Q-Learning"
3. **AgentDB**: Vector database for agent memory (150x faster)

### Related Documentation

- [Agent Architecture](./AGENT_ARCHITECTURE.md)
- [ReasoningBank Integration](./REASONINGBANK_IMPLEMENTATION.md)
- [Q-Learning Configuration](./RL_SERVICE_CONFIGURATION.md)
- [Pattern Recognition](./PATTERN_RECOGNITION_GUIDE.md)

---

## Support

### Getting Help

- **Documentation**: [https://sentinel-docs.example.com](https://sentinel-docs.example.com)
- **Issues**: [GitHub Issues](https://github.com/your-org/sentinel/issues)
- **Discord**: [Community Server](https://discord.gg/sentinel)
- **Email**: support@sentinel.example.com

### Contributing

We welcome feedback improvements! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

---

**Last Updated:** 2025-10-29
**Version:** 1.0.0
**Maintainer:** Sentinel Core Team
