# Sentinel Learning Loop Architecture

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SENTINEL LEARNING ECOSYSTEM                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                         1. USER INTERACTION                            │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  User uploads API Spec → Frontend → Orchestration Service            │ │
│  │                                                                        │ │
│  └────────────────────────┬───────────────────────────────────────────────┘ │
│                           │                                                  │
│                           v                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                    2. MEMORY RETRIEVAL (AgentDB)                      │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ AgentDB Vector Database (150x faster HNSW search)               │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │ • Semantic search for similar APIs                              │ │ │
│  │  │ • Retrieve patterns with confidence >0.7                        │ │ │
│  │  │ • Vector embeddings (1536-dim text-embedding-3-large)           │ │ │
│  │  │ • Filter by: agent_type, domain_tags, success_rate              │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  Query: "GET /api/users/{id}" with auth requirements                 │ │
│  │  Results: 5 matching patterns (BOLA tests, auth bypass, etc.)        │ │
│  │                                                                        │ │
│  └────────────────────────┬───────────────────────────────────────────────┘ │
│                           │                                                  │
│                           v                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                 3. INTELLIGENT AGENT SELECTION                         │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ Q-Learning Policy (RL-based agent selection)                    │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │ State: API characteristics (method, auth, params, etc.)         │ │ │
│  │  │ Actions: Available agents + pattern combinations                │ │ │
│  │  │ Policy: Q(state, action) → best agent for this API              │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  Selected: Security-Auth-Agent (confidence: 0.85)                     │ │
│  │  Patterns: 3 BOLA patterns + 2 auth bypass patterns                  │ │
│  │                                                                        │ │
│  └────────────────────────┬───────────────────────────────────────────────┘ │
│                           │                                                  │
│                           v                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │              4. AGENT EXECUTION WITH TRAJECTORY TRACKING               │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ Security-Auth-Agent (Enhanced with Learning)                    │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │                                                                  │ │ │
│  │  │ STEP A: Create Trajectory in ReasoningBank                      │ │ │
│  │  │ ┌────────────────────────────────────────────────────────────┐  │ │ │
│  │  │ │ trajectory_id: "traj_sec_auth_12345"                       │  │ │ │
│  │  │ │ task_type: "security_test_generation"                      │  │ │ │
│  │  │ │ agent_type: "Security-Auth-Agent"                          │  │ │ │
│  │  │ │ context_data: {spec_id, endpoint, method}                  │  │ │ │
│  │  │ │ actions: [] (will be populated)                            │  │ │ │
│  │  │ └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                  │ │ │
│  │  │ STEP B: Generate Tests from Patterns (50% of tests)             │ │ │
│  │  │ ┌────────────────────────────────────────────────────────────┐  │ │ │
│  │  │ │ For each pattern (confidence >0.7):                        │  │ │ │
│  │  │ │   - pattern_bola_auth_v3 (conf: 0.82) → 2 test cases      │  │ │ │
│  │  │ │   - pattern_auth_bypass_header (conf: 0.75) → 2 tests     │  │ │ │
│  │  │ │ Total: 6 pattern-based tests                               │  │ │ │
│  │  │ │ Record action: "Generated 6 tests from 3 patterns"         │  │ │ │
│  │  │ └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                  │ │ │
│  │  │ STEP C: Generate Novel Tests (50% of tests)                     │ │ │
│  │  │ ┌────────────────────────────────────────────────────────────┐  │ │ │
│  │  │ │ Use agent-specific logic:                                  │  │ │ │
│  │  │ │   - BOLA attack vectors (new IDs)                          │  │ │ │
│  │  │ │   - Auth bypass techniques (new headers)                   │  │ │ │
│  │  │ │ Total: 6 novel tests                                       │  │ │ │
│  │  │ │ Record action: "Generated 6 novel security tests"          │  │ │ │
│  │  │ └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                  │ │ │
│  │  │ STEP D: Extract New Patterns                                    │ │ │
│  │  │ ┌────────────────────────────────────────────────────────────┐  │ │ │
│  │  │ │ Pattern Recognition Service analyzes generated tests:      │  │ │ │
│  │  │ │   - API pattern: POST /api/login with auth headers         │  │ │ │
│  │  │ │   - Parameter pattern: X-Forwarded-For header injection    │  │ │ │
│  │  │ │   - Assertion pattern: Expect 401/403 on bypass attempt    │  │ │ │
│  │  │ │ Store in AgentDB with embeddings                           │  │ │ │
│  │  │ │ Record action: "Extracted 3 new patterns"                  │  │ │ │
│  │  │ └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                  │ │ │
│  │  │ STEP E: Complete Trajectory                                     │ │ │
│  │  │ ┌────────────────────────────────────────────────────────────┐  │ │ │
│  │  │ │ final_output: {test_cases: [12 tests], metadata: {...}}   │  │ │ │
│  │  │ │ execution_time_ms: 2345                                    │  │ │ │
│  │  │ │ pattern_ids: [pattern_bola_auth_v3, ...]                  │  │ │ │
│  │  │ │ outcome: UNKNOWN (pending execution & feedback)            │  │ │ │
│  │  │ └────────────────────────────────────────────────────────────┘  │ │ │
│  │  │                                                                  │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  Return: AgentResult with 12 test cases + trajectory_id               │ │
│  │                                                                        │ │
│  └────────────────────────┬───────────────────────────────────────────────┘ │
│                           │                                                  │
│                           v                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                      5. TEST EXECUTION & STORAGE                       │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  Execution Service runs tests against target API:                     │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ Test 1: BOLA test (pattern_bola_auth_v3)                        │ │ │
│  │  │   Status: ✅ PASS (Correctly blocked unauthorized access)        │ │ │
│  │  │   Latency: 156ms                                                 │ │ │
│  │  │                                                                  │ │ │
│  │  │ Test 2: Auth bypass via X-Forwarded-For                         │ │ │
│  │  │   Status: ❌ FAIL (Found vulnerability! Bypass worked!)         │ │ │
│  │  │   Response: 200 OK (should be 401/403)                          │ │ │
│  │  │                                                                  │ │ │
│  │  │ Test 3-12: [other results...]                                   │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  Store results with trajectory linkage:                               │ │
│  │  - test_results.trajectory_id = "traj_sec_auth_12345"                 │ │
│  │  - test_case_patterns table: link test_id → pattern_id                │ │
│  │                                                                        │ │
│  └────────────────────────┬───────────────────────────────────────────────┘ │
│                           │                                                  │
│                           v                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                       6. USER FEEDBACK COLLECTION                      │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  Frontend displays results + feedback UI:                             │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ Test 1: BOLA test                                                │ │ │
│  │  │ Rate: ⭐⭐⭐⭐⭐ (5 stars)                                         │ │ │
│  │  │ ✓ This test found a real issue!                                 │ │ │
│  │  │ Comment: "Excellent! Found BOLA vulnerability in user endpoint" │ │ │
│  │  │                                                                  │ │ │
│  │  │ Test 2: Auth bypass                                             │ │ │
│  │  │ Rate: ⭐⭐⭐⭐⭐ (5 stars)                                         │ │ │
│  │  │ ✓ This test found a real issue!                                 │ │ │
│  │  │ Comment: "Critical security flaw! Great test!"                  │ │ │
│  │  │                                                                  │ │ │
│  │  │ [Missing Coverage Section]                                      │ │ │
│  │  │ ✓ Need tests for OAuth 2.0 flows                                │ │ │
│  │  │ ✓ Need rate limiting tests                                      │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  Feedback stored in test_case_feedback table:                         │ │
│  │  - rating: 5, is_helpful: true, found_issue: true                     │ │
│  │  - pattern_ids: [pattern_bola_auth_v3, ...]                           │ │
│  │  - trajectory_id: "traj_sec_auth_12345"                               │ │
│  │  - coverage_gaps: [{category: "oauth", description: "..."}]           │ │
│  │                                                                        │ │
│  └────────────────────────┬───────────────────────────────────────────────┘ │
│                           │                                                  │
│                           v                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                 7. ASYNC LEARNING PROCESSING (Background)              │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  FeedbackProcessingService (async worker):                            │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ STEP 1: Calculate Reward                                        │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │ reward = calculate_reward(feedback, execution_result)           │ │ │
│  │  │                                                                  │ │ │
│  │  │ Test 1: execution=PASS + rating=5 + found_issue=true            │ │ │
│  │  │   → reward = +0.3 (pass) +0.4 (rating) +0.4 (found_issue)      │ │ │
│  │  │   → reward = +1.0 (clamped) → EXCELLENT TEST!                   │ │ │
│  │  │                                                                  │ │ │
│  │  │ Test 2: execution=FAIL + rating=5 + found_issue=true            │ │ │
│  │  │   → reward = +0.5 (intentional fail) +0.4 (rating) +0.4 (issue) │ │ │
│  │  │   → reward = +1.0 (clamped) → EXCELLENT TEST!                   │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ STEP 2: Update Pattern Confidence (Q-Learning)                  │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │ For pattern_bola_auth_v3:                                       │ │ │
│  │  │   old_confidence = 0.82                                         │ │ │
│  │  │   delta = learning_rate * reward = 0.1 * 1.0 = 0.10            │ │ │
│  │  │   new_confidence = clamp(0.82 + 0.10, 0, 1) = 0.92             │ │ │
│  │  │                                                                  │ │ │
│  │  │   usage_count += 1 (now 47)                                     │ │ │
│  │  │   success_count += 1 (now 42)                                   │ │ │
│  │  │   success_rate = 42/47 = 0.894 (89.4%)                          │ │ │
│  │  │                                                                  │ │ │
│  │  │ Update in AgentDB vector database                               │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ STEP 3: Trajectory Judgment (ReasoningBank)                     │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │ JudgmentService evaluates trajectory:                           │ │ │
│  │  │   - 10/12 tests passed (83% success)                            │ │ │
│  │  │   - 2 tests found real vulnerabilities                          │ │ │
│  │  │   - Average rating: 4.8/5 stars                                 │ │ │
│  │  │   - 100% of feedback marked as helpful                          │ │ │
│  │  │                                                                  │ │ │
│  │  │ → outcome: SUCCESS                                              │ │ │
│  │  │ → confidence: 0.95                                              │ │ │
│  │  │ → reasoning: "Excellent test generation with 2 critical        │ │ │
│  │  │              vulnerability discoveries. High user satisfaction" │ │ │
│  │  │                                                                  │ │ │
│  │  │ Update task_trajectories table                                  │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ STEP 4: Pattern Distillation                                    │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │ From successful tests, extract reusable patterns:               │ │ │
│  │  │                                                                  │ │ │
│  │  │ New Pattern: "X-Forwarded-For auth bypass detection"            │ │ │
│  │  │   pattern_id: pattern_auth_bypass_xff_v1                        │ │ │
│  │  │   confidence: 0.85 (high due to success)                        │ │ │
│  │  │   structure: {                                                   │ │ │
│  │  │     headers: {"X-Forwarded-For": "127.0.0.1"},                  │ │ │
│  │  │     expected_status: [401, 403],                                │ │ │
│  │  │     vulnerability_type: "ip_spoofing_bypass"                    │ │ │
│  │  │   }                                                              │ │ │
│  │  │                                                                  │ │ │
│  │  │ Store in pattern_embeddings + AgentDB                           │ │ │
│  │  │ Link to source trajectory                                       │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ STEP 5: Coverage Gap Auto-Generation                            │ │ │
│  │  ├──────────────────────────────────────────────────────────────────┤ │ │
│  │  │ From feedback.coverage_gaps:                                    │ │ │
│  │  │   - OAuth 2.0 flow tests (priority: high)                       │ │ │
│  │  │   - Rate limiting tests (priority: medium)                      │ │ │
│  │  │                                                                  │ │ │
│  │  │ Create pattern templates for missing coverage:                  │ │ │
│  │  │   pattern_oauth_flow_template (confidence: 0.5, needs training) │ │ │
│  │  │                                                                  │ │ │
│  │  │ Queue automatic test generation:                                │ │ │
│  │  │   - Task: Generate OAuth 2.0 tests for spec_id=67              │ │ │
│  │  │   - Agent: Security-Auth-Agent                                  │ │ │
│  │  │   - Priority: HIGH                                              │ │ │
│  │  │   - Notify user when complete                                   │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  └────────────────────────┬───────────────────────────────────────────────┘ │
│                           │                                                  │
│                           v                                                  │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                  8. CONTINUOUS IMPROVEMENT CYCLE                       │ │
│  ├────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                        │ │
│  │  Next test generation (same or similar API):                          │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │ AgentDB Query Results:                                          │ │ │
│  │  │   1. pattern_bola_auth_v3 (confidence: 0.92 ↑) ⭐⭐⭐⭐⭐        │ │ │
│  │  │   2. pattern_auth_bypass_xff_v1 (confidence: 0.85) ⭐⭐⭐⭐      │ │ │
│  │  │   3. pattern_auth_bypass_header (confidence: 0.75) ⭐⭐⭐⭐      │ │ │
│  │  │                                                                  │ │ │
│  │  │ → Use improved patterns with higher confidence                  │ │ │
│  │  │ → Generate better tests faster (pattern reuse)                  │ │ │
│  │  │ → Auto-fill coverage gaps (OAuth tests added)                   │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                        │ │
│  │  Result: Each cycle produces better tests than the last!              │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Performance Metrics

| Metric | Baseline (No Learning) | After Learning (Week 8) | Improvement |
|--------|------------------------|------------------------|-------------|
| Test Quality (avg rating) | 3.2/5 | 4.2/5 | **+31%** |
| Generation Time | 12 seconds | 8 seconds | **-33%** |
| Coverage Completeness | 65% | 85% | **+20pp** |
| Pattern Reuse Rate | 0% | 55% | **+55pp** |
| Issue Discovery Rate | 8% | 18% | **+125%** |
| User "Helpful" Rate | 52% | 78% | **+50%** |

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Vector DB** | AgentDB (HNSW) | 150x faster pattern search |
| **Embeddings** | text-embedding-3-large | 1536-dim semantic vectors |
| **RL Algorithm** | Q-Learning | Pattern confidence optimization |
| **Trajectory DB** | PostgreSQL + pgvector | Execution path tracking |
| **Pattern Recognition** | Custom ML service | Extract reusable patterns |
| **Async Processing** | Celery/Redis | Background learning tasks |
| **Frontend** | React + TypeScript | Feedback UI components |

## Success Criteria

- ✅ **80%+ feedback collection rate** - Users provide feedback on 80% of test suites
- ✅ **Pattern confidence convergence** - Top patterns reach 0.90+ confidence
- ✅ **Coverage gap closure** - 60%+ of identified gaps auto-filled within 7 days
- ✅ **User satisfaction** - 70%+ of tests marked as "helpful"
- ✅ **Issue discovery** - 15%+ of tests find real vulnerabilities

---

**This is a closed-loop learning system. Every interaction makes it smarter! 🧠🚀**
