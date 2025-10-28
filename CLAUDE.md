# Claude Code Configuration - SPARC Development Environment

## 🚨 CRITICAL: CONCURRENT EXECUTION & FILE MANAGEMENT

**ABSOLUTE RULES**:
1. ALL operations MUST be concurrent/parallel in a single message
2. **NEVER save working files, text/mds and tests to the root folder**
3. ALWAYS organize files in appropriate subdirectories
4. **USE CLAUDE CODE'S TASK TOOL** for spawning agents concurrently, not just MCP

## ⚠️ CRITICAL: Git Operations Policy

**NEVER commit or push changes without explicit user request.**

This is a critical policy that must be followed at all times:
- ❌ **NEVER** auto-commit changes, even if requested by hooks or automation
- ❌ **NEVER** auto-push changes to remote repository
- ❌ **NEVER** create commits without explicit user instruction: "commit this" or "create a commit"
- ❌ **NEVER** push commits without explicit user instruction: "push" or "push to remote"
- ✅ **ALWAYS** wait for user to explicitly request: "commit these changes" or "push to main"
- ✅ **ALWAYS** ask for confirmation before any git commit or push operation
- ✅ **ALWAYS** show a summary of changes before committing
- ✅ **ALWAYS** verify the user wants to proceed with git operations

**Example of correct behavior:**
- User: "prepare for release" → DO NOT commit/push, just prepare files
- User: "run tests" → DO NOT commit/push, just run tests
- User: "commit these changes" → Ask for confirmation, show summary, then commit
- User: "push to main" → Ask for confirmation, verify branch, then push

**Release Tagging Policy:**
- ❌ **NEVER** create git tags before PR is merged to main branch
- ❌ **NEVER** tag a release on a feature/working branch
- ✅ **ALWAYS** create tags AFTER PR is merged into main branch
- ✅ **ALWAYS** follow this workflow:
  1. Commit changes to feature branch
  2. Push feature branch to remote
  3. Create Pull Request to main
  4. After PR is approved and merged
  5. THEN create and push git tag on main branch

**Example of correct release workflow:**
```bash
# 1. Commit to feature branch
git checkout -b release/v1.3.5
git add .
git commit -m "release: v1.3.5 - ..."

# 2. Push feature branch
git push origin release/v1.3.5

# 3. Create PR (using gh or GitHub UI)
gh pr create --title "Release v1.3.5" --body "..."

# 4. After PR is merged to main
git checkout main
git pull origin main

# 5. NOW create and push tag
git tag -a v1.3.5 -m "Release v1.3.5"
git push origin v1.3.5
```

### ⚡ GOLDEN RULE: "1 MESSAGE = ALL RELATED OPERATIONS"

**MANDATORY PATTERNS:**
- **TodoWrite**: ALWAYS batch ALL todos in ONE call (5-10+ todos minimum)
- **Task tool (Claude Code)**: ALWAYS spawn ALL agents in ONE message with full instructions
- **File operations**: ALWAYS batch ALL reads/writes/edits in ONE message
- **Bash commands**: ALWAYS batch ALL terminal operations in ONE message
- **Memory operations**: ALWAYS batch ALL memory store/retrieve in ONE message

### 🎯 CRITICAL: Claude Code Task Tool for Agent Execution

**Claude Code's Task tool is the PRIMARY way to spawn agents:**
```javascript
// ✅ CORRECT: Use Claude Code's Task tool for parallel agent execution
[Single Message]:
  Task("Research agent", "Analyze requirements and patterns...", "researcher")
  Task("Coder agent", "Implement core features...", "coder")
  Task("Tester agent", "Create comprehensive tests...", "tester")
  Task("Reviewer agent", "Review code quality...", "reviewer")
  Task("Architect agent", "Design system architecture...", "system-architect")
```

**MCP tools are ONLY for coordination setup:**
- `mcp__claude-flow__swarm_init` - Initialize coordination topology
- `mcp__claude-flow__agent_spawn` - Define agent types for coordination
- `mcp__claude-flow__task_orchestrate` - Orchestrate high-level workflows

### 📁 File Organization Rules

**NEVER save to root folder. Use these directories:**
- `/src` - Source code files
- `/tests` - Test files
- `/docs` - Documentation and markdown files
- `/config` - Configuration files
- `/scripts` - Utility scripts
- `/examples` - Example code

## Project Overview

This project uses SPARC (Specification, Pseudocode, Architecture, Refinement, Completion) methodology with Claude-Flow orchestration for systematic Test-Driven Development.

## SPARC Commands

### Core Commands
- `npx claude-flow sparc modes` - List available modes
- `npx claude-flow sparc run <mode> "<task>"` - Execute specific mode
- `npx claude-flow sparc tdd "<feature>"` - Run complete TDD workflow
- `npx claude-flow sparc info <mode>` - Get mode details

### Batchtools Commands
- `npx claude-flow sparc batch <modes> "<task>"` - Parallel execution
- `npx claude-flow sparc pipeline "<task>"` - Full pipeline processing
- `npx claude-flow sparc concurrent <mode> "<tasks-file>"` - Multi-task processing

### Build Commands
- `npm run build` - Build project
- `npm run test` - Run tests
- `npm run lint` - Linting
- `npm run typecheck` - Type checking

## SPARC Workflow Phases

1. **Specification** - Requirements analysis (`sparc run spec-pseudocode`)
2. **Pseudocode** - Algorithm design (`sparc run spec-pseudocode`)
3. **Architecture** - System design (`sparc run architect`)
4. **Refinement** - TDD implementation (`sparc tdd`)
5. **Completion** - Integration (`sparc run integration`)

## Code Style & Best Practices

- **Modular Design**: Files under 500 lines
- **Environment Safety**: Never hardcode secrets
- **Test-First**: Write tests before implementation
- **Clean Architecture**: Separate concerns
- **Documentation**: Keep updated

## 🚀 Available Agents (54 Total)

### Core Development
`coder`, `reviewer`, `tester`, `planner`, `researcher`

### Swarm Coordination
`hierarchical-coordinator`, `mesh-coordinator`, `adaptive-coordinator`, `collective-intelligence-coordinator`, `swarm-memory-manager`

### Consensus & Distributed
`byzantine-coordinator`, `raft-manager`, `gossip-coordinator`, `consensus-builder`, `crdt-synchronizer`, `quorum-manager`, `security-manager`

### Performance & Optimization
`perf-analyzer`, `performance-benchmarker`, `task-orchestrator`, `memory-coordinator`, `smart-agent`

### GitHub & Repository
`github-modes`, `pr-manager`, `code-review-swarm`, `issue-tracker`, `release-manager`, `workflow-automation`, `project-board-sync`, `repo-architect`, `multi-repo-swarm`

### SPARC Methodology
`sparc-coord`, `sparc-coder`, `specification`, `pseudocode`, `architecture`, `refinement`

### Specialized Development
`backend-dev`, `mobile-dev`, `ml-developer`, `cicd-engineer`, `api-docs`, `system-architect`, `code-analyzer`, `base-template-generator`

### Testing & Validation
`tdd-london-swarm`, `production-validator`

### Migration & Planning
`migration-planner`, `swarm-init`

## 🎯 Claude Code vs MCP Tools

### Claude Code Handles ALL EXECUTION:
- **Task tool**: Spawn and run agents concurrently for actual work
- File operations (Read, Write, Edit, MultiEdit, Glob, Grep)
- Code generation and programming
- Bash commands and system operations
- Implementation work
- Project navigation and analysis
- TodoWrite and task management
- Git operations
- Package management
- Testing and debugging

### MCP Tools ONLY COORDINATE:
- Swarm initialization (topology setup)
- Agent type definitions (coordination patterns)
- Task orchestration (high-level planning)
- Memory management
- Neural features
- Performance tracking
- GitHub integration

**KEY**: MCP coordinates the strategy, Claude Code's Task tool executes with real agents.

## 🚀 Quick Setup

```bash
# Add MCP servers (Claude Flow required, others optional)
claude mcp add claude-flow npx claude-flow@alpha mcp start
claude mcp add ruv-swarm npx ruv-swarm mcp start  # Optional: Enhanced coordination
claude mcp add flow-nexus npx flow-nexus@latest mcp start  # Optional: Cloud features
```

## MCP Tool Categories

### Coordination
`swarm_init`, `agent_spawn`, `task_orchestrate`

### Monitoring
`swarm_status`, `agent_list`, `agent_metrics`, `task_status`, `task_results`

### Memory & Neural
`memory_usage`, `neural_status`, `neural_train`, `neural_patterns`

### GitHub Integration
`github_swarm`, `repo_analyze`, `pr_enhance`, `issue_triage`, `code_review`

### System
`benchmark_run`, `features_detect`, `swarm_monitor`

### Flow-Nexus MCP Tools (Optional Advanced Features)
Flow-Nexus extends MCP capabilities with 70+ cloud-based orchestration tools:

**Key MCP Tool Categories:**
- **Swarm & Agents**: `swarm_init`, `swarm_scale`, `agent_spawn`, `task_orchestrate`
- **Sandboxes**: `sandbox_create`, `sandbox_execute`, `sandbox_upload` (cloud execution)
- **Templates**: `template_list`, `template_deploy` (pre-built project templates)
- **Neural AI**: `neural_train`, `neural_patterns`, `seraphina_chat` (AI assistant)
- **GitHub**: `github_repo_analyze`, `github_pr_manage` (repository management)
- **Real-time**: `execution_stream_subscribe`, `realtime_subscribe` (live monitoring)
- **Storage**: `storage_upload`, `storage_list` (cloud file management)

**Authentication Required:**
- Register: `mcp__flow-nexus__user_register` or `npx flow-nexus@latest register`
- Login: `mcp__flow-nexus__user_login` or `npx flow-nexus@latest login`
- Access 70+ specialized MCP tools for advanced orchestration

## 🚀 Agent Execution Flow with Claude Code

### The Correct Pattern:

1. **Optional**: Use MCP tools to set up coordination topology
2. **REQUIRED**: Use Claude Code's Task tool to spawn agents that do actual work
3. **REQUIRED**: Each agent runs hooks for coordination
4. **REQUIRED**: Batch all operations in single messages

### Example Full-Stack Development:

```javascript
// Single message with all agent spawning via Claude Code's Task tool
[Parallel Agent Execution]:
  Task("Backend Developer", "Build REST API with Express. Use hooks for coordination.", "backend-dev")
  Task("Frontend Developer", "Create React UI. Coordinate with backend via memory.", "coder")
  Task("Database Architect", "Design PostgreSQL schema. Store schema in memory.", "code-analyzer")
  Task("Test Engineer", "Write Jest tests. Check memory for API contracts.", "tester")
  Task("DevOps Engineer", "Setup Docker and CI/CD. Document in memory.", "cicd-engineer")
  Task("Security Auditor", "Review authentication. Report findings via hooks.", "reviewer")
  
  // All todos batched together
  TodoWrite { todos: [...8-10 todos...] }
  
  // All file operations together
  Write "backend/server.js"
  Write "frontend/App.jsx"
  Write "database/schema.sql"
```

## 📋 Agent Coordination Protocol

### Every Agent Spawned via Task Tool MUST:

**1️⃣ BEFORE Work:**
```bash
npx claude-flow@alpha hooks pre-task --description "[task]"
npx claude-flow@alpha hooks session-restore --session-id "swarm-[id]"
```

**2️⃣ DURING Work:**
```bash
npx claude-flow@alpha hooks post-edit --file "[file]" --memory-key "swarm/[agent]/[step]"
npx claude-flow@alpha hooks notify --message "[what was done]"
```

**3️⃣ AFTER Work:**
```bash
npx claude-flow@alpha hooks post-task --task-id "[task]"
npx claude-flow@alpha hooks session-end --export-metrics true
```

## 🎯 Concurrent Execution Examples

### ✅ CORRECT WORKFLOW: MCP Coordinates, Claude Code Executes

```javascript
// Step 1: MCP tools set up coordination (optional, for complex tasks)
[Single Message - Coordination Setup]:
  mcp__claude-flow__swarm_init { topology: "mesh", maxAgents: 6 }
  mcp__claude-flow__agent_spawn { type: "researcher" }
  mcp__claude-flow__agent_spawn { type: "coder" }
  mcp__claude-flow__agent_spawn { type: "tester" }

// Step 2: Claude Code Task tool spawns ACTUAL agents that do the work
[Single Message - Parallel Agent Execution]:
  // Claude Code's Task tool spawns real agents concurrently
  Task("Research agent", "Analyze API requirements and best practices. Check memory for prior decisions.", "researcher")
  Task("Coder agent", "Implement REST endpoints with authentication. Coordinate via hooks.", "coder")
  Task("Database agent", "Design and implement database schema. Store decisions in memory.", "code-analyzer")
  Task("Tester agent", "Create comprehensive test suite with 90% coverage.", "tester")
  Task("Reviewer agent", "Review code quality and security. Document findings.", "reviewer")
  
  // Batch ALL todos in ONE call
  TodoWrite { todos: [
    {id: "1", content: "Research API patterns", status: "in_progress", priority: "high"},
    {id: "2", content: "Design database schema", status: "in_progress", priority: "high"},
    {id: "3", content: "Implement authentication", status: "pending", priority: "high"},
    {id: "4", content: "Build REST endpoints", status: "pending", priority: "high"},
    {id: "5", content: "Write unit tests", status: "pending", priority: "medium"},
    {id: "6", content: "Integration tests", status: "pending", priority: "medium"},
    {id: "7", content: "API documentation", status: "pending", priority: "low"},
    {id: "8", content: "Performance optimization", status: "pending", priority: "low"}
  ]}
  
  // Parallel file operations
  Bash "mkdir -p app/{src,tests,docs,config}"
  Write "app/package.json"
  Write "app/src/server.js"
  Write "app/tests/server.test.js"
  Write "app/docs/API.md"
```

### ❌ WRONG (Multiple Messages):
```javascript
Message 1: mcp__claude-flow__swarm_init
Message 2: Task("agent 1")
Message 3: TodoWrite { todos: [single todo] }
Message 4: Write "file.js"
// This breaks parallel coordination!
```

## Performance Benefits

- **84.8% SWE-Bench solve rate**
- **32.3% token reduction**
- **2.8-4.4x speed improvement**
- **27+ neural models**

## Hooks Integration

### Pre-Operation
- Auto-assign agents by file type
- Validate commands for safety
- Prepare resources automatically
- Optimize topology by complexity
- Cache searches

### Post-Operation
- Auto-format code
- Train neural patterns
- Update memory
- Analyze performance
- Track token usage

### Session Management
- Generate summaries
- Persist state
- Track metrics
- Restore context
- Export workflows

## Advanced Features (v2.0.0)

- 🚀 Automatic Topology Selection
- ⚡ Parallel Execution (2.8-4.4x speed)
- 🧠 Neural Training
- 📊 Bottleneck Analysis
- 🤖 Smart Auto-Spawning
- 🛡️ Self-Healing Workflows
- 💾 Cross-Session Memory
- 🔗 GitHub Integration

## Integration Tips

1. Start with basic swarm init
2. Scale agents gradually
3. Use memory for context
4. Monitor progress regularly
5. Train patterns from success
6. Enable hooks automation
7. Use GitHub tools first

## Support

- Documentation: https://github.com/ruvnet/claude-flow
- Issues: https://github.com/ruvnet/claude-flow/issues
- Flow-Nexus Platform: https://flow-nexus.ruv.io (registration required for cloud features)

---

Remember: **Claude Flow coordinates, Claude Code creates!**

---

# 🤖 SENTINEL PROJECT - Agentic API Testing Platform

## Project Overview

**Sentinel** is an AI-powered platform for automating the entire API testing lifecycle using specialized AI agents. The project combines **Claude-Flow orchestration** with **Agentic QE Fleet** for comprehensive testing.

### Core Architecture

- **Frontend**: React-based UI (Port 3000) with Redux state management
- **Backend Services**: Python microservices with FastAPI (Ports 8000-8005, 8088)
  - API Gateway (8000), Auth (8005), Spec (8001), Orchestration (8002), Execution (8003), Data (8004)
- **Rust Core**: High-performance agent core (8088) powered by ruv-swarm
- **Database**: PostgreSQL with pgvector extension (Port 5432)
- **Message Broker**: RabbitMQ for asynchronous task processing (Ports 5672/15672)
- **Observability**: Prometheus (9090), Jaeger (16686)

### Hybrid Python/Rust Agents

The platform implements **both Python and Rust agents** for optimal performance:

#### Functional Testing
- **Functional-Positive-Agent**: Valid "happy path" tests (Python/Rust)
- **Functional-Negative-Agent**: Boundary value analysis and negative tests (Python/Rust)
- **Functional-Stateful-Agent**: Multi-step workflows with SODG graphs (Python/Rust)

#### Security Testing
- **Security-Auth-Agent**: BOLA, authorization bypass (Python/Rust)
- **Security-Injection-Agent**: SQL/NoSQL/Command/LLM injection (Python/Rust)

#### Performance Testing
- **Performance-Planner-Agent**: k6/JMeter/Locust scripts (Python/Rust)

#### Data Generation
- **Data-Mocking-Agent**: Schema-aware test data (Python/Rust)

**Performance**: Rust agents provide **18-21x faster execution** with automatic fallback to Python for resilience.

### Advanced AI Features

- **Consciousness Verification**: Self-modifying test generation with pattern learning
- **Psycho-Symbolic Reasoning**: Combines psychological models with symbolic logic
- **Temporal Consciousness**: Nanosecond-precision scheduling
- **Knowledge Graph Integration**: Semantic understanding of API relationships
- **Sublinear Solvers**: O(log n) performance for large-scale optimization

### Multi-LLM Provider Support

Supports multiple LLM providers with automatic fallback:
- **Anthropic** (Default): Claude Opus 4.1/4, Sonnet 4, Haiku 3.5
- **OpenAI**: GPT-4 Turbo, GPT-4, GPT-3.5 Turbo
- **Google**: Gemini 2.5 Pro/Flash, Gemini 2.0 Flash
- **Mistral**: Large, Small 3, Codestral
- **Ollama** (Local): DeepSeek-R1, Llama 3.3, Qwen 2.5

Configure via: `cd sentinel_backend/scripts && ./switch_llm.sh`

### Testing Infrastructure

- **540+ comprehensive tests** with 97.8% pass rate
- **184 AI agent tests** (Phase 1 complete)
- **272 LLM provider tests** (Phase 2 complete)
- **45+ Playwright E2E tests** for frontend
- **Performance testing**: Load, stress, concurrent execution

### Quick Start Commands

```bash
# Complete setup
make setup

# Start all services
make start

# Initialize/repair database
make init-db

# Check service status
make status

# Run tests in Docker
cd sentinel_backend && ./run_tests.sh -d
```

---

# 🤖 AGENTIC QE FLEET (19 Specialized Agents)

## Overview

The **Agentic QE Fleet** provides 19 specialized AI agents for comprehensive software testing and quality assurance, integrated with Claude-Flow orchestration.

### Available Agents

#### Core Testing (5 agents)
- **qe-test-generator**: AI-powered test generation with sublinear optimization
- **qe-test-executor**: Multi-framework execution with parallel processing
- **qe-coverage-analyzer**: Real-time gap detection with O(log n) algorithms
- **qe-quality-gate**: Intelligent quality gate with risk assessment
- **qe-quality-analyzer**: Comprehensive quality metrics analysis

#### Performance & Security (2 agents)
- **qe-performance-tester**: Load testing (k6, JMeter, Gatling)
- **qe-security-scanner**: Multi-layer security with SAST/DAST

#### Strategic Planning (3 agents)
- **qe-requirements-validator**: INVEST criteria validation and BDD generation
- **qe-production-intelligence**: Production data to test scenarios conversion
- **qe-fleet-commander**: Hierarchical fleet coordination (50+ agents)

#### Deployment (1 agent)
- **qe-deployment-readiness**: Multi-factor risk assessment

#### Advanced Testing (4 agents)
- **qe-regression-risk-analyzer**: Smart test selection with ML patterns
- **qe-test-data-architect**: High-speed data generation (10k+ records/sec)
- **qe-api-contract-validator**: Breaking change detection
- **qe-flaky-test-hunter**: Statistical flakiness detection and auto-stabilization

#### Specialized (2 agents)
- **qe-visual-tester**: Visual regression with AI-powered comparison
- **qe-chaos-engineer**: Resilience testing with controlled fault injection

### Quick Start - AQE Agents

#### Using Claude Code Task Tool (Recommended)
```javascript
Task("Generate tests", "Create comprehensive test suite for UserService", "qe-test-generator")
Task("Analyze coverage", "Find gaps using O(log n) algorithms", "qe-coverage-analyzer")
Task("Quality check", "Run quality gate validation", "qe-quality-gate")
```

#### Using MCP Tools
```bash
# Check MCP connection
claude mcp list

# Use MCP tools
mcp__agentic_qe__test_generate({ type: "unit", framework: "jest" })
mcp__agentic_qe__test_execute({ parallel: true, coverage: true })
```

#### Using CLI
```bash
aqe test <module>       # Generate tests
aqe coverage            # Analyze coverage
aqe quality             # Run quality gate
aqe status              # Check fleet status
```

### Agent Coordination

All AQE agents coordinate through **native AQE hooks** (zero external dependencies, 100-500x faster than external hooks):

**Performance Comparison:**
| Feature | AQE Hooks | External Hooks |
|---------|-----------|----------------|
| Speed | <1ms | 100-500ms |
| Dependencies | Zero | External package |
| Type Safety | Full TypeScript | Shell strings |
| Performance | 100-500x faster | Baseline |

### Memory Namespace

Agents share state through the `aqe/*` memory namespace:
- `aqe/test-plan/*` - Test planning and requirements
- `aqe/coverage/*` - Coverage analysis and gaps
- `aqe/quality/*` - Quality metrics and gates
- `aqe/performance/*` - Performance test results
- `aqe/security/*` - Security scan findings
- `aqe/swarm/coordination` - Cross-agent coordination

### Claude Code Skills Integration (34 Specialized QE Skills)

#### Phase 1: Original Quality Engineering Skills (17 skills)
- **agentic-quality-engineering**, **context-driven-testing**, **holistic-testing-pact**
- **tdd-london-chicago**, **xp-practices**, **risk-based-testing**, **test-automation-strategy**
- **api-testing-patterns**, **exploratory-testing-advanced**, **performance-testing**, **security-testing**
- **code-review-quality**, **refactoring-patterns**, **quality-metrics**
- **bug-reporting-excellence**, **technical-writing**, **consultancy-practices**

#### Phase 2: Expanded QE Skills Library (17 skills)
- **regression-testing**, **shift-left-testing**, **shift-right-testing**, **test-design-techniques**, **mutation-testing**, **test-data-management**
- **accessibility-testing**, **mobile-testing**, **database-testing**, **contract-testing**, **chaos-engineering-resilience**
- **compatibility-testing**, **localization-testing**, **compliance-testing**, **visual-testing-advanced**
- **test-environment-management**, **test-reporting-analytics**

#### Using Skills
```bash
# List skills
aqe skills list

# Show skill details
aqe skills show agentic-quality-engineering

# Execute via Skill tool in Claude Code
Skill("agentic-quality-engineering")
```

### Q-Learning Integration (Phase 2)

All agents learn from task execution through Q-learning:

```bash
# Check learning status
aqe learn status --agent test-gen

# View patterns
aqe patterns list --framework jest

# Start continuous improvement
aqe improve start
```

### Multi-Model Router (v1.3.4)

**Status**: ⚠️ Disabled (opt-in) - Provides **70-81% cost savings**

Enable via configuration or environment variable:
```bash
export AQE_ROUTING_ENABLED=true
```

| Task Complexity | Model | Est. Cost | Use Case |
|----------------|-------|-----------|----------|
| Simple | GPT-3.5 | $0.0004 | Unit tests, basic validation |
| Moderate | GPT-3.5 | $0.0008 | Integration tests, mocks |
| Complex | GPT-4 | $0.0048 | Property-based, edge cases |
| Critical | Claude Sonnet 4.5 | $0.0065 | Security, architecture review |

### Streaming Progress (v1.3.4)

Real-time progress updates for long-running operations:
```javascript
for await (const event of handler.execute(params)) {
  if (event.type === 'progress') {
    console.log(`Progress: ${event.percent}% - ${event.message}`);
  }
}
```

---

# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.
Never save working files, text/mds and tests to the root folder.
