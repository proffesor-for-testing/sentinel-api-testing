# Claude Code Configuration - SPARC Development Environment

## 🚨 CRITICAL: CONCURRENT EXECUTION & FILE MANAGEMENT

**ABSOLUTE RULES**:
1. ALL operations MUST be concurrent/parallel in a single message
2. **NEVER save working files, text/mds and tests to the root folder**
3. ALWAYS organize files in appropriate subdirectories

### ⚡ GOLDEN RULE: "1 MESSAGE = ALL RELATED OPERATIONS"

**MANDATORY PATTERNS:**
- **TodoWrite**: ALWAYS batch ALL todos in ONE call (5-10+ todos minimum)
- **Task tool**: ALWAYS spawn ALL agents in ONE message with full instructions
- **File operations**: ALWAYS batch ALL reads/writes/edits in ONE message
- **Bash commands**: ALWAYS batch ALL terminal operations in ONE message
- **Memory operations**: ALWAYS batch ALL memory store/retrieve in ONE message

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

**Sentinel Platform**: AI-powered API testing platform with specialized ephemeral agents for intelligent test generation across functional, security, and performance domains.

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

### Backend Development (Python/FastAPI)
```bash
# Navigate to backend
cd sentinel_backend

# Install dependencies
poetry install

# Run individual services
cd api_gateway && poetry run uvicorn main:app --reload --port 8000
cd spec_service && poetry run uvicorn main:app --reload --port 8001
cd orchestration_service && poetry run uvicorn main:app --reload --port 8002
cd execution_service && poetry run uvicorn main:app --reload --port 8003
cd data_service && poetry run uvicorn main:app --reload --port 8004
cd auth_service && poetry run uvicorn main:app --reload --port 8005

# Full platform startup (Docker)
docker-compose up --build

# Run tests
./run_tests.sh                    # All tests with comprehensive options
./run_tests.sh -t unit           # Unit tests only
./run_tests.sh -t integration -d # Integration tests in Docker
./run_tests.sh -t agents         # Run AI agent tests
./run_agent_tests.sh             # Run agent tests with colored output
./run_agent_tests.sh -c          # Run agent tests with coverage
./run_agent_tests.sh base auth   # Run specific agent tests
pytest                           # Direct pytest execution
```

### Frontend Development (React)
```bash
# Navigate to frontend
cd sentinel_frontend

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build

# Run tests
npm test
```

### Rust Core Development
```bash
# Navigate to Rust core
cd sentinel_backend/sentinel_rust_core

# Build and run
cargo build --release
cargo run

# Run tests
cargo test
```

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

### Claude Code Handles ALL:
- File operations (Read, Write, Edit, MultiEdit, Glob, Grep)
- Code generation and programming
- Bash commands and system operations
- Implementation work
- Project navigation and analysis
- TodoWrite and task management
- Git operations
- Package management
- Testing and debugging

### MCP Tools ONLY:
- Coordination and planning
- Memory management
- Neural features
- Performance tracking
- Swarm orchestration
- GitHub integration

**KEY**: MCP coordinates, Claude Code executes.

## 🚀 Quick Setup

```bash
# Add Claude Flow MCP server
claude mcp add claude-flow npx claude-flow@alpha mcp start
```

## 🧪 Testing Strategy

### Backend Testing
- **Unit Tests**: 456+ tests (Agents: 184, LLM Providers: 272+)
- **Integration Tests**: 6 comprehensive test files (2,342 lines)
  - Service communication
  - Database operations
  - Message broker (RabbitMQ)
  - Security flows
- **API Workflow Tests**: End-to-end API testing scenarios
  - Complete workflow from spec to results
  - Authentication flows

### Frontend Testing (Playwright E2E)
- **Real Browser Testing**: Chrome, Firefox, Safari, Mobile
- **Page Object Model**: Maintainable test architecture
- **Test Coverage**:
  - Authentication & RBAC
  - API Specification Management
  - Test Generation Workflow
  - Results Visualization

```bash
# Run Playwright E2E tests
cd sentinel_frontend
npm install
npx playwright install
npm run test:e2e
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

## 📋 Agent Coordination Protocol

### Every Agent MUST:

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

### ✅ CORRECT (Single Message):
```javascript
[BatchTool]:
  // Initialize swarm
  mcp__claude-flow__swarm_init { topology: "mesh", maxAgents: 6 }
  mcp__claude-flow__agent_spawn { type: "researcher" }
  mcp__claude-flow__agent_spawn { type: "coder" }
  mcp__claude-flow__agent_spawn { type: "tester" }
  
  // Spawn agents with Task tool
  Task("Research agent: Analyze requirements...")
  Task("Coder agent: Implement features...")
  Task("Tester agent: Create test suite...")
  
  // Batch todos
  TodoWrite { todos: [
    {id: "1", content: "Research", status: "in_progress", priority: "high"},
    {id: "2", content: "Design", status: "pending", priority: "high"},
    {id: "3", content: "Implement", status: "pending", priority: "high"},
    {id: "4", content: "Test", status: "pending", priority: "medium"},
    {id: "5", content: "Document", status: "pending", priority: "low"}
  ]}
  
  // File operations
  Bash "mkdir -p app/{src,tests,docs}"
  Write "app/src/index.js"
  Write "app/tests/index.test.js"
  Write "app/docs/README.md"
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

## LLM Integration

### Multi-Provider Support
The platform includes a comprehensive LLM abstraction layer supporting multiple providers with automatic fallback capabilities. All AI agents can leverage LLM capabilities while maintaining backward compatibility.

### Default Configuration
The platform uses **Anthropic's Claude Sonnet 4** as the default LLM provider for all AI agents. This provides:
- Excellent balance of performance and cost
- 1 million token context window (as of August 2025)
- Strong reasoning capabilities with hybrid modes
- Vision support for multimodal testing
- API model: `claude-sonnet-4-20250514`

To use the default configuration:
```bash
export SENTINEL_APP_ANTHROPIC_API_KEY=your-anthropic-api-key
```

### Supported Providers

#### Commercial Providers
- **OpenAI**: GPT-4 Turbo, GPT-4, GPT-3.5 Turbo
- **Anthropic**: Claude Opus 4.1/4, Claude Sonnet 4, Claude Haiku 3.5
- **Google**: Gemini 2.5 Pro, Gemini 2.5 Flash, Gemini 2.0 Flash
- **Mistral**: Mistral Large, Mistral Small 3, Codestral

#### Open Source Models (via Ollama)
- **DeepSeek**: DeepSeek-R1 (671B/70B/32B variants)
- **Meta Llama**: Llama 3.3 70B, Llama 3.1 (405B/70B/8B)
- **Alibaba Qwen**: Qwen 2.5 (72B/32B/7B), Qwen 2.5 Coder
- **Others**: Mistral 7B, Phi-3 14B, Gemma 2 27B, Command R 35B

### LLM Configuration & Management
```bash
# Interactive LLM configuration
cd sentinel_backend/scripts
./switch_llm.sh                 # Interactive wizard
./switch_llm.sh claude          # Quick preset for Claude
./switch_llm.sh openai          # Quick preset for OpenAI
./switch_llm.sh local           # Quick preset for local Ollama

# Docker-specific configuration
./switch_llm_docker.sh gpt4     # Switch Docker to GPT-4
./switch_llm_docker.sh gemini   # Switch Docker to Gemini 2.5

# Validate LLM configuration
python scripts/validate_llm_config.py
```

## Architecture Overview

### Microservices Architecture
The platform follows a microservices pattern with specialized services:

- **API Gateway** (8000): Single entry point, RBAC integration, request routing
- **Auth Service** (8005): JWT authentication, user management, RBAC
- **Spec Service** (8001): OpenAPI specification parsing and management
- **Orchestration Service** (8002): AI agent coordination and task delegation
- **Execution Service** (8003): Test execution engine and scheduling
- **Data Service** (8004): Analytics, persistence, historical data
- **Sentinel Rust Core** (8088): High-performance agent execution via ruv-swarm

### AI Agent System (Sentinel-Specific)
The platform uses specialized ephemeral AI agents for different testing domains:

#### Functional Testing Agents
- **Functional-Positive-Agent**: Valid test case generation with schema-based data
- **Functional-Negative-Agent**: Boundary value analysis and creative negative testing
- **Functional-Stateful-Agent**: Multi-step workflows using Semantic Operation Dependency Graphs

#### Security Testing Agents
- **Security-Auth-Agent**: BOLA, function-level authorization, auth bypass testing
- **Security-Injection-Agent**: SQL/NoSQL/Command/Prompt injection vulnerability testing

#### Other Agents
- **Performance-Planner-Agent**: k6/JMeter script generation for load testing
- **Data-Mocking-Agent**: Schema-aware realistic test data generation

### Message Broker Architecture
- **RabbitMQ** integration for asynchronous task processing
- **Publisher**: Orchestration Service publishes agent tasks
- **Consumer**: Sentinel Rust Core consumes and processes tasks
- **Durability**: Messages persist across service restarts

## Configuration Management

### Key Environment Variables
```bash
# Database
SENTINEL_DB_URL=postgresql+asyncpg://user:pass@host/db
SENTINEL_DB_POOL_SIZE=20

# Service URLs
SENTINEL_SERVICE_AUTH_SERVICE_URL=http://auth:8005
SENTINEL_SERVICE_SERVICE_TIMEOUT=60

# Security
SENTINEL_SECURITY_JWT_SECRET_KEY=your-secret-key
SENTINEL_SECURITY_JWT_EXPIRATION_HOURS=24

# LLM Configuration (Multi-Vendor Support)
SENTINEL_APP_LLM_PROVIDER=anthropic  # Options: anthropic, openai, google, mistral, ollama, vllm, none
SENTINEL_APP_LLM_MODEL=claude-sonnet-4  # Default model for the provider
SENTINEL_APP_ANTHROPIC_API_KEY=sk-ant-...  # Anthropic API key
SENTINEL_APP_OPENAI_API_KEY=sk-...  # OpenAI API key
SENTINEL_APP_LLM_TEMPERATURE=0.5
SENTINEL_APP_LLM_MAX_TOKENS=2000

# Observability
SENTINEL_NETWORK_JAEGER_AGENT_HOST=localhost
SENTINEL_NETWORK_JAEGER_AGENT_PORT=6831
SENTINEL_BROKER_URL=amqp://guest:guest@message_broker:5672/
```

## Testing Patterns & Current Status

### Test Execution Guidelines
**IMPORTANT**: Always run tests in Docker to ensure consistent environment:
```bash
cd sentinel_backend
./run_tests.sh -d              # Run all tests in Docker
./run_tests.sh -d -t unit      # Run only unit tests in Docker
./run_tests.sh -d -t integration # Run only integration tests in Docker

# Rebuild test Docker image after dependency changes
docker-compose -f docker-compose.test.yml build test_runner
```

**Current Test Status** (as of August 16, 2025):
- **408 total tests** (184 AI agent tests + 224 other tests)
- **97.8% pass rate** (399 passing, 9 failing)
- **100% AI agent coverage** with dedicated test runner
- All critical unit tests passing
- Test infrastructure includes full mocking, fixtures, and async support

## RBAC System

### Default Admin Credentials
- Email: `admin@sentinel.com`
- Password: `admin123`

### Role Hierarchy
- **Admin**: Full access including user management
- **Manager**: Most permissions except user management  
- **Tester**: Testing operations (create/edit test cases, run tests)
- **Viewer**: Read-only access

## Git & Version Control Guidelines

### Commit Message Rules
**IMPORTANT**: Always use clear, concise commit messages following this format:

```
<type>: <subject>

[optional body]
[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### Staging and Committing
```bash
# Always use git add -A to stage all changes
git add -A  # Stages all changes (new, modified, and deleted files)
git commit -m "type: Clear description of changes"
```

### Docker Service Updates
**CRITICAL**: When making code changes to services:
```bash
# ALWAYS rebuild the service, not just restart
docker-compose build <service_name>
docker-compose up -d <service_name>

# Wrong approach (won't pick up code changes):
docker-compose restart <service_name>  # DON'T DO THIS
```

## Common Issues & Solutions

### Frontend Issues
- **specifications.map is not a function**: Handle wrapped API responses
- **Layout excessive white space**: Use flexbox layout with proper positioning
- **Quick Test returns 500**: Ensure all agents have `execute` method implemented

### Backend Issues
- **Foreign key constraint errors**: Remove cross-service database dependencies
- **Docker services not reflecting code changes**: Always rebuild, not restart
- **No API key error**: Set SENTINEL_APP_ANTHROPIC_API_KEY environment variable

## Support

- **Sentinel Documentation**: See `/docs` folder and memory-bank files
- **Claude-Flow Documentation**: https://github.com/ruvnet/claude-flow
- **Claude-Flow Issues**: https://github.com/ruvnet/claude-flow/issues

---

Remember: **Claude Flow coordinates, Claude Code creates!**