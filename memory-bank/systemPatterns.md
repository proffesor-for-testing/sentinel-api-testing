# System Patterns: Sentinel Architecture

## 1. High-Level Architecture: Modular, Microservices-Inspired

Sentinel's architecture is designed to be a modular, scalable, and maintainable ecosystem. It avoids a monolithic design in favor of a microservices-inspired approach where core functionalities are encapsulated within independent services.

This pattern provides several key advantages:
- **Independent Development & Deployment:** Teams can work on different services concurrently.
- **Scalability:** Individual services can be scaled based on demand (e.g., scaling the Test Execution Service during heavy load).
- **Resilience:** A failure in one service is less likely to bring down the entire platform.
- **Technology Flexibility:** Different services can potentially use different technologies if needed, though the primary stack is Python-based.

The primary services are:
- **API Gateway & Frontend:** The single entry point for all interactions.
- **Specification Service:** Manages the lifecycle of API specifications.
- **Agent Orchestration Service:** The central brain that manages agentic workflows.
- **Test Execution Service:** Handles the practical aspects of running tests.
- **Data & Analytics Service:** The abstraction layer for data persistence and analysis.

## 2. Agentic Framework: Ephemeral Swarm Intelligence

This is the core pattern for Sentinel's intelligent capabilities. It is built on the **ruv-FANN** and **ruv-swarm** frameworks.

- **Ephemeral Agents:** Instead of maintaining a pool of persistent testing infrastructure, Sentinel dynamically spawns lightweight, specialized agents for specific tasks.
- **WASM-Based Execution:** Agents are compiled to WebAssembly (WASM), making them highly portable, secure, and CPU-native. This avoids the need for specialized hardware like GPUs for the agent execution itself.
- **"Spin up, Execute, Dissolve" Lifecycle:** This cycle ensures resource efficiency and clean, isolated test environments for every task.
- **Specialization:** The system relies on a "workforce" of different agent types, each an expert in a specific domain (e.g., `Security-Auth-Agent`, `Functional-Stateful-Agent`). This division of labor leads to more effective and focused testing.

## 3. Task Management: The "Boomerang" Pattern

The Agent Orchestration Service implements the "Boomerang" task management pattern to ensure reliable and auditable workflows.

1.  **Decomposition:** A high-level user objective (e.g., "Run regression tests") is broken down by the Orchestrator into a series of smaller, structured sub-tasks.
2.  **Delegation:** Each sub-task is delegated to the most appropriate specialist agent.
3.  **Execution:** The spawned ephemeral agent executes its task, generating an artifact (e.g., a set of test cases, a performance report).
4.  **Reporting & Integration:** The agent returns the completed artifact to the Orchestrator, which persists it via the Data & Analytics Service and marks the sub-task as complete.

This closed-loop pattern ensures that all tasks are tracked, no work is lost, and the entire process is fully traceable.

## 4. Data Model: Graph-Based Specification Intelligence

The platform's intelligence originates from its deep understanding of API contracts.

- **Internal Graph Model:** Raw OpenAPI or RAML specifications are not used directly by the agents. Instead, the Specification Service parses them and transforms them into a standardized, internal graph-based data model.
- **Semantic Dependencies:** This model explicitly represents not just endpoints and schemas, but also the *dependencies* between operations. For example, it creates a directed edge from `POST /users` to `GET /users/{id}`, signifying that the latter depends on the former.
- **Source of Truth:** This graph serves as the definitive "source of truth" for all test-generating agents, particularly the `Functional-Stateful-Agent`, which traverses the graph to generate realistic, multi-step user workflows.

## 5. Test Generation: Hybrid AI Approach

The agents employ a hybrid approach that combines the strengths of deterministic algorithms and probabilistic Large Language Models (LLMs).

- **Deterministic Foundation:** For tasks like boundary value analysis, agents use proven, classical algorithms to guarantee coverage of specific, known edge cases.
- **Multi-Vendor LLM Support:** The platform features a comprehensive abstraction layer supporting 6+ LLM providers (Anthropic Claude, OpenAI, Google Gemini 2.5, Mistral, Ollama, vLLM) with automatic fallback, cost tracking, and response caching.
- **LLM-Powered Creativity:** This deterministic baseline is then augmented by LLMs, which are used to generate a wider, more creative, and more realistic set of test data and scenarios that a purely algorithmic approach would miss.
- **Provider Flexibility:** Agents can leverage different models based on requirements - Claude Sonnet 4 for balanced performance, GPT-4 Turbo for complex reasoning, Gemini 2.5 Pro for massive context windows (2M tokens), or local models via Ollama for zero-cost/offline operation.
- **Example:** The `Functional-Negative-Agent` first performs Boundary Value Analysis and then uses an LLM to generate creatively malformed and unexpected payloads. This fusion provides both rigor and comprehensive coverage.
