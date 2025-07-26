# Technical Context: Sentinel Platform

This document outlines the recommended technology stack and development environment for the Sentinel platform, based on the project specification.

## 1. Core Technology Stack

| Component              | Technology                        | Rationale & Key Libraries                                                                                                                                                                                          |
| ---------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Backend Framework**  | Python 3.10+ with FastAPI         | Python's dominance in AI/ML provides an unparalleled library ecosystem. FastAPI offers high performance, automatic OpenAPI documentation for internal APIs, and robust data validation via Pydantic.                 |
| **Agentic Framework**  | ruv-swarm / ruv-FANN              | A foundational requirement. This provides the core mechanism for creating ephemeral, CPU-native, WASM-based agents, enabling a resource-efficient and highly scalable testing architecture.                        |
| **Database**           | PostgreSQL with pgvector          | A reliable, feature-rich relational database. The `pgvector` extension is critical for storing and querying vector embeddings, enabling advanced Retrieval-Augmented Generation (RAG) techniques for test generation. |
| **Frontend Framework** | React or Vue.js                   | Both are mature, component-based frameworks well-suited for building the complex, interactive dashboard required for test management, visualization, and reporting.                                                 |
| **API Spec Parsing**   | `prance`, `openapi-core`          | Specialized Python libraries to handle the complexities of parsing, validating, and resolving references within OpenAPI specifications, which is fundamental to the platform's intelligence.                       |
| **Test Execution**     | pytest                            | A powerful and highly extensible Python testing framework. The platform will dynamically generate test logic to be executed by the pytest runner, leveraging its rich plugin ecosystem (e.g., `pytest-xdist`).   |
| **Job Scheduling**     | `schedule` (Python) / Cron        | The `schedule` library for simple, in-process interval-based jobs. System `cron` for more robust, time-based scheduling.                                                                                         |
| **Data Mocking**       | Faker.js / Custom Mock Server     | A library like Faker.js will be integrated to generate realistic mock data. The mocking agent will configure a mock server to simulate various API behaviors, including latency and error conditions.           |

## 2. Development & CI/CD

- **Version Control:** Git, hosted on a platform like GitHub or GitLab.
- **Containerization:** Docker and Docker Compose will be used to create a consistent, reproducible development environment for all backend services and the database.
- **CI/CD Integration:** The platform will be designed for seamless integration with major CI/CD systems (GitHub Actions, GitLab CI, Jenkins). It will expose a stable CLI and/or REST API hooks to be invoked from pipeline scripts for true continuous testing.

## 3. Technical Constraints & Considerations

- **LLM Integration:** The system will interact with Large Language Models (LLMs). This introduces dependencies on external APIs (e.g., OpenAI, Anthropic) or requires hosting open-source models.
- **Security Agent Architecture:** To avoid self-censorship by commercial LLM providers when generating security exploits, the `Security-Injection-Agent` will use a two-tiered approach: a powerful model for high-level strategy and a less-restricted (potentially locally hosted) model for final payload generation.
- **WASM Compilation:** A toolchain for compiling Python code (or Rust, as is common in the ruv-FANN ecosystem) to WebAssembly will be a necessary part of the agent development workflow.
- **Data Privacy:** The platform will handle potentially sensitive API specifications and test data. All data must be handled securely, with encryption at rest and in transit.
