# Contributing to Sentinel API Testing Platform

First off, thank you for considering contributing to Sentinel! It's people like you that make Sentinel such a great tool for the API testing community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)
  - [Git Commit Messages](#git-commit-messages)
  - [Python Style Guide](#python-style-guide)
  - [JavaScript Style Guide](#javascript-style-guide)
  - [Rust Style Guide](#rust-style-guide)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by the [Sentinel Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

Sentinel is a comprehensive API testing platform that combines deterministic algorithms with AI-powered testing capabilities. Before contributing, please:

1. Read the [README.md](README.md) to understand the project's purpose and architecture
2. Review the [Memory Bank documentation](memory-bank/) to understand the system design
3. Check the [project roadmap](memory-bank/progress.md) to see what's being worked on
4. Look through existing [issues](https://github.com/proffesor-for-testing/sentinel-api-testing/issues) to avoid duplicates

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible using our bug report template.

**How to Submit a Good Bug Report:**

Bugs are tracked as GitHub issues. Create an issue and provide the following information:

- **Use a clear and descriptive title** for the issue to identify the problem
- **Describe the exact steps which reproduce the problem** in as many details as possible
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps**
- **Explain which behavior you expected to see instead and why**
- **Include screenshots and animated GIFs** if possible
- **Include your environment details** (OS, Python version, Node.js version, Docker version)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title** for the issue to identify the suggestion
- **Provide a step-by-step description of the suggested enhancement**
- **Provide specific examples to demonstrate the steps**
- **Describe the current behavior** and **explain which behavior you expected to see instead**
- **Explain why this enhancement would be useful** to most Sentinel users
- **List some other API testing tools where this enhancement exists** if applicable

### Your First Code Contribution

Unsure where to begin contributing? You can start by looking through these issues:

- Issues labeled `good first issue` - issues which should only require a few lines of code
- Issues labeled `help wanted` - issues which need extra attention
- Issues labeled `documentation` - issues related to improving documentation

### Pull Requests

The process described here has several goals:

- Maintain Sentinel's quality
- Fix problems that are important to users
- Engage the community in working toward the best possible Sentinel
- Enable a sustainable system for Sentinel's maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. **Fork the repository** and create your branch from `main`
2. **Follow the branch naming convention**: `feature/description` or `fix/description`
3. **If you've added code that should be tested**, add tests
4. **If you've changed APIs**, update the documentation
5. **Ensure the test suite passes** by running `pytest` in the backend and `npm test` in the frontend
6. **Make sure your code lints** (see style guidelines below)
7. **Issue that pull request!**

## Development Setup

### Prerequisites

- Python 3.10+
- Node.js 16+
- Docker and Docker Compose
- Rust 1.70+ (for the Rust core)
- Make (for convenient commands)
- Anthropic API Key (for AI features)

### Setting Up Your Development Environment

#### Quick Setup (Recommended)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/proffesor-for-testing/sentinel-api-testing.git
   cd sentinel-api-testing
   ```

2. **Set up environment:**
   ```bash
   export SENTINEL_APP_ANTHROPIC_API_KEY=your-anthropic-api-key
   ```

3. **Complete setup:**
   ```bash
   make setup  # Builds images, initializes database, starts services
   ```

4. **Start the frontend:**
   ```bash
   cd sentinel_frontend
   npm install
   npm start
   ```

#### Manual Setup (Alternative)

1. **Set up the Python backend:**
   ```bash
   cd sentinel_backend
   poetry install  # or: pip install -e ".[dev]"
   ```

2. **Set up the Rust core:**
   ```bash
   cd sentinel_backend/sentinel_rust_core
   cargo build
   ```

3. **Start services and initialize database:**
   ```bash
   docker-compose up -d
   make init-db  # Initializes all tables and columns
   ```

### Useful Development Commands

```bash
make help          # Show all available commands
make start         # Start all services
make stop          # Stop all services
make restart       # Restart services
make logs          # View service logs
make test          # Run tests
make init-db       # Initialize/repair database
make reset-db      # Reset database (WARNING: data loss)
make status        # Check service status
```

### Running Tests

- **Backend tests:** `cd sentinel_backend && pytest`
- **Frontend tests:** `cd sentinel_frontend && npm test`
- **Rust tests:** `cd sentinel_backend/sentinel_rust_core && cargo test`
- **End-to-end tests:** `python test_observability_e2e.py`

## Style Guidelines

### Git Commit Messages

Follow the guidelines in `.clinerules`:

- Keep commit messages concise (under 50 characters for the title)
- Use format: "Action: Brief description" (e.g., "Add: Analytics dashboard", "Fix: Database connection")
- Use present tense ("Add feature" not "Added feature")
- Reference issues and pull requests liberally after the first line

Example:
```
Add: OAuth2 authentication support

- Implement OAuth2 flow in auth service
- Add Google and GitHub providers
- Update frontend login component
- Add tests for OAuth2 endpoints

Fixes #123
```

### Python Style Guide

We follow PEP 8 with the following additions:

- Use type hints for all function signatures
- Use Pydantic models for data validation
- Use async/await for all I/O operations
- Maximum line length: 100 characters
- Use Black for code formatting: `black sentinel_backend/`
- Use isort for import sorting: `isort sentinel_backend/`

### JavaScript Style Guide

- Use ES6+ features
- Use functional components and hooks in React
- Use Prettier for formatting: `npm run format`
- Use ESLint for linting: `npm run lint`
- Prefer async/await over promises
- Use meaningful variable and function names

### Rust Style Guide

- Follow the official Rust style guide
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Write idiomatic Rust code
- Document public APIs with doc comments

## Testing Guidelines

- **Write tests for all new features**
- **Maintain test coverage above 80%**
- **Use pytest fixtures for test data**
- **Mock external dependencies**
- **Write both unit and integration tests**
- **Test error cases and edge conditions**
- **Use descriptive test names**

Example test structure:
```python
def test_should_create_test_case_with_valid_data():
    """Test that a test case is created successfully with valid input data."""
    # Arrange
    test_data = {...}
    
    # Act
    result = create_test_case(test_data)
    
    # Assert
    assert result.status == "success"
    assert result.test_case.name == test_data["name"]
```

## Documentation

- **Document all public APIs**
- **Keep README.md up to date**
- **Update Memory Bank files when making architectural changes**
- **Add docstrings to all functions and classes**
- **Include examples in documentation**
- **Document configuration options**

## Community


- **Discussions:** Use GitHub Discussions for general questions
- **Stack Overflow:** Tag questions with `sentinel-api-testing`


## Recognition

Contributors who make significant contributions will be:

- Added to the CONTRIBUTORS.md file
- Mentioned in release notes
- Given credit in the documentation
- Invited to become maintainers (for sustained contributions)

## Questions?

Feel free to open an issue with the `question` label or reach out to the maintainers directly.

Thank you for contributing to Sentinel! 🚀
