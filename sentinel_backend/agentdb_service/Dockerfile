FROM python:3.11-slim

# Install Node.js for claude-flow (AgentDB MCP tools)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install claude-flow globally
RUN npm install -g claude-flow@alpha

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install Poetry
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false

# Install Python dependencies
RUN poetry install --no-dev --no-interaction --no-ansi

# Copy service code
COPY agentdb_service/ ./agentdb_service/
COPY config/ ./config/

# Create data directory for AgentDB
RUN mkdir -p /data/agentdb

# Set environment variables
ENV PYTHONPATH=/app
ENV EMBEDDING_MODEL=all-MiniLM-L6-v2
ENV AGENTDB_COLLECTION_PREFIX=sentinel
ENV AGENTDB_DATA_DIR=/data/agentdb

# Expose port
EXPOSE 8006

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8006/health || exit 1

# Run the service
CMD ["uvicorn", "agentdb_service.main:app", "--host", "0.0.0.0", "--port", "8006"]
