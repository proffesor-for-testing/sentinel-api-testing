FROM python:3.10-slim

WORKDIR /app
ENV PYTHONPATH /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY pyproject.toml .

# Install Python dependencies
RUN pip install poetry
RUN poetry config virtualenvs.create false && poetry install --no-root

# Copy application code
COPY config/ /app/config
COPY auth_service/ .

# Expose port
EXPOSE ${AUTH_SERVICE_PORT:-8000}

# Run the application
CMD uvicorn main:app --host ${SENTINEL_NETWORK_HOST:-0.0.0.0} --port ${AUTH_SERVICE_PORT:-8000} --reload
