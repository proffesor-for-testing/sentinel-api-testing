# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Install build dependencies for compiling Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    build-essential \
    python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Create the sentinel_backend directory structure
RUN mkdir -p /app/sentinel_backend

# Copy the entire project into sentinel_backend directory
COPY . /app/sentinel_backend/

# Install poetry and dependencies (without installing the project itself)
RUN cd /app/sentinel_backend && \
    pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

# Set Python path to include the app directory
ENV PYTHONPATH=/app:$PYTHONPATH

# Command to run the application
CMD ["uvicorn", "sentinel_backend.api_gateway.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
