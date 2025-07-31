# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app
ENV PYTHONPATH /app

# Install poetry
RUN pip install poetry

# Copy the dependency files to the working directory
COPY pyproject.toml ./

# Install project dependencies
RUN poetry config virtualenvs.create false && poetry install --no-root

# Copy the content of the local src directory to the working directory
COPY config/ /app/config
COPY data_service/ .

# Command to run the application
CMD uvicorn main:app --host ${SENTINEL_NETWORK_HOST:-0.0.0.0} --port ${DATA_SERVICE_PORT:-8004}
