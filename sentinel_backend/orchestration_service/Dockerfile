# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

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
CMD ["uvicorn", "sentinel_backend.orchestration_service.main:app", "--host", "0.0.0.0", "--port", "8002", "--reload"]
