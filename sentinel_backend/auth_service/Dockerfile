FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

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

# Expose port
EXPOSE 8005

# Run the application
CMD ["uvicorn", "sentinel_backend.auth_service.main:app", "--host", "0.0.0.0", "--port", "8005", "--reload"]
