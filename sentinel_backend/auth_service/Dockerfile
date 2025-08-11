FROM python:3.10-slim

WORKDIR /app
ENV PYTHONPATH /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY pyproject.toml ./

# Install dependencies only (not the package itself yet)
RUN pip install fastapi uvicorn sqlalchemy asyncpg psycopg2-binary pgvector alembic prance openapi-core pyyaml pytest pytest-asyncio httpx schedule openai pyjwt bcrypt python-multipart email-validator python-dotenv pydantic pydantic-settings Faker

# Copy application code
COPY . .

# Now install the package in development mode
RUN pip install -e .

# Expose port
EXPOSE ${AUTH_SERVICE_PORT:-8000}

# Run the application
CMD ["uvicorn", "sentinel_backend.auth_service.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
