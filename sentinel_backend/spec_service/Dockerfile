# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app
ENV PYTHONPATH /app

# Copy the dependency files to the working directory
COPY pyproject.toml ./

# Install dependencies only (not the package itself yet)
RUN pip install fastapi uvicorn sqlalchemy asyncpg psycopg2-binary pgvector alembic prance openapi-core pyyaml pytest pytest-asyncio httpx schedule openai pyjwt bcrypt python-multipart email-validator python-dotenv pydantic pydantic-settings Faker

# Copy the content of the local src directory to the working directory
COPY . .

# Now install the package in development mode
RUN pip install -e .

# Command to run the application
CMD ["uvicorn", "sentinel_backend.spec_service.main:app", "--host", "0.0.0.0", "--port", "8001", "--reload"]
