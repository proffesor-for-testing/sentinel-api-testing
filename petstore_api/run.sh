#!/bin/bash

echo "🐾 Starting Petstore API Service..."
echo "================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Running with Python directly..."
    
    # Check if Python is installed
    if ! command -v python3 &> /dev/null; then
        echo "❌ Python3 is not installed. Please install Python 3.11 or higher."
        exit 1
    fi
    
    # Install dependencies if not in virtual environment
    if [ -z "$VIRTUAL_ENV" ]; then
        echo "📦 Installing dependencies..."
        pip3 install -r requirements.txt
    fi
    
    echo "✅ Starting API server on http://localhost:8080"
    echo "📚 API Documentation available at http://localhost:8080/docs"
    echo "🔍 Alternative docs at http://localhost:8080/redoc"
    echo ""
    echo "Press Ctrl+C to stop the server"
    python3 main.py
else
    echo "🐳 Using Docker to run the service..."
    
    # Build and run with Docker Compose
    docker-compose up --build
fi