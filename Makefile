# Sentinel API Testing Platform - Makefile
# Convenient commands for development and deployment

.PHONY: help init-db reset-db start stop restart logs test clean

# Default target
help:
	@echo "Sentinel API Testing Platform - Available Commands:"
	@echo ""
	@echo "Database Management:"
	@echo "  make init-db        - Initialize database with all tables"
	@echo "  make reset-db       - Drop and recreate database (WARNING: data loss)"
	@echo "  make backup-db      - Backup database to file"
	@echo "  make restore-db     - Restore database from backup"
	@echo ""
	@echo "Service Management:"
	@echo "  make start          - Start all services"
	@echo "  make stop           - Stop all services"
	@echo "  make restart        - Restart all services"
	@echo "  make logs           - Show logs from all services"
	@echo "  make status         - Show service status"
	@echo ""
	@echo "Development:"
	@echo "  make test           - Run tests"
	@echo "  make clean          - Clean up containers and volumes"
	@echo "  make build          - Build all Docker images"
	@echo "  make dev            - Start in development mode"
	@echo ""
	@echo "Quick Start:"
	@echo "  make setup          - Complete setup (build, init-db, start)"

# Database initialization
init-db:
	@echo "Initializing database..."
	@docker-compose exec -T db psql -U sentinel sentinel_db < sentinel_backend/init_db.sql || true
	@python3 sentinel_backend/init_database.py || true
	@echo "Database initialized!"

# Reset database (WARNING: destroys all data)
reset-db:
	@echo "WARNING: This will delete all data! Press Ctrl+C to cancel, or wait 5 seconds..."
	@sleep 5
	@docker-compose exec -T db psql -U postgres -c "DROP DATABASE IF EXISTS sentinel_db;"
	@docker-compose exec -T db psql -U postgres -c "CREATE DATABASE sentinel_db OWNER sentinel;"
	@make init-db

# Backup database
backup-db:
	@echo "Backing up database..."
	@mkdir -p backups
	@docker-compose exec -T db pg_dump -U sentinel sentinel_db > backups/sentinel_db_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Database backed up to backups/"

# Restore database from latest backup
restore-db:
	@echo "Restoring database from latest backup..."
	@docker-compose exec -T db psql -U sentinel sentinel_db < $(shell ls -t backups/*.sql | head -1)
	@echo "Database restored!"

# Start all services
start:
	@echo "Starting all services..."
	@docker-compose up -d
	@echo "Waiting for services to be ready..."
	@sleep 10
	@make init-db
	@echo "Starting frontend..."
	@cd sentinel_frontend && nohup npm start > /tmp/frontend.log 2>&1 &
	@echo "All services started!"
	@echo ""
	@echo "Access points:"
	@echo "  Frontend:    http://localhost:3000"
	@echo "  API Gateway: http://localhost:8000"
	@echo "  Petstore:    http://localhost:8080"
	@echo ""
	@echo "Login: admin@sentinel.com / admin123"

# Stop all services
stop:
	@echo "Stopping all services..."
	@docker-compose down
	@pkill -f "react-scripts" || true
	@echo "All services stopped!"

# Restart all services
restart:
	@make stop
	@make start

# Show logs
logs:
	@docker-compose logs -f --tail=50

# Show service status
status:
	@echo "Service Status:"
	@docker-compose ps
	@echo ""
	@echo "Frontend Status:"
	@ps aux | grep -E "react-scripts" | grep -v grep || echo "Frontend not running"

# Build Docker images
build:
	@echo "Building Docker images..."
	@docker-compose build --no-cache
	@echo "Build complete!"

# Clean up everything
clean:
	@echo "Cleaning up containers and volumes..."
	@docker-compose down -v
	@docker volume prune -f
	@docker network prune -f
	@rm -rf backups/
	@echo "Cleanup complete!"

# Run tests
test:
	@echo "Running tests..."
	@docker-compose exec -T orchestration_service pytest tests/ || true
	@docker-compose exec -T data_service pytest tests/ || true
	@echo "Tests complete!"

# Development mode
dev:
	@echo "Starting in development mode..."
	@docker-compose up -d db message_broker
	@sleep 5
	@make init-db
	@docker-compose up

# Complete setup from scratch
setup:
	@echo "Setting up Sentinel from scratch..."
	@make build
	@make start
	@echo ""
	@echo "✅ Setup complete!"
	@echo "Access the application at: http://localhost:3000"
	@echo "Login with: admin@sentinel.com / admin123"

# Start Petstore test application
start-petstore:
	@echo "Starting Petstore test application..."
	@cd petstore_api && docker-compose up -d
	@echo "Petstore running at: http://localhost:8080"

# Stop Petstore
stop-petstore:
	@cd petstore_api && docker-compose down