# Sentinel Frontend - Quick Start Guide

## Docker Commands

### Build & Start
```bash
# Build the frontend image
docker-compose build frontend

# Start frontend service
docker-compose up -d frontend

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f frontend
```

### Testing
```bash
# Health check
curl http://localhost:3000/health

# API proxy test
curl http://localhost:3000/api/health

# Open in browser
open http://localhost:3000
```

### Management
```bash
# Stop frontend
docker-compose stop frontend

# Restart frontend
docker-compose restart frontend

# Remove frontend
docker-compose down frontend

# Rebuild without cache
docker-compose build --no-cache frontend
```

## Development

### Local Development (without Docker)
```bash
cd sentinel_frontend
npm install
npm start
# Opens on http://localhost:3000
```

### E2E Testing
```bash
# Install Playwright
npm run playwright:install

# Run E2E tests
npm run test:e2e

# Run with UI
npm run test:e2e:ui
```

## Architecture

```
Browser → Nginx (Port 3000) → React App
                           ↓
                    API Gateway (Port 8000)
```

## Endpoints

- `/` - React SPA
- `/health` - Health check
- `/api/*` - Proxied to API Gateway
- `/ws/*` - WebSocket connections

## Environment Variables

Edit `.env.docker` to configure:
- `REACT_APP_API_URL` - External API URL
- `REACT_APP_WS_URL` - WebSocket URL
- `REACT_APP_ENV` - Environment (production/development)

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs frontend

# Verify network
docker network inspect api-testing-agents_sentinel_network
```

### API proxy not working
```bash
# Verify API Gateway is running
docker-compose ps api_gateway

# Test direct connection
curl http://localhost:8000/health
```

### Permission errors
```bash
# Rebuild with no cache
docker-compose build --no-cache frontend
docker-compose up -d frontend
```

## File Structure

```
sentinel_frontend/
├── Dockerfile.prod       # Multi-stage Docker build
├── nginx.conf           # Main nginx configuration
├── nginx-default.conf   # Server block with proxy
├── .dockerignore        # Build exclusions
├── .env.docker          # Environment variables
├── public/
│   └── health          # Health check endpoint
├── src/                # React source code
└── docs/
    ├── PHASE_1.1_COMPLETION_SUMMARY.md
    └── QUICK_START.md  # This file
```

## Next Steps

1. **Start Services**: `docker-compose up -d`
2. **Verify Health**: `curl http://localhost:3000/health`
3. **Open UI**: Navigate to `http://localhost:3000`
4. **Run Tests**: `npm run test:e2e`

---

**Phase**: 1.1 - Frontend Containerization ✅
**Status**: Production Ready
