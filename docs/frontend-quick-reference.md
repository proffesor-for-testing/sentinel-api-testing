# Frontend Quick Reference

## Quick Commands

### Start/Stop Frontend

```bash
# Start frontend with all services
docker-compose up -d frontend

# Stop frontend
docker-compose stop frontend

# Restart frontend
docker-compose restart frontend

# View logs
docker-compose logs -f frontend
```

### Build Frontend

```bash
# Build frontend image
docker-compose build frontend

# Build without cache
docker-compose build --no-cache frontend

# Build and start
docker-compose up -d --build frontend
```

### Health Checks

```bash
# Check container status
docker-compose ps frontend

# Test health endpoint
curl http://localhost:3000/health

# Check nginx configuration
docker exec sentinel_frontend nginx -t
```

### Debugging

```bash
# Enter container shell
docker exec -it sentinel_frontend sh

# View nginx logs
docker exec sentinel_frontend tail -f /var/log/nginx/access.log
docker exec sentinel_frontend tail -f /var/log/nginx/error.log

# Test API connectivity
docker exec sentinel_frontend curl http://api_gateway:8000/health
```

## Environment Variables

Key environment variables for the frontend:

```bash
REACT_APP_API_URL=http://localhost:8000          # External API URL
REACT_APP_API_GATEWAY_URL=http://api_gateway:8000  # Internal API URL
REACT_APP_WS_URL=ws://localhost:8000/ws         # WebSocket URL
REACT_APP_ENV=production
```

Edit in `/workspaces/api-testing-agents/sentinel_frontend/.env.docker` or override in `docker-compose.yml`.

## Ports

- **Frontend**: http://localhost:3000
- **API Gateway**: http://localhost:8000
- **Health Check**: http://localhost:3000/health

## Files

- `sentinel_frontend/Dockerfile.prod` - Multi-stage production build
- `sentinel_frontend/nginx.conf` - Main nginx configuration
- `sentinel_frontend/nginx-default.conf` - Server routing configuration
- `sentinel_frontend/.dockerignore` - Build optimization
- `sentinel_frontend/.env.docker` - Environment variables

## Common Issues

### Build Failures
```bash
# Clear cache and rebuild
docker-compose build --no-cache frontend
docker system prune -f
```

### Connection Issues
```bash
# Verify network
docker network inspect sentinel_network

# Check API Gateway
docker-compose ps api_gateway
curl http://localhost:8000/health
```

### Performance Issues
```bash
# Check resource usage
docker stats sentinel_frontend

# Increase resources
docker update --cpus="2" --memory="512m" sentinel_frontend
```

## Production Deployment

```bash
# Build optimized image
docker-compose -f docker-compose.prod.yml build frontend

# Deploy with zero downtime
docker-compose up -d --no-deps --build frontend

# Verify deployment
curl -f http://localhost:3000/health || echo "Deployment failed"
```

## Development Mode

For local development with hot reload:

```bash
cd sentinel_frontend
npm install
npm start  # Runs on port 3000
```

## Documentation

Full documentation: `/workspaces/api-testing-agents/docs/frontend-containerization.md`
