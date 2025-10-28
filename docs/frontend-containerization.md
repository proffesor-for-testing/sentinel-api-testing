# Frontend Containerization Guide

## Overview

The Sentinel frontend is now fully containerized using Docker with a production-ready nginx setup. This guide covers the containerization architecture, deployment, and maintenance.

## Architecture

### Multi-Stage Build Process

The frontend uses a two-stage Docker build:

1. **Build Stage**: Node.js 18 Alpine image compiles the React application
2. **Production Stage**: Nginx Alpine serves the static files with optimized configuration

### Key Features

- **Optimized Image Size**: Multi-stage build reduces final image size by ~90%
- **Production-Ready**: Nginx with gzip compression, security headers, and caching
- **API Routing**: Reverse proxy configuration for backend services
- **Health Checks**: Built-in health endpoint for monitoring
- **WebSocket Support**: Full support for real-time features

## File Structure

```
sentinel_frontend/
├── Dockerfile.prod          # Multi-stage production build
├── nginx.conf              # Main nginx configuration
├── nginx-default.conf      # Server block and routing rules
├── .dockerignore          # Build optimization
└── .env.docker            # Environment variables
```

## Quick Start

### Build Frontend Container

```bash
# Build the frontend image
docker-compose build frontend

# Or build standalone
docker build -f sentinel_frontend/Dockerfile.prod -t sentinel-frontend:latest .
```

### Start All Services

```bash
# Start entire stack including frontend
docker-compose up -d

# Start only frontend (requires backend services running)
docker-compose up -d frontend
```

### Access Frontend

- **Frontend UI**: http://localhost:3000
- **Health Check**: http://localhost:3000/health
- **API Gateway**: http://localhost:8000

## Environment Variables

The frontend container uses the following environment variables (defined in `.env.docker`):

```bash
# API Configuration
REACT_APP_API_URL=http://localhost:8000        # External API URL
REACT_APP_API_GATEWAY_URL=http://api_gateway:8000  # Internal API URL
REACT_APP_WS_URL=ws://localhost:8000/ws       # WebSocket URL

# Application Configuration
REACT_APP_ENV=production
REACT_APP_VERSION=1.0.0
REACT_APP_NAME=Sentinel

# Feature Flags
REACT_APP_ENABLE_ANALYTICS=false
REACT_APP_ENABLE_DEBUG=false

# Build Configuration
GENERATE_SOURCEMAP=false
NODE_ENV=production
```

### Customizing Environment Variables

You can override environment variables in `docker-compose.yml`:

```yaml
frontend:
  environment:
    - REACT_APP_API_URL=http://your-custom-api.com
    - REACT_APP_ENV=staging
```

## Nginx Configuration

### Reverse Proxy Setup

The nginx configuration includes:

1. **API Routing**: `/api/*` routes to API Gateway (port 8000)
2. **WebSocket Support**: `/ws/*` routes with WebSocket upgrade headers
3. **Static File Serving**: Optimized caching for assets
4. **SPA Support**: React Router support with fallback to index.html

### Security Headers

Automatic security headers:
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: no-referrer-when-downgrade
- Content-Security-Policy

### Performance Optimizations

- **Gzip Compression**: Level 6 compression for text assets
- **Static Asset Caching**: 1-year cache for immutable assets
- **Client Body Buffer**: Optimized buffer sizes
- **Worker Connections**: Auto-scaling based on CPU cores

## Health Checks

The frontend container includes built-in health monitoring:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:80/health"]
  interval: 30s
  timeout: 3s
  retries: 3
  start_period: 5s
```

### Check Health Status

```bash
# Via Docker
docker-compose ps frontend

# Via curl
curl http://localhost:3000/health

# Check container logs
docker-compose logs frontend
```

## Networking

### Docker Network

All services communicate via the `sentinel_network` bridge network:

```yaml
networks:
  sentinel_network:
    driver: bridge
```

### Service Communication

- **Frontend → API Gateway**: Internal DNS resolution via service name
- **External Access**: Port mapping 3000:80
- **Backend Services**: All accessible via internal network

### Port Mapping

| Service | Internal Port | External Port |
|---------|--------------|---------------|
| Frontend | 80 | 3000 |
| API Gateway | 8000 | 8000 |
| Auth Service | 8005 | 8005 |
| Spec Service | 8001 | 8001 |

## Troubleshooting

### Build Failures

```bash
# Clear build cache
docker-compose build --no-cache frontend

# Check build logs
docker-compose build frontend 2>&1 | tee build.log

# Verify node_modules aren't included
docker build -f sentinel_frontend/Dockerfile.prod --progress=plain .
```

### Runtime Issues

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs -f frontend

# Check nginx configuration
docker exec sentinel_frontend nginx -t

# Inspect container
docker exec -it sentinel_frontend sh
```

### API Connection Issues

```bash
# Verify network connectivity
docker exec sentinel_frontend ping api_gateway

# Check API Gateway is running
docker-compose ps api_gateway

# Test API from frontend container
docker exec sentinel_frontend curl http://api_gateway:8000/health
```

### Health Check Failures

```bash
# Manually test health endpoint
curl http://localhost:3000/health

# Check nginx status
docker exec sentinel_frontend ps aux | grep nginx

# Verify nginx logs
docker exec sentinel_frontend cat /var/log/nginx/error.log
```

## Development vs Production

### Development Mode

For local development without Docker:

```bash
cd sentinel_frontend
npm install
npm start  # Runs on port 3000 with hot reload
```

### Production Mode

For production deployment with Docker:

```bash
# Build and start
docker-compose up -d frontend

# Zero-downtime updates
docker-compose up -d --no-deps --build frontend
```

## Performance Tuning

### Build Optimization

```dockerfile
# Adjust Node memory for large builds
NODE_OPTIONS=--max_old_space_size=4096

# Enable parallel builds
docker build --build-arg MAKEFLAGS=-j4
```

### Nginx Tuning

Edit `nginx.conf` for high-traffic scenarios:

```nginx
worker_processes auto;  # Auto-detect CPU cores
worker_connections 2048;  # Increase from 1024
keepalive_timeout 75;  # Adjust based on load
```

### Cache Configuration

Adjust caching in `nginx-default.conf`:

```nginx
# Aggressive caching for assets
location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

## Security Best Practices

1. **Environment Variables**: Never commit secrets to `.env.docker`
2. **Image Scanning**: Run `docker scan sentinel-frontend:latest`
3. **Minimal Base Image**: Alpine Linux reduces attack surface
4. **Non-Root User**: Nginx runs as `nginx` user
5. **Security Headers**: Enforced via nginx configuration

## Monitoring

### Container Metrics

```bash
# CPU and memory usage
docker stats sentinel_frontend

# Resource limits
docker update --cpus="2" --memory="512m" sentinel_frontend
```

### Nginx Metrics

```bash
# Access logs
docker exec sentinel_frontend tail -f /var/log/nginx/access.log

# Error logs
docker exec sentinel_frontend tail -f /var/log/nginx/error.log

# Active connections
docker exec sentinel_frontend cat /var/run/nginx.pid
```

## Backup and Recovery

### Container State

```bash
# Export container
docker export sentinel_frontend > frontend-backup.tar

# Import container
docker import frontend-backup.tar sentinel-frontend:backup
```

### Configuration Backup

```bash
# Backup nginx configs
docker cp sentinel_frontend:/etc/nginx/nginx.conf ./backup/
docker cp sentinel_frontend:/etc/nginx/conf.d/default.conf ./backup/
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Build Frontend
  run: docker-compose build frontend

- name: Test Frontend
  run: docker-compose run frontend npm test

- name: Push Image
  run: |
    docker tag sentinel-frontend:latest ${{ secrets.REGISTRY }}/sentinel-frontend:${{ github.sha }}
    docker push ${{ secrets.REGISTRY }}/sentinel-frontend:${{ github.sha }}
```

## Maintenance

### Updates

```bash
# Update base images
docker-compose pull

# Rebuild with latest base
docker-compose build --pull frontend

# Update dependencies
docker-compose run frontend npm update
```

### Cleanup

```bash
# Remove unused images
docker image prune -a

# Clean build cache
docker builder prune

# Remove stopped containers
docker container prune
```

## Support

For issues or questions:
- Check logs: `docker-compose logs frontend`
- Verify health: `curl http://localhost:3000/health`
- Review nginx config: `docker exec sentinel_frontend nginx -t`
- Inspect network: `docker network inspect sentinel_network`
