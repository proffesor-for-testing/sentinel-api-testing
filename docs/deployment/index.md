# Deployment Guide - Sentinel API Testing Platform

This guide provides comprehensive instructions for deploying Sentinel in various environments, from local development to production-scale deployments.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Deployment Options](#deployment-options)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Cloud Deployments](#cloud-deployments)
6. [Production Configuration](#production-configuration)
7. [Scaling Strategies](#scaling-strategies)
8. [Monitoring & Observability](#monitoring--observability)
9. [Backup & Recovery](#backup--recovery)
10. [Security Hardening](#security-hardening)

## System Requirements

### Minimum Requirements (Development)

| Component | Requirement |
|-----------|-------------|
| **CPU** | 4 cores |
| **RAM** | 8 GB |
| **Storage** | 20 GB SSD |
| **OS** | Linux, macOS, Windows (with WSL2) |
| **Docker** | 20.10+ |
| **Docker Compose** | 2.0+ |

### Recommended Requirements (Production)

| Component | Requirement |
|-----------|-------------|
| **CPU** | 16+ cores |
| **RAM** | 32+ GB |
| **Storage** | 100+ GB SSD |
| **OS** | Ubuntu 22.04 LTS, RHEL 8+ |
| **Kubernetes** | 1.25+ |
| **PostgreSQL** | 14+ |
| **RabbitMQ** | 3.11+ |

## Deployment Options

### 1. Local Development
- Docker Compose
- Single machine
- All services on one host
- Suitable for development and testing

### 2. Small Production
- Docker Swarm or single Kubernetes cluster
- 3-5 nodes
- Basic high availability
- Suitable for small teams

### 3. Enterprise Production
- Multi-region Kubernetes
- 10+ nodes per region
- Full high availability
- Auto-scaling enabled
- Suitable for large organizations

## Docker Deployment

### Quick Start with Docker Compose

1. **Clone the repository:**
```bash
git clone https://github.com/proffesor-for-testing/sentinel-api-testing.git
cd "Agents for API testing"
```

2. **Configure environment:**
```bash
# Copy environment template
cp sentinel_backend/.env.docker sentinel_backend/.env

# Edit configuration
nano sentinel_backend/.env
```

3. **Start services:**
```bash
# Build and start all services
docker-compose up -d --build

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: sentinel
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinel"]
      interval: 10s
      timeout: 5s
      retries: 5

  rabbitmq:
    image: rabbitmq:3.11-management
    environment:
      RABBITMQ_DEFAULT_USER: sentinel
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD}
    ports:
      - "5672:5672"
      - "15672:15672"
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  api-gateway:
    build: ./api_gateway
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://sentinel:${DB_PASSWORD}@postgres:5432/sentinel
      RABBITMQ_URL: amqp://sentinel:${RABBITMQ_PASSWORD}@rabbitmq:5672/
      JWT_SECRET_KEY: ${JWT_SECRET_KEY}
    depends_on:
      postgres:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    restart: unless-stopped

  # Additional services...

volumes:
  postgres_data:
  rabbitmq_data:

networks:
  default:
    name: sentinel-network
```

### Production Docker Deployment

For production Docker deployments, use Docker Swarm:

```bash
# Initialize Swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.prod.yml sentinel

# Scale services
docker service scale sentinel_api-gateway=3

# Update service
docker service update --image sentinel/api-gateway:v2 sentinel_api-gateway
```

## Kubernetes Deployment

### Prerequisites

1. **Install required tools:**
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

2. **Configure cluster access:**
```bash
# For AWS EKS
aws eks update-kubeconfig --region us-east-1 --name sentinel-cluster

# For GKE
gcloud container clusters get-credentials sentinel-cluster --zone us-central1-a

# For Azure AKS
az aks get-credentials --resource-group sentinel-rg --name sentinel-cluster
```

### Kubernetes Manifests

#### Namespace and ConfigMap

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: sentinel

---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sentinel-config
  namespace: sentinel
data:
  DATABASE_HOST: "postgres-service"
  RABBITMQ_HOST: "rabbitmq-service"
  JAEGER_AGENT_HOST: "jaeger-agent"
  PROMETHEUS_ENABLED: "true"
```

#### Database Deployment

```yaml
# postgres-deployment.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: sentinel
spec:
  serviceName: postgres-service
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:14-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: sentinel
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: username
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1"
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
```

#### API Gateway Deployment

```yaml
# api-gateway-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: sentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api-gateway
        image: sentinel/api-gateway:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: database-secret
              key: url
        - name: JWT_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: secret
        envFrom:
        - configMapRef:
            name: sentinel-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
```

#### Service and Ingress

```yaml
# services.yaml
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-service
  namespace: sentinel
spec:
  selector:
    app: api-gateway
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: sentinel-ingress
  namespace: sentinel
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.sentinel.example.com
    secretName: sentinel-tls
  rules:
  - host: api.sentinel.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway-service
            port:
              number: 80
```

### Helm Chart Deployment

```bash
# Add Helm repository
helm repo add sentinel https://charts.sentinel.example.com
helm repo update

# Install with custom values
helm install sentinel sentinel/sentinel \
  --namespace sentinel \
  --create-namespace \
  --values values.yaml

# Upgrade deployment
helm upgrade sentinel sentinel/sentinel \
  --namespace sentinel \
  --values values.yaml
```

#### Helm Values Configuration

```yaml
# values.yaml
global:
  environment: production
  domain: sentinel.example.com

postgresql:
  enabled: true
  auth:
    database: sentinel
    username: sentinel
    existingSecret: postgres-secret
  persistence:
    size: 50Gi
    storageClass: fast-ssd

rabbitmq:
  enabled: true
  auth:
    username: sentinel
    existingPasswordSecret: rabbitmq-secret
  persistence:
    size: 10Gi

api-gateway:
  replicaCount: 3
  image:
    repository: sentinel/api-gateway
    tag: v1.0.0
  resources:
    requests:
      memory: 256Mi
      cpu: 250m
    limits:
      memory: 512Mi
      cpu: 500m
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: api.sentinel.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: sentinel-tls
      hosts:
        - api.sentinel.example.com
```

## Cloud Deployments

### AWS Deployment

#### Using AWS EKS

```bash
# Create EKS cluster
eksctl create cluster \
  --name sentinel-cluster \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type t3.large \
  --nodes 3 \
  --nodes-min 3 \
  --nodes-max 10 \
  --managed

# Install AWS Load Balancer Controller
kubectl apply -k "github.com/aws/eks-charts/stable/aws-load-balancer-controller/crds"
helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=sentinel-cluster

# Deploy Sentinel
kubectl apply -f k8s/
```

#### Using AWS ECS

```bash
# Create ECS cluster
aws ecs create-cluster --cluster-name sentinel-cluster

# Register task definitions
aws ecs register-task-definition --cli-input-json file://task-definitions/api-gateway.json

# Create services
aws ecs create-service \
  --cluster sentinel-cluster \
  --service-name api-gateway \
  --task-definition api-gateway:1 \
  --desired-count 3 \
  --launch-type FARGATE
```

### Google Cloud Platform

```bash
# Create GKE cluster
gcloud container clusters create sentinel-cluster \
  --zone us-central1-a \
  --num-nodes 3 \
  --machine-type n2-standard-4 \
  --enable-autoscaling \
  --min-nodes 3 \
  --max-nodes 10

# Get credentials
gcloud container clusters get-credentials sentinel-cluster --zone us-central1-a

# Deploy
kubectl apply -f k8s/
```

### Azure Deployment

```bash
# Create resource group
az group create --name sentinel-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group sentinel-rg \
  --name sentinel-cluster \
  --node-count 3 \
  --enable-addons monitoring \
  --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group sentinel-rg --name sentinel-cluster

# Deploy
kubectl apply -f k8s/
```

## Production Configuration

### Environment Variables

```bash
# Production environment variables
SENTINEL_ENVIRONMENT=production
SENTINEL_DEBUG=false
SENTINEL_LOG_LEVEL=INFO

# Database
SENTINEL_DB_URL=postgresql://user:pass@db-host:5432/sentinel
SENTINEL_DB_POOL_SIZE=20
SENTINEL_DB_MAX_OVERFLOW=40

# Security
SENTINEL_JWT_SECRET_KEY=<strong-random-key>
SENTINEL_JWT_EXPIRATION_HOURS=24
SENTINEL_CORS_ORIGINS=https://app.sentinel.example.com

# Services
SENTINEL_SERVICE_TIMEOUT=30
SENTINEL_MAX_RETRIES=3

# Monitoring
SENTINEL_METRICS_ENABLED=true
SENTINEL_TRACING_ENABLED=true
SENTINEL_JAEGER_AGENT_HOST=jaeger-agent
```

### Database Migrations

```bash
# Run migrations before deployment
alembic upgrade head

# In Kubernetes, use init container
initContainers:
- name: migrate
  image: sentinel/api-gateway:latest
  command: ["alembic", "upgrade", "head"]
  env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: database-secret
        key: url
```

### SSL/TLS Configuration

```yaml
# cert-manager for automatic SSL
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@sentinel.example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

## Scaling Strategies

### Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
  namespace: sentinel
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Vertical Pod Autoscaling

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: api-gateway-vpa
  namespace: sentinel
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  updatePolicy:
    updateMode: "Auto"
```

### Database Scaling

```bash
# PostgreSQL read replicas
helm upgrade postgres bitnami/postgresql \
  --set replication.enabled=true \
  --set replication.slaveReplicas=2 \
  --set replication.synchronousCommit=true
```

## Monitoring & Observability

### Prometheus Setup

```bash
# Install Prometheus
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace

# Configure service monitors
kubectl apply -f monitoring/service-monitors/
```

### Grafana Dashboards

```bash
# Install Grafana
helm install grafana grafana/grafana \
  --namespace monitoring \
  --set persistence.enabled=true \
  --set adminPassword=admin

# Import dashboards
kubectl apply -f monitoring/dashboards/
```

### Jaeger Tracing

```bash
# Install Jaeger
kubectl create namespace observability
kubectl apply -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.41.0/jaeger-operator.yaml -n observability

# Deploy Jaeger instance
kubectl apply -f monitoring/jaeger.yaml
```

## Backup & Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="sentinel_backup_${TIMESTAMP}.sql"

# Create backup
pg_dump -h $DB_HOST -U $DB_USER -d sentinel > $BACKUP_FILE

# Upload to S3
aws s3 cp $BACKUP_FILE s3://sentinel-backups/

# Clean old backups (keep 30 days)
find /backups -name "*.sql" -mtime +30 -delete
```

### Automated Backups with CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: sentinel
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: postgres-backup
            image: postgres:14-alpine
            command:
            - /bin/sh
            - -c
            - |
              pg_dump -h postgres-service -U sentinel sentinel > /backup/backup.sql
              aws s3 cp /backup/backup.sql s3://sentinel-backups/$(date +%Y%m%d).sql
          restartPolicy: OnFailure
```

### Disaster Recovery

```bash
# Restore from backup
psql -h $DB_HOST -U $DB_USER -d sentinel < backup.sql

# Point-in-time recovery
pg_restore -h $DB_HOST -U $DB_USER -d sentinel --clean --no-owner backup.dump
```

## Security Hardening

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-gateway-netpol
  namespace: sentinel
spec:
  podSelector:
    matchLabels:
      app: api-gateway
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

### Pod Security Policies

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: sentinel-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

### Secrets Management

```bash
# Use external secrets operator
helm install external-secrets \
  external-secrets/external-secrets \
  -n external-secrets-system \
  --create-namespace

# Configure AWS Secrets Manager
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets
  namespace: sentinel
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
EOF
```

## Health Checks

### Deployment Validation

```bash
#!/bin/bash
# validate-deployment.sh

echo "Checking pod status..."
kubectl get pods -n sentinel

echo "Checking service endpoints..."
kubectl get endpoints -n sentinel

echo "Testing API Gateway..."
curl -f http://api.sentinel.example.com/health || exit 1

echo "Testing database connection..."
kubectl exec -n sentinel postgres-0 -- pg_isready

echo "Deployment validation successful!"
```

## Troubleshooting Deployment

### Common Issues

1. **Pods not starting**
```bash
# Check pod events
kubectl describe pod <pod-name> -n sentinel

# Check logs
kubectl logs <pod-name> -n sentinel
```

2. **Database connection issues**
```bash
# Test connection
kubectl run -it --rm debug --image=postgres:14 --restart=Never -- psql -h postgres-service -U sentinel
```

3. **Service discovery problems**
```bash
# Check DNS
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup api-gateway-service
```

## Next Steps

- Configure [monitoring and alerting](./monitoring.md)
- Set up [CI/CD pipelines](../user-guide/cicd-integration.md)
- Review [security best practices](./security.md)
- Plan [disaster recovery](./disaster-recovery.md)

---

← [Back to Documentation](../index.md) | [Next: Troubleshooting Guide](../troubleshooting/index.md) →