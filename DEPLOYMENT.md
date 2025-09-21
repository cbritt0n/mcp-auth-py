# Quick Deployment Guide

> 📖 **For comprehensive production deployment with security, monitoring, and advanced features, see [docs/production_deployment.md](docs/production_deployment.md)**

This guide provides quick deployment options for getting MCP Auth running in different environments.

## 🚀 Quick Start Options

### Option 1: Docker (Recommended)

```bash
# 1. Clone and setup
git clone https://github.com/cbritt0n/mcp-auth-py.git
cd mcp-auth-py

# 2. Configure your auth provider
cp .env.example .env
# Edit .env with your settings

# 3. Build and run with Docker
docker build -t mcp-auth .
docker run -p 8000:8000 --env-file .env mcp-auth
```

### Option 2: Docker Compose (Multi-provider)

```bash
# Run multiple auth providers simultaneously
docker-compose up -d

# Access different providers:
# Local JWT:    http://localhost:8000
# AWS Cognito:  http://localhost:8001
# Google OAuth: http://localhost:8002
```

### Option 3: Kubernetes

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Get service URL
kubectl get service mcp-auth-service
```

## 🔧 Environment Configuration

### Local Development
```bash
# Clone and install with all providers
git clone https://github.com/cbritt0n/mcp-auth-py.git
cd mcp-auth-py
pip install -e .[all]

# Quick setup
python scripts/setup.py

# Run development server
uvicorn examples.complete_app:app --reload
```

### Production Environment Variables

```bash
# Core settings
AUTH_PROVIDER=google  # local|google|aws|azure
JWT_SECRET=your-256-bit-secret
JWT_ALGORITHM=HS256

# Provider-specific (JSON format)
PROVIDER_CONFIG='{"audience": "your-client-id"}'

# Performance optimization
REDIS_JWKS=true
REDIS_URL=redis://redis-cluster:6379/0

# Optional features
USE_REDIS_RATELIMIT=true
CASBIN_POLICY_PATH=/app/policies/rbac.conf
```

## ☁️ Cloud Provider Setup

### AWS Cognito Setup
1. Create Cognito User Pool
2. Create App Client (note the client ID)
3. Configure hosted UI (optional)
4. Set environment variables:

```bash
AUTH_PROVIDER=aws
PROVIDER_CONFIG='{"cognito_region":"us-west-2","cognito_user_pool_id":"us-west-2_XXXXXXXXX","audience":"your-client-id"}'
```

### Google OAuth2 Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create OAuth2 Client ID
3. Add authorized redirect URIs
4. Set environment variables:

```bash
AUTH_PROVIDER=google
PROVIDER_CONFIG='{"audience":"your-client-id.apps.googleusercontent.com"}'
```

### Azure AD Setup
1. Register application in Azure Portal
2. Note Tenant ID and Application ID
3. Configure API permissions
4. Set environment variables:

```bash
AUTH_PROVIDER=azure
PROVIDER_CONFIG='{"tenant":"your-tenant-id","audience":"your-app-client-id"}'
```

## 🏗️ Production Architecture

### Recommended Stack
```
[Load Balancer] → [Nginx] → [App Instances] → [Redis Cluster]
                                           → [Database]
```

### High Availability Setup
- Multiple app instances behind load balancer
- Redis cluster for JWKS caching
- Health checks on `/health` endpoint
- Horizontal pod autoscaling (Kubernetes)

### Security Checklist
- ✅ Use strong JWT secrets (256-bit minimum)
- ✅ Enable Redis JWKS caching for performance
- ✅ Use HTTPS in production (TLS termination at load balancer)
- ✅ Implement proper CORS policies
- ✅ Monitor auth failures and rate limit
- ✅ Rotate JWT secrets regularly
- ✅ Use dedicated service accounts for cloud providers

### Monitoring & Observability
- Health check endpoint: `GET /health`
- Metrics: Authentication success/failure rates
- Logging: Failed auth attempts, provider errors
- Alerting: JWKS fetch failures, Redis connectivity

## 📊 Performance Tuning

### Redis Configuration
```bash
# Optimal Redis settings for JWKS caching
maxmemory 256mb
maxmemory-policy allkeys-lru
save ""  # Disable persistence for cache-only usage
```

### Application Scaling
```yaml
# Kubernetes horizontal pod autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mcp-auth-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mcp-auth
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## 🔍 Troubleshooting

### Common Issues

**Authentication Failures**
```bash
# Check provider configuration
curl -H "Authorization: Bearer invalid-token" http://localhost:8000/me

# Verify JWKS endpoint accessibility
curl https://your-provider.com/.well-known/jwks.json
```

**Redis Connection Issues**
```bash
# Test Redis connectivity
redis-cli -h redis-host ping

# Check JWKS cache status
redis-cli -h redis-host keys "jwks:*"
```

**Performance Issues**
```bash
# Monitor auth middleware latency
# Enable DEBUG logging to see JWKS fetch times
export PYTHONPATH=debug
```

### Health Checks
```bash
# Application health
curl http://localhost:8000/health

# Full authentication test
curl -H "Authorization: Bearer $(python scripts/generate_token.py)" \
     http://localhost:8000/me
```
