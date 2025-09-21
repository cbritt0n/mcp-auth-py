# Production Deployment Guide

This guide provides comprehensive instructions for deploying MCP Auth in production environments with full security features enabled.

## Security Features Overview

MCP Auth includes enterprise-grade security features for production deployment:

### 🔐 Authentication & Authorization
- **JWT Token Security**: Industry-standard JWT tokens with configurable expiration, audience validation, and secure secret management
- **Multi-Provider Support**: AWS Cognito, Azure AD, Google OAuth, OIDC, local authentication, and Redis JWKS
- **Role-Based Access Control (RBAC)**: Comprehensive permission system with role inheritance and resource-based access control
- **Admin Authorization**: Dedicated admin endpoints with enhanced security validation

### 🛡️ Security Hardening
- **Rate Limiting**: Configurable per-IP request throttling with adaptive limits
- **Brute Force Protection**: Login attempt tracking with automatic lockout
- **Security Headers**: HTTPS enforcement, CSP, HSTS, and comprehensive security headers
- **Request Validation**: Input sanitization and malicious payload detection
- **Token Validation**: Comprehensive JWT validation with expiration, issuer, and audience checking

### 📊 Monitoring & Compliance
- **Audit Logging**: Complete audit trail with security event categorization
- **Real-time Monitoring**: WebSocket-based security event notifications
- **Security Metrics**: Request pattern analysis and anomaly detection
- **Compliance Reporting**: Access patterns and security compliance metrics

### ⚡ Performance & Scalability
- **Redis Caching**: Distributed caching with intelligent invalidation
- **Connection Pooling**: Optimized database and Redis connections
- **Async Operations**: Full async/await support for high concurrency
- **Resource Monitoring**: Performance metrics and health checks

## Quick Production Setup

### 1. Environment Configuration

Create a production environment file `.env.prod`:

```bash
# JWT Configuration - CRITICAL FOR SECURITY
MCP_AUTH_JWT_SECRET=prod-your-super-secure-256-bit-jwt-secret-key-here-minimum-32-characters
MCP_AUTH_JWT_ALGORITHM=HS256
MCP_AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
MCP_AUTH_JWT_AUDIENCE=your-api-audience
MCP_AUTH_JWT_ISSUER=your-organization

# Security Settings
MCP_AUTH_REQUIRE_HTTPS=true
MCP_AUTH_ENABLE_SECURITY_HEADERS=true
MCP_AUTH_ENABLE_RATE_LIMITING=true
MCP_AUTH_MAX_LOGIN_ATTEMPTS=5
MCP_AUTH_LOCKOUT_DURATION_MINUTES=15
MCP_AUTH_RATE_LIMIT_REQUESTS_PER_MINUTE=100

# Redis Configuration (for caching and session management)
MCP_AUTH_REDIS_URL=redis://your-redis-server:6379/0
MCP_AUTH_REDIS_PASSWORD=your-redis-password
MCP_AUTH_REDIS_SSL=true
MCP_AUTH_REDIS_MAX_CONNECTIONS=20

# Database Configuration
MCP_AUTH_DATABASE_URL=postgresql://user:password@host:port/dbname
MCP_AUTH_DATABASE_POOL_SIZE=20
MCP_AUTH_DATABASE_MAX_OVERFLOW=30

# Audit Configuration
MCP_AUTH_ENABLE_AUDIT=true
MCP_AUTH_AUDIT_LOG_SECURITY_EVENTS=true
MCP_AUTH_AUDIT_RETENTION_DAYS=90
MCP_AUTH_AUDIT_EXPORT_FORMAT=json

# Real-time Notifications
MCP_AUTH_ENABLE_REALTIME=true
MCP_AUTH_REALTIME_ADMIN_ONLY=true

# Provider-specific configurations
# AWS Cognito
AWS_REGION=us-east-1
AWS_USER_POOL_ID=your-user-pool-id
AWS_CLIENT_ID=your-client-id

# Azure AD
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
```

### 2. Docker Production Deployment

Use the provided production Dockerfile:

```bash
# Build production image
docker build -t mcp-auth-prod .

# Run with production environment
docker run -d \
  --name mcp-auth-production \
  --env-file .env.prod \
  -p 80:8000 \
  --restart unless-stopped \
  mcp-auth-prod
```

### 3. Docker Compose Production Stack

```bash
# Start full production stack
docker-compose -f docker-compose.yml up -d

# Check service health
docker-compose ps
docker-compose logs mcp-auth
```

### 4. Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -l app=mcp-auth
kubectl get services mcp-auth
```

## Security Configuration Guide

### JWT Token Security

**Critical**: Use a strong JWT secret in production:

```python
# Generate a secure JWT secret
import secrets
jwt_secret = f"prod-{secrets.token_urlsafe(32)}"
```

**Token Configuration**:
```bash
# Minimum recommended settings
MCP_AUTH_JWT_SECRET=prod-your-256-bit-secret-here-at-least-32-characters
MCP_AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60    # 1 hour
MCP_AUTH_JWT_REFRESH_TOKEN_EXPIRE_HOURS=168    # 7 days
MCP_AUTH_JWT_AUDIENCE=api.yourcompany.com
MCP_AUTH_JWT_ISSUER=auth.yourcompany.com
```

### Rate Limiting Configuration

Configure rate limiting based on your expected traffic:

```bash
# Conservative settings for high-security environments
MCP_AUTH_RATE_LIMIT_REQUESTS_PER_MINUTE=60
MCP_AUTH_RATE_LIMIT_BURST_SIZE=20
MCP_AUTH_MAX_LOGIN_ATTEMPTS=3
MCP_AUTH_LOCKOUT_DURATION_MINUTES=30

# Higher throughput settings for API-heavy applications
MCP_AUTH_RATE_LIMIT_REQUESTS_PER_MINUTE=300
MCP_AUTH_RATE_LIMIT_BURST_SIZE=100
MCP_AUTH_MAX_LOGIN_ATTEMPTS=5
MCP_AUTH_LOCKOUT_DURATION_MINUTES=15
```

### HTTPS and Security Headers

**Always enforce HTTPS in production**:

```bash
MCP_AUTH_REQUIRE_HTTPS=true
MCP_AUTH_ENABLE_SECURITY_HEADERS=true
MCP_AUTH_HSTS_MAX_AGE=31536000  # 1 year
MCP_AUTH_CSP_POLICY="default-src 'self'; script-src 'self' 'unsafe-inline'"
```

## Provider Configuration

### AWS Cognito Setup

```bash
# Environment variables
AWS_REGION=us-east-1
AWS_USER_POOL_ID=us-east-1_xxxxxxxxx
AWS_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# IAM Policy (minimum required permissions)
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:GetUser",
                "cognito-idp:AdminGetUser",
                "cognito-idp:ListUsers"
            ],
            "Resource": "arn:aws:cognito-idp:us-east-1:account:userpool/us-east-1_xxxxxxxxx"
        }
    ]
}
```

### Azure AD Setup

```bash
# Environment variables
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your-client-secret

# Azure AD App Registration requirements:
# - API permissions: User.Read, Directory.Read.All
# - Authentication: Single-page application + Web
# - Redirect URIs: https://yourdomain.com/auth/callback
```

### Google OAuth Setup

```bash
# Environment variables
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret

# Google Cloud Console setup:
# - Enable Google+ API
# - Configure OAuth consent screen
# - Add authorized domains: yourdomain.com
# - Add redirect URIs: https://yourdomain.com/auth/callback
```

## Database Configuration

### PostgreSQL Setup (Recommended)

```bash
# Production PostgreSQL configuration
MCP_AUTH_DATABASE_URL=postgresql://mcp_user:secure_password@postgres:5432/mcp_auth_prod
MCP_AUTH_DATABASE_POOL_SIZE=20
MCP_AUTH_DATABASE_MAX_OVERFLOW=30
MCP_AUTH_DATABASE_ECHO=false  # Disable SQL logging in production

# PostgreSQL server configuration (postgresql.conf)
max_connections = 200
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB
```

### Database Migration

```bash
# Run database migrations
python -m mcp_auth.scripts.setup --database-init

# Verify installation
python -m mcp_auth.scripts.validate_install
```

## Redis Configuration

### Redis for Caching and Sessions

```bash
# Redis configuration
MCP_AUTH_REDIS_URL=redis://redis-server:6379/0
MCP_AUTH_REDIS_PASSWORD=your-redis-password
MCP_AUTH_REDIS_SSL=true
MCP_AUTH_REDIS_MAX_CONNECTIONS=20
MCP_AUTH_REDIS_SOCKET_TIMEOUT=30
MCP_AUTH_REDIS_SOCKET_CONNECT_TIMEOUT=10

# Cache settings
MCP_AUTH_CACHE_DEFAULT_TTL=3600        # 1 hour
MCP_AUTH_CACHE_RBAC_TTL=1800          # 30 minutes
MCP_AUTH_CACHE_PRINCIPAL_TTL=900       # 15 minutes
```

### Redis Server Configuration

```bash
# redis.conf production settings
maxmemory 512mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
requirepass your-redis-password
tcp-keepalive 300
timeout 300
```

## Monitoring and Observability

### Health Checks

Configure health check endpoints:

```python
# Application health check
GET /health
{
    "status": "healthy",
    "components": {
        "cache": "healthy",
        "rbac": "healthy",
        "database": "healthy"
    }
}

# Security-specific health check (admin only)
GET /health/security
{
    "security": {
        "rate_limiting_enabled": true,
        "https_enforced": true,
        "jwt_secret_strength": "strong",
        "failed_attempts_last_hour": 3
    }
}
```

### Audit Logging

Configure comprehensive audit logging:

```bash
# Audit configuration
MCP_AUTH_ENABLE_AUDIT=true
MCP_AUTH_AUDIT_LOG_SECURITY_EVENTS=true
MCP_AUTH_AUDIT_RETENTION_DAYS=90
MCP_AUTH_AUDIT_EXPORT_FORMAT=json

# Log levels for different events
MCP_AUTH_AUDIT_LEVEL_LOGIN=INFO
MCP_AUTH_AUDIT_LEVEL_PERMISSION_DENIED=WARNING
MCP_AUTH_AUDIT_LEVEL_ADMIN_ACTION=INFO
MCP_AUTH_AUDIT_LEVEL_SECURITY_VIOLATION=ERROR
```

### Real-time Monitoring

Enable real-time security monitoring:

```bash
# Real-time configuration
MCP_AUTH_ENABLE_REALTIME=true
MCP_AUTH_REALTIME_ADMIN_ONLY=true
MCP_AUTH_REALTIME_SECURITY_EVENTS=true
MCP_AUTH_REALTIME_MAX_CONNECTIONS=100
```

## Performance Tuning

### Application Server

```bash
# Uvicorn production settings
uvicorn mcp_auth.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --access-log \
  --no-server-header \
  --no-date-header \
  --log-level info
```

### Load Balancer Configuration

Example Nginx configuration:

```nginx
upstream mcp_auth_backend {
    server 127.0.0.1:8000;
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
    server 127.0.0.1:8003;

    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    # SSL configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://mcp_auth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # WebSocket support for real-time features
    location /realtime/ {
        proxy_pass http://mcp_auth_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Best Practices

### 1. Network Security
- Use HTTPS everywhere (TLS 1.2+)
- Configure proper firewall rules
- Use VPN or private networks for internal communication
- Implement network segmentation

### 2. Authentication Security
- Use strong JWT secrets (256+ bits)
- Implement proper token rotation
- Configure appropriate token expiration times
- Enable multi-factor authentication where possible

### 3. Access Control
- Follow principle of least privilege
- Regularly audit user permissions
- Implement role-based access control
- Monitor admin actions closely

### 4. Data Protection
- Encrypt sensitive data at rest and in transit
- Implement proper password policies
- Use secure password hashing (bcrypt/argon2)
- Regular security audits and penetration testing

### 5. Monitoring and Incident Response
- Implement comprehensive logging
- Set up alerting for security events
- Regular security monitoring and analysis
- Have incident response procedures in place

## Troubleshooting

### Common Issues

**JWT Token Issues**:
```bash
# Check JWT secret configuration
python -c "from mcp_auth.settings import Settings; print(f'JWT secret length: {len(Settings().jwt_secret)}')"

# Validate JWT token
python -m mcp_auth.scripts.validate_token YOUR_TOKEN_HERE
```

**Redis Connection Issues**:
```bash
# Test Redis connectivity
python -c "
from mcp_auth.caching import get_cache
import asyncio
async def test():
    cache = get_cache()
    await cache.ping()
    print('Redis connection OK')
asyncio.run(test())
"
```

**Database Connection Issues**:
```bash
# Test database connection
python -c "
from mcp_auth.rbac.engine import get_rbac_engine
import asyncio
async def test():
    engine = get_rbac_engine()
    print('Database connection OK')
asyncio.run(test())
"
```

**Rate Limiting Issues**:
```bash
# Check current rate limits
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://yourapi.com/admin/stats | jq '.security.rate_limiting'
```

### Performance Issues

**High Memory Usage**:
- Check Redis memory usage
- Review cache TTL settings
- Monitor connection pools

**Slow Response Times**:
- Enable query logging temporarily
- Check database connection pool settings
- Review Redis performance metrics
- Monitor rate limiting delays

**High CPU Usage**:
- Check JWT validation performance
- Review async/await usage
- Monitor request processing times

### Support and Updates

For production support:
- Monitor the project repository for security updates
- Subscribe to security advisories
- Regular dependency updates
- Security scanning and vulnerability assessments

Remember to always test configuration changes in a staging environment before applying to production.
