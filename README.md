# mcp-auth-py — pluggable auth for ASGI apps (FastAPI-friendly)

[![CI](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml/badge.svg)](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml)

**TL;DR:** Pluggable auth for FastAPI/ASGI — swap providers (local/google/aws/azure), async-capable, with JWKS caching (optional Redis).

🔒 mcp-auth-py is a small, framework-friendly library that adds pluggable authentication providers
for FastAPI (or other ASGI apps). It provides a lightweight middleware and a small provider
registry so you can swap in authentication backends for Local (JWT), Google, AWS (Cognito),
and Azure (AAD) without changing application code.

## Why use mcp-auth-py?
- Plug-and-play providers: swap `local`, `google`, `aws` (Cognito), `azure`, `github`, or `discord` without changing app code.
- Cloud-aware: supports Google ID tokens, AWS Cognito OIDC, Azure AD OIDC, GitHub OAuth2, and Discord OAuth2 out of the box.
- Enterprise ready: Multi-tenant architecture, compliance monitoring (GDPR, HIPAA, SOX), and performance optimization.
- Async-friendly: middleware and providers can be async; blocking SDKs are offloaded to threadpools.
- JWKS caching: per-process TTL cache plus an optional Redis-backed JWKS adapter for multi-process sharing.
- Minimal core deps: keep your app light; provider SDKs are optional extras you install as needed.
- Testable & CI-ready: unit tests and CI pre-commit hooks are included to keep quality high.

What this library does
- Adds a small middleware and provider registry for ASGI apps (FastAPI example provided).
- Provides a canonical `Principal` model and an `AuthResult` contract so providers return a uniform shape.
- Makes it easy to add new providers: implement the `Provider` interface and register it.
- **Production Security**: Comprehensive JWT validation, rate limiting, brute force protection, security headers
- **Enterprise RBAC**: Role-based access control with hierarchical permissions and resource-specific authorization
- **Real-time Notifications**: WebSocket-based live updates for security events and permission changes
- **High-Performance Caching**: Redis-based distributed caching with intelligent invalidation patterns
- **Audit & Compliance**: Complete audit trail with security analytics and compliance reporting

## Features
- **🔐 Multi-Provider Authentication**: Local JWT, Google OAuth2, AWS Cognito, Azure AD, GitHub OAuth2, Discord OAuth2
- **🏢 Enterprise Multi-Tenancy**: Database/schema isolation, hierarchical organizations, conditional access policies
- **🛡️ Production Security**: Enterprise-grade JWT validation, rate limiting, brute force protection, security headers
- **📋 Compliance Monitoring**: Automated GDPR, HIPAA, SOX compliance with real-time assessments and reporting
- **⚡ High Performance**: Redis-based distributed caching with circuit breakers and performance monitoring
- **🚀 RBAC System**: Complete role-based access control with hierarchical permissions and resource-specific authorization
- **📡 Real-time Updates**: WebSocket-based live notifications for security events and permission changes
- **📊 Audit & Compliance**: Comprehensive audit trail with security analytics and compliance reporting
- **🔧 Developer Friendly**: Async-capable flows, FastAPI decorators, comprehensive examples and documentation
- **☁️ Cloud Native**: Kubernetes deployments, Docker support, production-ready configurations

## Installation

### 🚀 **Quick Setup**
```bash
# Clone and install locally
git clone https://github.com/cbritt0n/mcp-auth-py.git
cd mcp-auth-py
pip install -e .

# Run example application
uvicorn examples.server:app --reload

# Visit http://localhost:8000/docs to see the API
```

### 📦 **Installation Options**
```bash
# Clone the repository
git clone https://github.com/cbritt0n/mcp-auth-py.git
cd mcp-auth-py

# Basic installation (local JWT only)
pip install -e .

# With specific cloud providers
pip install -e .[google]        # Google OAuth2
pip install -e .[aws]           # AWS Cognito
pip install -e .[azure]         # Azure AD
pip install -e .[github]        # GitHub OAuth2 (built-in)
pip install -e .[discord]       # Discord OAuth2 (built-in)
pip install -e .[redis_jwks]    # Redis caching
pip install -e .[rbac]          # RBAC Extension
pip install -e .[realtime]      # WebSocket real-time features
pip install -e .[audit]         # Audit trail and analytics
pip install -e .[enterprise]    # Multi-tenant enterprise features

```bash
# All providers + RBAC + Real-time + Audit + Security
pip install -e .[full]

# Production security with comprehensive hardening
pip install -e .[security]      # JWT validation, rate limiting, security headers

# Development with all testing tools
pip install -e .[dev]          # Testing, linting, pre-commit hooks
```
```

## Quick start

Run the example app in `examples/server.py`:

```bash
uvicorn examples.server:app --reload
```

Visit http://localhost:8000/hello — the middleware is installed and will block requests without a valid token.

### Single-file FastAPI example with production security
Here's a minimal, copy-paste FastAPI app with comprehensive security:

```python
from fastapi import FastAPI, Request, Depends
from mcp_auth.settings import Settings
from mcp_auth.setup import setup_auth
from mcp_auth.security import get_validated_principal, require_admin_principal
from mcp_auth.middleware_security import setup_production_security

# Configure settings for production
settings = Settings(
    auth_provider="local",
    jwt_secret="prod-your-super-secure-256-bit-jwt-secret-key-here-minimum-32-chars",
    enable_rate_limiting=True,
    enable_security_headers=True,
    require_https=False,  # Set to True in production
    max_login_attempts=5,
    rate_limit_requests_per_minute=100
)

# Create FastAPI app with authentication and security
app = FastAPI(title="Secure API")
app = setup_auth(app, settings)
setup_production_security(app, settings)

@app.get("/hello")
def hello(principal=Depends(get_validated_principal)):
    """Public endpoint with authentication required"""
    return {
        "message": f"Hello {principal.name or principal.id}!",
        "user_id": principal.id,
        "provider": principal.provider,
        "roles": principal.roles
    }

@app.get("/admin/stats")
def admin_stats(principal=Depends(require_admin_principal)):
    """Admin-only endpoint with enhanced security"""
    return {
        "message": f"Admin access granted to {principal.name}",
        "system_status": "healthy",
        "security_level": "high"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## Running tests

```bash
# Install with dev dependencies
pip install -e .[dev]

# Run the test suite
pytest -v
```

## Provider SDKs (optional)

mcp-auth-py uses optional dependencies for cloud providers to keep the core package lightweight:

```bash
# Install specific providers as needed
pip install -e .[google]        # Google OAuth2 (google-auth)
pip install -e .[aws]           # AWS Cognito (boto3)
pip install -e .[azure]         # Azure AD (OIDC only, no extra deps)
pip install -e .[github]        # GitHub OAuth2 (built-in, no extra deps)
pip install -e .[discord]       # Discord OAuth2 (built-in, no extra deps)
pip install -e .[redis_jwks]    # Redis JWKS caching
pip install -e .[enterprise]    # Multi-tenant enterprise features

# Or install everything
pip install -e .[full]          # All providers + Redis + uvicorn + enterprise
```

## Async support & production readiness

### Async support
- Middleware and providers are async-capable. Providers can be implemented as coroutines or sync
  functions — the middleware will `await` coroutine results automatically.
- For blocking SDKs (e.g. `boto3`) we use threadpool offloading to avoid blocking the event loop.
- To be fully non-blocking in production, enable async-capable libs like `httpx` (JWKS) and `aioredis`.

### Production checklist
- Use the `redis_jwks` adapter for shared JWKS caching across processes. Set `redis_url` in `Settings`.
- Install only the provider SDKs you need in production (avoid shipping dev shims).
- Run `pre-commit run --all-files` locally before pushing to keep CI green.
- Run under a production ASGI server (Uvicorn/Gunicorn with workers) and terminate TLS at the edge.
- Configure timeouts, connection pools, and monitoring for JWKS fetches and cache hit rates.

## Adapters (non-ASGI / MCP servers)

The package includes `mcp_auth.adapters` with helpers for calling providers from non-ASGI or
sync MCP servers:

- `authenticate_request(provider, request)` — async helper that awaits provider results.
- `authenticate_request_sync(provider, request)` — sync wrapper for legacy servers.
- `token_to_principal(provider, token)` / `token_to_principal_sync(...)` — minimal token helpers.

Example (sync server):

```python
from mcp_auth.providers.registry import get_provider
from mcp_auth.adapters import token_to_principal_sync

provider = get_provider("aws")
principal = token_to_principal_sync(provider, token)
if principal is None:
    # unauthorized
    ...
```

## Provider configuration

Set `auth_provider` and `provider_config` via `mcp_auth.settings.Settings` (Pydantic Settings if available).

### Local (default)

```python
from mcp_auth.settings import Settings
settings = Settings(auth_provider="local")
```

### Google

```python
settings = Settings(
    auth_provider="google",
    provider_config={"audience": "GOOGLE_CLIENT_ID"},
)
```

### AWS Cognito

```python
settings = Settings(
    auth_provider="aws",
    provider_config={
        "cognito_region": "us-west-2",
        "cognito_user_pool_id": "us-west-2_XXXXXXXXX",
        "audience": "YOUR_COGNITO_APP_CLIENT_ID",
        "use_cognito_get_user": False,
    },
)
```

### Azure AD

```python
settings = Settings(
    auth_provider="azure",
    provider_config={"tenant": "your-tenant-id", "audience": "APP_CLIENT_ID"},
)
```

### GitHub OAuth2

```python
settings = Settings(
    auth_provider="github",
    provider_config={
        "client_id": "your_github_client_id",
        "client_secret": "your_github_client_secret",  # Optional
        "scopes": ["user:email", "read:org"],
        "allowed_organizations": ["your-org", "partner-org"],  # Optional
    },
)
```

### Discord OAuth2

```python
settings = Settings(
    auth_provider="discord",
    provider_config={
        "client_id": "your_discord_client_id",
        "client_secret": "your_discord_client_secret",  # Optional
        "bot_token": "your_discord_bot_token",  # Optional, for role verification
        "scopes": ["identify", "email", "guilds"],
        "allowed_guilds": ["123456789012345678"],  # Optional server restrictions
    },
)
```

## 🏢 **Enterprise Multi-Tenancy**

MCP Auth provides enterprise-grade multi-tenancy with multiple isolation strategies:

### Setup Enterprise Features
```bash
# Install enterprise features
pip install -e .[enterprise]

# Configure multi-tenancy
python tests/setup_wizard.py  # Choose option 7: Enterprise
```

### Multi-Tenant Configuration
```python
from mcp_auth.enterprise import MultiTenantAuth, TenantStrategy
from mcp_auth.enterprise.compliance import ComplianceMonitor

# Configure tenant isolation strategy
settings = Settings(
    auth_provider="google",  # Any provider works
    tenant_strategy=TenantStrategy.ROW_LEVEL_SECURITY,  # or DATABASE_PER_TENANT, SCHEMA_PER_TENANT
    tenant_resolver="header",  # header, subdomain, path, jwt
    redis_url="redis://localhost:6379/0"
)

# Setup multi-tenant authentication
app = FastAPI()
tenant_auth = MultiTenantAuth(settings)
app = tenant_auth.setup_app(app)

# Compliance monitoring
compliance = ComplianceMonitor(settings)
app.include_router(compliance.get_router(), prefix="/compliance")

@app.get("/api/data")
async def get_tenant_data(
    principal=Depends(get_validated_principal),
    tenant=Depends(get_current_tenant)
):
    # Automatic tenant isolation based on strategy
    return {
        "tenant_id": tenant.id,
        "user": principal.name,
        "isolation": tenant.strategy.value
    }
```

### Multi-Tenancy Features
- **Flexible Isolation**: Database-per-tenant, schema-per-tenant, or row-level security
- **Hierarchical Organizations**: Parent-child tenant relationships with inherited permissions
- **Conditional Access Policies**: IP restrictions, time-based access, device requirements
- **Tenant Administration**: REST APIs for tenant management and configuration
- **Performance Optimization**: Tenant-aware caching and connection pooling
- **Compliance Integration**: Automated tenant-level compliance monitoring

See **[docs/enterprise_guide.md](docs/enterprise_guide.md)** for complete enterprise setup and **[examples/enterprise_demo.py](examples/enterprise_demo.py)** for working examples.

## 🔧 **Quick Setup Wizard**

Use the interactive setup wizard to configure any provider:

```bash
# Run the setup wizard
python tests/setup_wizard.py

# Choose your provider:
# 1. Local (JWT with secret key)
# 2. Google (OAuth2)
# 3. AWS (Cognito)
# 4. Azure (Active Directory)
# 5. GitHub (OAuth2)
# 6. Discord (OAuth2)
# 7. Enterprise (Multi-tenant)
```

The wizard will:
- Generate secure `.env` configuration files
- Walk you through provider-specific setup (OAuth apps, client IDs, etc.)
- Configure optional features (Redis caching, enterprise features)
- Provide next steps and testing commands

## Using Redis-backed JWKS cache

Install the optional `redis_jwks` extra and enable it per-provider via `redis_jwks=True` and `redis_url`:

```bash
pip install .[redis_jwks]
```

```python
from mcp_auth.providers.aws import AWSProvider

provider = AWSProvider({
    "cognito_region": "us-west-2",
    "cognito_user_pool_id": "us-west-2_XXXX",
    "redis_jwks": True,
    "redis_url": "redis://redis.example.local:6379/0",
})
```

The adapter is optional; when unset the provider falls back to the in-process cache.

## Important Notes
- JWKS are cached per provider instance; use Redis for multi-process sharing.
- The test suite includes provider shims for testing without requiring all cloud SDKs.

## Contributing

See `CONTRIBUTING.md` for contributor guidelines.

## License

Apache-2.0 — see `LICENSE`.

Environment variables are supported via `pydantic-settings` (see `Settings.Config.env_file`).

## 🚀 **Production Deployment**

### Docker (Recommended)
```bash
# Quick start with Docker
docker build -t mcp-auth .
docker run -p 8000:8000 --env-file .env mcp-auth

# Multi-provider setup with docker-compose
docker-compose up -d  # Runs local, AWS, and Google providers
```

### Kubernetes
```bash
kubectl apply -f k8s/deployment.yaml
```

See **[docs/production_deployment.md](docs/production_deployment.md)** for comprehensive production setup guides, including:
- Complete security configuration and hardening
- JWT token security and rotation policies
- Rate limiting and brute force protection
- AWS Cognito, Google OAuth2, Azure AD setup
- Redis clustering and high availability
- Kubernetes deployment and load balancing
- Monitoring, alerting, and incident response
- Security best practices and compliance

## 🛡️ **Production Security Features**

MCP Auth includes enterprise-grade security features for production deployment:

### Authentication Security
- **JWT Token Validation**: Industry-standard JWT tokens with expiration, audience, and issuer validation
- **Multi-Provider Support**: Seamless switching between AWS Cognito, Azure AD, Google OAuth, and local auth
- **Token Security**: Configurable expiration, secure secret management, token rotation support
- **Admin Authorization**: Dedicated admin endpoints with enhanced security validation

### Security Hardening
- **Rate Limiting**: Per-IP request throttling with configurable limits and adaptive throttling
- **Brute Force Protection**: Login attempt tracking with automatic lockout and escalating delays
- **Security Headers**: Comprehensive HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
- **Request Validation**: Input sanitization and malicious payload detection
- **HTTPS Enforcement**: Configurable HTTPS requirement with proper redirect handling

### Monitoring & Compliance
- **Security Event Logging**: Complete audit trail with security event categorization and risk scoring
- **Real-time Monitoring**: WebSocket-based security event notifications with admin dashboards
- **Anomaly Detection**: Request pattern analysis and automatic threat detection
- **Compliance Reporting**: SOX, GDPR, HIPAA compliance with automated reporting

### Example Security Configuration
```python
from mcp_auth.settings import Settings
from mcp_auth.security import TokenValidator, RateLimiter, AdminAuthorizer

# Production security settings
settings = Settings(
    # JWT Security
    jwt_secret="prod-your-super-secure-256-bit-jwt-secret-key-here-minimum-32-chars",
    jwt_access_token_expire_minutes=60,  # 1 hour
    jwt_audience="api.yourcompany.com",
    jwt_issuer="auth.yourcompany.com",

    # Rate Limiting & Protection
    enable_rate_limiting=True,
    rate_limit_requests_per_minute=100,
    max_login_attempts=5,
    lockout_duration_minutes=15,

    # Security Headers & HTTPS
    enable_security_headers=True,
    require_https=True,
    hsts_max_age=31536000,  # 1 year

    # Redis for distributed security
    redis_url="redis://redis-server:6379/0",
    redis_password="your-secure-redis-password"
)

# Initialize security components
token_validator = TokenValidator(settings)
rate_limiter = RateLimiter(settings)
admin_authorizer = AdminAuthorizer()

# Validate JWT tokens with comprehensive checks
principal = await token_validator.validate_token(
    token,
    check_expiration=True,
    check_audience=True,
    check_issuer=True
)

# Apply rate limiting with automatic IP tracking
await rate_limiter.check_rate_limit(request.client.host)

# Require admin privileges for sensitive operations
await admin_authorizer.require_admin_access(principal, "system.admin")
```

See **[examples/production_example.py](examples/production_example.py)** for a complete production setup with all security features enabled.

## 💡 **Examples & Use Cases**

- **[complete_app.py](examples/complete_app.py)** — Full FastAPI app with user endpoints
- **[multi_provider.py](examples/multi_provider.py)** — Different auth providers in one app
- **[docker_app.py](examples/docker_app.py)** — Production containerized deployment
- **[rbac_demo.py](examples/rbac_demo.py)** — Complete RBAC system with role-based access control

## 🔐 **RBAC Extension**

The RBAC (Role-Based Access Control) extension adds comprehensive authorization capabilities:

```python
from mcp_auth.rbac import RBACEngine, Role, Permission, require_permissions

# Setup RBAC engine
engine = RBACEngine()

# Create roles with hierarchical permissions
admin_role = Role("admin", "Administrator", [
    Permission.from_string("*:*:*")  # Full access
])
editor_role = Role("editor", "Content Editor", [
    Permission.from_string("posts:create"),
    Permission.from_string("posts:*:edit"),
    Permission.from_string("posts:*:delete")
])

engine.add_role(admin_role)
engine.add_role(editor_role)
engine.assign_role("user123", "editor")

# Protect endpoints with decorators
@app.post("/posts")
@require_permissions("posts:create")
async def create_post():
    return {"message": "Post created"}

@app.put("/posts/{post_id}")
@require_permissions("posts:edit")  # Auto-resolves to posts:{post_id}:edit
async def update_post(post_id: str):
    return {"message": f"Post {post_id} updated"}
```

### RBAC Features
- **Hierarchical Roles**: Roles inherit permissions from parent roles
- **Resource-Specific Permissions**: Fine-grained control with wildcards support
- **FastAPI Decorators**: `@require_permissions`, `@require_roles`, `@require_access`
- **Admin Interface**: REST API for managing roles and permissions
- **Flexible Architecture**: Works with any authentication provider

See **[docs/rbac_extension.md](docs/rbac_extension.md)** for complete RBAC documentation and **[examples/rbac_demo.py](examples/rbac_demo.py)** for a working example.

## 🌐 **Real-time Features**

Add live WebSocket support for instant RBAC event notifications:

```python
from mcp_auth.realtime import setup_realtime_system, notify_rbac_event

# Enable WebSocket real-time features
realtime_router = setup_realtime_system(app)

# Client WebSocket connection at /ws
# Automatic broadcasting of permission changes, role assignments, security events
await notify_rbac_event(RBACEvent(
    event_type=EventType.PERMISSION_GRANTED,
    user_id="user123",
    resource="documents",
    action="read"
))
```

**Real-time Features:**
- **WebSocket Management**: Automatic connection lifecycle and authentication
- **Event Broadcasting**: Live notifications for permission changes and security events
- **Redis Distribution**: Events distributed across multiple server instances
- **Graceful Degradation**: Works with or without Redis
- **Client Filtering**: Users receive only relevant events

See **[docs/realtime_guide.md](docs/realtime_guide.md)** for complete WebSocket integration guide.

## ⚡ **High-Performance Caching**

Redis-based distributed caching dramatically improves authorization performance:

```python
from mcp_auth.caching import setup_caching_system, enable_rbac_caching

# Setup Redis caching
await setup_caching_system(redis_url="redis://localhost:6379/0")
enable_rbac_caching(app)

# Permission checks are automatically cached
# 25x performance improvement for repeated operations
# Intelligent cache invalidation on role/permission changes
```

**Caching Features:**
- **Distributed Redis Cache**: Shared cache across multiple server instances
- **Intelligent Invalidation**: Automatic cleanup when permissions change
- **Performance Monitoring**: Built-in hit rate and timing metrics
- **Bulk Operations**: Efficient bulk get/set operations
- **Pattern-based Cleanup**: Smart cache key management

See **[docs/caching_guide.md](docs/caching_guide.md)** for caching configuration and optimization.

## 📊 **Audit Trail & Security Analytics**

Comprehensive audit logging and security analytics for compliance and monitoring:

```python
from mcp_auth.audit import setup_audit_system, get_audit_logger

# Enable audit system with analytics dashboard
audit_router = setup_audit_system(app, enable_analytics=True)

# All RBAC operations automatically logged with context
# Custom security events
audit = get_audit_logger()
await audit.log_security_event(
    AuditEventType.SECURITY_VIOLATION,
    "Multiple failed login attempts detected",
    risk_score=85
)

# Built-in analytics dashboard at /audit/dashboard
# Security metrics, user access patterns, compliance reports
```

**Audit Features:**
- **Comprehensive Logging**: All RBAC operations with full context
- **Security Analytics**: Anomaly detection and risk scoring
- **Compliance Reports**: SOX, GDPR, HIPAA reporting
- **Access Pattern Analysis**: User behavior monitoring
- **Real-time Alerts**: Integration with security monitoring systems
- **Performance Tracking**: Authorization performance and cache metrics

See **[docs/audit_guide.md](docs/audit_guide.md)** for complete audit and analytics documentation.
