# Changelog

All notable changes to mcp-auth-py will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-09-22

### 🎉 Initial Release with Enterprise Features

This is the first major release of mcp-auth-py, featuring a complete authentication and authorization framework for FastAPI/ASGI applications with enterprise-grade features.

### ✨ Added

#### Core Authentication Framework
- **Multi-Provider Support**: Local JWT, Google OAuth2, AWS Cognito, Azure AD authentication
- **FastAPI Integration**: Native ASGI middleware with async support
- **Provider Registry**: Pluggable provider architecture with runtime swapping
- **JWT Security**: Comprehensive JWT validation with expiration, audience, and issuer checks
- **Settings Management**: Pydantic-based configuration with environment variable support

#### New OAuth2 Providers
- **GitHub OAuth2 Provider**: Organization membership verification, team role mapping, Enterprise GitHub Server support
- **Discord OAuth2 Provider**: Guild membership verification, role hierarchy mapping, bot integration

#### Enterprise Multi-Tenancy
- **Tenant Isolation**: Database-per-tenant, schema-per-tenant, and row-level security strategies
- **Hierarchical Organizations**: Parent-child tenant relationships with permission inheritance
- **Conditional Access Policies**: IP restrictions, time-based access, device requirements
- **Tenant Resolution**: Header, subdomain, path, and JWT-based tenant identification

#### Compliance & Security
- **Compliance Monitoring**: Automated GDPR, HIPAA, SOX compliance assessment and reporting
- **Security Headers**: Comprehensive HTTP security headers (HSTS, CSP, X-Frame-Options)
- **Rate Limiting**: Per-IP request throttling with adaptive limits
- **Brute Force Protection**: Login attempt tracking with automatic lockout
- **Audit Trail**: Complete security event logging with risk scoring

#### Performance & Scalability
- **Circuit Breakers**: Fault tolerance with configurable failure thresholds
- **Optimized Caching**: Redis-based distributed caching with intelligent invalidation
- **Performance Monitoring**: Real-time metrics collection and alerting
- **Load Testing**: Built-in performance testing utilities

#### Role-Based Access Control (RBAC)
- **Hierarchical Permissions**: Role inheritance with fine-grained resource control
- **FastAPI Decorators**: `@require_permissions`, `@require_roles`, `@require_access`
- **Resource Wildcards**: Pattern-based permission matching
- **Admin Interface**: REST API for role and permission management

#### Real-time Features
- **WebSocket Support**: Live security event notifications
- **Event Broadcasting**: Distributed events across multiple server instances
- **Connection Management**: Automatic WebSocket lifecycle and authentication
- **Client Filtering**: User-specific event delivery

#### High-Performance Caching
- **Redis Integration**: Distributed JWKS and permission caching
- **Hit Rate Optimization**: 25x performance improvement for repeated operations
- **Bulk Operations**: Efficient batch get/set operations
- **Pattern Cleanup**: Smart cache key management and invalidation

#### Developer Experience
- **Setup Wizard**: Interactive configuration tool for all providers (`tests/setup_wizard.py`)
- **Validation Scripts**: Production readiness and installation validation (`tests/validate_*.py`)
- **Token Generation**: Development token generator utility (`tests/generate_token.py`)
- **Comprehensive Examples**: Real-world usage patterns and deployments
- **Docker Support**: Production-ready containerization with multi-stage builds
- **Kubernetes Manifests**: Complete K8s deployment configurations

#### Production Deployment
- **Docker Compose**: Multi-provider development environment
- **Nginx Configuration**: Load balancing and SSL termination
- **Health Checks**: Comprehensive application health monitoring
- **Environment Configuration**: Secure secret management and settings

### 🔧 Technical Details

#### Dependencies
- **Core**: FastAPI >=0.100.0, python-jose[cryptography] >=3.3.0, pydantic-settings >=2.0.0
- **Optional**: google-auth (Google), boto3 (AWS), redis (caching), httpx (HTTP client)
- **Development**: pytest, black, isort, ruff, pre-commit hooks

#### Python Support
- Python 3.9, 3.10, 3.11, 3.12
- Fully async-compatible with FastAPI/ASGI
- Thread pool offloading for blocking SDK operations

#### Testing
- 97 comprehensive test cases with >90% coverage
- Unit, integration, and provider-specific tests
- Redis integration tests with fakeredis support
- Continuous integration with GitHub Actions

### 📚 Documentation

- **README.md**: Complete setup and usage guide
- **COMMUNITY.md**: Contributor guidelines and project governance
- **docs/enterprise_guide.md**: Enterprise multi-tenancy documentation
- **docs/**: Comprehensive guides for all features
- **examples/**: Production-ready implementation examples

### 🚀 Installation

```bash
# Basic installation
pip install -e .

# With specific providers
pip install -e .[google,aws,azure,github,discord]

# Enterprise features
pip install -e .[enterprise]

# Full installation
pip install -e .[full]
```

### 🔄 Migration

This is the initial release - no migration required.

### 🤝 Contributors

- Christian Britton (@cbritt0n) - Initial implementation and enterprise features

---

## Future Releases

### Planned Features
- Additional OAuth2 providers (Microsoft, Okta, Auth0)
- Advanced RBAC with attribute-based access control (ABAC)
- Enhanced compliance reporting with automated remediation
- Machine learning-based anomaly detection
- GraphQL API support
- OpenID Connect provider certification

### Community Contributions
We welcome contributions! See [COMMUNITY.md](COMMUNITY.md) for guidelines.

---

*For detailed technical documentation, see the [docs/](docs/) directory.*
