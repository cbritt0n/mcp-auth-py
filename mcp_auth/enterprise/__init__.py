"""
Enterprise Multi-Tenancy Support for mcp-auth-py

This module provides comprehensive multi-tenant authentication and authorization
with tenant isolation, hierarchical organizations, and enterprise-grade features.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

try:
    import redis.asyncio as aioredis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None

from ..models import Principal

logger = logging.getLogger(__name__)


class TenantStrategy(str, Enum):
    """Multi-tenancy isolation strategies"""

    DATABASE_PER_TENANT = "database_per_tenant"
    SCHEMA_PER_TENANT = "schema_per_tenant"
    ROW_LEVEL_SECURITY = "row_level_security"
    SHARED_EVERYTHING = "shared_everything"


class TenantStatus(str, Enum):
    """Tenant status values"""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    EXPIRED = "expired"
    PENDING_SETUP = "pending_setup"


class TenantPlan(str, Enum):
    """Tenant subscription plans"""

    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class TenantConfig(BaseModel):
    """Tenant configuration model"""

    tenant_id: str
    display_name: str
    status: TenantStatus = TenantStatus.ACTIVE
    plan: TenantPlan = TenantPlan.STARTER
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    # Authentication settings
    auth_settings: Dict[str, Any] = Field(default_factory=dict)

    # RBAC settings
    rbac_settings: Dict[str, Any] = Field(default_factory=dict)

    # Security settings
    security_settings: Dict[str, Any] = Field(default_factory=dict)

    # Resource limits
    limits: Dict[str, Any] = Field(default_factory=dict)

    # Custom attributes
    attributes: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class OrganizationConfig(BaseModel):
    """Hierarchical organization configuration"""

    org_id: str
    tenant_id: str
    parent_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    level: int = 0  # Depth in hierarchy
    path: str = ""  # Full path from root

    # Organization-specific settings
    settings: Dict[str, Any] = Field(default_factory=dict)

    # RBAC inheritance rules
    inherit_roles: List[str] = Field(default_factory=list)
    local_roles: List[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TenantContext:
    """Context object for current tenant"""

    def __init__(
        self,
        tenant_config: TenantConfig,
        organization: Optional[OrganizationConfig] = None,
    ):
        self.config = tenant_config
        self.organization = organization
        self.request_id = str(uuid.uuid4())
        self.created_at = datetime.utcnow()

    @property
    def tenant_id(self) -> str:
        return self.config.tenant_id

    @property
    def is_active(self) -> bool:
        return self.config.status == TenantStatus.ACTIVE and (
            self.config.expires_at is None or self.config.expires_at > datetime.utcnow()
        )

    @property
    def is_trial(self) -> bool:
        return self.config.status == TenantStatus.TRIAL

    @property
    def plan_limits(self) -> Dict[str, Any]:
        """Get plan-specific limits"""
        base_limits = {
            TenantPlan.STARTER: {
                "max_users": 100,
                "max_roles": 10,
                "max_organizations": 1,
                "api_rate_limit": 100,
                "storage_gb": 1,
                "audit_retention_days": 30,
            },
            TenantPlan.PROFESSIONAL: {
                "max_users": 1000,
                "max_roles": 50,
                "max_organizations": 10,
                "api_rate_limit": 1000,
                "storage_gb": 10,
                "audit_retention_days": 90,
            },
            TenantPlan.ENTERPRISE: {
                "max_users": 10000,
                "max_roles": 200,
                "max_organizations": 100,
                "api_rate_limit": 10000,
                "storage_gb": 100,
                "audit_retention_days": 365,
            },
        }

        limits = base_limits.get(
            self.config.plan, base_limits[TenantPlan.STARTER]
        ).copy()
        limits.update(self.config.limits)
        return limits


class TenantResolver:
    """Base class for tenant resolution strategies"""

    async def resolve_tenant(self, request: Request) -> Optional[str]:
        """Resolve tenant ID from request"""
        raise NotImplementedError


class HeaderTenantResolver(TenantResolver):
    """Resolve tenant from HTTP header"""

    def __init__(self, header_name: str = "X-Tenant-ID"):
        self.header_name = header_name

    async def resolve_tenant(self, request: Request) -> Optional[str]:
        return request.headers.get(self.header_name)


class SubdomainTenantResolver(TenantResolver):
    """Resolve tenant from subdomain"""

    def __init__(self, domain_suffix: str = ".example.com"):
        self.domain_suffix = domain_suffix

    async def resolve_tenant(self, request: Request) -> Optional[str]:
        host = request.headers.get("host", "")
        if host.endswith(self.domain_suffix):
            subdomain = host.replace(self.domain_suffix, "")
            if subdomain and "." not in subdomain:  # Single-level subdomain
                return subdomain
        return None


class PathTenantResolver(TenantResolver):
    """Resolve tenant from URL path"""

    def __init__(self, path_prefix: str = "/tenant"):
        self.path_prefix = path_prefix

    async def resolve_tenant(self, request: Request) -> Optional[str]:
        path = request.url.path
        if path.startswith(f"{self.path_prefix}/"):
            parts = path.split("/")
            if len(parts) >= 3:
                return parts[2]  # /tenant/{tenant_id}/...
        return None


class JWTTenantResolver(TenantResolver):
    """Resolve tenant from JWT token claims"""

    def __init__(self, claim_name: str = "tenant_id"):
        self.claim_name = claim_name

    async def resolve_tenant(self, request: Request) -> Optional[str]:
        # Get principal from request state (set by auth middleware)
        principal = getattr(request.state, "principal", None)
        if principal and hasattr(principal, "attributes"):
            return principal.attributes.get(self.claim_name)
        return None


class TenantManager:
    """Manages tenant configurations and operations"""

    def __init__(
        self, storage_backend: str = "memory", redis_url: Optional[str] = None
    ):
        self.storage_backend = storage_backend
        self.redis_url = redis_url
        self.redis = None

        # In-memory storage (for development/testing)
        self._tenants: Dict[str, TenantConfig] = {}
        self._organizations: Dict[str, OrganizationConfig] = {}
        self._lock = None

    def _ensure_lock(self):
        """Ensure async lock is initialized"""
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize tenant manager"""
        self._ensure_lock()

        if self.storage_backend == "redis" and REDIS_AVAILABLE and self.redis_url:
            try:
                self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
                await self.redis.ping()
                logger.info("Tenant manager initialized with Redis backend")
            except Exception as e:
                logger.warning(
                    f"Failed to initialize Redis: {e}, falling back to memory"
                )
                self.storage_backend = "memory"

        logger.info(f"Tenant manager initialized with {self.storage_backend} backend")

    async def create_tenant(
        self,
        tenant_id: str,
        display_name: str,
        plan: TenantPlan = TenantPlan.STARTER,
        **kwargs,
    ) -> TenantConfig:
        """Create a new tenant"""
        if await self.get_tenant(tenant_id):
            raise ValueError(f"Tenant {tenant_id} already exists")

        config = TenantConfig(
            tenant_id=tenant_id, display_name=display_name, plan=plan, **kwargs
        )

        await self._store_tenant(config)
        logger.info(f"Created tenant: {tenant_id}")
        return config

    async def get_tenant(self, tenant_id: str) -> Optional[TenantConfig]:
        """Get tenant configuration"""
        if self.storage_backend == "redis" and self.redis:
            try:
                data = await self.redis.hget("tenants", tenant_id)
                if data:
                    return TenantConfig.parse_raw(data)
            except Exception as e:
                logger.warning(f"Redis error: {e}")

        return self._tenants.get(tenant_id)

    async def update_tenant(
        self, tenant_id: str, updates: Dict[str, Any]
    ) -> TenantConfig:
        """Update tenant configuration"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")

        # Update fields
        for key, value in updates.items():
            if hasattr(tenant, key):
                setattr(tenant, key, value)

        tenant.updated_at = datetime.utcnow()
        await self._store_tenant(tenant)
        return tenant

    async def delete_tenant(self, tenant_id: str) -> bool:
        """Delete tenant and all associated data"""
        if not await self.get_tenant(tenant_id):
            return False

        # Delete organizations
        orgs = await self.list_organizations(tenant_id)
        for org in orgs:
            await self.delete_organization(org.org_id)

        # Delete tenant
        if self.storage_backend == "redis" and self.redis:
            try:
                await self.redis.hdel("tenants", tenant_id)
            except Exception as e:
                logger.warning(f"Redis error: {e}")

        self._tenants.pop(tenant_id, None)
        logger.info(f"Deleted tenant: {tenant_id}")
        return True

    async def list_tenants(
        self, status: Optional[TenantStatus] = None
    ) -> List[TenantConfig]:
        """List all tenants, optionally filtered by status"""
        tenants = []

        if self.storage_backend == "redis" and self.redis:
            try:
                tenant_data = await self.redis.hgetall("tenants")
                for data in tenant_data.values():
                    tenant = TenantConfig.parse_raw(data)
                    if status is None or tenant.status == status:
                        tenants.append(tenant)
            except Exception as e:
                logger.warning(f"Redis error: {e}")
        else:
            for tenant in self._tenants.values():
                if status is None or tenant.status == status:
                    tenants.append(tenant)

        return tenants

    async def _store_tenant(self, config: TenantConfig):
        """Store tenant configuration"""
        if self.storage_backend == "redis" and self.redis:
            try:
                await self.redis.hset("tenants", config.tenant_id, config.json())
            except Exception as e:
                logger.warning(f"Redis error: {e}")

        self._tenants[config.tenant_id] = config

    # Organization management methods

    async def create_organization(
        self,
        org_id: str,
        tenant_id: str,
        name: str,
        parent_id: Optional[str] = None,
        **kwargs,
    ) -> OrganizationConfig:
        """Create organization within tenant"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")

        if await self.get_organization(org_id):
            raise ValueError(f"Organization {org_id} already exists")

        # Calculate level and path
        level = 0
        path = org_id
        if parent_id:
            parent = await self.get_organization(parent_id)
            if not parent or parent.tenant_id != tenant_id:
                raise ValueError(f"Parent organization {parent_id} not found in tenant")
            level = parent.level + 1
            path = f"{parent.path}/{org_id}"

        org = OrganizationConfig(
            org_id=org_id,
            tenant_id=tenant_id,
            parent_id=parent_id,
            name=name,
            level=level,
            path=path,
            **kwargs,
        )

        await self._store_organization(org)
        logger.info(f"Created organization: {org_id} in tenant: {tenant_id}")
        return org

    async def get_organization(self, org_id: str) -> Optional[OrganizationConfig]:
        """Get organization configuration"""
        if self.storage_backend == "redis" and self.redis:
            try:
                data = await self.redis.hget("organizations", org_id)
                if data:
                    return OrganizationConfig.parse_raw(data)
            except Exception as e:
                logger.warning(f"Redis error: {e}")

        return self._organizations.get(org_id)

    async def list_organizations(self, tenant_id: str) -> List[OrganizationConfig]:
        """List organizations for tenant"""
        organizations = []

        if self.storage_backend == "redis" and self.redis:
            try:
                org_data = await self.redis.hgetall("organizations")
                for data in org_data.values():
                    org = OrganizationConfig.parse_raw(data)
                    if org.tenant_id == tenant_id:
                        organizations.append(org)
            except Exception as e:
                logger.warning(f"Redis error: {e}")
        else:
            for org in self._organizations.values():
                if org.tenant_id == tenant_id:
                    organizations.append(org)

        return organizations

    async def delete_organization(self, org_id: str) -> bool:
        """Delete organization"""
        org = await self.get_organization(org_id)
        if not org:
            return False

        # Delete child organizations first
        children = [
            o
            for o in await self.list_organizations(org.tenant_id)
            if o.parent_id == org_id
        ]
        for child in children:
            await self.delete_organization(child.org_id)

        if self.storage_backend == "redis" and self.redis:
            try:
                await self.redis.hdel("organizations", org_id)
            except Exception as e:
                logger.warning(f"Redis error: {e}")

        self._organizations.pop(org_id, None)
        logger.info(f"Deleted organization: {org_id}")
        return True

    async def _store_organization(self, config: OrganizationConfig):
        """Store organization configuration"""
        if self.storage_backend == "redis" and self.redis:
            try:
                await self.redis.hset("organizations", config.org_id, config.json())
            except Exception as e:
                logger.warning(f"Redis error: {e}")

        self._organizations[config.org_id] = config


class MultiTenantAuth:
    """Multi-tenant authentication manager"""

    def __init__(
        self,
        strategy: TenantStrategy,
        tenant_resolver: TenantResolver,
        tenant_manager: TenantManager,
        default_tenant: Optional[str] = None,
        require_tenant: bool = True,
    ):
        self.strategy = strategy
        self.tenant_resolver = tenant_resolver
        self.tenant_manager = tenant_manager
        self.default_tenant = default_tenant
        self.require_tenant = require_tenant

        # Tenant-specific configurations cache
        self._tenant_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = None

    def _ensure_lock(self):
        """Ensure async lock is initialized"""
        if self._cache_lock is None:
            self._cache_lock = asyncio.Lock()

    async def initialize(self):
        """Initialize multi-tenant auth system"""
        self._ensure_lock()
        await self.tenant_manager.initialize()

        # Create default tenant if specified
        if self.default_tenant:
            try:
                await self.tenant_manager.create_tenant(
                    tenant_id=self.default_tenant,
                    display_name="Default Tenant",
                    plan=TenantPlan.STARTER,
                )
            except ValueError:
                # Tenant already exists
                pass

    async def resolve_tenant_context(self, request: Request) -> TenantContext:
        """Resolve tenant context from request"""
        tenant_id = await self.tenant_resolver.resolve_tenant(request)

        if not tenant_id:
            if self.default_tenant:
                tenant_id = self.default_tenant
            elif self.require_tenant:
                raise HTTPException(
                    status_code=400, detail="Tenant identification required"
                )
            else:
                # No tenant required, use default context
                default_config = TenantConfig(
                    tenant_id="default", display_name="Default", plan=TenantPlan.STARTER
                )
                return TenantContext(default_config)

        # Get tenant configuration
        tenant_config = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant_config:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

        # Check tenant status
        if tenant_config.status not in [TenantStatus.ACTIVE, TenantStatus.TRIAL]:
            raise HTTPException(
                status_code=403, detail=f"Tenant {tenant_id} is {tenant_config.status}"
            )

        # Check expiration
        if tenant_config.expires_at and tenant_config.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=403, detail=f"Tenant {tenant_id} has expired"
            )

        return TenantContext(tenant_config)

    async def get_tenant_database_config(self, tenant_id: str) -> Dict[str, Any]:
        """Get database configuration for tenant based on strategy"""
        if self.strategy == TenantStrategy.DATABASE_PER_TENANT:
            # Each tenant has its own database
            return {
                "database_url": f"postgresql://user:pass@db-{tenant_id}:5432/{tenant_id}",
                "schema": "public",
            }
        elif self.strategy == TenantStrategy.SCHEMA_PER_TENANT:
            # Shared database with tenant-specific schemas
            return {
                "database_url": "postgresql://user:pass@shared-db:5432/app",
                "schema": f"tenant_{tenant_id}",
            }
        elif self.strategy == TenantStrategy.ROW_LEVEL_SECURITY:
            # Single schema with RLS
            return {
                "database_url": "postgresql://user:pass@db:5432/app",
                "schema": "public",
                "rls_tenant_id": tenant_id,
            }
        else:
            # Shared everything
            return {
                "database_url": "postgresql://user:pass@db:5432/app",
                "schema": "public",
            }

    async def create_tenant_resources(self, tenant_id: str) -> Dict[str, Any]:
        """Create tenant-specific resources (databases, schemas, etc.)"""
        result = {"created_resources": []}

        if self.strategy == TenantStrategy.DATABASE_PER_TENANT:
            # Create dedicated database for tenant
            # This would typically involve database creation SQL
            result["database"] = f"tenant_{tenant_id}"
            result["created_resources"].append("database")

        elif self.strategy == TenantStrategy.SCHEMA_PER_TENANT:
            # Create tenant schema
            schema_name = f"tenant_{tenant_id}"
            result["schema"] = schema_name
            result["created_resources"].append("schema")

        # Create tenant-specific cache keys
        if hasattr(self, "redis") and self.redis:
            cache_key = f"tenant:{tenant_id}:*"
            result["cache_namespace"] = cache_key
            result["created_resources"].append("cache_namespace")

        return result

    async def cleanup_tenant_resources(self, tenant_id: str) -> Dict[str, Any]:
        """Clean up tenant-specific resources"""
        result = {"cleaned_resources": []}

        if self.strategy == TenantStrategy.DATABASE_PER_TENANT:
            # Drop tenant database
            result["database"] = f"tenant_{tenant_id}"
            result["cleaned_resources"].append("database")

        elif self.strategy == TenantStrategy.SCHEMA_PER_TENANT:
            # Drop tenant schema
            schema_name = f"tenant_{tenant_id}"
            result["schema"] = schema_name
            result["cleaned_resources"].append("schema")

        # Clean up cache
        if hasattr(self, "redis") and self.redis:
            # Delete all tenant cache keys
            pattern = f"tenant:{tenant_id}:*"
            # Implementation would scan and delete keys
            result["cache_cleanup"] = pattern
            result["cleaned_resources"].append("cache")

        return result


# Middleware for multi-tenant request handling


class MultiTenantMiddleware:
    """ASGI middleware for multi-tenant support"""

    def __init__(self, app, multi_tenant_auth: MultiTenantAuth):
        self.app = app
        self.multi_tenant_auth = multi_tenant_auth

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            from fastapi import Request

            request = Request(scope, receive)

            try:
                # Resolve tenant context
                tenant_context = await self.multi_tenant_auth.resolve_tenant_context(
                    request
                )

                # Add tenant context to request state
                request.state.tenant_context = tenant_context

                # Modify scope for tenant-specific routing if needed
                if hasattr(request.state, "tenant_context"):
                    scope["tenant_id"] = tenant_context.tenant_id

            except HTTPException as e:
                # Send error response for tenant resolution failures
                response = {
                    "type": "http.response.start",
                    "status": e.status_code,
                    "headers": [[b"content-type", b"application/json"]],
                }
                await send(response)

                body = {
                    "type": "http.response.body",
                    "body": f'{{"detail":"{e.detail}"}}'.encode(),
                }
                await send(body)
                return

        await self.app(scope, receive, send)


# Utility functions for tenant context access


def get_current_tenant_context(request: Request) -> Optional[TenantContext]:
    """Get current tenant context from request"""
    return getattr(request.state, "tenant_context", None)


def require_tenant_context(request: Request) -> TenantContext:
    """Require tenant context, raise exception if not found"""
    context = get_current_tenant_context(request)
    if not context:
        raise HTTPException(status_code=500, detail="Tenant context not available")
    return context


def check_tenant_limits(
    context: TenantContext, resource: str, current_count: int
) -> bool:
    """Check if tenant is within resource limits"""
    limits = context.plan_limits
    limit = limits.get(f"max_{resource}")

    if limit is not None and current_count >= limit:
        return False
    return True


def get_tenant_setting(
    context: TenantContext, setting_path: str, default: Any = None
) -> Any:
    """Get tenant-specific setting using dot notation"""
    parts = setting_path.split(".")
    current = context.config.model_dump()

    try:
        for part in parts:
            current = current[part]
        return current
    except (KeyError, TypeError):
        return default
