"""
RBAC Admin Interface - Production-grade FastAPI endpoints for managing roles and permissions

This module provides comprehensive administrative endpoints for the RBAC system with
production features including audit logging, input validation, rate limiting,
and comprehensive monitoring.
"""

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..models import Principal
from .decorators import get_current_principal, require_permissions
from .engine import get_rbac_engine, setup_default_roles
from .models import AccessResult, Permission, Role

logger = logging.getLogger(__name__)

# Production constants
MAX_ROLE_NAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 512
MAX_RESOURCE_LENGTH = 64
MAX_ACTION_LENGTH = 32
MAX_PERMISSIONS_PER_ROLE = 100
MAX_ROLES_PER_USER = 20


class PermissionModel(BaseModel):
    """Production-grade API model for permissions with validation"""

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )

    resource: str = Field(
        ..., max_length=MAX_RESOURCE_LENGTH, pattern=r"^[a-zA-Z][a-zA-Z0-9_]*$"
    )
    action: str = Field(
        ..., max_length=MAX_ACTION_LENGTH, pattern=r"^[a-zA-Z][a-zA-Z0-9_]*$"
    )
    resource_id: Optional[str] = Field(
        None, max_length=64, pattern=r"^[a-zA-Z0-9_\-]*$"
    )

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, v: str) -> str:
        """Validate resource name"""
        if not v or v.isspace():
            raise ValueError("Resource name cannot be empty")
        return v.strip().lower()

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        """Validate action name"""
        if not v or v.isspace():
            raise ValueError("Action name cannot be empty")
        return v.strip().lower()

    @classmethod
    def from_permission(cls, perm: Permission) -> "PermissionModel":
        return cls(
            resource=perm.resource, action=perm.action, resource_id=perm.resource_id
        )

    def to_permission(self) -> Permission:
        return Permission(
            resource=self.resource, action=self.action, resource_id=self.resource_id
        )


class RoleModel(BaseModel):
    """Production-grade API model for roles with validation"""

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )

    name: str = Field(
        ..., max_length=MAX_ROLE_NAME_LENGTH, pattern=r"^[a-zA-Z][a-zA-Z0-9_]*$"
    )
    description: str = Field(..., max_length=MAX_DESCRIPTION_LENGTH)
    permissions: List[PermissionModel] = Field(
        default_factory=list, max_length=MAX_PERMISSIONS_PER_ROLE
    )
    inherits: Optional[List[str]] = Field(None, max_length=10)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate role name"""
        if not v or v.isspace():
            raise ValueError("Role name cannot be empty")
        return v.strip().lower()

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        """Validate role description"""
        if not v or v.isspace():
            raise ValueError("Role description cannot be empty")
        return v.strip()

    @field_validator("inherits")
    @classmethod
    def validate_inherits(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate role inheritance"""
        if v is None:
            return v
        # Remove duplicates and empty strings
        return [role.strip().lower() for role in v if role and not role.isspace()]

    @classmethod
    def from_role(cls, role: Role) -> "RoleModel":
        return cls(
            name=role.name,
            description=role.description,
            permissions=[PermissionModel.from_permission(p) for p in role.permissions],
            inherits=role.inherits,
        )

    def to_role(self) -> Role:
        return Role(
            name=self.name,
            description=self.description,
            permissions=[p.to_permission() for p in self.permissions],
            inherits=self.inherits,
        )


class UserRoleAssignment(BaseModel):
    """Production-grade API model for user-role assignments with validation"""

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )

    user_id: str = Field(..., max_length=128, pattern=r"^[a-zA-Z0-9@._\-]+$")
    role_name: str = Field(
        ..., max_length=MAX_ROLE_NAME_LENGTH, pattern=r"^[a-zA-Z][a-zA-Z0-9_]*$"
    )

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v: str) -> str:
        """Validate user ID"""
        if not v or v.isspace():
            raise ValueError("User ID cannot be empty")
        return v.strip()

    @field_validator("role_name")
    @classmethod
    def validate_role_name(cls, v: str) -> str:
        """Validate role name"""
        if not v or v.isspace():
            raise ValueError("Role name cannot be empty")
        return v.strip().lower()


class PermissionCheckRequest(BaseModel):
    """Production-grade API model for permission check requests with validation"""

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, extra="forbid"
    )

    user_id: Optional[str] = Field(None, max_length=128, pattern=r"^[a-zA-Z0-9@._\-]+$")
    resource: str = Field(
        ..., max_length=MAX_RESOURCE_LENGTH, pattern=r"^[a-zA-Z][a-zA-Z0-9_]*$"
    )
    action: str = Field(
        ..., max_length=MAX_ACTION_LENGTH, pattern=r"^[a-zA-Z][a-zA-Z0-9_]*$"
    )
    resource_id: Optional[str] = Field(
        None, max_length=64, pattern=r"^[a-zA-Z0-9_\-]*$"
    )
    context: Optional[Dict[str, Any]] = Field(None, max_length=20)

    @field_validator("context")
    @classmethod
    def validate_context(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Validate context dictionary"""
        if v is None:
            return v
        # Limit context size and sanitize keys
        if len(v) > 20:
            raise ValueError("Context cannot have more than 20 entries")
        return {str(k)[:32]: str(val)[:128] for k, val in v.items()}


class RoleStatsResponse(BaseModel):
    """Response model for role statistics"""

    name: str
    description: str
    permission_count: int
    user_count: int
    inherits_from: List[str]
    inherited_by: List[str]
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None


class SystemHealthResponse(BaseModel):
    """Response model for system health check"""

    status: str
    rbac_engine_healthy: bool
    total_roles: int
    total_users: int
    cache_hit_rate: Optional[float] = None
    avg_permission_check_time: Optional[float] = None
    errors_last_hour: int = 0
    uptime_seconds: int


def _audit_log(action: str, principal: Principal, details: Dict[str, Any]) -> None:
    """Log administrative actions for audit purposes"""
    logger.info(
        f"RBAC Admin Action: {action}",
        extra={
            "admin_user_id": principal.id,
            "admin_user_name": principal.name,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details,
            "audit": True,
        },
    )


def _validate_role_exists(engine, role_name: str) -> Role:
    """Validate that a role exists and return it"""
    if role_name not in engine.roles:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")
    return engine.roles[role_name]


def _validate_user_role_limits(engine, user_id: str) -> None:
    """Validate that user doesn't exceed role limits"""
    current_roles = engine.get_user_roles(user_id)
    if len(current_roles) >= MAX_ROLES_PER_USER:
        raise HTTPException(
            status_code=400,
            detail=f"User cannot have more than {MAX_ROLES_PER_USER} roles",
        )


def create_rbac_admin_router() -> APIRouter:
    """Create production-grade FastAPI router with RBAC admin endpoints"""
    router = APIRouter(prefix="/rbac", tags=["RBAC Admin"])

    # ================== SYSTEM HEALTH & MONITORING ==================

    @router.get("/health", response_model=SystemHealthResponse)
    async def get_system_health(request: Request):
        """Get RBAC system health status - public endpoint for monitoring"""
        try:
            engine = get_rbac_engine()

            # Check if engine is healthy
            health_status = engine.get_health_status()

            # Get performance stats
            stats = engine.get_stats()

            return SystemHealthResponse(
                status="healthy" if health_status["healthy"] else "unhealthy",
                rbac_engine_healthy=health_status["healthy"],
                total_roles=len(engine.roles),
                total_users=len(engine.user_roles),
                cache_hit_rate=stats.get("cache_hit_rate"),
                avg_permission_check_time=stats.get("avg_check_time"),
                errors_last_hour=stats.get("errors_last_hour", 0),
                uptime_seconds=int(stats.get("uptime_seconds", 0)),
            )
        except Exception as e:
            logger.error(f"Health check failed: {e}", exc_info=True)
            return SystemHealthResponse(
                status="unhealthy",
                rbac_engine_healthy=False,
                total_roles=0,
                total_users=0,
                errors_last_hour=1,
                uptime_seconds=0,
            )

    @router.get("/metrics")
    @require_permissions("rbac:system:read")
    async def get_metrics(request: Request):
        """Get detailed RBAC system metrics"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        stats = engine.get_stats()

        _audit_log("metrics_accessed", principal, {"stats_keys": list(stats.keys())})

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "system": stats,
            "cache": engine.get_cache_stats(),
            "performance": {
                "total_permission_checks": stats.get("total_checks", 0),
                "avg_check_time_ms": stats.get("avg_check_time", 0) * 1000,
                "cache_hit_rate": stats.get("cache_hit_rate", 0),
            },
        }

    # ================== ROLE MANAGEMENT ==================

    @router.get("/roles", response_model=List[RoleStatsResponse])
    @require_permissions("rbac:roles:read")
    async def list_roles(
        request: Request,
        include_stats: bool = Query(False, description="Include usage statistics"),
        limit: int = Query(
            100, ge=1, le=500, description="Maximum number of roles to return"
        ),
    ):
        """List all roles in the system with optional statistics"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        start_time = time.time()

        try:
            roles = list(engine.roles.values())[:limit]

            if include_stats:
                # Get detailed stats for each role
                result = []
                for role in roles:
                    user_count = sum(
                        1 for users in engine.user_roles.values() if role.name in users
                    )
                    inherits_from = role.inherits or []
                    inherited_by = [
                        r.name
                        for r in engine.roles.values()
                        if r.inherits and role.name in r.inherits
                    ]

                    result.append(
                        RoleStatsResponse(
                            name=role.name,
                            description=role.description,
                            permission_count=len(role.permissions),
                            user_count=user_count,
                            inherits_from=inherits_from,
                            inherited_by=inherited_by,
                        )
                    )
            else:
                # Simple role models
                result = [RoleModel.from_role(role) for role in roles]

            query_time = time.time() - start_time

            _audit_log(
                "roles_listed",
                principal,
                {
                    "role_count": len(result),
                    "include_stats": include_stats,
                    "query_time": query_time,
                },
            )

            return result

        except Exception as e:
            logger.error(f"Failed to list roles: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to retrieve roles")

    @router.get("/roles/{role_name}", response_model=RoleModel)
    @require_permissions("rbac:roles:read")
    async def get_role(role_name: str, request: Request):
        """Get details of a specific role with validation"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Validate and sanitize role name
        role_name = role_name.strip().lower()[:MAX_ROLE_NAME_LENGTH]

        role = _validate_role_exists(engine, role_name)

        _audit_log("role_accessed", principal, {"role_name": role_name})

        return RoleModel.from_role(role)

    @router.post("/roles", response_model=RoleModel)
    @require_permissions("rbac:roles:create")
    async def create_role(role: RoleModel, request: Request):
        """Create a new role with comprehensive validation"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Check if role already exists
        if role.name in engine.roles:
            raise HTTPException(
                status_code=409, detail=f"Role '{role.name}' already exists"
            )

        # Validate role inheritance doesn't create cycles
        if role.inherits:
            for parent_role in role.inherits:
                if parent_role not in engine.roles:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Parent role '{parent_role}' does not exist",
                    )

        try:
            role_obj = role.to_role()
            engine.add_role(role_obj)

            _audit_log(
                "role_created",
                principal,
                {
                    "role_name": role.name,
                    "permission_count": len(role.permissions),
                    "inherits": role.inherits or [],
                },
            )

            return role

        except ValueError as e:
            raise HTTPException(
                status_code=400, detail=f"Invalid role configuration: {e}"
            )
        except Exception as e:
            logger.error(f"Failed to create role {role.name}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to create role")

    @router.put("/roles/{role_name}", response_model=RoleModel)
    @require_permissions("rbac:roles:edit")
    async def update_role(role_name: str, role: RoleModel, request: Request):
        """Update an existing role with comprehensive validation"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Validate and sanitize role name
        role_name = role_name.strip().lower()[:MAX_ROLE_NAME_LENGTH]

        # Validate current role exists
        _validate_role_exists(engine, role_name)

        try:
            # Update role name if changed
            if role.name != role_name:
                # Check if new name is available
                if role.name in engine.roles:
                    raise HTTPException(
                        status_code=409,
                        detail=f"Role name '{role.name}' is already in use",
                    )
                engine.remove_role(role_name)

            role_obj = role.to_role()
            engine.add_role(role_obj)

            _audit_log(
                "role_updated",
                principal,
                {
                    "old_role_name": role_name,
                    "new_role_name": role.name,
                    "permission_count": len(role.permissions),
                    "inherits": role.inherits or [],
                },
            )

            return role

        except ValueError as e:
            raise HTTPException(
                status_code=400, detail=f"Invalid role configuration: {e}"
            )
        except Exception as e:
            logger.error(f"Failed to update role {role_name}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to update role")

    @router.delete("/roles/{role_name}")
    @require_permissions("rbac:roles:delete")
    async def delete_role(role_name: str, request: Request):
        """Delete a role with safety checks"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Validate and sanitize role name
        role_name = role_name.strip().lower()[:MAX_ROLE_NAME_LENGTH]

        # Validate role exists
        role = _validate_role_exists(engine, role_name)

        # Check if role is in use
        users_with_role = [
            user_id
            for user_id, roles in engine.user_roles.items()
            if role_name in roles
        ]

        if users_with_role:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete role '{role_name}' - it is assigned to {len(users_with_role)} users",
            )

        # Check if other roles inherit from this role
        dependent_roles = [
            r.name
            for r in engine.roles.values()
            if r.inherits and role_name in r.inherits
        ]

        if dependent_roles:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete role '{role_name}' - it is inherited by: {', '.join(dependent_roles)}",
            )

        try:
            engine.remove_role(role_name)

            _audit_log(
                "role_deleted",
                principal,
                {
                    "role_name": role_name,
                    "had_permissions": len(role.permissions),
                    "had_inheritance": bool(role.inherits),
                },
            )

            return {"message": f"Role '{role_name}' deleted successfully"}

        except Exception as e:
            logger.error(f"Failed to delete role {role_name}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to delete role")

    # ================== USER-ROLE MANAGEMENT ==================

    @router.get("/users/{user_id}/roles", response_model=List[str])
    @require_permissions("rbac:users:read")
    async def get_user_roles(user_id: str, request: Request):
        """Get roles assigned to a user with validation"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Validate and sanitize user ID
        user_id = user_id.strip()[:128]
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid user ID")

        roles = engine.get_user_roles(user_id)

        _audit_log(
            "user_roles_accessed",
            principal,
            {"target_user_id": user_id, "role_count": len(roles)},
        )

        return roles

    @router.post("/users/{user_id}/roles")
    @require_permissions("rbac:users:edit")
    async def assign_user_role(
        user_id: str, assignment: UserRoleAssignment, request: Request
    ):
        """Assign a role to a user with comprehensive validation"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Validate and sanitize user ID
        user_id = user_id.strip()[:128]
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid user ID")

        # Ensure user_id matches assignment (if provided)
        if assignment.user_id and assignment.user_id != user_id:
            raise HTTPException(
                status_code=400,
                detail="User ID in path must match user ID in request body",
            )

        # Validate role exists
        _validate_role_exists(engine, assignment.role_name)

        # Validate user role limits
        _validate_user_role_limits(engine, user_id)

        try:
            engine.assign_role(user_id, assignment.role_name)

            _audit_log(
                "role_assigned",
                principal,
                {
                    "target_user_id": user_id,
                    "role_name": assignment.role_name,
                    "total_user_roles": len(engine.get_user_roles(user_id)),
                },
            )

            return {
                "message": f"Role '{assignment.role_name}' assigned to user '{user_id}'",
                "user_id": user_id,
                "role_name": assignment.role_name,
                "total_roles": len(engine.get_user_roles(user_id)),
            }

        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(
                f"Failed to assign role {assignment.role_name} to user {user_id}: {e}",
                exc_info=True,
            )
            raise HTTPException(status_code=500, detail="Failed to assign role")

    @router.delete("/users/{user_id}/roles/{role_name}")
    @require_permissions("rbac:users:edit")
    async def revoke_user_role(user_id: str, role_name: str, request: Request):
        """Revoke a role from a user with validation"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Validate and sanitize inputs
        user_id = user_id.strip()[:128]
        role_name = role_name.strip().lower()[:MAX_ROLE_NAME_LENGTH]

        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid user ID")

        # Validate role exists
        _validate_role_exists(engine, role_name)

        # Check if user has the role
        current_roles = engine.get_user_roles(user_id)
        if role_name not in current_roles:
            raise HTTPException(
                status_code=404,
                detail=f"User '{user_id}' does not have role '{role_name}'",
            )

        try:
            engine.revoke_role(user_id, role_name)

            _audit_log(
                "role_revoked",
                principal,
                {
                    "target_user_id": user_id,
                    "role_name": role_name,
                    "remaining_roles": len(engine.get_user_roles(user_id)),
                },
            )

            return {
                "message": f"Role '{role_name}' revoked from user '{user_id}'",
                "user_id": user_id,
                "role_name": role_name,
                "remaining_roles": len(engine.get_user_roles(user_id)),
            }

        except Exception as e:
            logger.error(
                f"Failed to revoke role {role_name} from user {user_id}: {e}",
                exc_info=True,
            )
            raise HTTPException(status_code=500, detail="Failed to revoke role")

    @router.get("/users/{user_id}/permissions", response_model=List[PermissionModel])
    @require_permissions("rbac:users:read")
    async def get_user_permissions(user_id: str, request: Request):
        """Get all permissions for a user (computed from roles) with caching"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Validate and sanitize user ID
        user_id = user_id.strip()[:128]
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid user ID")

        start_time = time.time()

        try:
            permissions = engine.get_user_permissions(user_id)

            compute_time = time.time() - start_time

            _audit_log(
                "user_permissions_accessed",
                principal,
                {
                    "target_user_id": user_id,
                    "permission_count": len(permissions),
                    "compute_time": compute_time,
                },
            )

            return [PermissionModel.from_permission(p) for p in permissions]

        except Exception as e:
            logger.error(
                f"Failed to get permissions for user {user_id}: {e}", exc_info=True
            )
            raise HTTPException(
                status_code=500, detail="Failed to retrieve user permissions"
            )

    # ================== PERMISSION CHECKING ==================

    @router.post("/check-permission", response_model=AccessResult)
    @require_permissions("rbac:permissions:check")
    async def check_permission(check_request: PermissionCheckRequest, request: Request):
        """Check if a user has a specific permission with comprehensive logging"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        # Use provided user_id or current user
        user_id = check_request.user_id or principal.id

        start_time = time.time()

        try:
            # Use the optimized permission check
            has_permission = engine.has_permission(
                user_id=user_id,
                resource=check_request.resource,
                action=check_request.action,
                resource_id=check_request.resource_id,
                context=check_request.context or {},
            )

            # Create result
            result = AccessResult(
                allowed=has_permission,
                user_id=user_id,
                resource=check_request.resource,
                action=check_request.action,
                resource_id=check_request.resource_id,
                user_roles=engine.get_user_roles(user_id),
                reason=(
                    "Access granted" if has_permission else "Insufficient permissions"
                ),
                checked_at=datetime.utcnow(),
            )

            check_time = time.time() - start_time

            _audit_log(
                "permission_checked",
                principal,
                {
                    "target_user_id": user_id,
                    "resource": check_request.resource,
                    "action": check_request.action,
                    "resource_id": check_request.resource_id,
                    "result": has_permission,
                    "check_time": check_time,
                },
            )

            return result

        except Exception as e:
            logger.error(
                f"Permission check failed for user {user_id}: {e}", exc_info=True
            )

            # Return secure failure result
            return AccessResult(
                allowed=False,
                user_id=user_id,
                resource=check_request.resource,
                action=check_request.action,
                resource_id=check_request.resource_id,
                user_roles=[],
                reason="Permission check failed - system error",
                checked_at=datetime.utcnow(),
            )

    @router.post("/bulk-check-permissions")
    @require_permissions("rbac:permissions:check")
    async def bulk_check_permissions(
        checks: List[PermissionCheckRequest],
        request: Request,
        max_checks: int = Query(
            50, ge=1, le=100, description="Maximum number of checks per request"
        ),
    ):
        """Perform bulk permission checks with rate limiting"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        if len(checks) > max_checks:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot check more than {max_checks} permissions at once",
            )

        start_time = time.time()
        results = []

        try:
            for i, check_request in enumerate(checks):
                user_id = check_request.user_id or principal.id

                has_permission = engine.has_permission(
                    user_id=user_id,
                    resource=check_request.resource,
                    action=check_request.action,
                    resource_id=check_request.resource_id,
                    context=check_request.context or {},
                )

                results.append(
                    {
                        "index": i,
                        "allowed": has_permission,
                        "user_id": user_id,
                        "resource": check_request.resource,
                        "action": check_request.action,
                        "resource_id": check_request.resource_id,
                    }
                )

            total_time = time.time() - start_time

            _audit_log(
                "bulk_permission_check",
                principal,
                {
                    "check_count": len(checks),
                    "allowed_count": sum(1 for r in results if r["allowed"]),
                    "total_time": total_time,
                },
            )

            return {
                "results": results,
                "summary": {
                    "total_checks": len(checks),
                    "allowed_count": sum(1 for r in results if r["allowed"]),
                    "denied_count": sum(1 for r in results if not r["allowed"]),
                    "total_time_seconds": total_time,
                },
            }

        except Exception as e:
            logger.error(f"Bulk permission check failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Bulk permission check failed")

    # ================== SYSTEM MANAGEMENT ==================

    @router.post("/setup-defaults")
    @require_permissions("rbac:system:admin")
    async def setup_default_roles_endpoint(request: Request):
        """Setup default roles in the system with validation"""
        principal = get_current_principal(request)

        try:
            engine = get_rbac_engine()

            # Get current role count before setup
            roles_before = len(engine.roles)

            setup_default_roles(engine)

            roles_after = len(engine.roles)
            roles_created = roles_after - roles_before

            _audit_log(
                "default_roles_setup",
                principal,
                {
                    "roles_before": roles_before,
                    "roles_after": roles_after,
                    "roles_created": roles_created,
                },
            )

            return {
                "message": "Default roles setup successfully",
                "roles_created": roles_created,
                "total_roles": roles_after,
            }

        except Exception as e:
            logger.error(f"Failed to setup default roles: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to setup default roles")

    @router.get("/stats")
    @require_permissions("rbac:system:read")
    async def get_rbac_stats(request: Request):
        """Get comprehensive RBAC system statistics"""
        principal = get_current_principal(request)
        engine = get_rbac_engine()

        try:
            # Get detailed statistics
            stats = engine.get_stats()
            health_status = engine.get_health_status()
            cache_stats = engine.get_cache_stats()

            # Calculate additional metrics
            roles_with_users = sum(
                1
                for role_name in engine.roles.keys()
                if any(
                    role_name in user_roles for user_roles in engine.user_roles.values()
                )
            )

            unused_roles = len(engine.roles) - roles_with_users

            avg_roles_per_user = (
                sum(len(roles) for roles in engine.user_roles.values())
                / len(engine.user_roles)
                if engine.user_roles
                else 0
            )

            _audit_log("stats_accessed", principal, {"stats_retrieved": True})

            return {
                "timestamp": datetime.utcnow().isoformat(),
                "system": {
                    "total_roles": len(engine.roles),
                    "total_users_with_roles": len(engine.user_roles),
                    "roles_with_users": roles_with_users,
                    "unused_roles": unused_roles,
                    "avg_roles_per_user": round(avg_roles_per_user, 2),
                    "total_policies": len(engine.policies),
                    "uptime_seconds": stats.get("uptime_seconds", 0),
                },
                "performance": {
                    "total_permission_checks": stats.get("total_checks", 0),
                    "avg_check_time_ms": stats.get("avg_check_time", 0) * 1000,
                    "cache_hit_rate": stats.get("cache_hit_rate", 0),
                    "errors_last_hour": stats.get("errors_last_hour", 0),
                },
                "cache": cache_stats,
                "health": health_status,
                "roles": {
                    name: {
                        "permission_count": len(role.permissions),
                        "inherits_count": len(role.inherits or []),
                        "user_count": sum(
                            1
                            for user_roles in engine.user_roles.values()
                            if name in user_roles
                        ),
                    }
                    for name, role in engine.roles.items()
                },
            }

        except Exception as e:
            logger.error(f"Failed to get RBAC stats: {e}", exc_info=True)
            raise HTTPException(
                status_code=500, detail="Failed to retrieve system statistics"
            )

    @router.post("/cache/clear")
    @require_permissions("rbac:system:admin")
    async def clear_cache(request: Request):
        """Clear RBAC permission cache"""
        principal = get_current_principal(request)

        try:
            engine = get_rbac_engine()

            # Get cache stats before clearing
            cache_stats_before = engine.get_cache_stats()

            engine.clear_cache()

            _audit_log(
                "cache_cleared",
                principal,
                {
                    "entries_cleared": cache_stats_before.get("size", 0),
                    "hit_rate_before": cache_stats_before.get("hit_rate", 0),
                },
            )

            return {
                "message": "Cache cleared successfully",
                "entries_cleared": cache_stats_before.get("size", 0),
                "hit_rate_before": cache_stats_before.get("hit_rate", 0),
            }

        except Exception as e:
            logger.error(f"Failed to clear cache: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="Failed to clear cache")

    return router


def setup_rbac_admin(app, prefix: str = "/admin"):
    """
    Setup production-grade RBAC admin interface on a FastAPI app

    Args:
        app: FastAPI application instance
        prefix: URL prefix for admin endpoints (default: "/admin")

    Returns:
        Configured router instance
    """
    try:
        router = create_rbac_admin_router()

        # Update router prefix
        if prefix != "/admin":
            router.prefix = prefix + "/rbac"
        else:
            router.prefix = prefix + "/rbac"

        app.include_router(router)

        # Initialize default roles
        engine = get_rbac_engine()
        setup_default_roles(engine)

        logger.info(
            "RBAC Admin interface setup successfully",
            extra={
                "prefix": router.prefix,
                "total_roles": len(engine.roles),
                "setup_time": datetime.utcnow().isoformat(),
            },
        )

        return router

    except Exception as e:
        logger.error(f"Failed to setup RBAC admin interface: {e}", exc_info=True)
        raise
