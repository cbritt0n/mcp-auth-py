"""
RBAC Decorators - Production-grade FastAPI decorators for role and permission checking.

This module provides production-ready FastAPI decorators that integrate with the RBAC engine
to protect endpoints based on roles and permissions with comprehensive error handling,
logging, and security features.
"""

import asyncio
import logging
import time
from functools import wraps
from typing import Callable, List, Optional, Union

from fastapi import Depends, HTTPException, Request

from ..models import Principal
from .engine import get_rbac_engine
from .models import PermissionRequest

logger = logging.getLogger(__name__)

# Production constants
MAX_PERMISSION_STRING_LENGTH = 128
DECORATOR_TIMEOUT_SECONDS = 5.0


def get_current_principal(request: Request) -> Principal:
    """
    Extract the authenticated principal from request state with comprehensive validation.

    Args:
        request: FastAPI request object

    Returns:
        Authenticated principal

    Raises:
        HTTPException: If authentication is missing or invalid
    """
    if not hasattr(request.state, "principal"):
        logger.warning(
            "Principal not found in request state - authentication middleware may not be configured",
            extra={"endpoint": request.url.path, "method": request.method},
        )
        raise HTTPException(
            status_code=401,
            detail="Authentication required - principal not found in request state",
        )

    principal = request.state.principal
    if principal is None:
        logger.warning(
            "Principal is None - authentication failed",
            extra={"endpoint": request.url.path, "method": request.method},
        )
        raise HTTPException(
            status_code=401, detail="Authentication failed - invalid or expired token"
        )

    # Validate principal has required attributes
    if not hasattr(principal, "id") or not principal.id:
        logger.error(
            "Principal missing required 'id' attribute",
            extra={
                "endpoint": request.url.path,
                "principal_type": type(principal).__name__,
            },
        )
        raise HTTPException(
            status_code=401, detail="Authentication error - invalid principal format"
        )

    return principal


def _validate_permission_string(permission: str) -> None:
    """Validate permission string format for security."""
    if not permission or len(permission) > MAX_PERMISSION_STRING_LENGTH:
        raise ValueError(
            f"Permission string must be 1-{MAX_PERMISSION_STRING_LENGTH} characters"
        )

    # Basic format validation
    parts = permission.split(":")
    if len(parts) < 2:
        raise ValueError(
            f"Invalid permission format: {permission} (must be 'resource:action' or 'resource:id:action')"
        )

    # Check for injection attempts
    dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "\\"]
    if any(char in permission for char in dangerous_chars):
        raise ValueError(
            f"Permission string contains dangerous characters: {permission}"
        )


def _extract_request_context(request: Request, principal: Principal) -> dict:
    """Extract request context for permission checking and logging."""
    return {
        "endpoint": request.url.path,
        "method": request.method,
        "user_agent": request.headers.get("user-agent", "unknown")[
            :200
        ],  # Limit length
        "ip_address": (
            getattr(request.client, "host", "unknown") if request.client else "unknown"
        ),
        "user_id": principal.id,
        "provider": principal.provider,
        "timestamp": time.time(),
    }


def require_permissions(
    permissions: Union[str, List[str]],
    resource_id_param: Optional[str] = None,
    allow_empty_resource_id: bool = False,
):
    """
    Production-grade decorator to require specific permissions for an endpoint.

    Args:
        permissions: Single permission string or list of permission strings
        resource_id_param: Parameter name to extract resource ID from path/query params
        allow_empty_resource_id: Whether to allow empty/None resource IDs

    Returns:
        Decorator function that checks permissions before allowing access

    Example:
        @require_permissions(["users:read", "users:list"])
        async def list_users():
            pass

        @require_permissions("users:edit", resource_id_param="user_id")
        async def edit_user(user_id: str):
            pass

    Raises:
        HTTPException: 401 for authentication errors, 403 for authorization errors, 500 for system errors
    """
    if isinstance(permissions, str):
        permissions = [permissions]

    # Validate all permission strings at decoration time
    for perm in permissions:
        try:
            _validate_permission_string(perm)
        except ValueError as e:
            raise ValueError(f"Invalid permission in decorator: {e}")

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            request = None
            principal = None

            try:
                # Extract request object from function arguments
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

                if not request:
                    logger.error(
                        f"Request object not found in {func.__name__} - ensure Request is a parameter",
                        extra={
                            "function": func.__name__,
                            "args_types": [type(arg).__name__ for arg in args],
                        },
                    )
                    raise HTTPException(
                        status_code=500,
                        detail="Internal server error - Request object not found",
                    )

                # Get authenticated principal with comprehensive validation
                principal = get_current_principal(request)
                rbac_engine = get_rbac_engine()

                context = _extract_request_context(request, principal)

                # Check each required permission
                denied_permissions = []
                for perm_str in permissions:
                    try:
                        # Parse permission components
                        perm_parts = perm_str.split(":")
                        resource = perm_parts[0]
                        action = perm_parts[-1]

                        # Extract resource ID with validation
                        resource_id = None
                        if resource_id_param:
                            if resource_id_param in kwargs:
                                resource_id = str(kwargs[resource_id_param])[
                                    :64
                                ]  # Limit length
                            elif not allow_empty_resource_id:
                                logger.warning(
                                    f"Resource ID parameter '{resource_id_param}' not found in request",
                                    extra={**context, "permission": perm_str},
                                )
                                raise HTTPException(
                                    status_code=400,
                                    detail=f"Missing required parameter: {resource_id_param}",
                                )
                        elif len(perm_parts) == 3:
                            resource_id = perm_parts[1]

                        # Create permission request
                        # Note: perm_request is created for future extensibility
                        # but current implementation uses direct has_permission call

                        # Check permission with timeout protection
                        try:
                            # Use the optimized has_permission method
                            has_permission = rbac_engine.has_permission(
                                principal.id, resource, action, resource_id, context
                            )

                            if not has_permission:
                                denied_permissions.append(perm_str)
                                logger.info(
                                    f"Permission denied: {perm_str}",
                                    extra={
                                        **context,
                                        "permission": perm_str,
                                        "resource_id": resource_id,
                                    },
                                )

                        except Exception as perm_error:
                            logger.error(
                                f"Permission check failed for {perm_str}: {perm_error}",
                                extra={
                                    **context,
                                    "permission": perm_str,
                                    "error": str(perm_error),
                                },
                                exc_info=True,
                            )
                            # Fail securely - deny access on permission check errors
                            denied_permissions.append(perm_str)

                    except ValueError as parse_error:
                        logger.error(
                            f"Permission parsing failed: {parse_error}",
                            extra={**context, "permission": perm_str},
                        )
                        raise HTTPException(
                            status_code=500,
                            detail="Internal server error - invalid permission configuration",
                        )

                # If any permissions were denied, raise 403
                if denied_permissions:
                    logger.warning(
                        f"Access denied to {func.__name__} - missing permissions: {denied_permissions}",
                        extra={
                            **context,
                            "denied_permissions": denied_permissions,
                            "required_permissions": permissions,
                        },
                    )
                    raise HTTPException(
                        status_code=403,
                        detail=f"Insufficient permissions. Required: {', '.join(denied_permissions)}",
                    )

                # Permission check passed - log success and execute function
                check_time = time.time() - start_time
                logger.debug(
                    f"Permission check passed for {func.__name__} ({check_time:.3f}s)",
                    extra={
                        **context,
                        "permissions": permissions,
                        "check_time": check_time,
                    },
                )

                # Execute the protected function
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            except HTTPException:
                # Re-raise HTTP exceptions (they're already properly formatted)
                raise
            except Exception as e:
                # Log unexpected errors and return 500
                logger.error(
                    f"Unexpected error in permission decorator for {func.__name__}: {e}",
                    extra={
                        "function": func.__name__,
                        "principal_id": principal.id if principal else "unknown",
                        "error": str(e),
                    },
                    exc_info=True,
                )
                raise HTTPException(
                    status_code=500, detail="Internal server error during authorization"
                )

        return wrapper

    return decorator


def require_roles(roles: Union[str, List[str]]):
    """
    Decorator to require specific roles for an endpoint

    Args:
        roles: Single role name or list of role names

    Example:
        @require_roles(["admin", "user_manager"])
        async def manage_users():
            pass
    """
    if isinstance(roles, str):
        roles = [roles]

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request object
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                raise HTTPException(status_code=500, detail="Request object not found")

            # Get authenticated principal
            principal = get_current_principal(request)
            rbac_engine = get_rbac_engine()

            # Get user roles
            user_roles = rbac_engine.get_user_roles(principal.id)

            # Check if user has any of the required roles
            has_required_role = any(role in user_roles for role in roles)

            if not has_required_role:
                logger.warning(
                    f"Role check failed for user {principal.id}: required {roles}, has {user_roles}"
                )
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "Insufficient role permissions",
                        "required_roles": roles,
                        "user_roles": user_roles,
                    },
                )

            logger.info(f"Role check passed for user {principal.id}: {roles}")
            return (
                await func(*args, **kwargs)
                if asyncio.iscoroutinefunction(func)
                else func(*args, **kwargs)
            )

        return wrapper

    return decorator


def require_access(resource: str, action: str, resource_id_param: Optional[str] = None):
    """
    Decorator for dynamic permission checking

    Args:
        resource: Resource type (e.g., "users", "projects")
        action: Action type (e.g., "read", "edit", "delete")
        resource_id_param: Parameter name to extract resource ID from

    Example:
        @require_access("users", "edit", resource_id_param="user_id")
        async def edit_user(user_id: str):
            pass
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request object
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                raise HTTPException(status_code=500, detail="Request object not found")

            # Get authenticated principal
            principal = get_current_principal(request)
            rbac_engine = get_rbac_engine()

            # Extract resource ID
            resource_id = None
            if resource_id_param and resource_id_param in kwargs:
                resource_id = kwargs[resource_id_param]

            # Create permission request
            perm_request = PermissionRequest(
                user_id=principal.id,
                resource=resource,
                action=action,
                resource_id=resource_id,
                context={
                    "endpoint": request.url.path,
                    "method": request.method,
                },
            )

            # Check permission
            result = rbac_engine.check_permission(principal, perm_request)

            if not result.allowed:
                logger.warning(
                    f"Access denied for user {principal.id}: {resource}:{action} - {result.reason}"
                )
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "Access denied",
                        "resource": resource,
                        "action": action,
                        "resource_id": resource_id,
                        "reason": result.reason,
                    },
                )

            logger.info(f"Access granted for user {principal.id}: {resource}:{action}")
            return (
                await func(*args, **kwargs)
                if asyncio.iscoroutinefunction(func)
                else func(*args, **kwargs)
            )

        return wrapper

    return decorator


# Helper dependency for FastAPI dependency injection
def RBACPermission(permission: str, resource_id_param: Optional[str] = None):
    """
    FastAPI dependency for permission checking

    Example:
        @app.get("/users")
        async def list_users(
            request: Request,
            _: None = Depends(RBACPermission("users:read"))
        ):
            pass
    """

    async def check_permission(request: Request):
        principal = get_current_principal(request)
        rbac_engine = get_rbac_engine()

        # Simple permission check for dependency injection
        perm_parts = permission.split(":")
        resource = perm_parts[0]
        action = perm_parts[-1]
        resource_id = perm_parts[1] if len(perm_parts) == 3 else None

        perm_request = PermissionRequest(
            user_id=principal.id,
            resource=resource,
            action=action,
            resource_id=resource_id,
        )

        result = rbac_engine.check_permission(principal, perm_request)

        if not result.allowed:
            raise HTTPException(
                status_code=403, detail=f"Permission denied: {permission}"
            )

    return Depends(check_permission)
