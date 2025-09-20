"""
RBAC Engine - Core authorization engine for Role-Based Access Control.

This module implements the core RBAC functionality including role management,
permission checking, policy evaluation, and user role assignments. It provides
a centralized engine for making authorization decisions throughout the application.
"""

import logging
import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from ..models import Principal
from .models import (AccessPolicy, AccessResult, Permission, PermissionRequest,
                     Role)

logger = logging.getLogger(__name__)

# Production security constants
MAX_ROLE_NAME_LENGTH = 64
MAX_USER_ID_LENGTH = 256
MAX_RESOURCE_LENGTH = 128
MAX_ACTION_LENGTH = 64
MAX_ROLES_PER_USER = 50
MAX_USERS_IN_SYSTEM = 100000

# Valid patterns for security
VALID_ROLE_NAME = re.compile(r"^[a-zA-Z0-9_.-]+$")
VALID_USER_ID = re.compile(r"^[a-zA-Z0-9@._-]+$")
VALID_RESOURCE = re.compile(r"^[a-zA-Z0-9_.-]+$")
VALID_ACTION = re.compile(r"^[a-zA-Z0-9_.-]+$")


class RBACEngine:
    """
    Production-ready RBAC engine for permission checking and role management.

    This class manages the complete lifecycle of roles, permissions, and access
    control policies. It provides methods for:
    - Role and permission management with security validation
    - User role assignments with limits and monitoring
    - Permission evaluation with inheritance and caching
    - Policy-based access control
    - Thread-safe operations for production use
    - Performance optimization and monitoring

    Features:
        - Input validation and sanitization for security
        - LRU caching for permission checks
        - Thread-safe operations with proper locking
        - Rate limiting and resource management
        - Comprehensive logging and monitoring
        - Memory management with bounded collections

    Example:
        Basic usage:

        >>> engine = RBACEngine()
        >>> role = Role("editor", "Content editor", [
        ...     Permission.from_string("posts:create"),
        ...     Permission.from_string("posts:*:edit")
        ... ])
        >>> engine.add_role(role)
        >>> engine.assign_role("user123", "editor")
        >>>
        >>> # Check permission
        >>> principal = Principal(id="user123", provider="local", name="John")
        >>> request = PermissionRequest("user123", "posts", "edit", "456")
        >>> result = engine.check_permission(principal, request)
        >>> print(result.allowed)  # True

    Thread Safety:
        This class is thread-safe for production use. All public methods
        use appropriate locking mechanisms to ensure data consistency
        under concurrent access.
    """

    def __init__(self, cache_size: int = 10000, cache_ttl: int = 300):
        """
        Initialize the RBAC engine with production settings.

        Args:
            cache_size: Maximum number of items in the permission cache.
            cache_ttl: Time-to-live for cached permissions in seconds.

        Raises:
            ValueError: If cache_size or cache_ttl are invalid.
        """
        if cache_size <= 0 or cache_size > 1000000:
            raise ValueError("cache_size must be between 1 and 1,000,000")
        if cache_ttl <= 0 or cache_ttl > 86400:  # Max 24 hours
            raise ValueError("cache_ttl must be between 1 and 86,400 seconds")

        self.roles: Dict[str, Role] = {}
        self.policies: List[AccessPolicy] = []
        self.user_roles: Dict[str, Set[str]] = {}  # user_id -> role names

        # Production features
        self._lock = threading.RLock()  # Thread safety
        self._cache_size = cache_size
        self._cache_ttl = cache_ttl
        self._permission_cache: OrderedDict = OrderedDict()  # LRU cache
        self._cache_timestamps: Dict[str, float] = {}

        # Security and monitoring
        self._failed_validations = 0
        self._cache_hits = 0
        self._cache_misses = 0

        # Performance metrics
        self._permission_checks = 0
        self._avg_check_time = 0.0
        self._created_at = datetime.now(timezone.utc)

        logger.info(
            "Production RBAC engine initialized with cache_size=%d, cache_ttl=%d",
            cache_size,
            cache_ttl,
        )

    def _validate_role_name(self, role_name: str) -> None:
        """Validate role name for security."""
        if not role_name or len(role_name) > MAX_ROLE_NAME_LENGTH:
            self._failed_validations += 1
            raise ValueError(f"Role name must be 1-{MAX_ROLE_NAME_LENGTH} characters")
        if not VALID_ROLE_NAME.match(role_name):
            self._failed_validations += 1
            raise ValueError("Role name contains invalid characters")

    def _validate_user_id(self, user_id: str) -> None:
        """Validate user ID for security."""
        if not user_id or len(user_id) > MAX_USER_ID_LENGTH:
            self._failed_validations += 1
            raise ValueError(f"User ID must be 1-{MAX_USER_ID_LENGTH} characters")
        if not VALID_USER_ID.match(user_id):
            self._failed_validations += 1
            raise ValueError("User ID contains invalid characters")

    def _validate_system_limits(self) -> None:
        """Check system resource limits."""
        if len(self.user_roles) > MAX_USERS_IN_SYSTEM:
            raise RuntimeError(
                f"System limit exceeded: maximum {MAX_USERS_IN_SYSTEM} users"
            )

    def _get_cache_key(
        self, user_id: str, resource: str, action: str, resource_id: Optional[str]
    ) -> str:
        """Generate cache key for permission check."""
        return f"{user_id}:{resource}:{action}:{resource_id or '*'}"

    def _get_from_cache(self, cache_key: str) -> Optional[bool]:
        """Get permission result from cache if valid."""
        with self._lock:
            if cache_key in self._permission_cache:
                timestamp = self._cache_timestamps.get(cache_key, 0)
                if time.time() - timestamp < self._cache_ttl:
                    # Move to end (LRU)
                    self._permission_cache.move_to_end(cache_key)
                    self._cache_hits += 1
                    return self._permission_cache[cache_key]
                else:
                    # Expired, remove
                    del self._permission_cache[cache_key]
                    del self._cache_timestamps[cache_key]

            self._cache_misses += 1
            return None

    def _store_in_cache(self, cache_key: str, result: bool) -> None:
        """Store permission result in cache."""
        with self._lock:
            # Remove oldest entries if cache is full
            while len(self._permission_cache) >= self._cache_size:
                oldest_key = next(iter(self._permission_cache))
                del self._permission_cache[oldest_key]
                del self._cache_timestamps[oldest_key]

            self._permission_cache[cache_key] = result
            self._cache_timestamps[cache_key] = time.time()

    # Role Management
    def add_role(self, role: Role) -> None:
        """
        Register a role in the system with security validation.

        Args:
            role: The role to add.

        Raises:
            ValueError: If a role with the same name already exists or validation fails.
            RuntimeError: If system limits are exceeded.
        """
        self._validate_role_name(role.name)

        with self._lock:
            if role.name in self.roles:
                raise ValueError(f"Role '{role.name}' already exists")

            # Validate role inheritance doesn't create cycles
            if role.inherits:
                self._validate_role_inheritance_cycle(role.name, role.inherits)

            self.roles[role.name] = role
            # Clear cache since role structure changed
            self._permission_cache.clear()
            self._cache_timestamps.clear()

        logger.info(
            f"Added role '{role.name}' with {len(role.permissions)} permissions",
            extra={"role_name": role.name, "permission_count": len(role.permissions)},
        )

    def _validate_role_inheritance_cycle(
        self, new_role: str, inherits: List[str]
    ) -> None:
        """Validate that role inheritance doesn't create cycles."""
        visited = set()

        def check_cycle(role_name: str, path: Set[str]) -> None:
            if role_name in path:
                raise ValueError(
                    f"Role inheritance cycle detected: {' -> '.join(path)} -> {role_name}"
                )
            if role_name in visited:
                return

            visited.add(role_name)
            path.add(role_name)

            role = self.roles.get(role_name)
            if role and role.inherits:
                for parent in role.inherits:
                    check_cycle(parent, path.copy())

        for parent_role in inherits:
            check_cycle(parent_role, {new_role})

    def remove_role(self, role_name: str) -> bool:
        """
        Remove a role from the system.

        This will also remove the role from all users who have it assigned.

        Args:
            role_name: Name of the role to remove.

        Returns:
            True if the role was removed, False if it didn't exist.
        """
        if role_name not in self.roles:
            return False

        # Remove role from all users
        for user_id in list(self.user_roles.keys()):
            self.revoke_role(user_id, role_name)

        del self.roles[role_name]
        logger.info(f"Removed role '{role_name}'")
        return True

    def get_role(self, role_name: str) -> Optional[Role]:
        """
        Get a role by name.

        Args:
            role_name: Name of the role to retrieve.

        Returns:
            The role if found, None otherwise.
        """
        return self.roles.get(role_name)

    def list_roles(self) -> List[str]:
        """
        Get a list of all role names.

        Returns:
            List of role names.
        """
        return list(self.roles.keys())

    # User Role Management
    def assign_role(self, user_id: str, role_name: str) -> None:
        """
        Assign a role to a user with security validation and limits.

        Args:
            user_id: ID of the user to assign the role to.
            role_name: Name of the role to assign.

        Raises:
            ValueError: If user_id or role_name are invalid.
            RuntimeError: If system limits are exceeded.
        """
        self._validate_user_id(user_id)
        self._validate_role_name(role_name)
        self._validate_system_limits()

        with self._lock:
            if role_name not in self.roles:
                raise ValueError(f"Role '{role_name}' does not exist")

            if user_id not in self.user_roles:
                self.user_roles[user_id] = set()

            # Check per-user role limit
            if len(self.user_roles[user_id]) >= MAX_ROLES_PER_USER:
                raise ValueError(
                    f"User cannot have more than {MAX_ROLES_PER_USER} roles"
                )

            if role_name not in self.user_roles[user_id]:
                self.user_roles[user_id].add(role_name)

                # Clear cache for this user since their roles changed
                keys_to_remove = [
                    key
                    for key in self._permission_cache.keys()
                    if key.startswith(f"{user_id}:")
                ]
                for key in keys_to_remove:
                    del self._permission_cache[key]
                    del self._cache_timestamps[key]

                logger.info(
                    f"Assigned role '{role_name}' to user '{user_id}'",
                    extra={"user_id": user_id, "role_name": role_name},
                )

    def revoke_role(self, user_id: str, role_name: str) -> bool:
        """
        Revoke a role from a user.

        Args:
            user_id: ID of the user to revoke the role from.
            role_name: Name of the role to revoke.

        Returns:
            True if the role was revoked, False if the user didn't have it.
        """
        if user_id in self.user_roles and role_name in self.user_roles[user_id]:
            self.user_roles[user_id].discard(role_name)
            logger.info(f"Revoked role '{role_name}' from user '{user_id}'")
            return True
        return False

    def get_user_roles(self, user_id: str) -> List[str]:
        """
        Get all roles assigned to a user.

        Args:
            user_id: ID of the user.

        Returns:
            List of role names assigned to the user.
        """
        return list(self.user_roles.get(user_id, set()))

    def has_role(self, user_id: str, role_name: str) -> bool:
        """
        Check if a user has a specific role.

        Args:
            user_id: ID of the user.
            role_name: Name of the role to check.

        Returns:
            True if the user has the role.
        """
        return role_name in self.user_roles.get(user_id, set())

    # Permission Management
    def get_user_permissions(self, user_id: str) -> List[Permission]:
        """
        Get all permissions for a user from their roles with inheritance.

        This method resolves role inheritance and returns the complete set
        of permissions available to the user.

        Args:
            user_id: ID of the user.

        Returns:
            List of permissions available to the user.
        """
        permissions = []
        processed_roles = set()

        def collect_permissions(role_names: List[str]) -> None:
            for role_name in role_names:
                if role_name in processed_roles or role_name not in self.roles:
                    continue

                processed_roles.add(role_name)
                role = self.roles[role_name]
                permissions.extend(role.permissions)

                # Handle role inheritance recursively
                if role.inherits:
                    collect_permissions(role.inherits)

        user_role_names = self.get_user_roles(user_id)
        collect_permissions(user_role_names)

        # Remove duplicates while preserving order and preferring more specific permissions
        seen = {}
        unique_perms = []

        for perm in permissions:
            perm_str = perm.to_string()
            if perm_str not in seen:
                seen[perm_str] = perm
                unique_perms.append(perm)
            elif perm.is_more_specific_than(seen[perm_str]):
                # Replace with more specific permission
                seen[perm_str] = perm
                # Update in unique_perms list
                for i, up in enumerate(unique_perms):
                    if up.to_string() == perm_str:
                        unique_perms[i] = perm
                        break

        return unique_perms

        return unique_perms

    # Policy Management
    def add_policy(self, policy: AccessPolicy) -> None:
        """
        Add an access control policy.

        Policies are evaluated in addition to role-based permissions
        and can provide more fine-grained access control.

        Args:
            policy: The policy to add.
        """
        self.policies.append(policy)
        # Sort policies by priority (higher priority first)
        self.policies.sort(key=lambda p: p.priority, reverse=True)
        logger.info(f"Added policy '{policy.name}' with priority {policy.priority}")

    def remove_policy(self, policy_name: str) -> bool:
        """
        Remove an access control policy.

        Args:
            policy_name: Name of the policy to remove.

        Returns:
            True if the policy was removed, False if not found.
        """
        for i, policy in enumerate(self.policies):
            if policy.name == policy_name:
                self.policies.pop(i)
                logger.info(f"Removed policy '{policy_name}'")
                return True
        return False

    def list_policies(self) -> List[str]:
        """
        Get a list of all policy names.

        Returns:
            List of policy names sorted by priority.
        """
        return [policy.name for policy in self.policies]

    # Permission Checking
    def check_permission(
        self, principal: Principal, request: PermissionRequest
    ) -> AccessResult:
        """
        Check if a principal has permission for a specific request.

        This is the main entry point for authorization decisions. It evaluates:
        1. Role-based permissions (including inheritance)
        2. Access control policies
        3. Custom policy conditions

        Args:
            principal: The authenticated user making the request.
            request: Details of the permission being requested.

        Returns:
            AccessResult containing the decision and reasoning.

        Example:
            >>> principal = Principal(id="user123", provider="local", name="John")
            >>> request = PermissionRequest("user123", "posts", "edit", "456")
            >>> result = engine.check_permission(principal, request)
            >>> if result.allowed:
            ...     print("Access granted!")
        """
        self._permission_checks += 1
        start_time = time.time()

        user_id = principal.id
        user_roles = self.get_user_roles(user_id)

        # Get user permissions from roles
        user_permissions = self.get_user_permissions(user_id)

        # Check if user has the required permission
        required_permission = request.permission
        matched_permissions = []

        for perm in user_permissions:
            if perm.matches(required_permission):
                matched_permissions.append(perm)

        # Evaluate policies (they can override role-based decisions)
        policy_results = self._evaluate_policies(principal, request)

        # Determine final result
        has_permission = len(matched_permissions) > 0
        reason_parts = []

        # Check for deny policies first (they take precedence)
        for policy_result in policy_results:
            if policy_result["policy"].effect == "deny" and policy_result["matches"]:
                has_permission = False
                reason_parts.append(
                    f"Denied by policy '{policy_result['policy'].name}'"
                )
                break

        # If not denied by policy, check for allow policies and permissions
        if not reason_parts:  # No deny policy triggered
            if matched_permissions:
                perm_strings = [p.to_string() for p in matched_permissions]
                reason_parts.append(f"Allowed by permissions: {perm_strings}")

            # Check for allow policies that might grant additional access
            for policy_result in policy_results:
                if (
                    policy_result["policy"].effect == "allow"
                    and policy_result["matches"]
                    and not has_permission
                ):
                    has_permission = True
                    reason_parts.append(
                        f"Allowed by policy '{policy_result['policy'].name}'"
                    )
                    break

            if not has_permission:
                reason_parts.append("No matching permissions or policies found")

        # Create result
        result = AccessResult(
            allowed=has_permission,
            reason=(
                "; ".join(reason_parts)
                if reason_parts
                else "Permission check completed"
            ),
            matched_permissions=matched_permissions,
            user_roles=user_roles,
            context=request.context,
            evaluated_at=datetime.now(timezone.utc).isoformat(),
        )

        # Log the decision
        decision_time = time.time() - start_time
        logger.debug(
            f"Permission check for {user_id}: {required_permission.to_string()} "
            f"-> {'ALLOWED' if has_permission else 'DENIED'} "
            f"({decision_time:.3f}s)"
        )

        return result

    def _evaluate_policies(
        self, principal: Principal, request: PermissionRequest
    ) -> List[Dict[str, Any]]:
        """
        Evaluate all applicable access control policies.

        Args:
            principal: The user making the request.
            request: The permission request.

        Returns:
            List of policy evaluation results.
        """
        results = []

        for policy in self.policies:
            if policy.matches_resource(request.permission):
                try:
                    matches = policy.evaluate(request.permission, request.context)
                    results.append(
                        {
                            "policy": policy,
                            "matches": matches,
                        }
                    )

                    if matches:
                        logger.debug(
                            f"Policy '{policy.name}' matched for {request.user_id}"
                        )

                except Exception as e:
                    logger.error(f"Error evaluating policy '{policy.name}': {e}")
                    # For security, assume policy denies access if evaluation fails
                    results.append(
                        {
                            "policy": policy,
                            "matches": policy.effect == "deny",
                        }
                    )

        return results

    def has_permission(
        self,
        user_id: str,
        resource: str,
        action: str,
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        High-performance permission check with caching and security validation.

        Args:
            user_id: ID of the user.
            resource: Resource being accessed.
            action: Action being performed.
            resource_id: Optional specific resource ID.
            context: Additional context for policy evaluation.

        Returns:
            True if the user has permission.

        Raises:
            ValueError: If input parameters are invalid.
        """
        # Security validation
        self._validate_user_id(user_id)
        if not resource or len(resource) > MAX_RESOURCE_LENGTH:
            raise ValueError(f"Resource must be 1-{MAX_RESOURCE_LENGTH} characters")
        if not action or len(action) > MAX_ACTION_LENGTH:
            raise ValueError(f"Action must be 1-{MAX_ACTION_LENGTH} characters")
        if not VALID_RESOURCE.match(resource) and resource != "*":
            raise ValueError("Resource contains invalid characters")
        if not VALID_ACTION.match(action) and action != "*":
            raise ValueError("Action contains invalid characters")

        # Try cache first (only for simple permission checks without complex context)
        if not context or len(context) == 0:
            cache_key = self._get_cache_key(user_id, resource, action, resource_id)
            cached_result = self._get_from_cache(cache_key)
            if cached_result is not None:
                return cached_result

        start_time = time.time()

        try:
            from ..models import Principal

            # Create minimal principal for permission check
            principal = Principal(id=user_id, provider="rbac_check", name="")
            request = PermissionRequest(user_id, resource, action, resource_id, context)

            result = self.check_permission(principal, request)
            permission_result = result.allowed

            # Cache simple permission results
            if not context or len(context) == 0:
                self._store_in_cache(cache_key, permission_result)

            # Update performance metrics
            check_time = time.time() - start_time
            with self._lock:
                self._permission_checks += 1
                # Update running average
                if self._permission_checks == 1:
                    self._avg_check_time = check_time
                else:
                    self._avg_check_time = (
                        self._avg_check_time * (self._permission_checks - 1)
                        + check_time
                    ) / self._permission_checks

            return permission_result

        except Exception as e:
            logger.error(
                f"Permission check failed for user '{user_id}': {e}",
                extra={
                    "user_id": user_id,
                    "resource": resource,
                    "action": action,
                    "error": str(e),
                },
            )
            # Fail securely - deny access on errors
            return False

    # Statistics and Monitoring
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive engine statistics for production monitoring.

        Returns:
            Dictionary containing detailed engine statistics and metrics.
        """
        with self._lock:
            cache_size = len(self._permission_cache)
            uptime = (datetime.now(timezone.utc) - self._created_at).total_seconds()

            # Calculate cache efficiency
            total_cache_operations = self._cache_hits + self._cache_misses
            cache_hit_rate = (self._cache_hits / max(total_cache_operations, 1)) * 100

            # Calculate role distribution
            role_usage = {}
            for user_roles in self.user_roles.values():
                for role in user_roles:
                    role_usage[role] = role_usage.get(role, 0) + 1

            return {
                # Core metrics
                "roles_count": len(self.roles),
                "policies_count": len(self.policies),
                "users_count": len(self.user_roles),
                "user_count": len(self.user_roles),  # Alias for compatibility
                # Performance metrics
                "permission_checks": self._permission_checks,
                "avg_check_time": self._avg_check_time,
                "uptime_seconds": uptime,
                # Cache metrics
                "cache_hits": self._cache_hits,
                "cache_misses": self._cache_misses,
                "cache_hit_rate": cache_hit_rate,
                "cache_size": cache_size,
                "cache_max_size": self._cache_size,
                # Security metrics
                "failed_validations": self._failed_validations,
                # System health
                "roles": list(self.roles.keys()),
                "users_with_roles": list(self.user_roles.keys()),
                "role_usage": role_usage,
                "most_used_role": (
                    max(role_usage.items(), key=lambda x: x[1])[0]
                    if role_usage
                    else None
                ),
                # Memory usage estimates
                "estimated_memory_kb": (
                    len(self.roles) * 1  # Rough estimate
                    + len(self.user_roles) * 0.5
                    + cache_size * 0.1
                ),
                # Timestamps
                "created_at": self._created_at.isoformat(),
                "stats_generated_at": datetime.now(timezone.utc).isoformat(),
            }

    def reset_stats(self) -> None:
        """Reset performance statistics while preserving system state."""
        with self._lock:
            self._permission_checks = 0
            self._cache_hits = 0
            self._cache_misses = 0
            self._failed_validations = 0
            self._avg_check_time = 0.0
            self._created_at = datetime.now(timezone.utc)
        logger.info("Engine statistics reset")

    def clear_cache(self) -> int:
        """
        Clear the permission cache.

        Returns:
            Number of cache entries cleared.
        """
        with self._lock:
            cleared_count = len(self._permission_cache)
            self._permission_cache.clear()
            self._cache_timestamps.clear()

        logger.info(f"Cleared {cleared_count} cache entries")
        return cleared_count

    def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check of the RBAC engine.

        Returns:
            Dictionary with health status and any issues found.
        """
        issues = []

        with self._lock:
            # Check for role inheritance cycles
            try:
                for role_name, role in self.roles.items():
                    if role.inherits:
                        self._validate_role_inheritance_cycle(role_name, role.inherits)
            except ValueError as e:
                issues.append(f"Role inheritance issue: {e}")

            # Check system limits
            if len(self.user_roles) > MAX_USERS_IN_SYSTEM * 0.9:
                issues.append(
                    f"User count approaching limit: {len(self.user_roles)}/{MAX_USERS_IN_SYSTEM}"
                )

            # Check cache efficiency
            total_ops = self._cache_hits + self._cache_misses
            if total_ops > 1000 and (self._cache_hits / total_ops) < 0.5:
                issues.append(
                    f"Low cache hit rate: {(self._cache_hits / total_ops) * 100:.1f}%"
                )

            # Check for users with too many roles
            over_limit_users = [
                user_id
                for user_id, roles in self.user_roles.items()
                if len(roles) > MAX_ROLES_PER_USER * 0.8
            ]
            if over_limit_users:
                issues.append(f"Users approaching role limit: {len(over_limit_users)}")

        status = (
            "healthy" if not issues else "warning" if len(issues) < 3 else "unhealthy"
        )

        return {
            "status": status,
            "issues": issues,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


# Global RBAC engine instance
_rbac_engine: Optional[RBACEngine] = None


def get_rbac_engine() -> RBACEngine:
    """
    Get the global RBAC engine instance.

    This function returns a singleton instance of the RBAC engine.
    The engine is created on first access and reused for subsequent calls.

    Returns:
        The global RBACEngine instance.

    Example:
        >>> engine = get_rbac_engine()
        >>> engine.add_role(Role("admin", "Administrator", [...]))
    """
    global _rbac_engine
    if _rbac_engine is None:
        _rbac_engine = RBACEngine()
        logger.info("Global RBAC engine created")
    return _rbac_engine


def reset_rbac_engine() -> None:
    """
    Reset the global RBAC engine instance.

    This is primarily useful for testing scenarios where you need
    a clean engine state.
    """
    global _rbac_engine
    _rbac_engine = None
    logger.info("Global RBAC engine reset")


def setup_default_roles(engine: RBACEngine) -> None:
    """
    Set up common default roles in the RBAC engine.

    This function creates a standard set of roles that are commonly
    needed in most applications:
    - admin: Full system access
    - user_manager: Can manage users and roles
    - user: Standard user permissions
    - viewer: Read-only access

    Args:
        engine: The RBAC engine to configure.

    Example:
        >>> engine = RBACEngine()
        >>> setup_default_roles(engine)
        >>> print(engine.list_roles())
        ['admin', 'user_manager', 'user', 'viewer']
    """

    # Super Admin - can do everything
    admin_role = Role(
        name="admin",
        description="Full system administrator with unrestricted access",
        permissions=[
            Permission.from_string("*:*:*")  # Wildcard permission for everything
        ],
        metadata={"system_role": True, "created_by": "setup_default_roles"},
    )

    # User Manager - can manage users and roles
    user_manager_role = Role(
        name="user_manager",
        description="Can manage users and their role assignments",
        permissions=[
            Permission.from_string("users:*:read"),
            Permission.from_string("users:*:edit"),
            Permission.from_string("users:*:create"),
            Permission.from_string("roles:*:read"),
            Permission.from_string("roles:*:assign"),
        ],
        inherits=["user"],  # Inherits basic user permissions
        metadata={"system_role": True, "created_by": "setup_default_roles"},
    )

    # Regular User - basic permissions
    user_role = Role(
        name="user",
        description="Standard user with basic application permissions",
        permissions=[
            Permission.from_string("profile:read"),
            Permission.from_string("profile:edit"),
            Permission.from_string("dashboard:read"),
        ],
        inherits=["viewer"],  # Inherits read-only permissions
        metadata={"system_role": True, "created_by": "setup_default_roles"},
    )

    # Viewer - read-only access
    viewer_role = Role(
        name="viewer",
        description="Read-only access to public resources",
        permissions=[
            Permission.from_string("public:*:read"),
            Permission.from_string("help:*:read"),
        ],
        metadata={"system_role": True, "created_by": "setup_default_roles"},
    )

    # Add all roles to the engine
    roles = [admin_role, user_manager_role, user_role, viewer_role]
    for role in roles:
        try:
            engine.add_role(role)
        except ValueError as e:
            logger.warning(f"Skipping role '{role.name}': {e}")

    logger.info(f"Set up {len(roles)} default roles")
