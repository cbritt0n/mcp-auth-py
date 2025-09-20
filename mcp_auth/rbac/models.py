"""
RBAC Models - Data structures for Role-Based Access Control.

This module defines the core data models used in the RBAC extension:
- Permission: Represents specific access rights to resources
- Role: Collections of permissions that can be assigned to users
- PermissionRequest: Request to check access permissions
- AccessResult: Result of permission evaluation
- AccessPolicy: Advanced policy-based access control
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class AccessLevel(Enum):
    """
    Standard access levels for resources.

    These are common action types that can be used in permissions
    for consistency across the application.
    """

    READ = "read"
    WRITE = "write"
    EDIT = "edit"
    DELETE = "delete"
    ADMIN = "admin"
    CREATE = "create"
    UPDATE = "update"
    LIST = "list"


@dataclass(frozen=True)
class Permission:
    """
    Represents a specific permission on a resource.

    Permissions define what actions can be performed on which resources.
    They support hierarchical resource identification and wildcard matching.

    Permission Formats:
        - Simple: "users:read" (action on all resources of type)
        - Specific: "users:123:edit" (action on specific resource)
        - Wildcard: "users:*:admin" (action on any resource of type)
        - Global: "*:*:*" (all actions on all resources)

    Attributes:
        resource: The resource type (e.g., "users", "posts", "projects")
        action: The action to perform (e.g., "read", "write", "delete")
        resource_id: Optional specific resource identifier or "*" for wildcard

    Example:
        >>> perm = Permission.from_string("posts:123:edit")
        >>> print(perm.resource)  # "posts"
        >>> print(perm.resource_id)  # "123"
        >>> print(perm.action)  # "edit"
    """

    resource: str
    action: str
    resource_id: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate permission data after initialization."""
        if not self.resource:
            raise ValueError("Permission resource cannot be empty")
        if not self.action:
            raise ValueError("Permission action cannot be empty")

        # Validate resource and action format (alphanumeric, underscore, hyphen)
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.resource) and self.resource != "*":
            raise ValueError(f"Invalid resource format: {self.resource}")
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.action) and self.action != "*":
            raise ValueError(f"Invalid action format: {self.action}")

    @classmethod
    def from_string(cls, perm_str: str) -> "Permission":
        """
        Parse permission from string format.

        Args:
            perm_str: Permission string in format "resource:action" or
                     "resource:resource_id:action"

        Returns:
            Permission instance.

        Raises:
            ValueError: If permission string format is invalid.

        Example:
            >>> Permission.from_string("users:read")
            Permission(resource='users', action='read', resource_id=None)
            >>> Permission.from_string("users:123:edit")
            Permission(resource='users', action='edit', resource_id='123')
        """
        parts = perm_str.split(":")
        if len(parts) == 2:
            return cls(resource=parts[0], action=parts[1])
        elif len(parts) == 3:
            return cls(resource=parts[0], action=parts[2], resource_id=parts[1])
        else:
            raise ValueError(
                f"Invalid permission format: {perm_str}. "
                f"Expected 'resource:action' or 'resource:id:action'"
            )

    def to_string(self) -> str:
        """
        Convert permission to string format.

        Returns:
            String representation of the permission.
        """
        if self.resource_id:
            return f"{self.resource}:{self.resource_id}:{self.action}"
        return f"{self.resource}:{self.action}"

    def matches(self, other: "Permission") -> bool:
        """
        Check if this permission matches another permission.

        Supports wildcard matching where "*" matches any value.
        Either permission can contain wildcards.

        Args:
            other: The permission to match against.

        Returns:
            True if the permissions match, False otherwise.

        Example:
            >>> p1 = Permission.from_string("users:*:edit")
            >>> p2 = Permission.from_string("users:123:edit")
            >>> p1.matches(p2)  # True
            >>> p2.matches(p1)  # True (bidirectional)
        """
        # Check resource
        if (
            self.resource != "*"
            and other.resource != "*"
            and self.resource != other.resource
        ):
            return False

        # Check action
        if self.action != "*" and other.action != "*" and self.action != other.action:
            return False

        # Check resource ID (with wildcard support)
        if (
            self.resource_id is not None
            and other.resource_id is not None
            and self.resource_id != "*"
            and other.resource_id != "*"
            and self.resource_id != other.resource_id
        ):
            return False

        return True

    def is_more_specific_than(self, other: "Permission") -> bool:
        """
        Check if this permission is more specific than another.

        A permission is more specific if it has fewer wildcards.

        Args:
            other: The permission to compare against.

        Returns:
            True if this permission is more specific.
        """
        self_wildcards = sum(
            [1 for val in [self.resource, self.action, self.resource_id] if val == "*"]
        )
        other_wildcards = sum(
            [
                1
                for val in [other.resource, other.action, other.resource_id]
                if val == "*"
            ]
        )

        return self_wildcards < other_wildcards


@dataclass
class Role:
    """
    Represents a role with a collection of permissions.

    Roles are named collections of permissions that can be assigned to users.
    They support inheritance, allowing roles to build upon other roles.

    Attributes:
        name: Unique identifier for the role.
        description: Human-readable description of the role's purpose.
        permissions: List of permissions granted by this role.
        inherits: List of role names that this role inherits from.
        metadata: Additional metadata for the role.

    Example:
        >>> editor_role = Role(
        ...     name="editor",
        ...     description="Content editor with post management permissions",
        ...     permissions=[
        ...         Permission.from_string("posts:create"),
        ...         Permission.from_string("posts:*:edit"),
        ...         Permission.from_string("posts:*:delete")
        ...     ],
        ...     inherits=["user"]  # Inherits basic user permissions
        ... )
    """

    name: str
    description: str
    permissions: List[Permission] = field(default_factory=list)
    inherits: Optional[List[str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate role data after initialization."""
        if not self.name:
            raise ValueError("Role name cannot be empty")
        if not self.description:
            raise ValueError("Role description cannot be empty")

        # Validate role name format
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.name):
            raise ValueError(f"Invalid role name format: {self.name}")

        # Ensure permissions is a list
        if not isinstance(self.permissions, list):
            raise ValueError("Role permissions must be a list")

        # Ensure inherits is a list if provided
        if self.inherits is not None and not isinstance(self.inherits, list):
            raise ValueError("Role inherits must be a list")

    def has_permission(self, permission: Permission) -> bool:
        """
        Check if this role has a specific permission.

        Args:
            permission: The permission to check for.

        Returns:
            True if the role has the permission (directly, not through inheritance).
        """
        return any(p.matches(permission) for p in self.permissions)

    def add_permission(self, permission: Permission) -> None:
        """
        Add a permission to this role.

        Args:
            permission: The permission to add.
        """
        if permission not in self.permissions:
            self.permissions.append(permission)

    def remove_permission(self, permission: Permission) -> bool:
        """
        Remove a permission from this role.

        Args:
            permission: The permission to remove.

        Returns:
            True if the permission was removed, False if it wasn't found.
        """
        for i, p in enumerate(self.permissions):
            if p.matches(permission):
                self.permissions.pop(i)
                return True
        return False

    def get_permission_strings(self) -> List[str]:
        """
        Get all permissions as strings.

        Returns:
            List of permission strings.
        """
        return [p.to_string() for p in self.permissions]


@dataclass
class PermissionRequest:
    """
    Represents a request to check permissions for a user.

    This is used when checking if a user has permission to perform
    a specific action on a resource.

    Attributes:
        user_id: Identifier of the user requesting access.
        resource: The resource being accessed.
        action: The action being performed.
        resource_id: Optional specific resource identifier.
        context: Additional context information for the request.

    Example:
        >>> request = PermissionRequest(
        ...     user_id="user123",
        ...     resource="posts",
        ...     action="edit",
        ...     resource_id="456",
        ...     context={"ip": "192.168.1.1", "time": "2023-09-20T10:00:00Z"}
        ... )
    """

    user_id: str
    resource: str
    action: str
    resource_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Validate request data after initialization."""
        if not self.user_id:
            raise ValueError("User ID cannot be empty")
        if not self.resource:
            raise ValueError("Resource cannot be empty")
        if not self.action:
            raise ValueError("Action cannot be empty")

    @property
    def permission(self) -> Permission:
        """
        Get the Permission object for this request.

        Returns:
            Permission object representing the requested access.
        """
        return Permission(self.resource, self.action, self.resource_id)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the request to a dictionary.

        Returns:
            Dictionary representation of the request.
        """
        return {
            "user_id": self.user_id,
            "resource": self.resource,
            "action": self.action,
            "resource_id": self.resource_id,
            "context": self.context,
        }


@dataclass
class AccessResult:
    """
    Represents the result of a permission check.

    Contains detailed information about whether access was granted
    and the reasoning behind the decision.

    Attributes:
        allowed: Whether access is granted.
        reason: Human-readable explanation of the decision.
        matched_permissions: Permissions that matched the request.
        user_roles: Roles the user has that were considered.
        context: Additional context about the decision.
        evaluated_at: Timestamp when the evaluation occurred.

    Example:
        >>> result = AccessResult(
        ...     allowed=True,
        ...     reason="User has 'editor' role with posts:*:edit permission",
        ...     matched_permissions=[Permission.from_string("posts:*:edit")],
        ...     user_roles=["editor", "user"]
        ... )
    """

    allowed: bool
    reason: str
    matched_permissions: List[Permission] = field(default_factory=list)
    user_roles: List[str] = field(default_factory=list)
    context: Optional[Dict[str, Any]] = None
    evaluated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the result to a dictionary.

        Returns:
            Dictionary representation of the result.
        """
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "matched_permissions": [p.to_string() for p in self.matched_permissions],
            "user_roles": self.user_roles,
            "context": self.context,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class AccessPolicy:
    """
    Defines advanced access control policies with conditions.

    Policies allow for more complex access control rules beyond simple
    role-based permissions, including conditional logic and custom evaluation.

    Attributes:
        name: Unique identifier for the policy.
        description: Human-readable description of the policy.
        resource_pattern: Resource pattern this policy applies to (supports wildcards).
        conditions: Additional conditions that must be met.
        effect: Whether this policy allows or denies access ("allow" or "deny").
        priority: Policy priority (higher numbers take precedence).
        custom_check: Optional custom function for complex evaluation logic.

    Example:
        >>> policy = AccessPolicy(
        ...     name="owner_edit_policy",
        ...     description="Users can edit their own content",
        ...     resource_pattern="posts:*:edit",
        ...     conditions={"owner_check": True},
        ...     effect="allow",
        ...     priority=10
        ... )
    """

    name: str
    description: str
    resource_pattern: str
    conditions: Dict[str, Any] = field(default_factory=dict)
    effect: str = "allow"
    priority: int = 0
    custom_check: Optional[Callable] = None

    def __post_init__(self) -> None:
        """Validate policy data after initialization."""
        if not self.name:
            raise ValueError("Policy name cannot be empty")
        if not self.description:
            raise ValueError("Policy description cannot be empty")
        if not self.resource_pattern:
            raise ValueError("Policy resource pattern cannot be empty")

        if self.effect not in ["allow", "deny"]:
            raise ValueError("Policy effect must be 'allow' or 'deny'")

    def matches_resource(self, permission: Permission) -> bool:
        """
        Check if this policy applies to the given permission.

        Args:
            permission: The permission to check against.

        Returns:
            True if the policy applies to this permission.
        """
        pattern_parts = self.resource_pattern.split(":")
        perm_str = permission.to_string()
        perm_parts = perm_str.split(":")

        if len(pattern_parts) != len(perm_parts):
            return False

        for pattern_part, perm_part in zip(pattern_parts, perm_parts):
            if pattern_part != "*" and pattern_part != perm_part:
                return False

        return True

    def evaluate(
        self, permission: Permission, context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Evaluate this policy against a permission request.

        Args:
            permission: The permission being requested.
            context: Additional context for evaluation.

        Returns:
            True if the policy conditions are met.
        """
        if not self.matches_resource(permission):
            return False

        # If there's a custom check function, use it
        if self.custom_check:
            return self.custom_check(permission, context, self.conditions)

        # Default condition evaluation (basic key-value matching)
        context = context or {}
        return all(context.get(key) == value for key, value in self.conditions.items())
