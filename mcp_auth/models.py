"""
Core data models for mcp-auth-py authentication system.

This module defines the fundamental data structures used throughout the
authentication system, providing a consistent interface for all providers.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Principal:
    """
    Represents an authenticated user/principal in the system.

    This is the canonical representation of an authenticated user that all
    authentication providers must return. It provides a consistent interface
    regardless of the underlying authentication mechanism.

    Attributes:
        id: Unique identifier for the principal (e.g., sub, oid, username).
            This should be stable and unique within the provider's context.
        provider: Name of the authentication provider that verified this principal
            (e.g., "local", "google", "aws", "azure").
        name: Human-readable display name for the principal, if available.
        email: Email address associated with the principal, if available.
        roles: List of roles or groups assigned to the principal. Used for
            basic role-based authorization. For advanced RBAC, use the
            rbac extension.
        raw: Raw claims dictionary from the authentication provider. Contains
            the original token payload or user data for advanced use cases.

    Example:
        Basic principal from JWT token:

        >>> principal = Principal(
        ...     id="user123",
        ...     provider="local",
        ...     name="John Doe",
        ...     email="john@example.com",
        ...     roles=["user", "editor"],
        ...     raw={"sub": "user123", "exp": 1640995200}
        ... )

    Note:
        The `raw` field should contain the complete, unmodified token payload
        or user data from the provider for debugging and advanced scenarios.
    """

    id: str
    provider: str
    name: Optional[str] = None
    email: Optional[str] = None
    roles: Optional[list[str]] = None
    raw: Optional[dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Validate principal data after initialization."""
        if not self.id:
            raise ValueError("Principal ID cannot be empty")
        if not self.provider:
            raise ValueError("Principal provider cannot be empty")

        # Ensure roles is always a list if provided
        if self.roles is not None and not isinstance(self.roles, list):
            raise ValueError("Principal roles must be a list")

    def has_role(self, role: str) -> bool:
        """
        Check if the principal has a specific role.

        Args:
            role: Role name to check for.

        Returns:
            True if the principal has the specified role, False otherwise.
        """
        return self.roles is not None and role in self.roles

    def has_any_role(self, roles: list[str]) -> bool:
        """
        Check if the principal has any of the specified roles.

        Args:
            roles: List of role names to check for.

        Returns:
            True if the principal has at least one of the specified roles.
        """
        if not self.roles:
            return False
        return any(role in self.roles for role in roles)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the principal to a dictionary representation.

        Returns:
            Dictionary containing all principal data.
        """
        return {
            "id": self.id,
            "provider": self.provider,
            "name": self.name,
            "email": self.email,
            "roles": self.roles,
            "raw": self.raw,
        }
