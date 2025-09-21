"""
RBAC (Role-Based Access Control) Extension for mcp-auth-py

This extension adds fine-grained permission control on top of mcp-auth-py's
authentication system, enabling resource-based access control.

Features:
- Resource-based permissions (e.g., 'users:read', 'projects:123:edit')
- Role definitions with permission sets
- FastAPI decorators for endpoint protection
- Dynamic policy evaluation
- Admin interface for role/permission management
"""

from .admin import create_rbac_admin_router, setup_rbac_admin
from .decorators import require_access, require_permissions, require_roles
from .engine import (
    AccessPolicy,
    Permission,
    RBACEngine,
    Role,
    get_rbac_engine,
    setup_default_roles,
)
from .models import AccessResult, PermissionRequest

__version__ = "0.1.0"

__all__ = [
    "RBACEngine",
    "Permission",
    "Role",
    "AccessPolicy",
    "get_rbac_engine",
    "setup_default_roles",
    "require_permissions",
    "require_roles",
    "require_access",
    "PermissionRequest",
    "AccessResult",
    "setup_rbac_admin",
    "create_rbac_admin_router",
]
