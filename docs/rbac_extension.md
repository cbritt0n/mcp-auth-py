# RBAC Extension - Complete Guide

The RBAC (Role-Based Access Control) extension adds comprehensive authorization capabilities to mcp-auth-py, allowing you to implement fine-grained access control based on roles and permissions.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Core Concepts](#core-concepts)
4. [FastAPI Integration](#fastapi-integration)
5. [Admin Interface](#admin-interface)
6. [Advanced Usage](#advanced-usage)
7. [Production Deployment](#production-deployment)
8. [API Reference](#api-reference)

## Overview

The RBAC extension provides:

- **Hierarchical Roles**: Roles that can inherit permissions from other roles
- **Resource-Specific Permissions**: Permissions can target specific resources or use wildcards
- **FastAPI Integration**: Decorators for protecting endpoints with role/permission checks
- **Admin Interface**: REST API for managing roles and permissions
- **Production Ready**: Thread-safe operations, caching, monitoring, and audit logging
- **Flexible Architecture**: Can be used standalone or integrated with existing auth providers

### Key Features

- ✅ **Thread-safe operations** with RLock for concurrent environments
- ✅ **High-performance caching** with LRU cache and TTL support
- ✅ **Comprehensive input validation** and security controls
- ✅ **Production monitoring** with health checks and metrics
- ✅ **Audit logging** for compliance and security tracking
- ✅ **Pydantic v2 compatibility** with modern validation patterns

## Quick Start

### 1. Basic Setup

```python
from mcp_auth.rbac import RBACEngine, Role, Permission
from mcp_auth.rbac.engine import setup_default_roles

# Create RBAC engine
engine = RBACEngine()

# Setup default roles (admin, user, viewer, user_manager)
setup_default_roles(engine)

# Or create custom roles
custom_role = Role(
    name="editor",
    description="Can edit content",
    permissions=[
        Permission.from_string("posts:create"),
        Permission.from_string("posts:*:edit"),  # Can edit any post
        Permission.from_string("posts:*:delete")
    ]
)
engine.add_role(custom_role)

# Assign role to user
engine.assign_role("user123", "editor")
```

### 2. FastAPI Integration

```python
from fastapi import FastAPI, Depends
from mcp_auth.rbac import require_permissions, require_roles

app = FastAPI()

@app.get("/posts")
@require_permissions("posts:read")
async def get_posts():
    return {"posts": [...]}

@app.post("/posts")
@require_roles("editor", "admin")
async def create_post():
    return {"message": "Post created"}

@app.put("/posts/{post_id}")
@require_permissions("posts:edit")  # Will check posts:{post_id}:edit
async def update_post(post_id: str):
    return {"message": f"Post {post_id} updated"}
```

### 3. Manual Permission Checking

```python
from mcp_auth.rbac import get_rbac_engine, PermissionRequest
from mcp_auth.models import Principal

engine = get_rbac_engine()
principal = Principal(id="user123", provider="local", name="John Doe")

# Check specific permission
request = PermissionRequest("user123", "posts", "edit", "123")
result = engine.check_permission(principal, request)

if result.allowed:
    print("Access granted!")
else:
    print(f"Access denied: {result.reason}")
```

## Core Concepts

### Permissions

Permissions follow the format `resource:action` or `resource:resource_id:action`:

```python
# General permissions
Permission.from_string("users:read")      # Read all users
Permission.from_string("posts:create")    # Create posts

# Resource-specific permissions
Permission.from_string("users:123:edit")  # Edit user 123
Permission.from_string("posts:456:delete") # Delete post 456

# Wildcard permissions
Permission.from_string("users:*:edit")    # Edit any user
Permission.from_string("*:*:*")          # Admin permission
```

### Roles

Roles are collections of permissions that can inherit from other roles:

```python
# Base role
base_role = Role(
    name="member",
    description="Basic member",
    permissions=[Permission.from_string("profile:read")]
)

# Role with inheritance
moderator_role = Role(
    name="moderator",
    description="Community moderator",
    permissions=[
        Permission.from_string("posts:*:moderate"),
        Permission.from_string("users:read")
    ],
    inherits=["member"]  # Inherits profile:read
)
```

### Permission Matching

The system supports flexible permission matching:

```python
# Exact match
Permission.from_string("users:read").matches(
    Permission.from_string("users:read")
) # True

# Wildcard matching
Permission.from_string("users:*:edit").matches(
    Permission.from_string("users:123:edit")
) # True

# Reverse wildcard matching
Permission.from_string("users:123:edit").matches(
    Permission.from_string("users:*:edit")
) # True
```

## FastAPI Decorators

### @require_permissions

Protect endpoints with specific permissions:

```python
@app.get("/users/{user_id}")
@require_permissions("users:read")
async def get_user(user_id: str):
    # For resource-specific endpoints, the decorator will
    # automatically check users:{user_id}:read
    pass

@app.get("/admin/users")
@require_permissions("users:read", resource_id="*")
async def admin_get_users():
    # Explicitly require wildcard permission
    pass
```

### @require_roles

Protect endpoints with role requirements:

```python
@app.post("/admin/settings")
@require_roles("admin")
async def update_settings():
    pass

@app.get("/moderator/dashboard")
@require_roles("moderator", "admin")  # Either role works
async def moderator_dashboard():
    pass
```

### @require_access

Advanced access control with custom logic:

```python
from mcp_auth.rbac import require_access, AccessPolicy

def owner_or_admin_policy(principal, resource_id, **kwargs):
    # Custom logic for ownership check
    if resource_id == principal.id:
        return True
    # Fallback to role check
    return "admin" in get_rbac_engine().get_user_roles(principal.id)

@app.get("/users/{user_id}/private")
@require_access(AccessPolicy(
    permissions=["users:read"],
    custom_check=owner_or_admin_policy
))
async def get_private_data(user_id: str):
    pass
```

## Admin Interface

The RBAC extension includes a complete admin interface:

```python
from mcp_auth.rbac.admin import create_rbac_admin_router

app = FastAPI()

# Mount admin interface
admin_router = create_rbac_admin_router()
app.include_router(admin_router, prefix="/admin/rbac")
```

### Admin Endpoints

- `GET /roles` - List all roles
- `POST /roles` - Create new role
- `GET /roles/{role_name}` - Get role details
- `PUT /roles/{role_name}` - Update role
- `DELETE /roles/{role_name}` - Delete role
- `POST /users/{user_id}/roles` - Assign role to user
- `DELETE /users/{user_id}/roles/{role_name}` - Revoke user role
- `GET /users/{user_id}/roles` - Get user roles
- `GET /users/{user_id}/permissions` - Get user permissions
- `POST /check-permission` - Check permission for user

## Integration with Authentication

The RBAC extension works seamlessly with existing mcp-auth-py providers:

```python
from mcp_auth import AuthMiddleware
from mcp_auth.providers import LocalJWTProvider
from mcp_auth.rbac import require_permissions

# Setup authentication
auth_provider = LocalJWTProvider(secret_key="your-secret")
auth_middleware = AuthMiddleware(auth_provider)

app = FastAPI()
app.add_middleware(auth_middleware)

@app.get("/protected")
@require_permissions("resource:read")
async def protected_endpoint():
    # User must be authenticated AND have the required permission
    return {"message": "Access granted"}
```

## Advanced Usage

### Custom Permission Logic

```python
from mcp_auth.rbac.models import Permission

class CustomPermission(Permission):
    def matches(self, other: "Permission") -> bool:
        # Custom matching logic
        if self.action == "admin" and other.action in ["read", "write", "delete"]:
            return True
        return super().matches(other)
```

### Role Hierarchies

```python
# Create role hierarchy: admin > manager > employee > guest
roles = [
    Role("guest", "Guest user", [Permission.from_string("public:read")]),
    Role("employee", "Employee", [Permission.from_string("internal:read")], ["guest"]),
    Role("manager", "Manager", [Permission.from_string("internal:write")], ["employee"]),
    Role("admin", "Administrator", [Permission.from_string("*:*:*")], ["manager"])
]

for role in roles:
    engine.add_role(role)
```

### Async Operations

```python
# All RBAC operations are synchronous by default
# For async contexts, wrap in thread executor if needed
import asyncio
from functools import partial

async def async_permission_check(principal, request):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        partial(engine.check_permission, principal, request)
    )
```

## Best Practices

### 1. Permission Design

- Use hierarchical resource naming: `api:users:read`, `api:posts:write`
- Be specific with actions: `create`, `read`, `update`, `delete`, `list`
- Use wildcards sparingly: `*:*:*` should be admin-only

### 2. Role Design

- Keep roles focused and cohesive
- Use inheritance to avoid permission duplication
- Name roles after business functions: `content_editor`, `customer_support`

### 3. Security

- Always validate permissions at the API boundary
- Use resource-specific permissions for sensitive operations
- Regularly audit role assignments and permissions
- Log all permission checks for security monitoring

### 4. Performance

- Cache role/permission lookups for high-traffic endpoints
- Use specific permissions rather than checking multiple wildcards
- Consider pre-computing user permissions for frequent checks

## Migration Guide

### From Simple Auth to RBAC

```python
# Before: Simple role checks
@app.get("/admin")
async def admin_only():
    # Check user.role == "admin"
    pass

# After: RBAC permissions
@app.get("/admin")
@require_permissions("admin:access")
async def admin_only():
    pass

# Setup migration
engine = get_rbac_engine()
admin_role = Role("admin", "Administrator", [
    Permission.from_string("admin:access"),
    Permission.from_string("*:*:*")
])
engine.add_role(admin_role)
```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   - Check if user has required role assigned
   - Verify permission format matches expectation
   - Test with wildcard permissions for debugging

2. **Role Inheritance Not Working**
   - Ensure parent roles are added before child roles
   - Check for circular inheritance
   - Verify role names match exactly

3. **Decorator Not Working**
   - Ensure authentication middleware runs first
   - Check that request.state.principal is set
   - Verify decorator is applied to async functions correctly

### Debug Mode

```python
import logging

# Enable debug logging
logging.getLogger("mcp_auth.rbac").setLevel(logging.DEBUG)

# Check permissions manually
engine = get_rbac_engine()
result = engine.check_permission(principal, request)
print(f"Permission check: {result.allowed}, reason: {result.reason}")
```

## Examples

See `examples/rbac_demo.py` for a complete working example that demonstrates:

- Multiple authentication providers
- Role-based access control
- Resource-specific permissions
- Admin interface integration
- Custom permission logic

This example shows a blog system with different user roles (admin, editor, author, reader) and demonstrates how permissions work in practice.
