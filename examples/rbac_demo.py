"""
Complete RBAC Demonstration - Full-Featured Authorization Example

This comprehensive example demonstrates all aspects of the RBAC extension
for mcp-auth-py, including:

1. 🔐 FastAPI + mcp-auth-py Authentication Setup
2. 👥 Role-Based Access Control (RBAC) Configuration
3. 🛡️ Permission-based Endpoint Protection
4. ⚙️ Admin Interface for Role Management
5. 🌟 Real-World Permission Scenarios (Blog System)

## Architecture Overview

```
Authentication Layer (mcp-auth-py)
    ↓ JWT/OAuth2 token validation
Authorization Layer (RBAC Extension)
    ↓ Role & permission checking
Protected Endpoints
    ↓ Business logic
```

## Roles & Permissions Structure

- **admin**: Full system access (*:*:*)
- **blog_editor**: Can manage all blog content
  - posts:create, posts:*:edit, posts:*:delete
  - comments:*:moderate
- **author**: Can create and edit own posts
  - posts:create, posts:*:edit (with ownership check)
- **moderator**: Can moderate content
  - comments:*:moderate, users:*:suspend
- **user**: Basic authenticated user
  - profile:read, profile:edit, posts:read, comments:create

## Usage Instructions

1. **Start the server:**
   ```bash
   uvicorn examples.rbac_demo:app --reload
   ```

2. **Generate test tokens:**
   ```bash
   # Admin user
   mcp-auth-generate-token --user-id admin --name "Admin User"

   # Editor user
   mcp-auth-generate-token --user-id editor --name "Blog Editor"

   # Regular user
   mcp-auth-generate-token --user-id user123 --name "John Doe"
   ```

3. **Try the endpoints:**
   - GET / - Public welcome page
   - GET /posts - Read blog posts (requires posts:read)
   - POST /posts - Create new post (requires posts:create)
   - PUT /posts/{id} - Edit post (requires posts:*:edit or ownership)
   - DELETE /posts/{id} - Delete post (requires posts:*:delete)
   - GET /admin/rbac/roles - Manage roles (admin interface)

4. **Test authorization:**
   - Try accessing endpoints without tokens (401 Unauthorized)
   - Try accessing with insufficient permissions (403 Forbidden)
   - Use admin interface to manage roles and permissions

## API Documentation

Visit http://localhost:8000/docs for interactive API documentation.

## Admin Interface

The RBAC admin interface is mounted at `/admin/rbac/` and provides:
- Role management (create, read, update, delete)
- User role assignments
- Permission checking utilities
- System monitoring and statistics

Example admin endpoints:
- GET /admin/rbac/roles - List all roles
- POST /admin/rbac/roles - Create new role
- POST /admin/rbac/users/{user_id}/roles - Assign role to user

## Security Notes

⚠️  **Important for Production:**
- Change the JWT secret key
- Use proper authentication providers (Google, AWS, Azure)
- Implement rate limiting and request validation
- Add audit logging for permission checks
- Use HTTPS in production
"""

import logging
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from mcp_auth.rbac import (Permission, Role, get_rbac_engine, require_access,
                           require_permissions, require_roles,
                           setup_rbac_admin)
from mcp_auth.settings import Settings
from mcp_auth.setup import setup_auth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ================== CONFIGURATION ==================

# Configure authentication settings
settings = Settings(
    auth_provider="local",  # Can use any provider: google, aws, azure
    jwt_secret="rbac-demo-secret-key-change-in-production",
    debug=True,  # Enable debug mode for development
)


# ================== APP LIFESPAN ==================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager - replaces deprecated on_event"""
    # Startup
    setup_demo_roles()
    print("🔐 RBAC Demo API started!")
    print("📝 Visit /docs for interactive API documentation")
    print("🔧 Visit /admin/rbac/* for role management")
    print("🎯 Try these demo users:")
    print("   - user:admin (full access)")
    print("   - user:blogger123 (blog editor)")
    print("   - user:support456 (support agent)")
    print("   - user:manager789 (project manager)")

    yield

    # Shutdown (if needed)
    print("🔐 RBAC Demo API shutdown")


# Create FastAPI app with comprehensive metadata
app = FastAPI(
    title="RBAC Demo API",
    description="Comprehensive demonstration of mcp-auth-py with RBAC extension",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,  # Use new lifespan pattern instead of deprecated on_event
    openapi_tags=[
        {"name": "public", "description": "Public endpoints (no auth required)"},
        {"name": "blog", "description": "Blog content management"},
        {"name": "user", "description": "User profile and settings"},
        {"name": "admin", "description": "Administrative functions"},
        {"name": "rbac", "description": "Role-based access control"},
    ],
)

# Setup authentication middleware
app = setup_auth(app, settings)

# Setup RBAC admin interface at /admin/rbac/*
setup_rbac_admin(app, prefix="/admin")

# ================== DATA MODELS ==================


class BlogPost(BaseModel):
    """Blog post data model."""

    id: Optional[str] = None
    title: str
    content: str
    author_id: str
    published: bool = False
    tags: List[str] = []
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class Comment(BaseModel):
    """Comment data model."""

    id: Optional[str] = None
    post_id: str
    author_id: str
    content: str
    approved: bool = False
    created_at: Optional[str] = None


class UserProfile(BaseModel):
    """User profile data model."""

    id: str
    name: Optional[str] = None
    email: Optional[str] = None
    roles: List[str] = []
    created_at: Optional[str] = None


# Simple in-memory storage for demo purposes
blog_posts: Dict[str, BlogPost] = {}
comments: Dict[str, Comment] = {}
user_profiles: Dict[str, UserProfile] = {}

# ================== RBAC SETUP ==================


def setup_demo_roles():
    """Setup custom roles for our application"""
    engine = get_rbac_engine()

    # Blog Editor Role
    blog_editor = Role(
        name="blog_editor",
        description="Can create and edit blog posts",
        permissions=[
            Permission.from_string("blogs:read"),
            Permission.from_string("blogs:create"),
            Permission.from_string("blogs:edit"),
            Permission.from_string("comments:read"),
            Permission.from_string("comments:moderate"),
        ],
    )

    # Customer Support Role
    support_agent = Role(
        name="support_agent",
        description="Customer support agent with limited user access",
        permissions=[
            Permission.from_string("users:read"),
            Permission.from_string("tickets:*:read"),
            Permission.from_string("tickets:*:edit"),
            Permission.from_string("tickets:create"),
        ],
    )

    # Project Manager Role (inherits from user)
    project_manager = Role(
        name="project_manager",
        description="Can manage projects and assign team members",
        permissions=[
            Permission.from_string("projects:*:read"),
            Permission.from_string("projects:*:edit"),
            Permission.from_string("projects:create"),
            Permission.from_string("teams:*:read"),
            Permission.from_string("teams:*:edit"),
        ],
        inherits=["user"],  # Inherits basic user permissions
    )

    engine.add_role(blog_editor)
    engine.add_role(support_agent)
    engine.add_role(project_manager)

    # Assign some demo users to roles (in real app, you'd do this through admin interface)
    engine.assign_role("user:blogger123", "blog_editor")
    engine.assign_role("user:support456", "support_agent")
    engine.assign_role("user:manager789", "project_manager")
    engine.assign_role("user:admin", "admin")


# ================== PUBLIC ENDPOINTS ==================


@app.get("/")
async def root():
    """Public endpoint - no authentication required"""
    return {
        "message": "Welcome to RBAC Demo API",
        "auth_required": False,
        "endpoints": {
            "public": ["/", "/docs"],
            "protected": ["/profile", "/blogs", "/users", "/projects"],
            "admin": ["/admin/rbac/*"],
        },
        "demo_instructions": {
            "1": "Generate a token: POST /auth/token with user_id",
            "2": "Include in requests: Authorization: Bearer <token>",
            "3": "Try different user IDs to test different roles",
        },
    }


# ================== AUTHENTICATION & PROFILE ==================


@app.get("/profile")
async def get_profile(request: Request):
    """Get current user profile - requires authentication only"""
    user = request.state.principal
    engine = get_rbac_engine()

    return {
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "provider": user.provider,
        },
        "rbac": {
            "roles": engine.get_user_roles(user.id),
            "permissions": [
                p.to_string() for p in engine.get_user_permissions(user.id)
            ],
        },
    }


# ================== BLOG SYSTEM ==================


@app.get("/blogs")
@require_permissions("blogs:read")
async def list_blogs(request: Request):
    """List all blogs - requires blogs:read permission"""
    return {
        "blogs": [
            {"id": 1, "title": "RBAC Introduction", "author": "blogger123"},
            {"id": 2, "title": "FastAPI Security", "author": "blogger123"},
        ],
        "access_info": "You have blogs:read permission",
    }


@app.post("/blogs")
@require_permissions("blogs:create")
async def create_blog(request: Request):
    """Create a new blog post - requires blogs:create permission"""
    user = request.state.principal
    return {
        "message": "Blog post created successfully",
        "author": user.id,
        "access_info": "You have blogs:create permission",
    }


@app.put("/blogs/{blog_id}")
@require_access("blogs", "edit", resource_id_param="blog_id")
async def edit_blog(blog_id: str, request: Request):
    """Edit a blog post - demonstrates dynamic permission checking"""
    user = request.state.principal
    return {
        "message": f"Blog {blog_id} updated successfully",
        "editor": user.id,
        "access_info": f"You have blogs:{blog_id}:edit permission",
    }


# ================== USER MANAGEMENT ==================


@app.get("/users")
@require_roles(["admin", "support_agent", "user_manager"])
async def list_users(request: Request):
    """List users - requires specific roles"""
    user = request.state.principal
    engine = get_rbac_engine()
    user_roles = engine.get_user_roles(user.id)

    return {
        "users": [
            {"id": "user:blogger123", "name": "Blog Writer", "role": "blog_editor"},
            {"id": "user:support456", "name": "Support Agent", "role": "support_agent"},
            {
                "id": "user:manager789",
                "name": "Project Manager",
                "role": "project_manager",
            },
        ],
        "access_info": f"Access granted via roles: {user_roles}",
    }


@app.get("/users/{user_id}")
@require_permissions("users:read", resource_id_param="user_id")
async def get_user(user_id: str, request: Request):
    """Get specific user - demonstrates resource-specific permissions"""
    current_user = request.state.principal

    # Additional business logic: users can always see their own profile
    if current_user.id == user_id:
        access_method = "own profile"
    else:
        access_method = "users:read permission"

    return {
        "user": {"id": user_id, "name": f"User {user_id}"},
        "access_info": f"Access granted via: {access_method}",
    }


# ================== PROJECT MANAGEMENT ==================


@app.get("/projects")
@require_permissions("projects:read")
async def list_projects(request: Request):
    """List projects - requires projects:read permission"""
    return {
        "projects": [
            {"id": 1, "name": "Website Redesign", "manager": "manager789"},
            {"id": 2, "name": "Mobile App", "manager": "manager789"},
        ]
    }


@app.post("/projects")
@require_permissions("projects:create")
async def create_project(request: Request):
    """Create project - requires projects:create permission"""
    user = request.state.principal
    return {"message": "Project created successfully", "manager": user.id}


# ================== SUPPORT TICKETS ==================


@app.get("/tickets/{ticket_id}")
@require_access("tickets", "read", resource_id_param="ticket_id")
async def get_ticket(ticket_id: str, request: Request):
    """Get support ticket - dynamic permission check"""
    return {
        "ticket": {
            "id": ticket_id,
            "title": "Login Issue",
            "status": "open",
            "priority": "high",
        }
    }


# ================== TOKEN GENERATION (FOR DEMO) ==================


@app.post("/auth/token")
async def generate_demo_token(user_data: dict):
    """Generate a demo JWT token for testing (normally handled by your auth provider)"""
    try:
        from jose import jwt
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="python-jose not installed. Run: pip install python-jose[cryptography]",
        )

    user_id = user_data.get("user_id", "user:demo")
    name = user_data.get("name", "Demo User")

    payload = {
        "sub": user_id,
        "name": name,
        "email": f"{user_id.split(':')[-1]}@example.com",
    }

    token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")

    return {
        "token": token,
        "usage": f"Authorization: Bearer {token}",
        "user_id": user_id,
        "demo_users": {
            "user:blogger123": "Has blog_editor role",
            "user:support456": "Has support_agent role",
            "user:manager789": "Has project_manager role",
            "user:admin": "Has admin role (full access)",
        },
    }


# ================== ERROR HANDLERS ==================


@app.exception_handler(403)
async def rbac_exception_handler(request: Request, exc: HTTPException):
    """Custom 403 handler for RBAC errors"""
    user = getattr(request.state, "principal", None)
    engine = get_rbac_engine()

    response_data = {
        "error": "Access Denied",
        "detail": exc.detail,
        "endpoint": request.url.path,
        "method": request.method,
    }

    if user:
        response_data.update(
            {
                "user_id": user.id,
                "user_roles": engine.get_user_roles(user.id),
                "suggestion": "Check /profile to see your permissions, or contact admin",
            }
        )

    return JSONResponse(status_code=403, content=response_data)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
