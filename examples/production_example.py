"""
Production Security Example - Complete example of production-ready MCP Auth setup.

This example demonstrates how to set up MCP Auth with comprehensive security
features for production deployment, including:

1. Proper JWT secret configuration
2. Rate limiting and security middleware
3. Admin authorization
4. Token validation
5. Security monitoring
6. RBAC integration with caching
7. Audit logging
8. Real-time notifications
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request

from mcp_auth.audit import get_audit_logger, setup_audit_system
from mcp_auth.caching import get_cache, initialize_cache
from mcp_auth.middleware_security import get_security_monitor, setup_production_security
from mcp_auth.models import Principal
from mcp_auth.rbac.decorators import require_permissions, require_roles
from mcp_auth.rbac.engine import get_rbac_engine
from mcp_auth.realtime import ConnectionManager
from mcp_auth.security import (
    create_secure_token,
    get_validated_principal,
    require_admin_principal,
)
from mcp_auth.settings import Settings

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("mcp_auth_production.log")],
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan with proper initialization and cleanup"""
    logger.info("=" * 50)
    logger.info("MCP Auth Production Server Starting...")
    logger.info("=" * 50)

    try:
        # Initialize all systems
        await initialize_cache()
        await setup_audit_system(enable_realtime=True)

        # Initialize RBAC with sample data for demo
        rbac_engine = get_rbac_engine()
        await setup_sample_rbac_data(rbac_engine)

        logger.info("Security Features Enabled:")
        logger.info(f"  - Rate Limiting: {settings.enable_rate_limiting}")
        logger.info(f"  - Security Headers: {settings.enable_security_headers}")
        logger.info(f"  - HTTPS Required: {settings.require_https}")
        logger.info(
            f"  - JWT Expiration: {settings.jwt_access_token_expire_minutes} minutes"
        )
        logger.info(f"  - Max Login Attempts: {settings.max_login_attempts}")
        logger.info("=" * 50)
        logger.info("MCP Auth production application started successfully")

        yield

    except Exception as e:
        logger.error("Failed to start application: %s", str(e))
        raise
    finally:
        logger.info("Shutting down MCP Auth production application...")


# Production settings - override with environment variables
def get_production_settings() -> Settings:
    """Get production settings with security validation"""

    # Set secure defaults for production
    os.environ.setdefault("MCP_AUTH_ENABLE_RATE_LIMITING", "true")
    os.environ.setdefault("MCP_AUTH_ENABLE_SECURITY_HEADERS", "true")
    os.environ.setdefault(
        "MCP_AUTH_REQUIRE_HTTPS", "false"
    )  # Set to true in production
    os.environ.setdefault("MCP_AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "60")
    os.environ.setdefault("MCP_AUTH_MAX_LOGIN_ATTEMPTS", "5")
    os.environ.setdefault("MCP_AUTH_RATE_LIMIT_REQUESTS_PER_MINUTE", "100")

    settings = Settings()

    # Production security validation
    if settings.require_https and not settings.jwt_secret.startswith("prod-"):
        logger.warning("Consider using a production-specific JWT secret prefix")

    return settings


# Create FastAPI app with production settings
settings = get_production_settings()
app = FastAPI(
    title="MCP Auth Production API",
    description="Production-ready authentication and RBAC system",
    version="1.0.0",
    docs_url="/docs" if not settings.require_https else None,  # Disable in production
    redoc_url="/redoc" if not settings.require_https else None,
    lifespan=lifespan,
)

# Setup production security
setup_production_security(app, settings)

# Initialize components
audit_logger = get_audit_logger()
connection_manager = ConnectionManager()


async def setup_sample_rbac_data(rbac_engine) -> None:
    """Setup sample RBAC data for demonstration"""
    try:
        from mcp_auth.rbac.models import Permission, Role

        # Create sample roles
        admin_role = Role(
            name="admin",
            description="System Administrator",
            permissions=[Permission.from_string("*:*:*")],
        )

        user_role = Role(
            name="user",
            description="Regular User",
            permissions=[
                Permission.from_string("documents:read"),
                Permission.from_string("users:read"),
            ],
        )

        moderator_role = Role(
            name="moderator",
            description="Content Moderator",
            permissions=[
                Permission.from_string("documents:*:*"),
                Permission.from_string("moderator:access"),
            ],
        )

        # Add roles to engine
        rbac_engine.add_role(admin_role)
        rbac_engine.add_role(user_role)
        rbac_engine.add_role(moderator_role)

        # Assign sample users to roles (in production, this comes from your user management system)
        rbac_engine.assign_role("admin_user", "admin")
        rbac_engine.assign_role("regular_user", "user")
        rbac_engine.assign_role("mod_user", "moderator")

        logger.info("Sample RBAC data initialized")

    except Exception as e:
        logger.error("Error setting up RBAC data: %s", str(e))


# Authentication endpoints
@app.post("/auth/login")
async def login(username: str, password: str, request: Request):
    """Secure login endpoint with rate limiting and audit logging"""

    try:
        # In production, validate credentials against your user store
        # This is a simplified example
        if username == "admin_user" and password == "secure_password_123":
            user_id = "admin_user"
            roles = ["admin"]
            name = "Administrator"
            email = "admin@example.com"
        elif username == "regular_user" and password == "user_password_456":
            user_id = "regular_user"
            roles = ["user"]
            name = "Regular User"
            email = "user@example.com"
        else:
            # Record failed attempt for audit
            await audit_logger.log_security_event(
                "AUTHENTICATION_FAILED",
                f"Failed login attempt for username: {username}",
                ip_address=request.client.host if request.client else None,
                risk_score=30,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Create secure token
        token = create_secure_token(
            user_id=user_id,
            roles=roles,
            name=name,
            email=email,
            expires_in=settings.jwt_access_token_expire_minutes * 60,
        )

        # Log successful authentication
        principal = Principal(
            id=user_id, provider="local", name=name, email=email, roles=roles
        )
        await audit_logger.log_event(
            "USER_LOGIN",
            f"User {username} logged in successfully",
            principal=principal,
            request=request,
            access_granted=True,
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60,
            "user": {"id": user_id, "name": name, "email": email, "roles": roles},
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login error: %s", str(e))
        raise HTTPException(status_code=500, detail="Authentication error")


@app.get("/auth/profile")
async def get_profile(principal: Principal = Depends(get_validated_principal)):
    """Get user profile with proper authentication"""

    await audit_logger.log_event(
        "PROFILE_ACCESS", f"User {principal.id} accessed profile", principal=principal
    )

    return {
        "user": {
            "id": principal.id,
            "name": principal.name,
            "email": principal.email,
            "provider": principal.provider,
            "roles": principal.roles,
        }
    }


# Protected resource endpoints demonstrating RBAC
@app.get("/users")
@require_permissions(["users:read"])
async def list_users(
    request: Request, principal: Principal = Depends(get_validated_principal)
):
    """List users - requires users.read permission"""

    await audit_logger.log_event(
        "USERS_LIST",
        f"User {principal.id} listed users",
        principal=principal,
        resource="users",
        action="read",
    )

    # In production, fetch from your user store
    return {
        "users": [
            {"id": "admin_user", "name": "Administrator", "roles": ["admin"]},
            {"id": "regular_user", "name": "Regular User", "roles": ["user"]},
            {"id": "mod_user", "name": "Moderator", "roles": ["moderator"]},
        ]
    }


@app.post("/users")
@require_permissions(["users:write"])
async def create_user(
    request: Request,
    user_data: dict,
    principal: Principal = Depends(get_validated_principal),
):
    """Create user - requires users.write permission"""

    await audit_logger.log_event(
        "USER_CREATED",
        f"User {principal.id} created new user: {user_data.get('username')}",
        principal=principal,
        resource="users",
        action="write",
        details=user_data,
    )

    return {
        "message": "User created successfully",
        "user_id": user_data.get("username"),
    }


@app.delete("/users/{user_id}")
@require_roles(["admin"])  # Only admins can delete users
async def delete_user(
    request: Request,
    user_id: str,
    principal: Principal = Depends(get_validated_principal),
):
    """Delete user - requires admin role"""

    await audit_logger.log_security_event(
        "USER_DELETED",
        f"Admin {principal.id} deleted user: {user_id}",
        principal=principal,
        target_user_id=user_id,
        security_level="HIGH",
    )

    return {"message": f"User {user_id} deleted successfully"}


# Admin-only endpoints
@app.get("/admin/stats")
async def get_admin_stats(principal: Principal = Depends(require_admin_principal)):
    """Get system statistics - admin only"""

    rbac_engine = get_rbac_engine()
    cache = get_cache()
    security_monitor = get_security_monitor()

    stats = {
        "rbac": rbac_engine.health_check(),
        "cache": cache.get_stats() if cache else None,
        "security": security_monitor.get_security_summary(),
    }

    await audit_logger.log_event(
        "ADMIN_STATS_ACCESS",
        f"Admin {principal.id} accessed system statistics",
        principal=principal,
        resource="admin",
        action="stats",
    )

    return stats


@app.post("/admin/cache/clear")
async def clear_cache(principal: Principal = Depends(require_admin_principal)):
    """Clear application cache - admin only"""

    cache = get_cache()
    if cache:
        cleared_count = await cache.clear_all()

        await audit_logger.log_event(
            "CACHE_CLEARED",
            f"Admin {principal.id} cleared cache ({cleared_count} entries)",
            principal=principal,
            resource="cache",
            action="clear",
        )

        return {"message": f"Cache cleared successfully ({cleared_count} entries)"}
    else:
        return {"message": "No cache configured"}


# Health check endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""

    # Check system components
    health_status = {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "version": "1.0.0",
        "components": {},
    }

    try:
        # Check cache
        cache = get_cache()
        if cache:
            await cache.ping()
            health_status["components"]["cache"] = "healthy"
        else:
            health_status["components"]["cache"] = "not_configured"

        # Check RBAC engine
        get_rbac_engine()  # Just check it exists
        health_status["components"]["rbac"] = "healthy"

    except Exception as e:
        health_status["status"] = "degraded"
        health_status["error"] = str(e)

    return health_status


@app.get("/health/security")
async def security_health_check(
    principal: Principal = Depends(require_admin_principal),
):
    """Security-focused health check - admin only"""

    security_monitor = get_security_monitor()
    security_status = security_monitor.get_security_summary()

    # Add additional security checks
    security_status.update(
        {
            "jwt_secret_strength": (
                "strong" if len(settings.jwt_secret) >= 32 else "weak"
            ),
            "https_enforced": settings.require_https,
            "rate_limiting_enabled": settings.enable_rate_limiting,
            "security_headers_enabled": settings.enable_security_headers,
        }
    )

    return {"security": security_status}


# Include realtime WebSocket endpoints - create simple router for demo

realtime_router = APIRouter()


@realtime_router.websocket("/ws")
async def websocket_endpoint(websocket):
    """WebSocket endpoint for real-time notifications"""
    await connection_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await connection_manager.broadcast(f"Echo: {data}")
    except Exception:
        connection_manager.disconnect(websocket)


app.include_router(realtime_router, prefix="/realtime", tags=["realtime"])


# Production startup message is now handled in the lifespan function above


if __name__ == "__main__":
    # Production server setup
    import uvicorn

    uvicorn.run(
        "production_example:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        server_header=False,  # Hide server header for security
        date_header=False,  # Hide date header for security
        reload=False,  # Never use reload in production
        workers=1,  # Use multiple workers in production
    )
