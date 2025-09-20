"""
Complete FastAPI example with user info endpoint and authentication
"""

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from mcp_auth.models import Principal
from mcp_auth.setup import setup_auth

# Initialize FastAPI app with auth middleware
app = FastAPI(
    title="Secure MCP Server",
    description="Example MCP server with authentication",
    version="1.0.0",
)

# Setup authentication middleware
app = setup_auth(app)


def get_current_user(request: Request) -> Principal:
    """Dependency to get current authenticated user"""
    if not hasattr(request.state, "principal") or request.state.principal is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return request.state.principal


@app.get("/")
async def root():
    """Public endpoint - no auth required"""
    return {
        "message": "Welcome to MCP Auth Demo",
        "auth_required": False,
        "endpoints": {
            "public": "/",
            "protected": "/me",
            "user_data": "/user/{user_id}",
        },
    }


@app.get("/me")
async def get_me(current_user: Principal = Depends(get_current_user)):
    """Get current user info - requires authentication"""
    return {
        "message": f"Hello, {current_user.name or current_user.id}!",
        "user": {
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "provider": current_user.provider,
            "roles": current_user.roles,
        },
    }


@app.get("/user/{user_id}")
async def get_user_data(
    user_id: str, current_user: Principal = Depends(get_current_user)
):
    """Access user data - with role-based checks"""
    # Example: Only allow access to own data or admin users
    if current_user.id != user_id and "admin" not in (current_user.roles or []):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return {
        "user_id": user_id,
        "data": "User-specific data here",
        "accessed_by": current_user.id,
    }


@app.exception_handler(401)
async def auth_exception_handler(request: Request, exc: HTTPException):
    """Custom 401 handler with helpful auth info"""
    return JSONResponse(
        status_code=401,
        content={
            "detail": "Authentication required",
            "hint": "Include 'Authorization: Bearer <token>' header",
            "docs": "See README.md for token generation examples",
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
