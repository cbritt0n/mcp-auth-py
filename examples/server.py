"""
Basic FastAPI server with mcp-auth-py authentication.

This example demonstrates the simplest possible setup of mcp-auth-py
with FastAPI using default local JWT authentication.

To run this example:
    1. pip install -e .
    2. uvicorn examples.server:app --reload
    3. Visit http://localhost:8000/hello (will require JWT token)

To generate a test token:
    mcp-auth-generate-token --user-id test-user --name "Test User"
"""

from fastapi import FastAPI, HTTPException, Request

from mcp_auth.settings import Settings
from mcp_auth.setup import setup_auth

# Configure authentication settings
settings = Settings(
    auth_provider="local",
    jwt_secret="example-secret-key-change-in-production",
    debug=True,  # Enable debug mode for development
)

# Create FastAPI app
app = FastAPI(
    title="mcp-auth-py Example Server",
    description="Simple example of FastAPI with mcp-auth-py authentication",
    version="1.0.0",
)

# Set up authentication
app = setup_auth(app, settings)


@app.get("/")
async def root():
    """Public endpoint (no authentication required)."""
    return {
        "message": "Welcome to mcp-auth-py example server!",
        "docs": "/docs",
        "protected_endpoint": "/hello",
    }


@app.get("/hello")
async def hello(request: Request):
    """
    Protected endpoint that requires authentication.

    The user's principal information is available in request.state.principal
    after successful authentication by the middleware.
    """
    try:
        principal = request.state.principal
        return {
            "message": f"Hello, {principal.name or principal.id}!",
            "user_id": principal.id,
            "provider": principal.provider,
            "roles": principal.roles,
        }
    except AttributeError:
        # This shouldn't happen if middleware is working correctly
        raise HTTPException(status_code=500, detail="Authentication state not found")


@app.get("/profile")
async def get_profile(request: Request):
    """Get user profile information."""
    principal = request.state.principal

    return {
        "profile": {
            "id": principal.id,
            "name": principal.name,
            "email": principal.email,
            "provider": principal.provider,
            "roles": principal.roles or [],
            "raw_claims": principal.raw or {},
        }
    }


if __name__ == "__main__":
    import uvicorn

    print("Starting mcp-auth-py example server...")
    print("Visit http://localhost:8000/ for the root endpoint")
    print("Visit http://localhost:8000/docs for API documentation")
    print(
        "Generate a test token with: "
        "mcp-auth-generate-token --user-id test --name 'Test User'"
    )

    uvicorn.run(app, host="127.0.0.1", port=8000)
