"""
Docker Deployment Example - Production-ready containerized MCP Auth server.

This example demonstrates how to deploy mcp-auth-py in a Docker container
with production-ready configuration including:

1. Environment variable configuration
2. Health check endpoints for orchestration
3. Security-focused settings
4. Container-optimized logging

Build and run:
    docker build -t mcp-auth-server .
    docker run -p 8000:8000 \
        -e AUTH_PROVIDER=google \
        -e PROVIDER_CONFIG='{"audience": "your-client-id"}' \
        mcp-auth-server

Environment variables:
    - AUTH_PROVIDER: Authentication provider (local, google, aws, azure)
    - PROVIDER_CONFIG: JSON configuration for the provider
    - JWT_SECRET: Secret key for JWT signing
    - REDIS_JWKS: Enable Redis JWKS caching (true/false)
    - REDIS_URL: Redis connection URL
"""

from fastapi import FastAPI, Request

from mcp_auth.settings import Settings
from mcp_auth.setup import setup_auth

# Production-ready app configuration
app = FastAPI(
    title="Production MCP Auth Server",
    description="Containerized MCP server with authentication",
    version="1.0.0",
    docs_url="/docs" if __debug__ else None,  # Disable docs in production
)

# Load settings from environment (container env vars)
settings = Settings()
app = setup_auth(app, settings)


@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration"""
    return {
        "status": "healthy",
        "provider": settings.auth_provider,
        "redis_enabled": settings.redis_jwks,
    }


@app.get("/api/data")
async def get_data(request: Request):
    """Example authenticated API endpoint"""
    user = request.state.principal
    if not user:
        return {"error": "Authentication required"}, 401

    return {
        "data": "Protected resource accessed successfully",
        "user_id": user.id,
        "timestamp": "2024-01-01T00:00:00Z",
    }


if __name__ == "__main__":
    # For development only - use proper ASGI server in production
    import uvicorn

    uvicorn.run(
        "examples.docker_app:app", host="0.0.0.0", port=8000, reload=False, workers=1
    )
