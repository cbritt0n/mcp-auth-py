"""
Multi-provider example showing different authentication methods
"""

import os

from fastapi import FastAPI, Request

from mcp_auth.settings import Settings
from mcp_auth.setup import setup_auth


# Example 1: Google OAuth2
def create_google_app():
    """FastAPI app configured for Google OAuth2"""
    settings = Settings(
        auth_provider="google",
        provider_config={"audience": "your-client-id.apps.googleusercontent.com"},
    )

    app = FastAPI(title="Google Auth Example")
    app = setup_auth(app, settings)

    @app.get("/google-protected")
    async def google_endpoint(request: Request):
        user = request.state.principal
        return {"provider": "google", "user": user.name, "email": user.email}

    return app


# Example 2: AWS Cognito
def create_aws_app():
    """FastAPI app configured for AWS Cognito"""
    settings = Settings(
        auth_provider="aws",
        provider_config={
            "cognito_region": "us-west-2",
            "cognito_user_pool_id": "us-west-2_XXXXXXXXX",
            "audience": "your-cognito-client-id",
        },
    )

    app = FastAPI(title="AWS Cognito Example")
    app = setup_auth(app, settings)

    @app.get("/aws-protected")
    async def aws_endpoint(request: Request):
        user = request.state.principal
        return {"provider": "aws_cognito", "user_id": user.id, "groups": user.roles}

    return app


# Example 3: Local JWT with Redis caching
def create_local_app_with_redis():
    """FastAPI app with local JWT and Redis JWKS caching"""
    settings = Settings(
        auth_provider="local",
        jwt_secret="your-secret-key",
        redis_jwks=True,
        redis_url="redis://localhost:6379/0",
    )

    app = FastAPI(title="Local JWT + Redis Example")
    app = setup_auth(app, settings)

    @app.get("/local-protected")
    async def local_endpoint(request: Request):
        user = request.state.principal
        return {"provider": "local_jwt", "user": user.name, "cached": "via_redis"}

    @app.post("/generate-token")
    async def generate_token(user_id: str, name: str = "Test User"):
        """Helper endpoint to generate local JWT tokens for testing"""
        try:
            import jwt
        except ImportError:
            return {"error": "PyJWT not installed. Run: pip install PyJWT"}

        payload = {"sub": user_id, "name": name, "email": f"{user_id}@example.com"}
        token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
        return {"token": token, "usage": f"Authorization: Bearer {token}"}

    return app


# Example 4: Environment-based configuration
def create_env_configured_app():
    """FastAPI app that reads config from environment"""
    # This will read from .env file or environment variables
    settings = Settings()

    app = FastAPI(title="Environment Configured App")
    app = setup_auth(app, settings)

    @app.get("/")
    async def root():
        return {
            "message": "App configured from environment",
            "auth_provider": settings.auth_provider,
            "redis_enabled": settings.redis_jwks,
        }

    @app.get("/protected")
    async def protected_endpoint(request: Request):
        user = request.state.principal
        if not user:
            return {"error": "Authentication required"}, 401

        return {
            "provider": settings.auth_provider,
            "user": {"id": user.id, "name": user.name, "email": user.email},
        }

    return app


if __name__ == "__main__":
    # Choose which example to run
    app_type = os.getenv("APP_TYPE", "env")

    apps = {
        "google": create_google_app(),
        "aws": create_aws_app(),
        "local": create_local_app_with_redis(),
        "env": create_env_configured_app(),
    }

    app = apps.get(app_type, apps["env"])

    print(f"Starting {app_type} example app...")
    print("Install uvicorn: pip install uvicorn")
    print("Run: uvicorn examples.multi_provider:app --reload")
