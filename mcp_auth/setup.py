from fastapi import FastAPI

from .middleware import AuthMiddleware
from .providers.aws import AWSProvider
from .providers.azure import AzureProvider
from .providers.google import GoogleProvider
from .providers.local import LocalProvider
from .providers.registry import register_provider
from .settings import Settings


def setup_auth(app: FastAPI, settings: Settings = None):
    settings = settings or Settings()
    # register common providers; concrete providers can be registered by the app before calling setup
    # local provider receives full Settings for jwt_secret etc.
    register_provider("local", LocalProvider(settings))

    provider_cfg = settings.provider_config or {}
    # propagate redis_jwks and redis_url from top-level settings if present
    if hasattr(settings, "redis_jwks") and settings.redis_jwks:
        provider_cfg.setdefault("redis_jwks", True)
        if hasattr(settings, "redis_url") and settings.redis_url:
            provider_cfg.setdefault("redis_url", settings.redis_url)

    register_provider("azure", AzureProvider(provider_cfg))
    register_provider("aws", AWSProvider(provider_cfg))
    register_provider("google", GoogleProvider(provider_cfg))
    app.add_middleware(AuthMiddleware, settings=settings)
    return app
