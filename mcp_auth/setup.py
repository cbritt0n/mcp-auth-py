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
    register_provider("local", LocalProvider(settings))
    register_provider("azure", AzureProvider(settings.provider_config or {}))
    register_provider("aws", AWSProvider(settings.provider_config or {}))
    register_provider("google", GoogleProvider(settings.provider_config or {}))
    app.add_middleware(AuthMiddleware, settings=settings)
    return app
