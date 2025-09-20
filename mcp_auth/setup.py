"""
FastAPI application setup and configuration for mcp-auth-py.

This module provides the main setup function for integrating mcp-auth-py
with FastAPI applications, handling provider registration and middleware
configuration.
"""

import logging
from typing import Optional

from fastapi import FastAPI

from .middleware import AuthMiddleware
from .providers.local import LocalProvider
from .providers.registry import register_provider
from .settings import Settings

logger = logging.getLogger(__name__)


def setup_auth(app: FastAPI, settings: Optional[Settings] = None) -> FastAPI:
    """
    Set up authentication for a FastAPI application.

    This function configures the authentication system by:
    1. Validating the configuration
    2. Registering available authentication providers
    3. Adding the authentication middleware to the FastAPI app

    Args:
        app: The FastAPI application instance to configure.
        settings: Configuration settings. If None, default settings are used.

    Returns:
        The configured FastAPI application instance.

    Raises:
        ValueError: If the configuration is invalid.
        ImportError: If required dependencies for the selected provider are missing.

    Example:
        Basic setup with default local provider:

        >>> from fastapi import FastAPI
        >>> from mcp_auth import Settings, setup_auth
        >>>
        >>> app = FastAPI()
        >>> settings = Settings(auth_provider="local", jwt_secret="your-secret")
        >>> app = setup_auth(app, settings)

        Multi-provider setup:

        >>> settings = Settings(
        ...     auth_provider="aws",
        ...     provider_config={
        ...         "cognito_region": "us-west-2",
        ...         "cognito_user_pool_id": "us-west-2_XXXX",
        ...         "audience": "your-client-id"
        ...     }
        ... )
        >>> app = setup_auth(app, settings)
    """
    settings = settings or Settings()

    # Validate configuration before proceeding
    try:
        settings.validate_configuration()
    except ValueError as e:
        logger.error(f"Configuration validation failed: {e}")
        raise

    # Always register local provider as it has no optional dependencies
    local_provider = LocalProvider(settings)
    register_provider("local", local_provider)
    logger.info("Registered local JWT provider")

    # Prepare provider configuration with Redis settings if enabled
    provider_cfg = settings.get_provider_config()

    # Register cloud providers only if their dependencies are available
    _register_cloud_providers(provider_cfg)

    # Verify the selected provider is available
    from .providers.registry import get_provider

    try:
        get_provider(settings.auth_provider)
        logger.info(f"Using authentication provider: {settings.auth_provider}")
    except KeyError:
        available_providers = _get_available_providers()
        raise ImportError(
            f"Provider '{settings.auth_provider}' is not available. "
            f"Available providers: {available_providers}. "
            f"Install the required dependencies for your provider."
        )

    # Add authentication middleware
    app.add_middleware(AuthMiddleware, settings=settings)
    logger.info("Authentication middleware configured")

    return app


def _register_cloud_providers(provider_config: dict) -> None:
    """
    Register cloud authentication providers if their dependencies are available.

    Args:
        provider_config: Provider configuration dictionary.
    """
    # Try to register Google provider
    try:
        from .providers.google import GoogleProvider

        register_provider("google", GoogleProvider(provider_config))
        logger.info("Registered Google OAuth2 provider")
    except ImportError:
        logger.debug("Google provider dependencies not available")

    # Try to register AWS provider
    try:
        from .providers.aws import AWSProvider

        register_provider("aws", AWSProvider(provider_config))
        logger.info("Registered AWS Cognito provider")
    except ImportError:
        logger.debug("AWS provider dependencies not available")

    # Try to register Azure provider
    try:
        from .providers.azure import AzureProvider

        register_provider("azure", AzureProvider(provider_config))
        logger.info("Registered Azure AD provider")
    except ImportError:
        logger.debug("Azure provider dependencies not available")


def _get_available_providers() -> list[str]:
    """
    Get a list of currently registered providers.

    Returns:
        List of available provider names.
    """
    from .providers.registry import _providers

    return list(_providers.keys())
