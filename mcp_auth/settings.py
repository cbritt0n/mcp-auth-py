"""
Configuration settings for mcp-auth-py authentication system.

This module defines the configuration schema using Pydantic settings,
supporting environment variables, .env files, and direct configuration.
"""

from typing import Any, Optional

from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Configuration settings for the authentication system.

    This class defines all configurable options for mcp-auth-py, including
    provider selection, JWT settings, and optional features like Redis caching.
    Settings can be provided via environment variables, .env file, or direct
    instantiation.

    Environment Variable Mapping:
        All settings can be configured via environment variables by prefixing
        with 'MCP_AUTH_' (e.g., MCP_AUTH_JWT_SECRET, MCP_AUTH_AUTH_PROVIDER).

    Example:
        Basic local JWT configuration:

        >>> settings = Settings(
        ...     auth_provider="local",
        ...     jwt_secret="your-secret-key"
        ... )

        Google OAuth2 configuration:

        >>> settings = Settings(
        ...     auth_provider="google",
        ...     provider_config={"audience": "your-google-client-id"}
        ... )
    """

    # JWT Configuration
    jwt_secret: str = Field(
        default="supersecret",
        description="Secret key for JWT signing and verification. Change this in production!",
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    jwt_access_token_expire_minutes: int = Field(
        default=60, description="Access token expiration in minutes"
    )
    jwt_refresh_token_expire_days: int = Field(
        default=7, description="Refresh token expiration in days"
    )

    # Security Configuration
    token_issuer: Optional[str] = Field(
        default=None, description="JWT token issuer claim"
    )
    token_audience: Optional[str] = Field(
        default=None, description="JWT token audience claim"
    )
    enable_rate_limiting: bool = Field(
        default=True, description="Enable API rate limiting"
    )
    rate_limit_requests_per_minute: int = Field(
        default=60, description="Rate limit requests per minute"
    )
    max_login_attempts: int = Field(
        default=5, description="Maximum failed login attempts before lockout"
    )
    lockout_duration_minutes: int = Field(
        default=5, description="Account lockout duration in minutes"
    )
    require_https: bool = Field(
        default=False, description="Require HTTPS in production"
    )
    enable_security_headers: bool = Field(
        default=True, description="Enable security headers"
    )

    # Session Security
    session_timeout_minutes: int = Field(
        default=60, description="Session timeout in minutes"
    )
    admin_session_timeout_minutes: int = Field(
        default=30, description="Admin session timeout in minutes"
    )
    enable_session_ip_validation: bool = Field(
        default=True, description="Validate session IP consistency"
    )

    jwt_algorithm: str = "HS256"
    """JWT signing algorithm. Supports HS256, RS256, etc."""

    # Provider selection: 'local', 'google', 'aws', 'azure'
    auth_provider: str = "local"
    """
    Authentication provider to use.

    Supported providers:
        - 'local': Local JWT authentication
        - 'google': Google OAuth2 ID tokens
        - 'aws': AWS Cognito JWKS validation
        - 'azure': Azure AD OIDC tokens
    """

    # Provider-specific configuration (optional)
    provider_config: Optional[dict[str, Any]] = None
    """
    Provider-specific configuration dictionary.

    Configuration varies by provider:

    Local provider:
        No additional configuration required.

    Google provider:
        - audience: Google Client ID

    AWS provider:
        - cognito_region: AWS region (e.g., 'us-west-2')
        - cognito_user_pool_id: Cognito User Pool ID
        - audience: App Client ID
        - use_cognito_get_user: Whether to fetch additional user details

    Azure provider:
        - tenant: Azure AD tenant ID
        - audience: Application Client ID
    """

    # Redis JWKS caching settings (optional)
    redis_jwks: bool = False
    """Enable Redis-backed JWKS caching for improved performance across processes."""

    redis_url: Optional[str] = None
    """Redis connection URL for JWKS caching (e.g., 'redis://localhost:6379/0')."""

    # Development and debugging
    debug: bool = False
    """Enable debug logging and additional error information."""

    model_config = ConfigDict(
        env_file=".env", env_prefix="MCP_AUTH_", case_sensitive=False, extra="forbid"
    )

    def get_provider_config(self) -> dict[str, Any]:
        """
        Get provider configuration with defaults.

        Returns:
            Provider configuration dictionary with any necessary defaults applied.
        """
        config = self.provider_config or {}

        # Add Redis settings if enabled
        if self.redis_jwks and self.redis_url:
            config.update({"redis_jwks": True, "redis_url": self.redis_url})

        return config

    def validate_configuration(self) -> None:
        """
        Validate the current configuration for common issues.

        Raises:
            ValueError: If configuration is invalid.
        """
        # Validate provider
        valid_providers = ["local", "google", "aws", "azure"]
        if self.auth_provider not in valid_providers:
            raise ValueError(
                f"Invalid auth_provider '{self.auth_provider}'. "
                f"Must be one of: {valid_providers}"
            )

        # Validate local provider settings with enhanced security
        if self.auth_provider == "local":
            if self.jwt_secret == "supersecret":
                import warnings

                warnings.warn(
                    "Using default JWT secret in production is insecure! "
                    "Set MCP_AUTH_JWT_SECRET environment variable.",
                    UserWarning,
                    stacklevel=2,
                )

            # Additional JWT secret validation
            if len(self.jwt_secret) < 32:
                import warnings

                warnings.warn(
                    "JWT secret should be at least 32 characters for production use!",
                    UserWarning,
                    stacklevel=2,
                )

            # Check for common weak secrets
            weak_secrets = [
                "secret",
                "password",
                "supersecret",
                "jwt_secret",
                "change_me",
            ]
            if self.jwt_secret.lower() in weak_secrets:
                import warnings

                warnings.warn(
                    "JWT secret appears to be a common/weak value. Use a strong, unique secret!",
                    UserWarning,
                    stacklevel=2,
                )

        # Validate Redis settings
        if self.redis_jwks and not self.redis_url:
            raise ValueError("redis_url must be provided when redis_jwks is enabled")

        # Validate provider-specific settings
        if self.auth_provider == "google":
            config = self.provider_config or {}
            if "audience" not in config:
                raise ValueError(
                    "Google provider requires 'audience' in provider_config"
                )

        elif self.auth_provider == "aws":
            config = self.provider_config or {}
            required_keys = ["cognito_region", "cognito_user_pool_id", "audience"]
            missing_keys = [k for k in required_keys if k not in config]
            if missing_keys:
                raise ValueError(
                    f"AWS provider requires {missing_keys} in provider_config"
                )

        elif self.auth_provider == "azure":
            config = self.provider_config or {}
            required_keys = ["tenant", "audience"]
            missing_keys = [k for k in required_keys if k not in config]
            if missing_keys:
                raise ValueError(
                    f"Azure provider requires {missing_keys} in provider_config"
                )
