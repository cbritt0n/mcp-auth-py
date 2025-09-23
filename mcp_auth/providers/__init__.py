from .aws import AWSProvider
from .azure import AzureProvider
from .base import AuthResult, Provider, ProviderError
from .discord import DiscordProvider
from .github import GitHubProvider
from .google import GoogleProvider
from .local import LocalProvider
from .redis_jwks import RedisJWKSCache
from .registry import get_provider, register_provider

# Backward compatibility alias
BaseProvider = Provider

__all__ = [
    "Provider",
    "BaseProvider",  # Keep for backward compatibility
    "AuthResult",
    "ProviderError",
    "LocalProvider",
    "GoogleProvider",
    "AWSProvider",
    "AzureProvider",
    "GitHubProvider",
    "DiscordProvider",
    "RedisJWKSCache",
    "get_provider",
    "register_provider",
]
