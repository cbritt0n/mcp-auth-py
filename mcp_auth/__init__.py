"""
mcp-auth-py: Pluggable authentication for FastAPI/ASGI applications

This package provides a lightweight, pluggable authentication system for FastAPI
and other ASGI applications. It supports multiple authentication providers including
local JWT, Google OAuth2, AWS Cognito, and Azure AD.

Features:
    - Pluggable authentication providers
    - FastAPI/ASGI middleware integration
    - JWKS caching with optional Redis backend
    - Role-Based Access Control (RBAC) extension
    - Async-capable with thread pool offloading for blocking operations

Example:
    Basic setup with local JWT authentication:

    >>> from mcp_auth import Settings, setup_auth
    >>> from fastapi import FastAPI
    >>>
    >>> settings = Settings(auth_provider="local", jwt_secret="your-secret")
    >>> app = FastAPI()
    >>> app = setup_auth(app, settings)

See Also:
    - `examples/` directory for complete usage examples
    - `docs/rbac_extension.md` for RBAC documentation
"""

__version__ = "0.1.0"

# Core exports for easy import
from .models import Principal
from .providers import get_provider, register_provider
from .settings import Settings
from .setup import setup_auth

# RBAC extension (optional import)
try:
    from . import rbac

    _rbac_available = True
except ImportError:
    rbac = None
    _rbac_available = False

__all__ = [
    "Principal",
    "Settings",
    "setup_auth",
    "get_provider",
    "register_provider",
]

# Add RBAC to exports if available
if _rbac_available:
    __all__.extend(["rbac"])
