"""mcp-auth-py: Pluggable authentication for FastAPI/ASGI applications."""

__version__ = "0.1.0"

# Core exports for easy import
from .models import Principal
from .settings import Settings
from .setup import setup_auth
from .providers import get_provider, register_provider

__all__ = [
    "Principal",
    "Settings",
    "setup_auth",
    "get_provider",
    "register_provider",
]
