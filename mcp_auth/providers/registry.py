from typing import Dict

from .base import Provider

_PROVIDERS: Dict[str, Provider] = {}


def register_provider(name: str, provider: Provider):
    _PROVIDERS[name] = provider


def get_provider(name: str) -> Provider:
    provider = _PROVIDERS.get(name)
    if not provider:
        raise LookupError(f"Unknown provider: {name}")
    return provider
