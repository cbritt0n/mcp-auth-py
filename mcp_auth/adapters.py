from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .models import Principal
from .providers.base import AuthResult, Provider, ProviderError


@dataclass
class _RequestLike:
    headers: Dict[str, str]
    cookies: Dict[str, str]
    query_params: Dict[str, str]


async def authenticate_request(provider: Provider, request: Any) -> AuthResult:
    """Call provider.authenticate and await if it's a coroutine.

    Returns the provider's AuthResult or raises ProviderError.
    """
    try:
        result = provider.authenticate(request)
        if hasattr(result, "__await__"):
            result = await result
        return result
    except ProviderError:
        raise
    except Exception as exc:  # pragma: no cover - bubble runtime errors
        raise ProviderError(str(exc))


def _run_coro_sync(coro):
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        # no event loop in this thread
        return asyncio.run(coro)

    if loop.is_running():
        # Running inside an existing loop (e.g. interactive). Use asyncio.run as fallback.
        return asyncio.run(coro)
    return loop.run_until_complete(coro)


def authenticate_request_sync(provider: Provider, request: Any) -> AuthResult:
    """Sync wrapper for `authenticate_request`.

    If the provider returns a coroutine, this will run it to completion.
    """
    coro = authenticate_request(provider, request)
    return _run_coro_sync(coro)


async def token_to_principal(provider: Provider, token: str) -> Optional[Principal]:
    """Create a request-like object from a token and authenticate (async).

    Returns Principal on success or None.
    """
    req = _RequestLike(
        headers={"Authorization": f"Bearer {token}"}, cookies={}, query_params={}
    )
    result = await authenticate_request(provider, req)
    if result and result.valid:
        return result.principal
    return None


def token_to_principal_sync(provider: Provider, token: str) -> Optional[Principal]:
    """Sync wrapper for `token_to_principal`.

    Returns Principal on success or None.
    """
    coro = token_to_principal(provider, token)
    return _run_coro_sync(coro)


def map_context_to_requestlike(ctx: Dict[str, Any]) -> _RequestLike:
    """Map a simple context/dict to the internal Request-like shape.

    Expected keys (optional): `headers`, `cookies`, `query_params`.
    """
    return _RequestLike(
        headers=ctx.get("headers", {}),
        cookies=ctx.get("cookies", {}),
        query_params=ctx.get("query_params", {}),
    )
