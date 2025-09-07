import asyncio
from typing import Any

import pytest

from mcp_auth.adapters import authenticate_request, authenticate_request_sync
from mcp_auth.providers.base import AuthResult, Provider, ProviderError
from mcp_auth.models import Principal


class SimpleProvider(Provider):
    def authenticate(self, request: Any) -> AuthResult:
        auth = request.headers.get("Authorization", "")
        if auth == "Bearer ok":
            p = Principal(
                id="u1",
                provider="simple",
                name="OK",
                email="ok@example.com",
                roles=[],
                raw={},
            )
            return AuthResult(valid=True, principal=p, claims={"sub": "u1"}, raw={})
        return AuthResult(valid=False, principal=None, claims={}, raw={})


class ErrorProvider(Provider):
    def authenticate(self, request: Any) -> AuthResult:
        raise ProviderError("boom")


class CrashProvider(Provider):
    async def authenticate(self, request: Any) -> AuthResult:
        # raise a generic exception to ensure it's wrapped by ProviderError
        raise RuntimeError("crash")


def test_authenticate_request_sync_success():
    prov = SimpleProvider()
    req = type("R", (), {"headers": {"Authorization": "Bearer ok"}})()
    res = authenticate_request_sync(prov, req)
    assert res.valid and res.principal and res.principal.id == "u1"


def test_authenticate_request_sync_provider_error_propagates():
    prov = ErrorProvider()
    req = type("R", (), {"headers": {}})()
    with pytest.raises(ProviderError):
        authenticate_request_sync(prov, req)


def test_authenticate_request_async_exception_wrapped():
    prov = CrashProvider()
    req = type("R", (), {"headers": {}})()
    # call async wrapper via asyncio.run
    with pytest.raises(ProviderError):
        asyncio.run(authenticate_request(prov, req))
