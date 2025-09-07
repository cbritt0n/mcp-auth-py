import asyncio
import importlib.util
from typing import Any

from mcp_auth.adapters import token_to_principal
from mcp_auth.models import Principal
from mcp_auth.providers.base import AuthResult, Provider


class AsyncFakeProvider(Provider):
    def __init__(self, expect_token: str):
        self.expect_token = expect_token

    async def authenticate(self, request: Any) -> AuthResult:
        # simulate async work
        await asyncio.sleep(0)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return AuthResult(valid=False, principal=None, claims={}, raw={})
        token = auth.split(None, 1)[1]
        if token != self.expect_token:
            return AuthResult(valid=False, principal=None, claims={}, raw={})
        principal = Principal(
            id="user:async",
            provider="fake",
            name="Async User",
            email="async@example.com",
            roles=["user"],
            raw={},
        )
        return AuthResult(
            valid=True, principal=principal, claims={"sub": "user:async"}, raw={}
        )


HAS_PYTEST_ASYNCIO = importlib.util.find_spec("pytest_asyncio") is not None


if HAS_PYTEST_ASYNCIO:
    import pytest

    @pytest.mark.asyncio
    async def test_token_to_principal_async_success():
        provider = AsyncFakeProvider(expect_token="async-good")
        principal = await token_to_principal(provider, "async-good")
        assert principal is not None
        assert principal.id == "user:async"

    @pytest.mark.asyncio
    async def test_token_to_principal_async_failure():
        provider = AsyncFakeProvider(expect_token="async-good")
        principal = await token_to_principal(provider, "async-bad")
        assert principal is None

else:

    def test_token_to_principal_async_success():
        provider = AsyncFakeProvider(expect_token="async-good")
        principal = asyncio.run(token_to_principal(provider, "async-good"))
        assert principal is not None
        assert principal.id == "user:async"

    def test_token_to_principal_async_failure():
        provider = AsyncFakeProvider(expect_token="async-good")
        principal = asyncio.run(token_to_principal(provider, "async-bad"))
        assert principal is None
