from typing import Any

from mcp_auth.adapters import token_to_principal_sync
from mcp_auth.models import Principal
from mcp_auth.providers.base import AuthResult, Provider


class FakeProvider(Provider):
    def __init__(self, expect_token: str):
        self.expect_token = expect_token

    def authenticate(self, request: Any) -> AuthResult:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return AuthResult(valid=False, principal=None, claims={}, raw={})
        token = auth.split(None, 1)[1]
        if token != self.expect_token:
            return AuthResult(valid=False, principal=None, claims={}, raw={})
        principal = Principal(
            id="user:123",
            provider="fake",
            name="Test User",
            email="test@example.com",
            roles=["user"],
            raw={},
        )
        return AuthResult(
            valid=True, principal=principal, claims={"sub": "user:123"}, raw={}
        )


def test_token_to_principal_sync_success():
    provider = FakeProvider(expect_token="good-token")
    principal = token_to_principal_sync(provider, "good-token")
    assert principal is not None
    assert principal.id == "user:123"


def test_token_to_principal_sync_failure():
    provider = FakeProvider(expect_token="good-token")
    principal = token_to_principal_sync(provider, "bad-token")
    assert principal is None
