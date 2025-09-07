import sys
import types

import pytest


class DummyRequest:
    def __init__(self, auth_header=None):
        self.headers = {"Authorization": auth_header} if auth_header is not None else {}


def test_google_provider_valid(monkeypatch):
    from mcp_auth.providers.google import GoogleProvider

    provider = GoogleProvider({"audience": "audience-1"})

    # mock google id_token.verify_oauth2_token
    def fake_verify(token, req, audience):
        assert token == "good-token"
        return {"sub": "google-user", "email": "g@example.com"}

    monkeypatch.setattr(
        "mcp_auth.providers.google.id_token.verify_oauth2_token", fake_verify
    )
    # ensure google_requests.Request exists
    monkeypatch.setattr(
        "mcp_auth.providers.google.google_requests",
        types.SimpleNamespace(Request=lambda: None),
    )

    req = DummyRequest("Bearer good-token")
    res = provider.authenticate(req)
    assert res.valid is True
    assert res.principal == "google-user"


def test_google_provider_invalid(monkeypatch):
    from mcp_auth.providers.google import GoogleProvider

    provider = GoogleProvider({})

    def fake_verify_raise(token, req, audience):
        raise ValueError("invalid")

    monkeypatch.setattr(
        "mcp_auth.providers.google.id_token.verify_oauth2_token", fake_verify_raise
    )
    monkeypatch.setattr(
        "mcp_auth.providers.google.google_requests",
        types.SimpleNamespace(Request=lambda: None),
    )

    req = DummyRequest("Bearer bad-token")
    res = provider.authenticate(req)
    assert res.valid is False


def test_aws_provider_jwks(monkeypatch):
    from mcp_auth.providers.aws import AWSProvider

    provider = AWSProvider(
        {"cognito_region": "us-west-2", "cognito_user_pool_id": "pool"}
    )

    # patch _get_jwks_cache to return object with get_jwks
    class FakeCache:
        def get_jwks(self):
            return {"keys": []}

    monkeypatch.setattr(
        "mcp_auth.providers.aws.AWSProvider._get_jwks_cache", lambda self: FakeCache()
    )

    # mock jose.jwt.decode to return claims
    monkeypatch.setattr(
        "mcp_auth.providers.aws.jwt.decode",
        lambda token, jwks, algorithms, options, audience=None: {"sub": "aws-user"},
    )

    req = DummyRequest("Bearer token")
    res = provider.authenticate(req)
    assert res.valid is True
    assert res.principal == "aws-user"


def test_aws_provider_cognito_get_user(monkeypatch):
    import types

    from mcp_auth.providers.aws import AWSProvider

    provider = AWSProvider(
        {"use_cognito_get_user": True, "cognito_region": "us-east-1"}
    )

    # create fake boto3 in sys.modules
    class FakeClient:
        class exceptions:
            class NotAuthorizedException(Exception):
                pass

        def get_user(self, AccessToken=None):
            if AccessToken == "bad":
                raise FakeClient.exceptions.NotAuthorizedException()
            return {"Username": "someone"}

    def fake_client(name, region_name=None):
        assert name == "cognito-idp"
        return FakeClient()

    fake_boto3 = types.SimpleNamespace(client=fake_client)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    req = DummyRequest("Bearer token")
    res = provider.authenticate(req)
    assert res.valid is True

    # unauthorized token
    req2 = DummyRequest("Bearer bad")
    res2 = provider.authenticate(req2)
    assert res2.valid is False


def test_azure_provider_jwks(monkeypatch):
    from mcp_auth.providers.azure import AzureProvider

    provider = AzureProvider({"tenant": "common"})

    # set a fake jwks cache
    class FakeCache:
        def get_jwks(self):
            return {"keys": []}

    provider._jwks_cache = FakeCache()
    monkeypatch.setattr(
        "mcp_auth.providers.azure.jwt.decode",
        lambda token, jwks, algorithms, options, audience=None: {"sub": "azure-user"},
    )

    req = DummyRequest("Bearer token")
    res = provider.authenticate(req)
    assert res.valid is True
    assert res.principal == "azure-user"
