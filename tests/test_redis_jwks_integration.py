import json

import fakeredis


def test_redis_jwks_store_and_fetch(monkeypatch, tmp_path):
    # create a fake Redis server
    fake = fakeredis.FakeServer()
    fake_client = fakeredis.FakeStrictRedis(server=fake)

    # monkeypatch redis.from_url to return our fake client if called
    import types, sys

    redis_mod = types.SimpleNamespace(
        from_url=lambda url: fake_client, Redis=lambda **k: fake_client
    )
    monkeypatch.setitem(sys.modules, "redis", redis_mod)

    from mcp_auth.providers.redis_jwks import RedisJWKSCache

    # serve a small JWKS by monkeypatching requests.get
    class FakeResp:
        def __init__(self, data):
            self._data = data

        def raise_for_status(self):
            return None

        def json(self):
            return self._data

    jwks_data = {"keys": [{"kid": "k1"}]}

    def fake_get(url, timeout=5):
        return FakeResp(jwks_data)

    import requests

    monkeypatch.setattr(requests, "get", fake_get)

    adapter = RedisJWKSCache(
        "https://example.com/.well-known/jwks.json",
        ttl=10,
        redis_url="redis://fake",
    )

    jwks = adapter.get_jwks()
    assert jwks == jwks_data

    # now read directly from fake redis to ensure it was stored
    key = adapter._key()
    val = fake_client.get(key)
    assert val is not None
    assert json.loads(val.decode("utf-8")) == jwks_data
