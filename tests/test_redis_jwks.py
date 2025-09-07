def test_redis_jwks_adapter_constructs(monkeypatch):
    # ensure adapter can be imported even if redis libraries are missing
    monkeypatch.setitem(__import__("sys").modules, "redis", None)
    monkeypatch.setitem(__import__("sys").modules, "aioredis", None)
    from mcp_auth.providers.redis_jwks import RedisJWKSCache

    adapter = RedisJWKSCache("https://example.com/.well-known/jwks.json")
    # fallback to network fetch (we won't actually call network in test);
    # just ensure methods exist
    assert hasattr(adapter, "get_jwks")
    assert hasattr(adapter, "get_jwks_async")
