import hashlib
import json
from typing import Any

import requests

try:
    import httpx
except Exception:
    httpx = None

try:
    import redis as redis_sync
except Exception:
    redis_sync = None

try:
    import aioredis
except Exception:
    aioredis = None


class RedisJWKSCache:
    """Redis-backed JWKS cache adapter.

    This adapter stores JWKS JSON in Redis under a key derived from the JWKS URL.
    Both synchronous `get_jwks()` and asynchronous `get_jwks_async()` are provided.

    Optional dependencies:
      - `redis` for sync Redis access
      - `aioredis` for async Redis access
      - `httpx` for async HTTP fetches

    If Redis or async libs are unavailable, the adapter falls back to synchronous
    network fetches and executing them in a threadpool for async callers.
    """

    def __init__(
        self,
        url: str,
        ttl: int = 3600,
        redis_url: str = "redis://localhost:6379/0",
        namespace: str = "mcp:jwks",
    ):
        self.url = url
        self.ttl = ttl
        self.redis_url = redis_url
        self.namespace = namespace
        self._client = None
        self._aclient = None

    def _key(self) -> str:
        h = hashlib.sha256(self.url.encode("utf-8")).hexdigest()
        return f"{self.namespace}:{h}"

    def _get_sync_client(self):
        if self._client is None:
            mod = redis_sync
            if mod is None:
                try:
                    import importlib

                    mod = importlib.import_module("redis")
                except Exception:
                    mod = None
            if mod is None:
                return None
            # prefer redis.from_url if available
            if hasattr(mod, "from_url"):
                self._client = mod.from_url(self.redis_url)
            else:
                self._client = mod.Redis(host="localhost")
        return self._client

    async def _get_async_client(self):
        if self._aclient is None:
            mod = aioredis
            if mod is None:
                try:
                    import importlib

                    mod = importlib.import_module("aioredis")
                except Exception:
                    mod = None
            if mod is None:
                return None
            # modern aioredis (redis-py) provides from_url
            if hasattr(mod, "from_url"):
                self._aclient = await mod.from_url(self.redis_url)
            else:
                # older aioredis API
                self._aclient = await mod.create_redis_pool(self.redis_url)
        return self._aclient

    def get_jwks(self) -> dict[str, Any]:
        """Synchronous JWKS fetch with Redis caching."""
        key = self._key()
        client = self._get_sync_client()
        if client is not None:
            try:
                val = client.get(key)
                if val:
                    # redis returns bytes
                    if isinstance(val, (bytes, bytearray)):
                        val = val.decode("utf-8")
                    return json.loads(val)
            except Exception:
                # on any redis error, fall back to network fetch
                pass

        # fetch JWKS from network
        resp = requests.get(self.url, timeout=5)
        resp.raise_for_status()
        jwks = resp.json()

        if client is not None:
            try:
                client.set(key, json.dumps(jwks), ex=self.ttl)
            except Exception:
                # Fallback for older Redis versions that don't support ex parameter
                try:
                    client.setex(key, self.ttl, json.dumps(jwks))
                except Exception:
                    pass
        return jwks

    async def get_jwks_async(self) -> dict[str, Any]:
        """Async JWKS fetch with Redis caching when possible.

        If `aioredis` is available, use it; otherwise fall back to running the
        synchronous `get_jwks` in a threadpool.
        """
        key = self._key()

        if aioredis is not None:
            try:
                aclient = await self._get_async_client()
                if aclient is not None:
                    val = await aclient.get(key)
                    if val:
                        if isinstance(val, (bytes, bytearray)):
                            val = val.decode("utf-8")
                        return json.loads(val)

                    # fetch JWKS via async HTTP client if available
                    if httpx is not None:
                        client = httpx.AsyncClient()
                        resp = await client.get(self.url, timeout=5)
                        resp.raise_for_status()
                        jwks = resp.json()
                    else:
                        # fall back to sync fetch in threadpool
                        import asyncio as _asyncio

                        jwks = await _asyncio.get_event_loop().run_in_executor(
                            None, self.get_jwks
                        )

                    try:
                        await aclient.set(key, json.dumps(jwks), ex=self.ttl)
                    except Exception:
                        # Fallback for older Redis versions that don't support ex
                        try:
                            await aclient.setex(key, self.ttl, json.dumps(jwks))
                        except Exception:
                            pass
                    return jwks
            except Exception:
                # if async redis path fails, fall back to sync
                pass

        # fallback: run sync get_jwks in executor
        import asyncio as _asyncio

        return await _asyncio.get_event_loop().run_in_executor(None, self.get_jwks)
