import time

import requests

try:
    import httpx
except Exception:  # httpx is optional; async JWKS will be disabled without it
    httpx = None


class JWKSCache:
    def __init__(self, url: str, ttl: int = 3600):
        self.url = url
        self.ttl = ttl
        self._keys = None
        self._fetched = 0

    def get_jwks(self):
        """Synchronous JWKS fetch (blocking)."""
        now = time.time()
        if not self._keys or now - self._fetched > self.ttl:
            resp = requests.get(self.url, timeout=5)
            resp.raise_for_status()
            self._keys = resp.json()
            self._fetched = now
        return self._keys

    async def get_jwks_async(self):
        """Async JWKS fetch using httpx if available.

        Otherwise falls back to sync fetch in a threadpool to avoid blocking
        the event loop for async callers.
        """
        if httpx is None:
            # fallback: run blocking call in threadpool
            import asyncio
            from functools import partial

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, partial(self.get_jwks))

        now = time.time()
        if not self._keys or now - self._fetched > self.ttl:
            resp = await httpx.AsyncClient().get(self.url, timeout=5)
            resp.raise_for_status()
            self._keys = resp.json()
            self._fetched = now
        return self._keys


def get_jwks_url_from_well_known(well_known_url: str) -> str:
    resp = requests.get(well_known_url, timeout=5)
    resp.raise_for_status()
    jwks_uri = resp.json().get("jwks_uri")
    if not jwks_uri:
        raise RuntimeError("jwks_uri not found in well-known config")
    return jwks_uri
