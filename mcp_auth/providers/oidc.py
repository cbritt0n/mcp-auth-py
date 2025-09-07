import time
import requests

class JWKSCache:
    def __init__(self, url: str, ttl: int = 3600):
        self.url = url
        self.ttl = ttl
        self._keys = None
        self._fetched = 0

    def get_jwks(self):
        now = time.time()
        if not self._keys or now - self._fetched > self.ttl:
            resp = requests.get(self.url, timeout=5)
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