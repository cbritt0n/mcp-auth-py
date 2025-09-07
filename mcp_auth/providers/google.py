from typing import Optional

from .base import Provider, AuthResult, ProviderError
from fastapi import Request

try:
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
except Exception:  # pragma: no cover - handled at runtime
    id_token = None
    google_requests = None


class GoogleProvider(Provider):
    """Google provider that verifies Google ID tokens using google-auth.

    Config options:
      - audience: optional expected audience (client ID). If omitted, audience is not enforced.
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def authenticate(self, request: Request) -> AuthResult:
        if id_token is None or google_requests is None:
            raise ProviderError(
                "google-auth is required for GoogleProvider; install 'google-auth' (pip install google-auth)"
            )

        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return AuthResult(valid=False)
        token = auth.split(" ", 1)[1]

        audience = self.config.get("audience")
        req = google_requests.Request()
        try:
            # verify_oauth2_token raises ValueError on invalid token
            if audience:
                claims = id_token.verify_oauth2_token(token, req, audience)
            else:
                # verify without audience (will still validate signature/expiry)
                claims = id_token.verify_oauth2_token(token, req, None)
        except ValueError:
            return AuthResult(valid=False)
        except Exception as e:
            raise ProviderError(str(e))

        principal = claims.get("sub") or claims.get("email")
        return AuthResult(valid=True, principal=principal, claims=claims, raw={"token": token})
