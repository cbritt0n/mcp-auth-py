from typing import Optional

from fastapi import Request

from mcp_auth.models import Principal

from .base import AuthResult, Provider, ProviderError

try:
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token
except Exception:  # pragma: no cover - handled at runtime
    # provide a minimal shim so tests can monkeypatch id_token.verify_oauth2_token
    class _IDTokenShim:
        def verify_oauth2_token(self, token, req, audience):
            # No-op placeholder for environments without google-auth.
            # Tests should monkeypatch this function. In production,
            # google-auth should be installed.
            raise ValueError(
                "google-auth verify_oauth2_token not available; "
                "mock in tests or install google-auth"
            )

    id_token = _IDTokenShim()
    google_requests = None


class GoogleProvider(Provider):
    """Google provider that verifies Google ID tokens using google-auth.

    Config options:
        - audience: optional expected audience (client ID). If omitted, the
            audience is not enforced.
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def authenticate(self, request: Request) -> AuthResult:
        # If google-auth transport is missing, we still allow testing by
        # expecting test code to monkeypatch `id_token.verify_oauth2_token`.
        if google_requests is None and not hasattr(id_token, "verify_oauth2_token"):
            raise ProviderError(
                "google-auth is required for GoogleProvider in production; "
                "for tests mock id_token.verify_oauth2_token"
            )

        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return AuthResult(valid=False)
        token = auth.split(" ", 1)[1]

        audience = self.config.get("audience")
        req = google_requests.Request() if google_requests is not None else None

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

        principal_id = claims.get("sub") or claims.get("email")
        if not principal_id:
            return AuthResult(valid=False)  # No valid identifier in token
            
        principal = Principal(
            id=str(principal_id),
            provider="google",
            name=claims.get("name"),
            email=claims.get("email"),
            raw=claims,
        )
        return AuthResult(
            valid=True, principal=principal, claims=claims, raw={"token": token}
        )
