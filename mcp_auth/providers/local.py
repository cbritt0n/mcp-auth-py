from fastapi import Request
from jose import JWTError, jwt

from mcp_auth.settings import Settings

from .base import AuthResult, Provider, ProviderError


class LocalProvider(Provider):
    def __init__(self, settings: Settings):
        self.settings = settings

    def authenticate(self, request: Request) -> AuthResult:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return AuthResult(valid=False)
        token = auth.split(" ", 1)[1]
        try:
            claims = jwt.decode(
                token,
                self.settings.jwt_secret,
                algorithms=[self.settings.jwt_algorithm],
            )
        except JWTError:
            return AuthResult(valid=False)
        principal = claims.get("sub") or claims.get("email")
        return AuthResult(
            valid=True, principal=principal, claims=claims, raw={"token": token}
        )
