from typing import Optional

from jose import JWTError, jwt

from mcp_auth.models import Principal

from .base import AuthResult, Provider, ProviderError
from .oidc import JWKSCache, get_jwks_url_from_well_known

# Default well-known URL template for Azure AD
AZURE_WELL_KNOWN = (
    "https://login.microsoftonline.com/{tenant}/v2.0/"
    ".well-known/openid-configuration"
)


class AzureProvider(Provider):
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._jwks_cache = None

    async def authenticate(self, request) -> AuthResult:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return AuthResult(valid=False)
        token = auth.split(" ", 1)[1]

        tenant = self.config.get("tenant") or "common"
        well_known = self.config.get("well_known") or AZURE_WELL_KNOWN.format(
            tenant=tenant
        )
        try:
            if not self._jwks_cache:
                jwks_url = get_jwks_url_from_well_known(well_known)
                if self.config.get("redis_jwks"):
                    try:
                        from .redis_jwks import RedisJWKSCache

                        self._jwks_cache = RedisJWKSCache(
                            jwks_url, redis_url=self.config.get("redis_url")
                        )
                    except Exception:
                        self._jwks_cache = JWKSCache(jwks_url)
                else:
                    self._jwks_cache = JWKSCache(jwks_url)
            if hasattr(self._jwks_cache, "get_jwks_async"):
                jwks = await self._jwks_cache.get_jwks_async()
            else:
                import asyncio as _asyncio

                jwks = await _asyncio.get_event_loop().run_in_executor(
                    None, self._jwks_cache.get_jwks
                )
            audience = self.config.get("audience")
            options = {"verify_aud": bool(audience)}
            claims = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                options=options,
                audience=audience if audience else None,
            )
        except JWTError:
            return AuthResult(valid=False)
        except Exception as e:
            raise ProviderError(str(e))

        principal_id = claims.get("sub") or claims.get("upn") or claims.get("oid")
        if not principal_id:
            return AuthResult(valid=False)  # No valid identifier in token
            
        principal = Principal(
            id=str(principal_id), 
            provider="azure", 
            name=claims.get("name"),
            email=claims.get("upn") or claims.get("email"),  # UPN or email
            roles=claims.get("groups") or claims.get("roles"),  # Azure AD groups/roles
            raw=claims
        )
        return AuthResult(
            valid=True, principal=principal, claims=claims, raw={"token": token}
        )
