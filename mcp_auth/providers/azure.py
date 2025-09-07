from typing import Optional

from jose import JWTError, jwt

from .base import AuthResult, Provider, ProviderError
from .oidc import JWKSCache, get_jwks_url_from_well_known

try:
    import msal
except Exception:
    msal = None

# Default well-known URL template for Azure AD
AZURE_WELL_KNOWN = (
    "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
)


class AzureProvider(Provider):
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._jwks_cache = None

    def authenticate(self, request) -> AuthResult:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return AuthResult(valid=False)
        token = auth.split(" ", 1)[1]

        # If configured to attempt MSAL introspection or SDK checks, try those first
        if self.config.get("use_msal_introspect"):
            if msal is None:
                raise ProviderError("msal is required for use_msal_introspect option")
            # MSAL doesn't provide a direct introspect endpoint helper; fall back to OIDC if not implemented

        tenant = self.config.get("tenant") or "common"
        well_known = self.config.get("well_known") or AZURE_WELL_KNOWN.format(
            tenant=tenant
        )
        try:
            if not self._jwks_cache:
                jwks_url = get_jwks_url_from_well_known(well_known)
                self._jwks_cache = JWKSCache(jwks_url)
            jwks = self._jwks_cache.get_jwks()
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

        principal = claims.get("sub") or claims.get("upn") or claims.get("oid")
        return AuthResult(
            valid=True, principal=principal, claims=claims, raw={"token": token}
        )
