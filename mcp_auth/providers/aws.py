import asyncio
from typing import Optional

from jose import JWTError, jwt

from mcp_auth.models import Principal

from .base import AuthResult, Provider, ProviderError
from .oidc import JWKSCache, get_jwks_url_from_well_known

# Common Cognito well-known URL template (user-provided pool domain or issuer)
DEFAULT_WELL_KNOWN = None

# AWS-specific adapter stub. Options: Cognito JWT validation, STS, or SigV4 checks.


class AWSProvider(Provider):
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        # lazy-initialized shared JWKSCache for this provider instance
        self._jwks_cache = None

    def _build_well_known(self) -> Optional[str]:
        if self.config.get("well_known"):
            return self.config.get("well_known")
        region = self.config.get("cognito_region")
        pool = self.config.get("cognito_user_pool_id")
        if region and pool:
            return f"https://cognito-idp.{region}.amazonaws.com/{pool}/.well-known/openid-configuration"
        return None

    def _get_jwks_cache(self) -> Optional[JWKSCache]:
        if self._jwks_cache is not None:
            return self._jwks_cache
        well_known = self._build_well_known()
        if not well_known:
            return None
        jwks_url = get_jwks_url_from_well_known(well_known)
        self._jwks_cache = JWKSCache(jwks_url)
        return self._jwks_cache

    async def authenticate(self, request) -> AuthResult:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return AuthResult(valid=False)
        token = auth.split(" ", 1)[1]

        # Optionally validate using Cognito's get_user (requires boto3 and AccessToken)
        if self.config.get("use_cognito_get_user"):
            try:
                import boto3
            except Exception:
                raise ProviderError("boto3 is required for use_cognito_get_user option")

            # run blocking boto3 calls in threadpool to avoid blocking event loop
            def _call_get_user():
                client = boto3.client(
                    "cognito-idp", region_name=self.config.get("cognito_region")
                )
                return client.get_user(AccessToken=token)

            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, _call_get_user)
                # get_user does not return claims in this flow; construct a minimal principal
                principal = Principal(id="cognito-user", provider="aws", raw={"token": token})
                return AuthResult(valid=True, principal=principal, claims=None, raw={"token": token})
            except Exception as e:
                # handle NotAuthorizedException by name to avoid import coupling
                if e.__class__.__name__ == "NotAuthorizedException":
                    return AuthResult(valid=False)
                raise ProviderError(str(e))

        # Fallback: validate via OIDC JWKS
        well_known = self._build_well_known()
        if not well_known:
            raise ProviderError(
                "AWSProvider requires 'well_known' or cognito_region+cognito_user_pool_id in config"
            )

        try:
            cache = self._get_jwks_cache()
            if not cache:
                raise ProviderError("No JWKS configuration available for AWSProvider")
            # prefer async JWKS fetch, fall back to running sync fetch in threadpool
            if hasattr(cache, "get_jwks_async"):
                jwks = await cache.get_jwks_async()
            else:
                loop = asyncio.get_event_loop()
                jwks = await loop.run_in_executor(None, cache.get_jwks)
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

        principal_id = claims.get("sub") or claims.get("username")
        principal = Principal(id=str(principal_id), provider="aws", name=claims.get("name"), raw=claims)
        return AuthResult(valid=True, principal=principal, claims=claims, raw={"token": token})
