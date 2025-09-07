from typing import Callable, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from .providers import get_provider, register_provider
from .providers.local import LocalProvider
from .settings import Settings


def _default_token_extractor(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        return auth.split(" ", 1)[1]
    # fallback to cookie or query param
    token = request.cookies.get("access_token")
    if token:
        return token
    token = request.query_params.get("access_token")
    return token


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings, token_extractor: Callable = None):
        super().__init__(app)
        self.settings = settings
        self.token_extractor = token_extractor or _default_token_extractor
        # Ensure local provider is registered (backwards-compatible)
        try:
            get_provider(settings.auth_provider)
        except LookupError:
            register_provider("local", LocalProvider(settings))

    async def dispatch(self, request: Request, call_next):
        # Delegate authentication to the configured provider
        try:
            provider = get_provider(self.settings.auth_provider)
        except LookupError:
            return JSONResponse({"error": "Auth provider not found"}, status_code=500)

        # Allow providers to be sync or async
        try:
            result = provider.authenticate(request)
            # await if coroutine
            if hasattr(result, "__await__"):
                result = await result
        except Exception as e:
            return JSONResponse(
                {"error": "Auth error", "detail": str(e)},
                status_code=500,
            )

        if not result or not result.valid:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

        # attach structured principal and raw claims to request.state
        request.state.principal = result.principal
        request.state.claims = result.claims or {}
        return await call_next(request)
