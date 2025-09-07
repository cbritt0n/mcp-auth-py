from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from jose import jwt, JWTError
from .settings import Settings
from .providers import get_provider, register_provider
from .providers.local import LocalProvider

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings
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

        try:
            result = provider.authenticate(request)
        except Exception as e:
            return JSONResponse({"error": "Auth error", "detail": str(e)}, status_code=500)

        if not result or not result.valid:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)

        # attach principal to request state for downstream apps
        request.state.principal = result.principal
        request.state.claims = result.claims or {}
        return await call_next(request)
