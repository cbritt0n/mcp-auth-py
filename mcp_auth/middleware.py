from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from jose import jwt, JWTError
from .settings import Settings

class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        token = auth.split(" ")[1]
        try:
            jwt.decode(token, self.settings.jwt_secret, algorithms=[self.settings.jwt_algorithm])
        except JWTError:
            return JSONResponse({"error": "Invalid token"}, status_code=403)
        return await call_next(request)
