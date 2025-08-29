from fastapi import FastAPI
from .middleware import AuthMiddleware
from .settings import Settings

def setup_auth(app: FastAPI, settings: Settings = None):
    settings = settings or Settings()
    app.add_middleware(AuthMiddleware, settings=settings)
    return app
