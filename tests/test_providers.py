from fastapi import FastAPI
from fastapi.testclient import TestClient
from mcp_auth.setup import setup_auth
from mcp_auth.providers.registry import register_provider
from mcp_auth.providers.local import LocalProvider
from mcp_auth.settings import Settings

app = FastAPI()
settings = Settings()
# register local provider to mirror existing behavior
register_provider("local", LocalProvider(settings))
app = setup_auth(app, settings=settings)
client = TestClient(app)


def test_local_unauthorized():
    r = client.get("/hello")
    assert r.status_code == 401

