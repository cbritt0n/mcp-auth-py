from fastapi.testclient import TestClient
from fastapi import FastAPI
from mcp_auth.setup import setup_auth

app = FastAPI()
app = setup_auth(app)
client = TestClient(app)

def test_unauthorized():
    r = client.get("/hello")
    assert r.status_code == 401
