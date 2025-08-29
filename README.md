# mcp-auth-py

🔒 Plug-and-play authentication, authorization, and rate-limiting for MCP servers.

## Quickstart

```bash
pip install mcp-auth-py
```

Example:

```python
from fastapi import FastAPI
from mcp_auth.setup import setup_auth

app = FastAPI()
app = setup_auth(app)

@app.get("/hello")
async def hello():
    return {"message": "Hello, secure world!"}
```
