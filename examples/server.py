from fastapi import FastAPI

from mcp_auth.setup import setup_auth

app = FastAPI()
app = setup_auth(app)


@app.get("/hello")
async def hello():
    return {"message": "Hello, secure world!"}
