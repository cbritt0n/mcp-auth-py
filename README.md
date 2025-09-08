# mcp-auth-py

[![CI](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml/badge.svg)](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml)

🔒 mcp-auth-py is a small, framework-friendly library that adds pluggable authentication providers
for FastAPI (or other ASGI apps). It provides a lightweight middleware and a small provider
registry so you can swap in authentication backends for Local (JWT), Google, AWS (Cognito),
and Azure (AAD) without changing application code.

Why this project
- Make it easy to support multiple cloud identity providers through a single middleware contract.
- Minimal dependencies for the core; providers optionally use cloud SDKs when available.
- Designed to be easy to extend: add a provider and register it — no framework changes.

## Features

TL;DR: Pluggable auth for FastAPI/ASGI — swap providers (local/google/aws/azure), async-capable, with JWKS caching (optional Redis).

# mcp-auth-py — pluggable auth for ASGI apps (FastAPI-friendly)

[![CI](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml/badge.svg)](https://github.com/cbritt0n/mcp-auth-py/actions/workflows/ci.yml)

Quick pitch — why mcp-auth-py?
- Plug-and-play providers: swap `local`, `google`, `aws` (Cognito), or `azure` without changing app code.
- Cloud-aware: supports Google ID tokens, AWS Cognito OIDC, and Azure AD OIDC out of the box.
- Async-friendly: middleware and providers can be async; blocking SDKs are offloaded to threadpools.
- JWKS caching: per-process TTL cache plus an optional Redis-backed JWKS adapter for multi-process sharing.
- Minimal core deps: keep your app light; provider SDKs are optional extras you install as needed.
- Testable & CI-ready: unit tests and CI pre-commit hooks are included to keep quality high.

What this library does
- Adds a small middleware and provider registry for ASGI apps (FastAPI example provided).
- Provides a canonical `Principal` model and an `AuthResult` contract so providers return a uniform shape.
- Makes it easy to add new providers: implement the `Provider` interface and register it.

## Features
- Provider interface + registry for pluggable authentication backends
- Built-in `local` provider (HS256 JWT)
- `google` provider using `google-auth` for ID tokens
- `aws` provider with Cognito JWKS validation and optional `boto3` checks
- `azure` provider that validates tokens from your tenant's OIDC endpoint
- Per-provider JWKS caching and optional shared Redis JWKS adapter
- Async-capable flows and small sync/async adapters for non-ASGI MCP servers

## Quickstart (from source)

Clone and install dev dependencies (recommended):

```bash
git clone https://github.com/cbritt0n/mcp-auth-py.git
cd mcp-auth-py
./scripts/setup-dev.sh
```

Run the example app in `examples/server.py`:

```bash
uvicorn examples.server:app --reload
```

Visit http://localhost:8000/hello — the middleware is installed and will block requests without a valid token.

Single-file FastAPI example
---------------------------
Here's a minimal, copy-paste FastAPI app that registers the `local` provider and installs the middleware.

```python
from fastapi import FastAPI

from mcp_auth.settings import Settings
from mcp_auth.providers.local import LocalProvider
from mcp_auth.providers.registry import register_provider
from mcp_auth.setup import setup_auth

# configure Settings (for local provider we provide a jwt_secret)
settings = Settings(auth_provider="local", provider_config={"jwt_secret": "dev-secret"})

# register the provider and wire middleware
register_provider("local", LocalProvider(settings))
app = FastAPI()
app = setup_auth(app, settings=settings)


@app.get("/hello")
def hello():
    # request.state.principal will be set by the middleware on success
    return {"message": "hello from mcp-auth-py example"}

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
```

## Running tests

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

## Provider SDKs (optional)

Install cloud SDKs only when you need the extra features or want to run provider integration tests:

```bash
# install provider SDKs individually
pip install google-auth boto3 msal azure-identity

# or install package extras
pip install .[google]  # or .[aws] .[azure]
```

## Async support & production readiness

### Async support
- Middleware and providers are async-capable. Providers can be implemented as coroutines or sync
  functions — the middleware will `await` coroutine results automatically.
- For blocking SDKs (e.g. `boto3`) we use threadpool offloading to avoid blocking the event loop.
- To be fully non-blocking in production, enable async-capable libs like `httpx` (JWKS) and `aioredis`.

### Production checklist
- Use the `redis_jwks` adapter for shared JWKS caching across processes. Set `redis_url` in `Settings`.
- Install only the provider SDKs you need in production (avoid shipping dev shims).
- Run `pre-commit run --all-files` locally before pushing to keep CI green.
- Run under a production ASGI server (Uvicorn/Gunicorn with workers) and terminate TLS at the edge.
- Configure timeouts, connection pools, and monitoring for JWKS fetches and cache hit rates.

## Adapters (non-ASGI / MCP servers)

The package includes `mcp_auth.adapters` with helpers for calling providers from non-ASGI or
sync MCP servers:

- `authenticate_request(provider, request)` — async helper that awaits provider results.
- `authenticate_request_sync(provider, request)` — sync wrapper for legacy servers.
- `token_to_principal(provider, token)` / `token_to_principal_sync(...)` — minimal token helpers.

Example (sync server):

```python
from mcp_auth.providers.registry import get_provider
from mcp_auth.adapters import token_to_principal_sync

provider = get_provider("aws")
principal = token_to_principal_sync(provider, token)
if principal is None:
    # unauthorized
    ...
```

## Provider configuration

Set `auth_provider` and `provider_config` via `mcp_auth.settings.Settings` (Pydantic Settings if available).

### Local (default)

```python
from mcp_auth.settings import Settings
settings = Settings(auth_provider="local")
```

### Google

```python
settings = Settings(
    auth_provider="google",
    provider_config={"audience": "GOOGLE_CLIENT_ID"},
)
```

### AWS Cognito

```python
settings = Settings(
    auth_provider="aws",
    provider_config={
        "cognito_region": "us-west-2",
        "cognito_user_pool_id": "us-west-2_XXXXXXXXX",
        "audience": "YOUR_COGNITO_APP_CLIENT_ID",
        "use_cognito_get_user": False,
    },
)
```

### Azure AD

```python
settings = Settings(
    auth_provider="azure",
    provider_config={"tenant": "your-tenant-id", "audience": "APP_CLIENT_ID"},
)
```

## Using Redis-backed JWKS cache

Install the optional `redis_jwks` extra and enable it per-provider via `redis_jwks=True` and `redis_url`:

```bash
pip install .[redis_jwks]
```

```python
from mcp_auth.providers.aws import AWSProvider

provider = AWSProvider({
    "cognito_region": "us-west-2",
    "cognito_user_pool_id": "us-west-2_XXXX",
    "redis_jwks": True,
    "redis_url": "redis://redis.example.local:6379/0",
})
```

The adapter is optional; when unset the provider falls back to the in-process cache.

## Development notes
- JWKS are cached per provider instance; use Redis for multi-process sharing.
- Tests include shims so you can run the suite without every cloud SDK installed.

## Contributing

See `CONTRIBUTING.md` for contributor guidelines.

## License

Apache-2.0 — see `LICENSE`.

Environment variables are supported via `pydantic-settings` (see `Settings.Config.env_file`).


```python
from mcp_auth.providers.registry import get_provider
from mcp_auth.adapters import token_to_principal_sync

provider = get_provider("aws")
principal = token_to_principal_sync(provider, token)
if principal is None:
    # unauthorized
    ...
```

## Provider configuration

Set `auth_provider` and `provider_config` via `mcp_auth.settings.Settings` (Pydantic Settings if available).

### Local (default)

```python
from mcp_auth.settings import Settings
settings = Settings(auth_provider="local")
```

### Google

```python
settings = Settings(
    auth_provider="google",
    provider_config={"audience": "GOOGLE_CLIENT_ID"},
)
```

### AWS Cognito

```python
settings = Settings(
    auth_provider="aws",
    provider_config={
        "cognito_region": "us-west-2",
        "cognito_user_pool_id": "us-west-2_XXXXXXXXX",
        "audience": "YOUR_COGNITO_APP_CLIENT_ID",
        "use_cognito_get_user": False,
    },
)
```

### Azure AD

```python
settings = Settings(
    auth_provider="azure",
    provider_config={"tenant": "your-tenant-id", "audience": "APP_CLIENT_ID"},
)
```

## Using Redis-backed JWKS cache

Install the optional `redis_jwks` extra and enable it per-provider via `redis_jwks=True` and `redis_url`:

```bash
pip install .[redis_jwks]
```

```python
from mcp_auth.providers.aws import AWSProvider

provider = AWSProvider({
    "cognito_region": "us-west-2",
    "cognito_user_pool_id": "us-west-2_XXXX",
    "redis_jwks": True,
    "redis_url": "redis://redis.example.local:6379/0",
})
```

The adapter is optional; when unset the provider falls back to the in-process cache.

## Development notes
- JWKS are cached per provider instance; use Redis for multi-process sharing.
- Tests include shims so you can run the suite without every cloud SDK installed.

## Contributing

See `CONTRIBUTING.md` for contributor guidelines.

## License

Apache-2.0 — see `LICENSE`.

Environment variables are supported via `pydantic-settings` (see `Settings.Config.env_file`).
