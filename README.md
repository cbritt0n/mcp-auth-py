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
- Provider interface + registry for plug-and-play authentication backends
- Built-in `local` provider for HS256 JWT verification
- Google provider using `google-auth` for ID token verification
- AWS provider with Cognito JWKS validation and optional `get_user` verification via `boto3`
- Azure provider using OIDC JWKS validation with placeholders for SDK-based checks
- Per-provider JWKS caching (lazy, per-process)

## Quickstart (from source)

Clone and install dev deps (recommended):

```bash
git clone https://github.com/cbritt0n/mcp-auth-py.git
cd mcp-auth-py
./scripts/setup-dev.sh
```

Run the example app in `examples/server.py`:

```bash
uvicorn examples.server:app --reload
```

Visit http://localhost:8000/hello — the middleware is installed but will block requests without a valid token.

## Configuration
Configuration is provided through the `mcp_auth.settings.Settings` object (Pydantic Settings if available).
You can set `auth_provider` and `provider_config`.

Examples:

- Local (default):

```python
from mcp_auth.settings import Settings
settings = Settings(auth_provider="local")
```

- Google:

```python
settings = Settings(
    auth_provider="google",
    provider_config={"audience": "GOOGLE_CLIENT_ID"}
)
```

- AWS Cognito:

```python
settings = Settings(
    auth_provider="aws",
    provider_config={
        "cognito_region": "us-west-2",
        "cognito_user_pool_id": "us-west-2_XXX",
        "audience": "COGNITO_APP_CLIENT_ID",
    }
)
```

- Azure AD:

```python
settings = Settings(
    auth_provider="azure",
    provider_config={"tenant": "your-tenant-id", "audience": "APP_CLIENT_ID"}
)
```

## Running tests

The project contains unit tests that mock external SDKs and network calls. Run tests with pytest:

```bash
python -m pip install -r requirements-dev.txt  # or pip install pytest
pytest -q
```

## Development notes
- Providers cache JWKS per provider instance to reduce network calls. For cross-process sharing, consider
  using Redis or another shared cache.
- The code includes small shims so tests and local development work without installing every cloud SDK.

## Contributing
See `CONTRIBUTING.md` for guidelines on adding providers, tests, and style.

## License
Apache-2.0 — see `LICENSE`.

## Provider configuration

mcp-auth supports pluggable providers: `local`, `aws`, `azure`, and `google`.

Set the provider via environment or `Settings` using `auth_provider` and pass provider-specific configuration via `provider_config`.

Examples (pydantic `Settings` style):

- Local (default) — verifies JWT using `jwt_secret` in `Settings`:

```python
from mcp_auth.settings import Settings

settings = Settings(auth_provider="local")
app = setup_auth(app, settings=settings)
```

- Google — verify Google ID tokens (optionally enforce audience):

```python
settings = Settings(
    auth_provider="google",
    provider_config={"audience": "YOUR_GOOGLE_CLIENT_ID"}
)
app = setup_auth(app, settings=settings)
```

- AWS Cognito — verify JWT via Cognito's OIDC or optionally use `get_user` with Access Tokens:

```python
settings = Settings(
    auth_provider="aws",
    provider_config={
        "cognito_region": "us-west-2",
        "cognito_user_pool_id": "us-west-2_XXXXXXXXX",
        # optional: provide expected audience (client id)
        "audience": "YOUR_COGNITO_APP_CLIENT_ID",
        # optional: set to True to try boto3.get_user(AccessToken=...)
        "use_cognito_get_user": False,
    }
)
app = setup_auth(app, settings=settings)
```

- Azure AD — validate tokens issued by your tenant's OIDC endpoint:

```python
settings = Settings(
    auth_provider="azure",
    provider_config={
        "tenant": "your-tenant-id-or-name",
        "audience": "YOUR_APP_CLIENT_ID",
    }
)
app = setup_auth(app, settings=settings)
```

Environment variables are supported via `pydantic-settings` (see `Settings.Config.env_file`).
