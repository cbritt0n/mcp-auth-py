
try:
    from pydantic_settings import BaseSettings
except Exception:
    # Lightweight fallback used for tests or environments without pydantic-settings.
    class BaseSettings:
        """Minimal BaseSettings fallback: use class attributes as defaults and allow overrides via constructor."""
        def __init__(self, **kwargs):
            # populate defaults from class attributes
            for name, val in self.__class__.__dict__.items():
                if name.startswith("_") or callable(val) or isinstance(val, (staticmethod, classmethod)):
                    continue
                setattr(self, name, val)
            # override with kwargs
            for k, v in kwargs.items():
                setattr(self, k, v)
from typing import Optional, Dict, Any


class Settings(BaseSettings):
    jwt_secret: str = "supersecret"
    jwt_algorithm: str = "HS256"
    use_redis_ratelimit: bool = False
    casbin_policy_path: Optional[str] = None
    # pluggable provider name: 'local', 'azure', 'aws', 'google'
    auth_provider: str = "local"
    # provider specific configuration (optional)
    provider_config: Optional[Dict[str, Any]] = None

    class Config:
        env_file = ".env"
