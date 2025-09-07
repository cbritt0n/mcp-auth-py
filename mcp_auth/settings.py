from typing import Any, Dict, Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    jwt_secret: str = "supersecret"
    jwt_algorithm: str = "HS256"
    use_redis_ratelimit: bool = False
    casbin_policy_path: Optional[str] = None
    # pluggable provider name: 'local', 'azure', 'aws', 'google'
    auth_provider: str = "local"
    # provider specific configuration (optional)
    provider_config: Optional[Dict[str, Any]] = None
    # optional Redis JWKS settings
    redis_jwks: bool = False
    redis_url: Optional[str] = None

    class Config:
        env_file = ".env"
