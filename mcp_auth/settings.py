from typing import Any, Dict, Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # JWT settings for local provider
    jwt_secret: str = "supersecret"
    jwt_algorithm: str = "HS256"
    
    # Provider selection: 'local', 'google', 'aws', 'azure'
    auth_provider: str = "local"
    
    # Provider-specific configuration (optional)
    provider_config: Optional[Dict[str, Any]] = None
    
    # Redis JWKS caching settings (optional)
    redis_jwks: bool = False
    redis_url: Optional[str] = None

    class Config:
        env_file = ".env"
