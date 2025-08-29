from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    jwt_secret: str = "supersecret"
    jwt_algorithm: str = "HS256"
    use_redis_ratelimit: bool = False
    casbin_policy_path: str | None = None

    class Config:
        env_file = ".env"
