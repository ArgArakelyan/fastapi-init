from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class AppConfig(BaseSettings):
    name: str = "FastAPI"
    version: str = "unknown"
    commit_url: str = "unknown"
    commit_author: str = "unknown"
    environment: str = "local"

    model_config = {"env_prefix": "APP_", "extra": "ignore"}


class DatabaseConfig(BaseSettings):
    hostname: str = "localhost"
    port: int = 5432
    name: str = "app_db"
    user: str = "app_user"
    password: SecretStr

    pool_size: int = 10

    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:  # noqa
        return (
            f"postgresql+asyncpg://{self.user}:{self.password.get_secret_value()}"
            f"@{self.hostname}:{str(self.port)}/{self.name}"
        )

    model_config = {"env_prefix": "PG_", "extra": "ignore"}


class RedisConfig(BaseSettings):
    hostname: str = "localhost"
    port: int = 6379
    db: int = 3
    cache_prefix: str = "tiny-backend"

    @property
    def REDIS_URI(self) -> str:  # noqa
        return f"redis://{self.hostname}:{self.port}/{self.db}"

    model_config = {"env_prefix": "REDIS_", "extra": "ignore"}


class RabbitConfig(BaseSettings):
    host: str = "rabbitmq"  # ← ИЗМЕНИТЕ!
    port: int = 5672
    user: str = "guest"
    password: SecretStr = "guest"
    vhost: str = ""

    heartbeat: int = 60
    connection_attempts: int = 3
    retry_delay: int = 5

    @property
    def RABBITMQ_URI(self) -> str:  # noqa
        return f"amqp://{self.user}:{self.password.get_secret_value()}@{self.host}:{self.port}/{self.vhost}"

    model_config = {"env_prefix": "RABBITMQ_", "extra": "ignore"}


class PrometheusConfig(BaseSettings):
    metrics_port: int = 9010

    model_config = {"env_prefix": "PROMETHEUS_", "extra": "ignore"}


class AuthConfig(BaseSettings):
    jwt_secret: SecretStr
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    jwt_encode_algorithm: str = "HS256"
    bearer_token: SecretStr

    model_config = {"env_prefix": "AUTH_", "extra": "ignore"}


class FeatureConfig(BaseSettings):

    model_config = {"env_prefix": "FEATURE_", "extra": "ignore"}


class Config(BaseSettings):
    log_level: int = 20
    python_version: str = ""

    app: AppConfig = Field(default_factory=AppConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    rabbitmq: RabbitConfig = Field(default_factory=RabbitConfig)
    prometheus: PrometheusConfig = Field(default_factory=PrometheusConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    feature: FeatureConfig = Field(default_factory=FeatureConfig)


config = Config()


fastapi_settings = {
    "title": config.app.name,  # в идеале передавать slug проекта из репы (через CI)
    "version": config.app.version,  # притягивается через CI
    "docs_url": None if config.app.environment == "production" else "/docs",
    "redoc_url": None if config.app.environment == "production" else "/redoc",
    "openapi_url": None if config.app.environment == "production" else "/openapi.json",
}
