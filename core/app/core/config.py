from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # БД
    DATABASE_URL: str = "postgresql+asyncpg://easm:easm@postgres:5432/easm"

    # OpenSearch
    OPENSEARCH_URL: str = "http://opensearch:9200"
    OPENSEARCH_INDEX_EVENTS: str = "easm-events"

    # Redis / Celery
    REDIS_URL: str = "redis://redis:6379/0"

    # JWT
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Внутренний ключ для воркеров → Core
    INTERNAL_API_SECRET: str = "INTERNAL_CHANGE_ME"

    # Первый суперпользователь (создаётся при старте)
    FIRST_SUPERUSER_EMAIL: str = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "changeme"

    # GitHub поиск (опционально)
    GITHUB_TOKEN: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
