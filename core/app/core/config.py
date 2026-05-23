from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

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

    # Внутренний ключ для воркеров -> Core
    INTERNAL_API_SECRET: str = "INTERNAL_CHANGE_ME"

    # Первый суперпользователь (создаётся при старте)
    FIRST_SUPERUSER_EMAIL: str = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD: str = "changeme"

    # GitHub поиск (опционально)
    GITHUB_TOKEN: str = ""

    # HaveIBeenPwned API ключ (опционально, без ключа - ограниченный доступ)
    HIBP_API_KEY: str = ""

    # Telegram Bot API токен для алертов
    TELEGRAM_BOT_TOKEN: str = ""

    # Порт Core API (используется воркерами для ingest)
    APP_PORT: int = 8000


@lru_cache
def get_settings() -> Settings:
    """
    Lazy-инициализация настроек с кэшированием.
    lru_cache гарантирует один объект Settings на весь процесс.
    Тесты могут сбрасывать кэш через get_settings.cache_clear().
    Инициализация НЕ происходит при импорте модуля — только при первом вызове.
    """
    return Settings()


class _SettingsProxy:
    """
    Прокси для обратной совместимости: from app.core.config import settings.
    Делегирует все атрибуты к get_settings() без eager-инициализации на импорте.
    Это позволяет тестам переопределять переменные окружения до первого чтения.
    """

    def __getattr__(self, name: str):
        return getattr(get_settings(), name)

    def __repr__(self) -> str:
        return repr(get_settings())


# Алиас для удобного импорта. Значение вычисляется лениво при первом обращении.
settings = _SettingsProxy()
