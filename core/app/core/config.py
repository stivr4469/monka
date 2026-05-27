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

    # Разрешённые CORS-источники (список через запятую в .env)
    # Пример: ALLOWED_ORIGINS=http://localhost:3000,https://app.example.com
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]

    # Режим разработки — включает беспарольный /auth/dev-login
    # НИКОГДА не ставить True в production
    DEV_MODE: bool = False


# Лимиты доменов (активов) по тарифным планам.
# enterprise = фактически безлимит; избегаем float("inf") для совместимости с JSON.
PLAN_DOMAIN_LIMITS: dict[str, int] = {
    "starter": 3,
    "professional": 10,
    "enterprise": 999_999,
}


_UNSAFE_DEFAULTS: frozenset[str] = frozenset({
    "CHANGE_ME_IN_PRODUCTION",
    "INTERNAL_CHANGE_ME",
    "changeme",
})


_MIN_SECRET_KEY_LENGTH: int = 32


def validate_secrets(s: Settings) -> None:
    """При старте приложения убеждаемся что секреты не оставлены дефолтными."""
    if s.SECRET_KEY in _UNSAFE_DEFAULTS:
        raise ValueError(
            "SECRET_KEY не изменён. Установите безопасное значение в .env"
        )
    if len(s.SECRET_KEY) < _MIN_SECRET_KEY_LENGTH:
        raise ValueError(
            f"SECRET_KEY слишком короткий ({len(s.SECRET_KEY)} символов). "
            f"Минимум {_MIN_SECRET_KEY_LENGTH} символов. "
            "Генерация: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    if s.INTERNAL_API_SECRET in _UNSAFE_DEFAULTS:
        raise ValueError(
            "INTERNAL_API_SECRET не изменён. Установите безопасное значение в .env"
        )
    if len(s.INTERNAL_API_SECRET) < _MIN_SECRET_KEY_LENGTH:
        raise ValueError(
            f"INTERNAL_API_SECRET слишком короткий ({len(s.INTERNAL_API_SECRET)} символов). "
            f"Минимум {_MIN_SECRET_KEY_LENGTH} символов. "
            "Генерация: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    if s.FIRST_SUPERUSER_PASSWORD in _UNSAFE_DEFAULTS:
        raise ValueError(
            "FIRST_SUPERUSER_PASSWORD не изменён. Установите безопасное значение в .env"
        )
    if len(s.FIRST_SUPERUSER_PASSWORD) < 12:
        raise ValueError(
            "FIRST_SUPERUSER_PASSWORD слишком короткий. Минимум 12 символов."
        )
    if s.ALGORITHM not in {"HS256", "HS384", "HS512"}:
        raise ValueError(
            f"Небезопасный JWT алгоритм: {s.ALGORITHM!r}. Допустимы: HS256, HS384, HS512"
        )
    if not s.DEV_MODE and s.FIRST_SUPERUSER_EMAIL == "admin@example.com":
        raise ValueError(
            "FIRST_SUPERUSER_EMAIL не изменён. Установите реальный email в .env"
        )
    if s.DEV_MODE:
        import logging
        logging.getLogger(__name__).warning(
            "DEV_MODE=True — /auth/dev-login активен. НИКОГДА не включать в production."
        )


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
