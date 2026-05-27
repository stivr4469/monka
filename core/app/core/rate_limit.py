"""
Настройка rate limiting через slowapi.

slowapi — это обёртка над limits для FastAPI, совместимая с ASGI.
При наличии REDIS_URL использует RedisStorage для корректной работы
при нескольких репликах.

Политика при отказе Redis (fail-open vs fail-closed):
  - DEV_MODE=True  → fail-open: падаем на MemoryStorage, приложение продолжает работу.
  - DEV_MODE=False → fail-closed: если REDIS_URL задан, но Redis недоступен —
    бросаем исключение и блокируем старт. Это предотвращает обход rate limit
    при переезде/рестарте Redis в production-окружении.

Использование в эндпоинтах:
    from app.core.rate_limit import limiter
    from fastapi import Request

    @router.post("/token")
    @limiter.limit("10/minute")
    async def login(request: Request, ...):
        ...

ВАЖНО: декоратор @limiter.limit требует параметр request: Request
в сигнатуре функции — slowapi извлекает IP из него.
"""
import logging

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

logger = logging.getLogger(__name__)

# Redis storage для корректной работы при нескольких репликах.
_storage_uri: str | None = getattr(settings, "REDIS_URL", None) or None


def _redis_reachable(uri: str) -> bool:
    """Проверяет доступность Redis синхронным пингом (до 1с)."""
    try:
        import redis as _redis
        r = _redis.from_url(uri, socket_connect_timeout=1, socket_timeout=1)
        r.ping()
        return True
    except Exception as exc:
        logger.debug("Redis ping failed (%s): %s", uri, exc)
        return False


if _storage_uri:
    if _redis_reachable(_storage_uri):
        limiter = Limiter(key_func=get_remote_address, storage_uri=_storage_uri)
        logger.info("Rate limiter: RedisStorage (%s)", _storage_uri)
    else:
        # fail-open только в dev-режиме; в production отказ Redis — критический сигнал
        _dev_mode: bool = getattr(settings, "DEV_MODE", False)
        if _dev_mode:
            limiter = Limiter(key_func=get_remote_address)
            logger.warning(
                "Rate limiter: Redis недоступен (%s), DEV_MODE=True → MemoryStorage (fail-open). "
                "В production это недопустимо.",
                _storage_uri,
            )
        else:
            raise RuntimeError(
                f"REDIS_URL задан ({_storage_uri}), но Redis недоступен. "
                "Rate limiter не может быть инициализирован безопасно. "
                "Исправьте подключение к Redis или установите DEV_MODE=True для dev-окружения."
            )
else:
    limiter = Limiter(key_func=get_remote_address)
    logger.warning("Rate limiter: MemoryStorage — не работает при нескольких репликах")
