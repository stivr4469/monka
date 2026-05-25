"""
Настройка rate limiting через slowapi.

slowapi — это обёртка над limits для FastAPI, совместимая с ASGI.
При наличии REDIS_URL использует RedisStorage для корректной работы
при нескольких репликах. Fallback на MemoryStorage если Redis недоступен.

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

# HIGH-2: Redis storage для корректной работы при нескольких репликах.
# Fallback на MemoryStorage если REDIS_URL не задан.
_storage_uri: str | None = getattr(settings, "REDIS_URL", None) or None

def _redis_reachable(uri: str) -> bool:
    """Проверяет доступность Redis синхронным пингом (до 1с)."""
    try:
        import redis as _redis
        r = _redis.from_url(uri, socket_connect_timeout=1, socket_timeout=1)
        r.ping()
        return True
    except Exception:
        return False


if _storage_uri and _redis_reachable(_storage_uri):
    limiter = Limiter(key_func=get_remote_address, storage_uri=_storage_uri)
    logger.info("Rate limiter: RedisStorage (%s)", _storage_uri)
else:
    limiter = Limiter(key_func=get_remote_address)
    if _storage_uri:
        logger.warning("Rate limiter: Redis недоступен (%s), используется MemoryStorage", _storage_uri)
    else:
        logger.warning("Rate limiter: MemoryStorage — не работает при нескольких репликах")
