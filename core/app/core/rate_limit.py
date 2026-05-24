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

try:
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=_storage_uri,
    )
    if _storage_uri:
        logger.info("Rate limiter: RedisStorage (%s)", _storage_uri)
    else:
        logger.warning("Rate limiter: MemoryStorage — не работает при нескольких репликах")
except Exception as exc:
    logger.warning("Rate limiter: ошибка подключения к Redis (%s), используется MemoryStorage", exc)
    limiter = Limiter(key_func=get_remote_address)
