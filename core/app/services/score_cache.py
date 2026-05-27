"""Redis-кеш для Security Score (задача 11.A.9).

TTL 5 минут. При недоступности Redis — fail-open (возвращает None).
"""
import json
import logging

from app.core.config import get_settings

log = logging.getLogger(__name__)

_SCORE_TTL = 300  # 5 минут

# Ленивая инициализация клиента — не блокируем старт если Redis недоступен.
_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    try:
        import redis.asyncio as aioredis
        settings = get_settings()
        _client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
    except Exception as exc:
        log.debug("score_cache: Redis недоступен — %s", exc)
    return _client


async def score_cache_get(key: str) -> dict | None:
    client = _get_client()
    if client is None:
        return None
    try:
        raw = await client.get(f"easm:score:{key}")
        return json.loads(raw) if raw else None
    except Exception as exc:
        log.debug("score_cache get error: %s", exc)
        return None


async def score_cache_set(key: str, data: dict) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        await client.set(f"easm:score:{key}", json.dumps(data), ex=_SCORE_TTL)
    except Exception as exc:
        log.debug("score_cache set error: %s", exc)


async def score_cache_invalidate(key: str) -> None:
    """Сбрасывает кеш при изменении событий (resolve, ingest)."""
    client = _get_client()
    if client is None:
        return
    try:
        await client.delete(f"easm:score:{key}")
    except Exception as exc:
        log.debug("score_cache invalidate error: %s", exc)
