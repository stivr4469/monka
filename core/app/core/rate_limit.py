"""
Настройка rate limiting через slowapi.

slowapi — это обёртка над limits для FastAPI, совместимая с ASGI.
Использует in-memory хранилище (MemoryStorage) без Redis для простоты.
В production рекомендуется переключить на RedisStorage для корректной
работы при нескольких репликах.

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
from slowapi import Limiter
from slowapi.util import get_remote_address

# Используем IP клиента как ключ rate limiting.
# get_remote_address извлекает IP из X-Forwarded-For или request.client.host.
limiter = Limiter(key_func=get_remote_address)
