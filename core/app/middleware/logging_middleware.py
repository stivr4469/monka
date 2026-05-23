"""
Middleware логирования HTTP-запросов для EASM Core API.

Логирует:
  - метод, путь, статус, время выполнения для каждого запроса
  - event_type и target_domain для /api/v1/internal/ingest
  - добавляет X-Request-ID заголовок в ответ

НЕ логирует тело запроса для путей содержащих "auth" или "token"
(защита от попадания паролей и токенов в логи).
"""
import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger("easm.access")

# Пути содержащие эти подстроки — тело запроса в лог не пишем
_SENSITIVE_PATH_MARKERS = ("auth", "token")

# Путь эндпоинта ingest — логируем дополнительные поля из тела
_INGEST_PATH = "/api/v1/internal/ingest"


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware для структурированного логирования запросов.
    Добавляет X-Request-ID к каждому ответу для трассировки.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Генерируем уникальный ID запроса
        request_id = str(uuid.uuid4())
        # Сохраняем в state чтобы endpoint мог использовать при необходимости
        request.state.request_id = request_id

        start_time = time.perf_counter()

        # Для ingest-эндпоинта читаем тело ДО вызова handler,
        # чтобы извлечь event_type и target_domain для лога.
        # Тело буферизуем и подставляем обратно в request.
        ingest_event_type: str | None = None
        ingest_target_domain: str | None = None

        if request.url.path == _INGEST_PATH:
            try:
                body_bytes = await request.body()
                # Восстанавливаем body в request (Starlette позволяет это через _body)
                request._body = body_bytes  # type: ignore[attr-defined]

                import json
                body_json = json.loads(body_bytes)
                ingest_event_type = body_json.get("event_type")
                ingest_target_domain = body_json.get("target_domain")
            except Exception:
                pass  # Если тело невалидно — не ломаем запрос

        # Выполняем запрос
        try:
            response: Response = await call_next(request)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(
                "REQUEST ERROR | method=%s path=%s request_id=%s elapsed_ms=%.1f error=%s",
                request.method,
                request.url.path,
                request_id,
                elapsed_ms,
                exc,
            )
            raise

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Добавляем X-Request-ID в ответ
        response.headers["X-Request-ID"] = request_id

        # Базовый лог запроса
        log_parts = [
            f"method={request.method}",
            f"path={request.url.path}",
            f"status={response.status_code}",
            f"elapsed_ms={elapsed_ms:.1f}",
            f"request_id={request_id}",
        ]

        # Для ingest добавляем event_type и target_domain
        if request.url.path == _INGEST_PATH:
            if ingest_event_type:
                log_parts.append(f"event_type={ingest_event_type}")
            if ingest_target_domain:
                log_parts.append(f"target_domain={ingest_target_domain}")

        # Уровень лога зависит от статуса ответа
        log_line = " | ".join(log_parts)
        if response.status_code >= 500:
            logger.error(log_line)
        elif response.status_code >= 400:
            logger.warning(log_line)
        else:
            logger.info(log_line)

        return response
