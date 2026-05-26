"""
Эндпоинт Censys Enrichment (Phase 13.B).

POST /api/v1/scan/censys — обогащение данных о домене через Censys Search API.

Особенности:
  - Rate limit 5/minute (Censys API менее ограничен чем Shodan, но лимит есть)
  - 503 если CENSYS_API_ID/SECRET не настроены (в отличие от Shodan — явная ошибка)
  - Запускает воркер в ThreadPoolExecutor (fire-and-forget → 202 Accepted)
  - Результаты: /api/v1/events?source_name=censys
"""
import asyncio
import os
import re

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

ensure_workers_path()

try:
    from workers.tasks.censys_enricher import enrich_domain_with_censys
    _CENSYS_WORKER_AVAILABLE = True
except ImportError:
    _CENSYS_WORKER_AVAILABLE = False

# Паттерн валидации домена
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


class CensysRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Домен не может быть пустым")
        if "://" in cleaned or "/" in cleaned:
            raise ValueError("Укажите домен без схемы и пути, например: example.com")
        if not _DOMAIN_RE.match(cleaned):
            raise ValueError("Некорректный домен. Пример: example.com")
        return cleaned


class CensysResponse(BaseModel):
    status: str
    domain: str
    detail: str
    checked: int = 0
    sent: int = 0


@router.post(
    "/censys",
    response_model=CensysResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Censys Enrichment — обогащение данных о домене",
    description=(
        "Запускает Censys Search API enrichment для домена. "
        "Находит открытые порты, сервисы, геолокацию и информацию об AS. "
        "Требует CENSYS_API_ID и CENSYS_API_SECRET в .env — без ключей возвращает 503. "
        "Результаты: /api/v1/events/?source_name=censys"
    ),
)
@limiter.limit("5/minute")
async def censys_scan(
    request: Request,
    body: CensysRequest,
    current_user: CurrentUser,
) -> CensysResponse:
    """
    Запускает Censys enrichment для домена.

    Возвращает 503 если CENSYS_API_ID/SECRET не настроены.
    Возвращает 202 Accepted при запуске (fire-and-forget).
    """
    # Проверяем наличие credentials до запуска воркера
    if not os.environ.get("CENSYS_API_ID") or not os.environ.get("CENSYS_API_SECRET"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Censys API credentials не настроены. "
                "Добавьте CENSYS_API_ID и CENSYS_API_SECRET в .env"
            ),
        )

    if not _CENSYS_WORKER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Censys воркер недоступен: модуль не загружен",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    # Запускаем воркер в ThreadPoolExecutor (fire-and-forget)
    loop = asyncio.get_running_loop()
    loop.run_in_executor(
        get_executor(),
        enrich_domain_with_censys,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return CensysResponse(
        status="accepted",
        domain=body.domain,
        detail=(
            "Censys enrichment запущен в фоне. "
            "Результаты появятся в /api/v1/events/?source_name=censys"
        ),
    )
