"""
Эндпоинт запуска проверки по автоматическим источникам стилер-логов.

Источники:
  - Hudson Rock Cavalier     — бесплатно, без ключа
  - Snusbase                 — SNUSBASE_API_KEY в .env
  - LeakCheck                — LEAKCHECK_API_KEY в .env
  - Telegram-каналы (25+)   — скрейпинг t.me/s/, без ключа

Результаты появляются в /api/v1/events/?event_type=stealer_log
"""
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from workers.tasks.stealer_sources import query_stealer_sources
    _SOURCES_AVAILABLE = True
except ImportError as _e:
    _SOURCES_AVAILABLE = False
    _IMPORT_ERROR = str(_e)

router = APIRouter(prefix="/scan", tags=["scan"])


class StealerSourcesRequest(BaseModel):
    domain: str
    extra_tg_channels: Optional[list[str]] = None

    @field_validator("domain")
    @classmethod
    def normalise_domain(cls, v: str) -> str:
        v = v.strip().lower()
        for prefix in ("https://", "http://", "www."):
            if v.startswith(prefix):
                v = v[len(prefix):]
        v = v.rstrip("/").split("/")[0]
        if not v or "." not in v:
            raise ValueError("Укажите корректный домен, например example.com")
        return v

    @field_validator("extra_tg_channels", mode="before")
    @classmethod
    def clean_channels(cls, v):
        if not v:
            return []
        return [c.strip().lstrip("@") for c in v if c and c.strip()]


@router.post(
    "/stealer-sources",
    summary="Проверка по источникам стилер-логов",
)
@limiter.limit("20/minute")  # Ограничение запуска сканирований: 20 в минуту с IP
async def run_stealer_sources(
    request: Request,  # slowapi требует request для извлечения IP
    body: StealerSourcesRequest,
    current_user: CurrentUser,
):
    if not _SOURCES_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Воркер недоступен: {_IMPORT_ERROR}",
        )

    domain = body.domain
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        query_stealer_sources,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
        body.extra_tg_channels or [],
    )

    return {
        "status": "started",
        "domain": domain,
        "message": (
            "Проверка запущена. Результаты появятся в Events → stealer_log"
        ),
        "sources": {
            "hudsonrock":        "всегда активен",
            "snusbase":          "активен при наличии SNUSBASE_API_KEY",
            "leakcheck":         "активен при наличии LEAKCHECK_API_KEY",
            "telegram_channels": "25+ каналов, всегда активны (t.me/s/)",
        },
    }
