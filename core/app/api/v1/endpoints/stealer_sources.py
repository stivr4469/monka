"""
Эндпоинт запуска проверки по автоматическим источникам стилер-логов.

Опрашивает Hudson Rock Cavalier (бесплатно), Snusbase и LeakCheck
(требуют ключи SNUSBASE_API_KEY / LEAKCHECK_API_KEY в .env).
Результаты появляются в /api/v1/events/?event_type=stealer_log
"""
import concurrent.futures
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings

# ── импорт воркера ──────────────────────────────────────
_workers_path = Path(__file__).parent.parent.parent.parent.parent.parent / "workers"
if str(_workers_path) not in sys.path:
    sys.path.insert(0, str(_workers_path))

try:
    from tasks.stealer_sources import query_stealer_sources
    _SOURCES_AVAILABLE = True
except ImportError as _e:
    _SOURCES_AVAILABLE = False
    _IMPORT_ERROR = str(_e)

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=3)

router = APIRouter(prefix="/scan", tags=["scan"])


class StealerSourcesRequest(BaseModel):
    domain: str

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


@router.post(
    "/stealer-sources",
    summary="Проверка по источникам стилер-логов (Hudson Rock, Snusbase, LeakCheck)",
)
async def run_stealer_sources(
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

    _executor.submit(
        query_stealer_sources,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return {
        "status": "started",
        "domain": domain,
        "message": (
            "Проверка запущена по источникам: Hudson Rock Cavalier, Snusbase, LeakCheck. "
            "Результаты появятся в Events → stealer_log"
        ),
        "sources": {
            "hudsonrock": "всегда активен",
            "snusbase": "активен при наличии SNUSBASE_API_KEY",
            "leakcheck": "активен при наличии LEAKCHECK_API_KEY",
        },
    }
