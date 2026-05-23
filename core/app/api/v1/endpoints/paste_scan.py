"""
Эндпоинт запуска мониторинга paste-сервисов по домену.

Запускает monitor_pastes в фоне (ThreadPoolExecutor).
Результаты появятся в /api/v1/events/?event_type=paste_leak
"""
import concurrent.futures
import os
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.deps import CurrentUser
from app.core.config import settings

router = APIRouter(prefix="/scan", tags=["scan"])

# Пул потоков для фоновых задач — max_workers=4 позволяет параллельно
# сканировать несколько доменов без блокировки event loop FastAPI
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

# Добавляем workers/ в sys.path чтобы импортировать tasks.paste_monitor
_WORKERS_PATH = str(Path(__file__).parents[6] / "workers")
if _WORKERS_PATH not in sys.path:
    sys.path.insert(0, _WORKERS_PATH)

try:
    from tasks.paste_monitor import monitor_pastes
    _PASTE_MONITOR_AVAILABLE = True
except ImportError:
    _PASTE_MONITOR_AVAILABLE = False


# ──────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────

class PasteScanRequest(BaseModel):
    domain: str


class PasteScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


# ──────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────

@router.post(
    "/paste",
    response_model=PasteScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def trigger_paste_scan(
    body: PasteScanRequest,
    current_user: CurrentUser,
) -> PasteScanResponse:
    """
    Запускает мониторинг публичных paste-сервисов (Pastebin, Pastee.org)
    на упоминания домена в фоновом потоке.

    Результаты доступны через /api/v1/events/?event_type=paste_leak
    """
    if not _PASTE_MONITOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Paste-монитор недоступен: воркер не загружен",
        )

    domain = body.domain.strip().lower()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Домен не указан",
        )

    # Определяем URL Core API — воркер обращается к нему для ingest событий
    port = int(os.getenv("APP_PORT", "8000"))
    core_api_url = f"http://127.0.0.1:{port}"

    _executor.submit(
        monitor_pastes,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return PasteScanResponse(
        status="processing",
        domain=domain,
        detail=(
            "Мониторинг paste-сервисов запущен в фоне. "
            "Результаты: /api/v1/events/?event_type=paste_leak"
        ),
    )


# ROUTER: api_router.include_router(paste_scan.router) — но импорт scan уже есть, добавь к нему
# В router.py добавить строки:
#   from app.api.v1.endpoints import paste_scan
#   api_router.include_router(paste_scan.router)
