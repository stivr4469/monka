"""
Эндпоинт запуска мониторинга paste-сервисов по домену.

Запускает monitor_pastes в фоне (ThreadPoolExecutor).
Результаты появятся в /api/v1/events/?event_type=paste_leak
"""
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

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
@limiter.limit("20/minute")  # Ограничение запуска сканирований: 20 в минуту с IP
async def trigger_paste_scan(
    request: Request,  # slowapi требует request для извлечения IP
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

    # Определяем URL Core API через settings — единственный источник истины
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
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
