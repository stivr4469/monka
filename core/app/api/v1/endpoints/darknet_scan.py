"""
Эндпоинт запуска мониторинга даркнета на упоминания домена.

Запускает monitor_darknet в фоне (ThreadPoolExecutor).
Результаты появятся в /api/v1/events/?event_type=darknet_mention

Источники:
  - RansomWatch  → severity "critical"
  - Ahmia.fi     → severity "high"
  - DarkSearch   → severity "high"
"""
import concurrent.futures
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings

router = APIRouter(prefix="/scan", tags=["scan"])

# Пул потоков: max_workers=4 — достаточно для параллельного сканирования
# нескольких доменов без блокировки event loop FastAPI
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

# Добавляем workers/ в sys.path — паттерн аналогичен paste_scan.py / github_scan.py
_WORKERS_PATH = str(Path(__file__).parents[5] / "workers")
if _WORKERS_PATH not in sys.path:
    sys.path.insert(0, _WORKERS_PATH)

try:
    from tasks.darknet_monitor import monitor_darknet
    _DARKNET_MONITOR_AVAILABLE = True
except ImportError:
    _DARKNET_MONITOR_AVAILABLE = False


# ──────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────

class DarknetScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Нормализуем домен: убираем пробелы, приводим к нижнему регистру."""
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Домен не может быть пустым")
        return cleaned


class DarknetScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


# ──────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────

@router.post(
    "/darknet",
    response_model=DarknetScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Запуск мониторинга даркнета",
    description=(
        "Запускает асинхронный мониторинг упоминаний домена в индексах даркнета. "
        "Источники: RansomWatch (critical), Ahmia.fi (high), DarkSearch (high). "
        "Результаты доступны через /api/v1/events/?event_type=darknet_mention"
    ),
)
async def trigger_darknet_scan(
    body: DarknetScanRequest,
    current_user: CurrentUser,
) -> DarknetScanResponse:
    """
    Запускает мониторинг даркнета по домену в фоновом потоке.

    Требует JWT-аутентификации.
    Возвращает 202 Accepted — результаты появятся в событиях асинхронно.
    """
    if not _DARKNET_MONITOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Darknet-монитор недоступен: воркер не загружен",
        )

    domain = body.domain  # уже нормализован валидатором

    # URL Core API — воркер использует его для ingest событий через внутренний эндпоинт
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    _executor.submit(
        monitor_darknet,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return DarknetScanResponse(
        status="processing",
        domain=domain,
        detail=(
            "Мониторинг даркнета запущен в фоне. "
            "Результаты: /api/v1/events/?event_type=darknet_mention"
        ),
    )


# ROUTER: api_router.include_router(darknet_scan.router)
