"""
Эндпоинт запуска мониторинга даркнета на упоминания домена.

Запускает monitor_darknet в фоне (ThreadPoolExecutor).
Результаты появятся в /api/v1/events/?event_type=darknet_mention

Источники:
  - RansomWatch        → event_type "darknet_mention",    severity "critical"
  - Ahmia.fi           → event_type "darknet_mention",    severity "high"
  - DarkSearch         → event_type "darknet_mention",    severity "high"
  - Ransomware Sites   → event_type "ransomware_mention", severity "critical" (требует Tor)
  - IntelX.io phonebook→ event_type "forum_mention",      severity "high"
"""
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from workers.tasks.darknet_monitor import monitor_darknet
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
        "Источники: RansomWatch (critical), Ahmia.fi (high), DarkSearch (high), "
        "Ransomware Sites через Tor (critical, если Tor доступен), IntelX.io (high). "
        "Результаты доступны через /api/v1/events/?event_type=darknet_mention|ransomware_mention|forum_mention"
    ),
)
@limiter.limit("20/minute")  # Ограничение запуска сканирований: 20 в минуту с IP
async def trigger_darknet_scan(
    request: Request,  # slowapi требует request для извлечения IP
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

    get_executor().submit(
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
