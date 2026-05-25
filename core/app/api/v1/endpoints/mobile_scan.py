"""
Эндпоинт запуска мониторинга мобильных приложений.

Запускает monitor_mobile_apps в фоне (ThreadPoolExecutor).
Результаты появятся в /api/v1/events/?event_type=brand_abuse

Phase 12.D: App Store + Google Play mobile monitoring
"""
from typing import Optional

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
    from tasks.mobile_monitor import monitor_mobile_apps
    _MOBILE_MONITOR_AVAILABLE = True
except ImportError:
    _MOBILE_MONITOR_AVAILABLE = False


# ──────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────

class MobileScanRequest(BaseModel):
    domain: str
    brand_keywords: Optional[list[str]] = []
    official_developer: Optional[str] = None

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, v: str) -> str:
        stripped = v.strip().lower()
        if not stripped:
            raise ValueError("Домен не может быть пустым")
        return stripped

    @field_validator("brand_keywords")
    @classmethod
    def normalize_keywords(cls, v: Optional[list[str]]) -> list[str]:
        if v is None:
            return []
        return [kw.strip() for kw in v if kw.strip()]


class MobileScanResponse(BaseModel):
    status: str
    domain: str
    keywords: list[str]
    detail: str


# ──────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────

@router.post(
    "/mobile",
    response_model=MobileScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit("20/minute")
async def trigger_mobile_scan(
    request: Request,
    body: MobileScanRequest,
    current_user: CurrentUser,
) -> MobileScanResponse:
    """
    Запускает мониторинг мобильных приложений на App Store и Google Play.

    Ищет поддельные приложения по brand_keywords и сообщает о подозрительных.
    Результаты доступны через /api/v1/events/?event_type=brand_abuse
    """
    if not _MOBILE_MONITOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mobile-монитор недоступен: воркер не загружен",
        )

    domain = body.domain
    brand_keywords = body.brand_keywords or []

    # URL Core API — воркер обращается к нему для ingest событий
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    # Запускаем мониторинг в фоновом потоке
    get_executor().submit(
        monitor_mobile_apps,
        domain,
        brand_keywords,
        body.official_developer,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return MobileScanResponse(
        status="processing",
        domain=domain,
        keywords=brand_keywords,
        detail=(
            "Mobile-мониторинг запущен в фоне (App Store, Google Play). "
            "Результаты: /api/v1/events/?event_type=brand_abuse"
        ),
    )
