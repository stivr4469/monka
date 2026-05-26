"""
Эндпоинт запуска мониторинга упоминаний бренда.

Запускает monitor_brand в фоне (ThreadPoolExecutor).
Результаты появятся в /api/v1/events/?event_type=forum_mention

Phase 12.B: Reddit + Hacker News
Phase 12.E: Telegram brand monitoring (через monitor_brand_telegram)
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
    from workers.tasks.brand_monitor import monitor_brand
    _BRAND_MONITOR_AVAILABLE = True
except ImportError:
    _BRAND_MONITOR_AVAILABLE = False

try:
    from workers.tasks.telegram_monitor import monitor_brand_telegram
    _TELEGRAM_BRAND_AVAILABLE = True
except ImportError:
    _TELEGRAM_BRAND_AVAILABLE = False


# ──────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────

class BrandScanRequest(BaseModel):
    domain: str
    brand_keywords: Optional[list[str]] = []

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
        # Фильтруем пустые строки, сохраняем оригинальный регистр
        return [kw.strip() for kw in v if kw.strip()]


class BrandScanResponse(BaseModel):
    status: str
    domain: str
    keywords: list[str]
    detail: str


# ──────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────

@router.post(
    "/brand",
    response_model=BrandScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit("20/minute")  # Ограничение: 20 запросов в минуту с IP
async def trigger_brand_scan(
    request: Request,  # slowapi требует request для извлечения IP
    body: BrandScanRequest,
    current_user: CurrentUser,
) -> BrandScanResponse:
    """
    Запускает мониторинг упоминаний бренда в Reddit и Hacker News в фоновом потоке.

    Если brand_keywords не указаны — используется имя домена без TLD.
    Запускает как forum-мониторинг (Reddit/HN), так и Telegram brand monitor.

    Результаты доступны через /api/v1/events/?event_type=forum_mention
    """
    if not _BRAND_MONITOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Brand-монитор недоступен: воркер не загружен",
        )

    domain = body.domain
    brand_keywords = body.brand_keywords or []

    # URL Core API — воркер обращается к нему для ingest событий
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    # Запускаем Reddit + HN мониторинг в фоне
    get_executor().submit(
        monitor_brand,
        domain,
        brand_keywords,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    # Запускаем Telegram brand monitor если доступен
    if _TELEGRAM_BRAND_AVAILABLE and brand_keywords:
        get_executor().submit(
            monitor_brand_telegram,
            domain,
            brand_keywords,
            core_api_url,
            settings.INTERNAL_API_SECRET,
        )

    return BrandScanResponse(
        status="processing",
        domain=domain,
        keywords=brand_keywords,
        detail=(
            "Brand-мониторинг запущен в фоне (Reddit, HN"
            + (", Telegram" if _TELEGRAM_BRAND_AVAILABLE and brand_keywords else "")
            + "). Результаты: /api/v1/events/?event_type=forum_mention"
        ),
    )


# ROUTER: api_router.include_router(brand_scan.router)
