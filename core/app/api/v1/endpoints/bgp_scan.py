"""
Эндпоинт BGP/ASN Monitor.

POST /api/v1/scan/bgp — запускает проверку BGP/ASN данных домена.
Сравнивает текущие данные (ASN, IP-префиксы) с baseline.
При изменениях генерирует события типа asset_change.

Первый запуск: сохраняет baseline, событий нет.
Последующие запуски: сравнение, при изменениях — события.

Rate limit: 5/minute (внешний BGPView API запрос).
Результаты: /api/v1/events?event_type=asset_change&source_name=bgp_monitor
"""
import asyncio
import re

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

# Добавляем workers/ в sys.path один раз при импорте модуля
ensure_workers_path()

try:
    from workers.tasks.bgp_monitor import check_bgp
    _BGP_AVAILABLE = True
except ImportError:
    _BGP_AVAILABLE = False

# Паттерн валидации домена: без схемы и без пути
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


# ─────────────────────────────────────────────────────────────────────────────
# Схемы запроса / ответа
# ─────────────────────────────────────────────────────────────────────────────

class BgpScanRequest(BaseModel):
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


class BgpScanResponse(BaseModel):
    status: str
    domain: str


# ─────────────────────────────────────────────────────────────────────────────
# Эндпоинт
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/bgp",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=BgpScanResponse,
    summary="BGP/ASN Monitor",
    description=(
        "Запрашивает BGP-данные домена через BGPView API и сравнивает с baseline. "
        "Отслеживает: смену провайдера/ASN (severity=high), смену IP-блока (severity=medium), "
        "появление нового IP (severity=low). "
        "Первый запуск только сохраняет baseline — событий нет. "
        "Результаты: /api/v1/events?event_type=asset_change&source_name=bgp_monitor"
    ),
)
@limiter.limit("5/minute")
async def trigger_bgp_scan(
    request: Request,
    body: BgpScanRequest,
    current_user: CurrentUser,
) -> BgpScanResponse:
    """
    Запускает BGP/ASN мониторинг в thread pool.

    Требует JWT-аутентификации или API-ключа (Bearer easm_...).
    Возвращает 202 Accepted — воркер выполняется в фоне.
    Результаты появляются в /api/v1/events после завершения.
    """
    if not _BGP_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="BGP monitor недоступен: воркер не загружен",
        )

    domain = body.domain  # уже нормализован валидатором
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    loop = asyncio.get_running_loop()
    loop.run_in_executor(
        get_executor(),
        check_bgp,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return BgpScanResponse(status="accepted", domain=domain)
