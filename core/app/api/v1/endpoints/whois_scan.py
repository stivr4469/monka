"""
Эндпоинт WHOIS/Registrant Monitor.

POST /api/v1/scan/whois — запускает проверку RDAP-данных домена.
Сравнивает текущие данные (registrant, nameservers, expiry) с baseline.
При изменениях генерирует события типа asset_drift.

Первый запуск: сохраняет baseline, событий нет.
Последующие запуски: сравнение, при дрейфе — события.

Rate limit: 5/minute (RDAP запрос к внешнему API).
Результаты: /api/v1/events?event_type=asset_drift&source_name=whois_monitor
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
    from workers.tasks.whois_monitor import check_whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

# Паттерн валидации домена: без схемы и без пути
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


# ──────────────────────────────────────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────────────────────────────────────

class WhoisScanRequest(BaseModel):
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


class WhoisScanResponse(BaseModel):
    status: str
    domain: str


# ──────────────────────────────────────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/whois",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=WhoisScanResponse,
    summary="WHOIS / Registrant Monitor",
    description=(
        "Запрашивает RDAP-данные домена и сравнивает с baseline. "
        "Отслеживает: смену registrant (severity=high), смену nameservers (severity=high), "
        "истечение регистрации <30 дн. (severity=critical), <90 дн. (severity=medium). "
        "Первый запуск только сохраняет baseline — событий нет. "
        "Результаты: /api/v1/events?event_type=asset_drift&source_name=whois_monitor"
    ),
)
@limiter.limit("5/minute")
async def trigger_whois_scan(
    request: Request,
    body: WhoisScanRequest,
    current_user: CurrentUser,
) -> WhoisScanResponse:
    """
    Запускает WHOIS/Registrant мониторинг в thread pool.

    Требует JWT-аутентификации или API-ключа (Bearer easm_...).
    Возвращает 202 Accepted — воркер выполняется в фоне.
    Результаты появляются в /api/v1/events после завершения.
    """
    if not _WHOIS_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WHOIS monitor недоступен: воркер не загружен",
        )

    domain = body.domain  # уже нормализован валидатором
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    loop = asyncio.get_running_loop()
    loop.run_in_executor(
        get_executor(),
        check_whois,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return WhoisScanResponse(status="accepted", domain=domain)
