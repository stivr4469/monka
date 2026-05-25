"""
Эндпоинт Certificate Transparency Monitor (задача 12.A).

POST /api/v1/scan/ct — запускает проверку новых сертификатов через crt.sh.
Для каждого нового подозрительного сертификата создаётся событие с типом
phishing_domain и severity=high.

Rate limit: 5/minute (запрос к внешнему crt.sh API).
Результаты: /api/v1/events?event_type=phishing_domain&source_name=ct_monitor
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
    from tasks.ct_monitor import check_ct
    _CT_MONITOR_AVAILABLE = True
except ImportError:
    _CT_MONITOR_AVAILABLE = False

# Паттерн валидации домена: только a-z0-9 и символы . -
# Соответствует реальным DNS-именам, без схемы и пути
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,253}[a-z0-9]$")


# ──────────────────────────────────────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────────────────────────────────────

class CtScanRequest(BaseModel):
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
            raise ValueError(
                "Некорректный домен. Допустимы только a-z, 0-9, точки и дефисы. Пример: example.com"
            )
        return cleaned


class CtScanResponse(BaseModel):
    status: str
    domain: str


# ──────────────────────────────────────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/ct",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=CtScanResponse,
    summary="Certificate Transparency Monitor",
    description=(
        "Запрашивает новые сертификаты для домена через crt.sh и ищет подозрительные имена. "
        "Детектирует: contains (имя содержит домен), levenshtein (расстояние ≤ 2 к имени домена), "
        "wildcard_subdomain (легитимно — *.example.com). "
        "Результаты: /api/v1/events?event_type=phishing_domain&source_name=ct_monitor"
    ),
)
@limiter.limit("5/minute")
async def trigger_ct_scan(
    request: Request,
    body: CtScanRequest,
    current_user: CurrentUser,
) -> CtScanResponse:
    """Запускает CT Monitor в thread pool, немедленно возвращает 202 Accepted."""
    if not _CT_MONITOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CT Monitor недоступен: воркер не загружен",
        )

    domain = body.domain
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    loop = asyncio.get_running_loop()
    loop.run_in_executor(
        get_executor(),
        check_ct,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return CtScanResponse(status="accepted", domain=domain)
