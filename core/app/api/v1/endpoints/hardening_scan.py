"""
Эндпоинт проверки периметра домена (Domain Hardening).

Запускает проверки SPF / DMARC / AXFR / SSL в фоне.
Результаты появятся в /api/v1/events/?event_type=vulnerability&source_name=domain_hardening
"""
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

ensure_workers_path()

try:
    from workers.tasks.domain_hardening import run_domain_hardening
    _HARDENING_AVAILABLE = True
except ImportError:
    _HARDENING_AVAILABLE = False


class HardeningScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Домен не может быть пустым")
        return cleaned


class HardeningScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


@router.post(
    "/hardening",
    response_model=HardeningScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Проверка периметра домена",
    description=(
        "Проверяет SPF, DMARC, DNS Zone Transfer (AXFR) и SSL-сертификат. "
        "Результаты: /api/v1/events/?event_type=vulnerability&source_name=domain_hardening"
    ),
)
@limiter.limit("10/minute")
async def trigger_hardening_scan(
    request: Request,
    body: HardeningScanRequest,
    current_user: CurrentUser,
) -> HardeningScanResponse:
    if not _HARDENING_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Domain Hardening недоступен: воркер не загружен",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"
    get_executor().submit(
        run_domain_hardening,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return HardeningScanResponse(
        status="processing",
        domain=body.domain,
        detail=(
            "Проверка периметра запущена. "
            "Результаты: /api/v1/events/?event_type=vulnerability&source_name=domain_hardening"
        ),
    )
