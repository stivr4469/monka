"""
Эндпоинт обнаружения поддоменов (subfinder + crt.sh).

Запускает обнаружение поддоменов в фоне.
Результаты: /api/v1/events/?event_type=subdomain
"""
import re

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

ensure_workers_path()

try:
    from tasks.subfinder import run_subfinder_standalone
    _SUBFINDER_AVAILABLE = True
except ImportError:
    _SUBFINDER_AVAILABLE = False

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


class SubfinderRequest(BaseModel):
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


class SubfinderResponse(BaseModel):
    status: str
    domain: str
    detail: str


@router.post(
    "/subfinder",
    response_model=SubfinderResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Обнаружение поддоменов (subfinder + crt.sh)",
    description=(
        "Запускает subfinder + crt.sh для обнаружения поддоменов домена. "
        "Asset drift detection: новые поддомены → severity=medium, известные → info. "
        "Результаты: /api/v1/events/?event_type=subdomain"
    ),
)
@limiter.limit("5/minute")
async def trigger_subfinder(
    request: Request,
    body: SubfinderRequest,
    current_user: CurrentUser,
) -> SubfinderResponse:
    if not _SUBFINDER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Subfinder недоступен: воркер не загружен",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"
    get_executor().submit(
        run_subfinder_standalone,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return SubfinderResponse(
        status="processing",
        domain=body.domain,
        detail=(
            "Обнаружение поддоменов запущено (subfinder + crt.sh). "
            "Результаты: /api/v1/events/?event_type=subdomain"
        ),
    )
