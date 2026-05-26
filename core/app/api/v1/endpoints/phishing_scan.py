"""
Эндпоинт обнаружения фишинга / тайпосквотинга (Phishing Detector).

Запускает генерацию тайпосквот-вариантов домена и DNS-проверку в фоне.
Результаты появятся в /api/v1/events/?event_type=vulnerability&source_name=phishing_detector
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
    from workers.tasks.phishing_detector import detect_phishing_domains
    _PHISHING_AVAILABLE = True
except ImportError:
    _PHISHING_AVAILABLE = False


class PhishingScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Домен не может быть пустым")
        return cleaned


class PhishingScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


@router.post(
    "/phishing",
    response_model=PhishingScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Проверка тайпосквот-фишинга домена",
    description=(
        "Генерирует тайпосквот-варианты домена (vowel_swap, char_omission, "
        "char_duplication, hyphen_insert, tld_swap, prefix_add) и проверяет "
        "каждый через DNS. Резолвящиеся варианты — потенциальные фишинговые домены. "
        "Результаты: /api/v1/events/?event_type=vulnerability&source_name=phishing_detector"
    ),
)
@limiter.limit("5/minute")
async def trigger_phishing_scan(
    request: Request,
    body: PhishingScanRequest,
    current_user: CurrentUser,
) -> PhishingScanResponse:
    if not _PHISHING_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Phishing Detector недоступен: воркер не загружен",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"
    get_executor().submit(
        detect_phishing_domains,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return PhishingScanResponse(
        status="processing",
        domain=body.domain,
        detail=(
            "Проверка фишинг-доменов запущена. "
            "Результаты: /api/v1/events/?event_type=vulnerability&source_name=phishing_detector"
        ),
    )
