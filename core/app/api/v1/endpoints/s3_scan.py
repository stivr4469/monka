"""
Эндпоинт обнаружения открытых S3-корзин (S3 Bucket Discovery).

Генерирует кандидатов по имени компании из домена и проверяет
каждый через HEAD/GET-запросы к s3.amazonaws.com.
Результаты: /api/v1/events/?event_type=exposed_service&source_name=s3_scanner

Медленная операция (100+ HTTP-запросов) → rate limit 3/minute.
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
    from tasks.s3_scanner import run_s3_scan
    _S3_AVAILABLE = True
except ImportError:
    _S3_AVAILABLE = False


class S3ScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Домен не может быть пустым")
        return cleaned


class S3ScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


@router.post(
    "/s3",
    response_model=S3ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Обнаружение открытых S3-бакетов",
    description=(
        "Генерирует 100+ паттернов имён S3-бакетов на основе имени компании из домена "
        "и проверяет каждый через HEAD/GET-запросы. "
        "Открытые бакеты (публичный листинг) → severity=critical. "
        "Существующие, но закрытые → severity=medium. "
        "Результаты: /api/v1/events/?event_type=exposed_service&source_name=s3_scanner"
    ),
)
@limiter.limit("3/minute")
async def trigger_s3_scan(
    request: Request,
    body: S3ScanRequest,
    current_user: CurrentUser,
) -> S3ScanResponse:
    if not _S3_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="S3 Scanner недоступен: воркер не загружен",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"
    get_executor().submit(
        run_s3_scan,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return S3ScanResponse(
        status="processing",
        domain=body.domain,
        detail=(
            "Поиск S3-бакетов запущен. "
            "Результаты: /api/v1/events/?event_type=exposed_service&source_name=s3_scanner"
        ),
    )
