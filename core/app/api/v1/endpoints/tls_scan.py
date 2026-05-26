"""
Эндпоинт TLS/JA4 fingerprinting.

Анализирует TLS-конфигурацию домена: версия протокола, шифр, данные сертификата,
WAF/CDN по HTTP-заголовкам, упрощённый JA4S fingerprint.

Результаты: /api/v1/events/?event_type=tls_fingerprint&source_name=tls_fingerprinter
Rate limit: 10/minute (TLS handshake быстрый, но нагружает сеть).
"""
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

ensure_workers_path()

try:
    from workers.tasks.tls_fingerprinter import run_tls_scan
    _TLS_AVAILABLE = True
except ImportError:
    _TLS_AVAILABLE = False

# Паттерн валидации домена (без схемы, без пути)
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


# ──────────────────────────────────────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────────────────────────────────────

class TlsScanRequest(BaseModel):
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


class TlsScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


# ──────────────────────────────────────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/tls",
    response_model=TlsScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="TLS / JA4 fingerprinting",
    description=(
        "Анализирует TLS-конфигурацию домена: версию протокола, шифр, "
        "срок действия сертификата, WAF/CDN по HTTP-заголовкам, JA4S fingerprint. "
        "Сертификаты истекающие <30 дней → severity=high. Остальное → severity=info. "
        "Результаты: /api/v1/events/?event_type=tls_fingerprint&source_name=tls_fingerprinter"
    ),
)
@limiter.limit("10/minute")
async def trigger_tls_scan(
    request: Request,
    body: TlsScanRequest,
    current_user: CurrentUser,
) -> TlsScanResponse:
    """
    Запускает TLS/JA4 fingerprinting в фоновом потоке.

    Требует JWT-аутентификации.
    Возвращает 202 Accepted — результаты появятся в событиях асинхронно.
    """
    if not _TLS_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="TLS fingerprinter недоступен: воркер не загружен",
        )

    domain = body.domain  # уже нормализован валидатором
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        run_tls_scan,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return TlsScanResponse(
        status="processing",
        domain=domain,
        detail=(
            "TLS/JA4 сканирование запущено в фоне. "
            "Результаты: /api/v1/events/?event_type=tls_fingerprint&source_name=tls_fingerprinter"
        ),
    )
