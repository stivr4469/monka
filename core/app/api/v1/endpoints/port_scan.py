"""
Эндпоинт сканирования открытых портов (nmap).

Запускает nmap-сканирование публичных IP домена в фоне.
Результаты появятся в /api/v1/events/?event_type=exposed_service&source_name=nmap

Ограничения:
  - Rate limit 5/minute: nmap — тяжёлая операция (до 2 мин на IP)
  - Только публичные IP: приватные диапазоны фильтруются в воркере
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
    from workers.tasks.port_scanner import run_port_scan
    _PORT_SCAN_AVAILABLE = True
except ImportError:
    _PORT_SCAN_AVAILABLE = False

# Паттерн валидации домена: буквы, цифры, дефисы, точки. Без схемы и пути.
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


class PortScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        # Убираем пробелы и приводим к нижнему регистру
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Домен не может быть пустым")
        # Отклоняем URL (содержит схему или путь)
        if "://" in cleaned or "/" in cleaned:
            raise ValueError(
                "Укажите домен без схемы и пути, например: example.com"
            )
        # Базовая валидация формата домена
        if not _DOMAIN_RE.match(cleaned):
            raise ValueError(
                "Некорректный домен. Пример допустимого значения: example.com"
            )
        return cleaned


class PortScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


@router.post(
    "/ports",
    response_model=PortScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Сканирование открытых портов (nmap)",
    description=(
        "Сканирует публичные IP домена на наличие открытых сервисов: "
        "FTP, SSH, Telnet, SMTP, HTTP/S, SMB, MSSQL, Oracle, MySQL, RDP, "
        "PostgreSQL, VNC, Redis, MongoDB, Elasticsearch и нестандартных HTTP. "
        "Результаты: /api/v1/events/?event_type=exposed_service&source_name=nmap"
    ),
)
@limiter.limit("5/minute")
async def scan_ports(
    request: Request,
    body: PortScanRequest,
    current_user: CurrentUser,
) -> PortScanResponse:
    if not _PORT_SCAN_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Port Scanner недоступен: воркер не загружен",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"
    get_executor().submit(
        run_port_scan,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return PortScanResponse(
        status="processing",
        domain=body.domain,
        detail=(
            "Сканирование портов запущено. "
            "Результаты: /api/v1/events/?event_type=exposed_service&source_name=nmap"
        ),
    )
