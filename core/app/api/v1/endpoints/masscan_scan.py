"""
Эндпоинт быстрого сканирования IP-диапазонов через masscan (Phase 13.A).

POST /api/v1/scan/masscan — запускает masscan-сканирование публичных IP домена.
masscan сканирует /24 за секунды (rate 500 pps), nmap уточняет сервисы.

Ограничения:
  - Только Enterprise план: массовое сканирование требует расширенных прав
  - Rate limit 3/minute: masscan — тяжёлая сетевая операция
  - Только публичные IP: приватные диапазоны фильтруются в воркере

Результаты: /api/v1/events/?event_type=exposed_service&source_name=masscan
"""
import asyncio
import re

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.core.rate_limit import limiter
from app.models.organization import Organization, OrgPlan
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

# Добавляем workers/ в sys.path один раз при импорте модуля
ensure_workers_path()

try:
    from workers.tasks.masscan_scanner import scan_domain
    _MASSCAN_AVAILABLE = True
except ImportError:
    _MASSCAN_AVAILABLE = False

# Паттерн валидации домена: буквы, цифры, дефисы, точки. Без схемы и пути.
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


class MasscanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        # Убираем пробелы, приводим к нижнему регистру
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


class MasscanResponse(BaseModel):
    status: str
    domain: str


@router.post(
    "/masscan",
    response_model=MasscanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Быстрое сканирование портов (masscan + nmap)",
    description=(
        "Сканирует публичные IP домена через masscan (rate 500 pps) "
        "с последующим уточнением сервисов через nmap -sV. "
        "Доступно только на плане Enterprise. "
        "Результаты: /api/v1/events/?event_type=exposed_service&source_name=masscan"
    ),
)
@limiter.limit("3/minute")
async def scan_masscan(
    request: Request,
    body: MasscanRequest,
    db: DBDep,
    current_user: CurrentUser,
) -> MasscanResponse:
    """Запускает masscan-сканирование домена в фоне (Thread Pool)."""
    if not _MASSCAN_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Masscan Scanner недоступен: воркер не загружен",
        )

    # Проверяем план организации — только Enterprise
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуется план Enterprise",
        )

    org = await db.get(Organization, current_user.organization_id)
    if org is None or org.plan != OrgPlan.enterprise.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Требуется план Enterprise",
        )

    # Запускаем сканирование асинхронно через run_in_executor
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"
    loop = asyncio.get_running_loop()
    loop.run_in_executor(
        get_executor(),
        scan_domain,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return MasscanResponse(status="accepted", domain=body.domain)
