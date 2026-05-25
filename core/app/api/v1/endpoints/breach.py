"""
Эндпоинты проверки email-адресов по базам утечек.

Маршруты:
  POST /breach/check    — проверить явный список email
  POST /breach/discover — авто-обнаружение + проверка для домена
  GET  /breach/results  — последние события email_breach (с фильтром по домену)

Все маршруты требуют JWT-аутентификации.
Фоновые задачи запускаются в общем ThreadPoolExecutor через workers_client.
"""
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.models.asset import Asset
from app.models.event import Event
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/breach", tags=["breach"])

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from tasks.breach_checker import check_domain_emails, discover_and_check
    _BREACH_CHECKER_AVAILABLE = True
except ImportError:
    _BREACH_CHECKER_AVAILABLE = False


# ── Схемы запросов / ответов ───────────────────────────────────────────────

class BreachCheckRequest(BaseModel):
    """Запрос на проверку явного списка email-адресов."""
    domain: str = Field(..., min_length=1, max_length=253, description="Целевой домен")
    emails: list[str] = Field(..., min_length=1, max_length=200, description="Список email (макс. 200)")

    @field_validator("emails")
    @classmethod
    def emails_not_empty(cls, v: list[str]) -> list[str]:
        stripped = [e.strip().lower() for e in v if e.strip()]
        if not stripped:
            raise ValueError("Список email не может быть пустым")
        return stripped

    @field_validator("domain")
    @classmethod
    def domain_lowercase(cls, v: str) -> str:
        return v.strip().lower()


class BreachCheckResponse(BaseModel):
    """Ответ запуска проверки email (асинхронная обработка)."""
    status: str
    domain: str
    emails_queued: int
    detail: str


class BreachDiscoverRequest(BaseModel):
    """Запрос авто-обнаружения + проверки для домена."""
    domain: str = Field(..., min_length=1, max_length=253, description="Целевой домен")

    @field_validator("domain")
    @classmethod
    def domain_lowercase(cls, v: str) -> str:
        return v.strip().lower()


class BreachDiscoverResponse(BaseModel):
    """Ответ запуска авто-обнаружения (асинхронная обработка)."""
    status: str
    domain: str
    detail: str


class BreachEventRead(BaseModel):
    """Представление события email_breach для клиента."""
    id: str
    target_domain: str
    severity: str
    source_name: str
    payload: dict
    detected_at: str

    model_config = {"from_attributes": True}


# ── Эндпоинты ──────────────────────────────────────────────────────────────

@router.post(
    "/check",
    response_model=BreachCheckResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def check_breach(
    body: BreachCheckRequest,
    current_user: CurrentUser,
) -> BreachCheckResponse:
    """
    Запускает проверку явно переданного списка email по HIBP и LeakCheck.
    Обработка выполняется асинхронно — результаты появятся в /api/v1/events/?event_type=email_breach

    Лимит: не более 200 email за один запрос (rate limit HIBP).
    """
    if not _BREACH_CHECKER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Breach checker недоступен (workers не найдены)",
        )

    if not body.emails:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Список email пуст после валидации",
        )

    # Берём порт из settings — единственный источник истины
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        check_domain_emails,
        body.domain,
        body.emails,
        core_api_url,
        settings.INTERNAL_API_SECRET,
        settings.HIBP_API_KEY,
    )

    return BreachCheckResponse(
        status="processing",
        domain=body.domain,
        emails_queued=len(body.emails),
        detail=(
            f"Проверка {len(body.emails)} email запущена в фоне. "
            "Результаты: /api/v1/events/?event_type=email_breach"
        ),
    )


@router.post(
    "/discover",
    response_model=BreachDiscoverResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def discover_breach(
    body: BreachDiscoverRequest,
    current_user: CurrentUser,
) -> BreachDiscoverResponse:
    """
    Авто-обнаружение email домена (из stealer-логов + типичные паттерны)
    и последующая проверка по базам утечек.
    Результаты появятся в /api/v1/events/?event_type=email_breach
    """
    if not _BREACH_CHECKER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Breach checker недоступен (workers не найдены)",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        discover_and_check,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
        settings.HIBP_API_KEY,
    )

    return BreachDiscoverResponse(
        status="processing",
        domain=body.domain,
        detail=(
            f"Авто-обнаружение email для '{body.domain}' запущено в фоне. "
            "Результаты: /api/v1/events/?event_type=email_breach"
        ),
    )


@router.get(
    "/results",
    response_model=list[BreachEventRead],
)
async def get_breach_results(
    db: DBDep,
    current_user: CurrentUser,
    domain: str | None = Query(default=None, description="Фильтр по домену"),
    limit: int = Query(default=50, ge=1, le=500, description="Максимум записей"),
) -> list[BreachEventRead]:
    """
    Возвращает последние события email_breach.
    Опциональный фильтр по домену через query-параметр ?domain=
    """
    if current_user.organization_id is None:
        return []

    q = (
        select(Event)
        .join(Asset, Event.asset_id == Asset.id)
        .where(
            Event.event_type == "email_breach",
            Asset.organization_id == current_user.organization_id,
        )
        .order_by(Event.detected_at.desc())
        .limit(limit)
    )

    if domain:
        q = q.where(Event.target_domain == domain.strip().lower())

    result = await db.execute(q)
    events = result.scalars().all()

    return [
        BreachEventRead(
            id=e.id,
            target_domain=e.target_domain,
            severity=e.severity,
            source_name=e.source_name,
            payload=e.payload,
            detected_at=e.detected_at.isoformat(),
        )
        for e in events
    ]


# ROUTER: api_router.include_router(breach.router)
