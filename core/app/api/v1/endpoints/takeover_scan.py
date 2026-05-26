"""
Эндпоинт обнаружения Subdomain Takeover.

Проверяет поддомены домена (из БД событий) на уязвимость к захвату:
CNAME указывает на несуществующий ресурс внешнего сервиса (GitHub Pages, Heroku, S3...).

Результаты: /api/v1/events/?event_type=vulnerability&source_name=takeover_detector
Rate limit: 5/minute (нагружает DNS + HTTP для каждого поддомена).
"""
import re

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.core.rate_limit import limiter
from app.models.event import Event
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

ensure_workers_path()

try:
    from workers.tasks.takeover_detector import scan_takeover
    _TAKEOVER_AVAILABLE = True
except ImportError:
    _TAKEOVER_AVAILABLE = False

# Паттерн валидации домена (без схемы, без пути)
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


# ──────────────────────────────────────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────────────────────────────────────

class TakeoverScanRequest(BaseModel):
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


class TakeoverScanResponse(BaseModel):
    status: str
    domain: str
    subdomains_checked: int
    detail: str


# ──────────────────────────────────────────────────────────────────────────────
# Вспомогательная функция: загрузка поддоменов из БД
# ──────────────────────────────────────────────────────────────────────────────

async def _get_subdomains_from_db(db: DBDep, domain: str) -> list[str]:
    """
    Загружает известные поддомены для домена из таблицы событий.

    Ищет события event_type='subdomain' где target_domain совпадает с domain.
    Извлекает поле payload->>'subdomain' из каждого события.
    Дедублицирует и возвращает отсортированный список.
    """
    result = await db.execute(
        select(Event)
        .where(
            Event.event_type == "subdomain",
            Event.target_domain == domain,
        )
        .limit(2000)  # Защита от чрезмерно большого списка
    )
    events = result.scalars().all()

    subdomains: set[str] = set()
    for event in events:
        payload = event.payload or {}
        subdomain = payload.get("subdomain", "")
        if subdomain and isinstance(subdomain, str):
            # Нормализуем: нижний регистр, убираем пробелы
            subdomains.add(subdomain.strip().lower())

    return sorted(subdomains)


# ──────────────────────────────────────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/takeover",
    response_model=TakeoverScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Проверка Subdomain Takeover",
    description=(
        "Проверяет известные поддомены домена на уязвимость к захвату. "
        "Поддомены загружаются из базы данных (результаты предыдущих сканов subfinder). "
        "Для каждого поддомена: резолвит CNAME → проверяет fingerprint уязвимого сервиса. "
        "Результаты: /api/v1/events/?event_type=vulnerability&source_name=takeover_detector"
    ),
)
@limiter.limit("5/minute")
async def trigger_takeover_scan(
    request: Request,
    body: TakeoverScanRequest,
    current_user: CurrentUser,
    db: DBDep,
) -> TakeoverScanResponse:
    """
    Запускает Subdomain Takeover detection в фоновом потоке.

    Требует JWT-аутентификации.
    Поддомены берутся из ранее накопленных событий event_type='subdomain' в БД.
    Результаты появляются как события event_type='vulnerability' асинхронно.
    """
    if not _TAKEOVER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Takeover detector недоступен: воркер не загружен",
        )

    domain = body.domain  # уже нормализован валидатором

    # Загружаем поддомены из БД синхронно (быстро)
    subdomains = await _get_subdomains_from_db(db, domain)

    if not subdomains:
        return TakeoverScanResponse(
            status="skipped",
            domain=domain,
            subdomains_checked=0,
            detail=(
                "Нет известных поддоменов для проверки. "
                "Сначала запустите сканирование поддоменов через Assets."
            ),
        )

    # URL Core API для ingest событий из воркера
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        scan_takeover,
        domain,
        subdomains,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return TakeoverScanResponse(
        status="processing",
        domain=domain,
        subdomains_checked=len(subdomains),
        detail=(
            f"Проверка {len(subdomains)} поддоменов запущена в фоне. "
            "Результаты: /api/v1/events/?event_type=vulnerability&source_name=takeover_detector"
        ),
    )
