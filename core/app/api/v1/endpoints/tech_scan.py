"""
Эндпоинт запуска Technology Profiling (задача 10.A).

POST /api/v1/scan/tech-profile — запускает Wappalyzer-like детектирование технологий.
Анализирует HTTP-ответ домена, определяет CMS / фреймворки / серверы / CDN,
проверяет версии на End-of-Life.

Rate limit: 5/minute (HTTP-запрос к целевому домену, не быстрее чем TLS-scan).
Результаты: /api/v1/events?event_type=tech_profile&source_name=tech_profiler
"""
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
    from tasks.tech_profiler import run_tech_profiler
    _TECH_PROFILER_AVAILABLE = True
except ImportError:
    _TECH_PROFILER_AVAILABLE = False

# Паттерн валидации домена: без схемы и без пути
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


# ──────────────────────────────────────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────────────────────────────────────

class TechScanRequest(BaseModel):
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


class TechDetected(BaseModel):
    """Одна обнаруженная технология."""
    name: str
    version: str | None = None


class EolItem(BaseModel):
    """Технология, находящаяся на End-of-Life."""
    tech: str
    version: str | None = None
    eol_date: str


class TechScanResponse(BaseModel):
    status: str
    domain: str
    technologies: list[TechDetected] = []
    eol_detected: list[EolItem] = []
    severity: str = "info"


# ──────────────────────────────────────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/tech-profile",
    response_model=TechScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Technology Profiling (Wappalyzer-like)",
    description=(
        "Определяет технологии домена по HTTP-заголовкам, кукам и телу страницы. "
        "Покрывает 30+ технологий: CMS, фреймворки, веб-серверы, CDN, DevOps-инструменты. "
        "Версии проверяются по базе End-of-Life — устаревшие версии получают severity=medium. "
        "Результаты: /api/v1/events?event_type=tech_profile&source_name=tech_profiler"
    ),
)
@limiter.limit("5/minute")
async def trigger_tech_scan(
    request: Request,
    body: TechScanRequest,
    current_user: CurrentUser,
) -> TechScanResponse:
    """
    Запускает Technology Profiling в фоновом потоке.

    Ждёт результата до 30 секунд (timeout).
    Возвращает список обнаруженных технологий и EOL-предупреждения.
    """
    if not _TECH_PROFILER_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Tech profiler недоступен: воркер не загружен",
        )

    domain = body.domain  # нормализован валидатором
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    # Запускаем в пуле потоков и ждём результат (синхронный HTTP-запрос в воркере)
    future = get_executor().submit(
        run_tech_profiler,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    try:
        result: dict = future.result(timeout=30)
    except TimeoutError:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Таймаут сканирования домена {domain} (30с). Попробуйте позже.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Ошибка сканирования: {exc}",
        )

    # Обработка ошибки недостижимости домена
    if "error" in result:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Домен недостижим: {result['error']}",
        )

    return TechScanResponse(
        status="completed",
        domain=domain,
        technologies=[TechDetected(**t) for t in result.get("technologies", [])],
        eol_detected=[EolItem(**e) for e in result.get("eol_detected", [])],
        severity=result.get("severity", "info"),
    )
