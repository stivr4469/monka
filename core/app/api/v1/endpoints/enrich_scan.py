"""
Эндпоинт Shodan Enrichment (задача 9.J).

POST /api/v1/scan/enrich — обогащение данных о домене через Shodan API.

Особенности:
  - Rate limit 10/minute (Shodan ограничивает бесплатные ключи)
  - Graceful: если SHODAN_API_KEY не задан → 200 {"status": "skipped"}
  - Запускает воркер в ThreadPoolExecutor (не блокирует event loop)
  - Синхронный воркер shodan_enricher совместим с Celery-архитектурой
"""
import re

from fastapi import APIRouter, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

ensure_workers_path()

try:
    from workers.tasks.shodan_enricher import run_shodan_enrichment
    _SHODAN_AVAILABLE = True
except ImportError:
    _SHODAN_AVAILABLE = False

# Паттерн валидации домена (совпадает с port_scan.py)
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


class EnrichRequest(BaseModel):
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


class EnrichResponse(BaseModel):
    status: str
    domain: str
    detail: str
    # Поля заполняются при синхронном запуске (если воркер быстрый)
    ips_checked: int = 0
    hidden_ports_found: int = 0
    skipped: bool = False
    reason: str | None = None


@router.post(
    "/enrich",
    response_model=EnrichResponse,
    status_code=status.HTTP_200_OK,
    summary="Shodan Enrichment — обогащение данных о домене",
    description=(
        "Запрашивает Shodan API для публичных IP домена. "
        "Находит исторические открытые порты (Asset Drift). "
        "Требует SHODAN_API_KEY в .env — без ключа возвращает status=skipped. "
        "Результаты: /api/v1/events/?event_type=asset_drift&source_name=shodan"
    ),
)
@limiter.limit("10/minute")
async def enrich_scan(
    request: Request,
    body: EnrichRequest,
    current_user: CurrentUser,
) -> EnrichResponse:
    """
    Запускает Shodan enrichment для домена.

    Если SHODAN_API_KEY не задан — возвращает 200 с status=skipped.
    Не возвращает 4xx/5xx для отсутствующего ключа — это допустимая конфигурация.
    """
    if not _SHODAN_AVAILABLE:
        return EnrichResponse(
            status="skipped",
            domain=body.domain,
            detail="Shodan воркер недоступен: модуль не загружен",
            skipped=True,
            reason="worker_unavailable",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    # Запускаем воркер в ThreadPoolExecutor.
    # Future позволяет получить результат сразу — enrichment обычно занимает 5-15 секунд.
    future = get_executor().submit(
        run_shodan_enrichment,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    # Пробуем получить результат (таймаут 20 секунд для 5 IP × 1 req/sec + overhead)
    try:
        result: dict = future.result(timeout=20)
    except TimeoutError:
        # Воркер ещё работает в фоне — возвращаем processing
        return EnrichResponse(
            status="processing",
            domain=body.domain,
            detail=(
                "Shodan enrichment запущен в фоне. "
                "Результаты: /api/v1/events/?event_type=asset_drift&source_name=shodan"
            ),
        )
    except Exception:
        # Воркер упал — graceful degradation
        return EnrichResponse(
            status="error",
            domain=body.domain,
            detail="Ошибка Shodan enrichment — проверьте логи воркера",
            skipped=False,
        )

    # Ключ не задан → graceful skipped
    if result.get("status") == "skipped":
        return EnrichResponse(
            status="skipped",
            domain=body.domain,
            detail="Shodan API ключ не настроен. Добавьте SHODAN_API_KEY в .env",
            skipped=True,
            reason=result.get("reason"),
        )

    return EnrichResponse(
        status="ok",
        domain=body.domain,
        detail=(
            f"Shodan enrichment завершён. "
            f"Проверено IP: {result.get('ips_checked', 0)}. "
            f"Скрытых портов: {result.get('hidden_ports_found', 0)}. "
            "Результаты: /api/v1/events/?event_type=asset_drift&source_name=shodan"
        ),
        ips_checked=result.get("ips_checked", 0),
        hidden_ports_found=result.get("hidden_ports_found", 0),
        skipped=False,
    )
