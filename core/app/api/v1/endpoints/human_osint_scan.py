"""
Эндпоинт Human OSINT (задача 9.D).

POST /api/v1/scan/human-osint — профилирование сотрудников компании.

Источники (публичные, без авторизации):
  - GitHub Search API: пользователи с email @domain.com
  - DuckDuckGo Lite: site:linkedin.com/in поиск

Результаты: /api/v1/events/?event_type=human_intel
VIP-персоны (CEO/CTO/DevOps/SysAdmin) помечены severity=medium,
остальные — severity=low.

Rate limit: 5/minute (DDG/GitHub сами ограничивают агрессивные запросы).
"""
import os
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
    from tasks.human_osint import run_human_osint
    _HUMAN_OSINT_AVAILABLE = True
except ImportError:
    _HUMAN_OSINT_AVAILABLE = False

# Паттерн валидации домена (единый с другими сканерами проекта)
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)


class HumanOsintRequest(BaseModel):
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


class HumanOsintResponse(BaseModel):
    status: str
    domain: str
    detail: str
    # Заполняются при быстром завершении воркера
    github_profiles: int = 0
    linkedin_profiles: int = 0
    vip_found: int = 0
    email_patterns_generated: int = 0


@router.post(
    "/human-osint",
    response_model=HumanOsintResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Human OSINT — профилирование сотрудников",
    description=(
        "Ищет публичные профили сотрудников компании через GitHub Search API "
        "и DuckDuckGo Lite (site:linkedin.com/in). "
        "Определяет VIP-персоны (CEO/CTO/DevOps/SysAdmin) как потенциальные цели фишинга. "
        "Генерирует паттерны корпоративных email-адресов. "
        "Использует только публичные данные, без авторизации. "
        "Результаты: /api/v1/events/?event_type=human_intel"
    ),
)
@limiter.limit("5/minute")
async def trigger_human_osint(
    request: Request,
    body: HumanOsintRequest,
    current_user: CurrentUser,
) -> HumanOsintResponse:
    """
    Запускает Human OSINT в фоне.

    GITHUB_TOKEN (опциональный) повышает rate limit GitHub API с 10 до 30 req/min.
    Без токена сканирование всё равно работает, но может быть ограничено.
    """
    if not _HUMAN_OSINT_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Human OSINT недоступен: воркер не загружен",
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"
    github_token: str | None = os.environ.get("GITHUB_TOKEN") or None

    future = get_executor().submit(
        run_human_osint,
        body.domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
        github_token,
    )

    # Пробуем получить результат до таймаута (DDG + GitHub занимают ~10-30 секунд)
    try:
        result: dict = future.result(timeout=35)
    except TimeoutError:
        return HumanOsintResponse(
            status="processing",
            domain=body.domain,
            detail=(
                "Human OSINT запущен в фоне (поиск занимает до 30 секунд). "
                "Результаты: /api/v1/events/?event_type=human_intel"
            ),
        )
    except Exception:
        # Не поднимаем 500 — graceful degradation
        return HumanOsintResponse(
            status="error",
            domain=body.domain,
            detail="Ошибка Human OSINT — проверьте логи воркера",
        )

    return HumanOsintResponse(
        status="ok",
        domain=body.domain,
        detail=(
            f"Human OSINT завершён. "
            f"GitHub профилей: {result.get('github_profiles', 0)}, "
            f"LinkedIn профилей: {result.get('linkedin_profiles', 0)}, "
            f"VIP-персон: {result.get('vip_found', 0)}. "
            "Результаты: /api/v1/events/?event_type=human_intel"
        ),
        github_profiles=result.get("github_profiles", 0),
        linkedin_profiles=result.get("linkedin_profiles", 0),
        vip_found=result.get("vip_found", 0),
        email_patterns_generated=result.get("email_patterns_generated", 0),
    )
