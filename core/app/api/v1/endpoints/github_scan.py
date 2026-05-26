"""
Эндпоинт запуска GitHub-поиска по домену.
"""
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from workers.tasks.github_search import search_github
    _GITHUB_AVAILABLE = True
except ImportError:
    _GITHUB_AVAILABLE = False


class GitHubScanRequest(BaseModel):
    domain: str


class GitHubScanResponse(BaseModel):
    status: str
    domain: str
    detail: str


@router.post("/github", response_model=GitHubScanResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("20/minute")  # Ограничение запуска сканирований: 20 в минуту с IP
async def trigger_github_scan(
    request: Request,  # slowapi требует request для извлечения IP
    body: GitHubScanRequest,
    current_user: CurrentUser,
) -> GitHubScanResponse:
    """
    Запускает поиск упоминаний домена в GitHub.
    Результаты появятся в /api/v1/events/?event_type=github_leak
    """
    if not _GITHUB_AVAILABLE:
        raise HTTPException(status_code=503, detail="GitHub воркер недоступен")

    if not settings.GITHUB_TOKEN:
        raise HTTPException(
            status_code=400,
            detail="GITHUB_TOKEN не настроен. Добавьте токен в .env для поиска.",
        )

    domain = body.domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=422, detail="Домен не указан")

    # Берём порт из settings — единственный источник истины
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        search_github,
        domain,
        settings.GITHUB_TOKEN,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return GitHubScanResponse(
        status="processing",
        domain=domain,
        detail="Поиск по GitHub запущен в фоне. Результаты: /api/v1/events/?event_type=github_leak",
    )
