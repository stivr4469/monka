"""
Эндпоинт запуска GitHub-поиска по домену.
"""
import concurrent.futures
import os
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings

router = APIRouter(prefix="/scan", tags=["scan"])

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

_WORKERS_PATH = str(Path(__file__).parents[6] / "workers")
if _WORKERS_PATH not in sys.path:
    sys.path.insert(0, _WORKERS_PATH)

try:
    from tasks.github_search import search_github
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
async def trigger_github_scan(
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

    port = int(os.getenv("APP_PORT", "8000"))
    core_api_url = f"http://127.0.0.1:{port}"

    _executor.submit(
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
