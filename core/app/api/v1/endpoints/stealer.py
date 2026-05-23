"""
Эндпоинт загрузки стилер-логов.
Принимает ZIP-архив или TXT-файл, запускает парсер в фоне.
"""
import concurrent.futures
import sys
import os
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from sqlalchemy import select
from app.models.asset import Asset

router = APIRouter(prefix="/stealer", tags=["stealer-logs"])

_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

# Импортируем парсер из workers (доступен в монорепо)
_WORKERS_PATH = str(Path(__file__).parents[6] / "workers")
if _WORKERS_PATH not in sys.path:
    sys.path.insert(0, _WORKERS_PATH)

try:
    from tasks.stealer_parser import parse_stealer_log
    _PARSER_AVAILABLE = True
except ImportError:
    _PARSER_AVAILABLE = False


class StealerUploadResponse(BaseModel):
    status: str
    filename: str
    size_bytes: int
    target_domains: list[str]
    detail: str


MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 МБ


@router.post("/upload", response_model=StealerUploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_stealer_log(
    db: DBDep,
    current_user: CurrentUser,
    file: UploadFile = File(...),
    domains: str | None = Query(
        default=None,
        description="Домены через запятую. Если не указаны — берутся все активы организации.",
    ),
) -> StealerUploadResponse:
    """
    Загружает стилер-лог (ZIP или TXT).
    Парсинг запускается в фоне — ответ приходит мгновенно.
    Результаты появятся в /api/v1/events/?event_type=stealer_log
    """
    if not _PARSER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Парсер недоступен (workers не найдены)")

    # Определяем целевые домены
    if domains:
        target_domains = [d.strip().lower() for d in domains.split(",") if d.strip()]
    else:
        if current_user.organization_id is None:
            raise HTTPException(status_code=400, detail="Нет организации и не указаны домены")
        result = await db.execute(
            select(Asset.domain).where(
                Asset.organization_id == current_user.organization_id,
                Asset.is_active == True,  # noqa: E712
            )
        )
        target_domains = [row[0] for row in result.all()]

    if not target_domains:
        raise HTTPException(status_code=400, detail="Нет доменов для сопоставления")

    # Читаем файл
    file_bytes = await file.read()
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Файл превышает 100 МБ")

    filename = file.filename or "upload.txt"

    # Запускаем парсинг в фоне
    port = int(os.getenv("APP_PORT", "8000"))
    core_api_url = f"http://127.0.0.1:{port}"

    _executor.submit(
        parse_stealer_log,
        file_bytes,
        filename,
        target_domains,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return StealerUploadResponse(
        status="processing",
        filename=filename,
        size_bytes=len(file_bytes),
        target_domains=target_domains,
        detail="Парсинг запущен в фоне. Результаты появятся в /api/v1/events/?event_type=stealer_log",
    )
