"""
Эндпоинт загрузки стилер-логов.
Принимает ZIP-архив или TXT-файл, запускает парсер в фоне.

7.A: Файл сохраняется на диск (/tmp/stealer_<uuid>.zip) — не в RAM.
     Парсер читает построчно и сам удаляет временный файл после обработки.
"""
import uuid
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.core.rate_limit import limiter
from app.models.asset import Asset
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/stealer", tags=["stealer-logs"])

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from workers.tasks.stealer_parser import parse_stealer_log
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
_TMP_DIR = Path("/tmp")


@router.post("/upload", response_model=StealerUploadResponse, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")  # Загрузка файлов — дорогая операция, ограничиваем до 5 в минуту с IP
async def upload_stealer_log(
    request: Request,  # slowapi требует request для извлечения IP
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
    Файл сохраняется на диск — не загружается в RAM целиком (OOM protection).
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

    filename = file.filename or "upload.txt"
    ext = Path(filename).suffix.lower() or ".bin"
    tmp_path = _TMP_DIR / f"stealer_{uuid.uuid4().hex}{ext}"

    # 7.A.1: Сохраняем файл на диск чанками — не в RAM
    size_bytes = 0
    try:
        with tmp_path.open("wb") as f_out:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB чанки
                if not chunk:
                    break
                size_bytes += len(chunk)
                if size_bytes > MAX_FILE_SIZE:
                    tmp_path.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail="Файл превышает 100 МБ")
                f_out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения файла: {exc}") from exc

    # Запускаем парсинг в фоне (парсер сам удалит tmp_path после обработки)
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        parse_stealer_log,
        tmp_path,       # Path на диске вместо bytes
        filename,
        target_domains,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    return StealerUploadResponse(
        status="processing",
        filename=filename,
        size_bytes=size_bytes,
        target_domains=target_domains,
        detail="Парсинг запущен в фоне. Результаты появятся в /api/v1/events/?event_type=stealer_log",
    )
