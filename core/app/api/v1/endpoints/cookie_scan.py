"""
Эндпоинт проверки активности сессионных кук из стилер-логов (задача 9.C).

Уникальная конкурентная фича: пассивная проверка живых сессий украденных токенов
через HEAD-запросы. Не генерирует алертов на WAF/EDR стороне жертвы.

POST /api/v1/scan/cookies
"""
import glob
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])

ensure_workers_path()

try:
    from workers.tasks.cookie_validator import validate_cookies_from_zip
    _COOKIE_VALIDATOR_AVAILABLE = True
except ImportError:
    _COOKIE_VALIDATOR_AVAILABLE = False


# ──────────────────────────────────────────────
# Утилиты поиска стилер-архивов
# ──────────────────────────────────────────────

# Директории, где воркер сохраняет временные ZIP-файлы стилеров
_STEALER_SEARCH_DIRS: list[str] = ["/tmp", "/var/tmp"]
_STEALER_GLOB_PATTERNS: list[str] = [
    "stealer_*.zip",
    "stealer-*.zip",
    "upload_*.zip",
    "log_*.zip",
    "*.zip",  # последний приоритет — любой ZIP
]


def _find_stealer_zip(stealer_log_id: Optional[str] = None) -> Optional[Path]:
    """
    Ищет ZIP-файл стилер-лога.

    Если stealer_log_id задан — ищет файл с этим ID/именем в имени.
    Иначе — возвращает самый свежий ZIP из временных директорий.
    Возвращает None если ничего не найдено.
    """
    # HIGH-1: проверяем что результирующий путь остаётся внутри разрешённых директорий
    allowed_dirs = {Path(d).resolve() for d in _STEALER_SEARCH_DIRS}
    candidates: list[Path] = []

    for search_dir in _STEALER_SEARCH_DIRS:
        for pattern in _STEALER_GLOB_PATTERNS:
            full_pattern = f"{search_dir}/{pattern}"
            for path_str in glob.glob(full_pattern):
                p = Path(path_str).resolve()
                if not p.is_file():
                    continue
                # Path traversal guard: реальный путь должен быть внутри разрешённой директории
                if p.parent not in allowed_dirs:
                    logger.warning("[cookie_scan] Путь вне разрешённых директорий: %s", p)
                    continue
                # Если задан ID — фильтруем по вхождению в имя файла
                if stealer_log_id and stealer_log_id not in p.name:
                    continue
                candidates.append(p)
            # Если нашли по конкретному ID — не продолжаем поиск
            if stealer_log_id and candidates:
                break
        if stealer_log_id and candidates:
            break

    if not candidates:
        return None

    # Возвращаем самый свежий файл
    return max(candidates, key=lambda p: p.stat().st_mtime)


# ──────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────

class CookieScanRequest(BaseModel):
    domain: str
    stealer_log_id: Optional[str] = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Домен не может быть пустым")
        # Базовая защита от инъекций в имени домена
        if any(c in cleaned for c in ("/", "\\", ":", "@", " ")):
            raise ValueError("Недопустимые символы в домене")
        return cleaned

    @field_validator("stealer_log_id")
    @classmethod
    def validate_log_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        # Допускаем только безопасные символы в ID файла
        cleaned = v.strip()
        if any(c in cleaned for c in ("/", "\\", "\0", "..")):
            raise ValueError("Недопустимые символы в stealer_log_id")
        return cleaned


class CookieScanResponse(BaseModel):
    status: str
    domain: str
    stealer_file: Optional[str] = None
    detail: str


class CookieScanResultResponse(BaseModel):
    status: str
    domain: str
    checked: int
    alive: int
    dead: int
    sent: int
    stealer_file: str


# ──────────────────────────────────────────────
# Воркер-функция для ThreadPoolExecutor
# ──────────────────────────────────────────────

def _run_cookie_scan_sync(
    zip_path: Path,
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """Синхронная обёртка для запуска в пуле потоков."""
    return validate_cookies_from_zip(zip_path, domain, core_api_url, internal_secret)


# ──────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────

@router.post(
    "/cookies",
    response_model=CookieScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Проверка живых сессий из стилер-лога",
    description=(
        "Пассивная проверка активности украденных сессионных кук. "
        "Использует HEAD-запросы — не генерирует алертов на WAF/EDR жертвы. "
        "Живые сессии создают события active_session_leak (critical). "
        "Результаты: /api/v1/events/?event_type=active_session_leak"
    ),
)
@limiter.limit("10/minute")
async def trigger_cookie_scan(
    request: Request,
    body: CookieScanRequest,
    current_user: CurrentUser,
) -> CookieScanResponse:
    """
    Запускает проверку активности сессионных кук из стилер-архива.

    Требует JWT-аутентификации.
    Возвращает 202 Accepted — результаты появятся в событиях асинхронно.
    Возвращает 404 если стилер-архивы не найдены.
    Возвращает 503 если воркер недоступен.
    """
    if not _COOKIE_VALIDATOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cookie Validator недоступен: воркер не загружен",
        )

    domain = body.domain
    stealer_log_id = body.stealer_log_id

    zip_path = _find_stealer_zip(stealer_log_id)
    if zip_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Стилер-архивы не найдены. "
                "Сначала загрузите ZIP-файл стилер-лога через /api/v1/stealer/upload"
            ),
        )

    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    get_executor().submit(
        _run_cookie_scan_sync,
        zip_path,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
    )

    logger.info(
        "[cookie_scan] Проверка куков запущена: domain=%s file=%s user=%s",
        domain, zip_path.name, current_user.email,
    )

    return CookieScanResponse(
        status="processing",
        domain=domain,
        stealer_file=zip_path.name,
        detail=(
            "Проверка сессионных кук запущена в фоне. "
            "Живые сессии: /api/v1/events/?event_type=active_session_leak. "
            "Проверка может занять до 30 секунд."
        ),
    )
