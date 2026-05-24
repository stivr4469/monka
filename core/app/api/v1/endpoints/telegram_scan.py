"""
Эндпоинт запуска мониторинга публичных Telegram-каналов по домену.

Запускает monitor_telegram_channels в фоне (ThreadPoolExecutor).
Результаты появятся в /api/v1/events/?event_type=telegram_leak
"""
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.rate_limit import limiter
from app.workers_client import ensure_workers_path, get_executor

router = APIRouter(prefix="/scan", tags=["scan"])

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()

try:
    from tasks.telegram_monitor import DEFAULT_LEAK_CHANNELS, monitor_telegram_channels
    _TELEGRAM_MONITOR_AVAILABLE = True
except ImportError:
    _TELEGRAM_MONITOR_AVAILABLE = False


# ──────────────────────────────────────────────
# Схемы запроса / ответа
# ──────────────────────────────────────────────

class TelegramScanRequest(BaseModel):
    domain: str
    extra_channels: Optional[list[str]] = None

    @field_validator("domain")
    @classmethod
    def domain_not_empty(cls, v: str) -> str:
        stripped = v.strip().lower()
        if not stripped:
            raise ValueError("Домен не может быть пустым")
        return stripped

    @field_validator("extra_channels")
    @classmethod
    def normalize_channels(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return None
        # Нормализуем: убираем @ и пробелы, фильтруем пустые
        return [ch.strip().lstrip("@") for ch in v if ch.strip().lstrip("@")]


class TelegramScanResponse(BaseModel):
    status: str
    domain: str
    channels: int
    detail: str


# ──────────────────────────────────────────────
# Эндпоинт
# ──────────────────────────────────────────────

@router.post(
    "/telegram",
    response_model=TelegramScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@limiter.limit("20/minute")  # Ограничение запуска сканирований: 20 в минуту с IP
async def trigger_telegram_scan(
    request: Request,  # slowapi требует request для извлечения IP
    body: TelegramScanRequest,
    current_user: CurrentUser,
) -> TelegramScanResponse:
    """
    Запускает мониторинг публичных Telegram-каналов на упоминания домена
    в фоновом потоке.

    По умолчанию сканируются каналы из DEFAULT_LEAK_CHANNELS.
    Дополнительные каналы передаются в extra_channels (без @).

    Результаты доступны через /api/v1/events/?event_type=telegram_leak
    """
    if not _TELEGRAM_MONITOR_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Telegram-монитор недоступен: воркер не загружен",
        )

    domain = body.domain
    extra_channels = body.extra_channels

    # Определяем URL Core API — воркер обращается к нему для ingest событий
    core_api_url = f"http://127.0.0.1:{settings.APP_PORT}"

    # Общее количество каналов для информирования пользователя
    total_channels = len(DEFAULT_LEAK_CHANNELS) + len(extra_channels or [])

    get_executor().submit(
        monitor_telegram_channels,
        domain,
        core_api_url,
        settings.INTERNAL_API_SECRET,
        extra_channels,
    )

    return TelegramScanResponse(
        status="processing",
        domain=domain,
        channels=total_channels,
        detail=(
            f"Мониторинг {total_channels} Telegram-каналов запущен в фоне. "
            "Результаты: /api/v1/events/?event_type=telegram_leak"
        ),
    )


# ROUTER: api_router.include_router(telegram_scan.router)
