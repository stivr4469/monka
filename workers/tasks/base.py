"""Базовые утилиты для всех воркеров."""
import logging
import subprocess
from typing import Any

import httpx

from workers.config import settings

logger = logging.getLogger(__name__)


def run_tool(cmd: list[str], timeout: int = 300) -> tuple[str, str]:
    """
    Запускает внешний инструмент без shell=True.
    Возвращает (stdout, stderr).
    Поднимает RuntimeError при ненулевом коде возврата.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,  # ОБЯЗАТЕЛЬНО False — защита от инъекции команд
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Таймаут команды {cmd[0]}: {timeout}s") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f"Инструмент не найден: {cmd[0]}") from exc

    if result.returncode != 0:
        logger.warning("Команда %s завершилась с кодом %d: %s", cmd[0], result.returncode, result.stderr)

    return result.stdout, result.stderr


def send_event(event: dict[str, Any]) -> None:
    """Отправляет нормализованное событие в Core API."""
    url = f"{settings.CORE_API_URL}/api/v1/internal/ingest"
    headers = {"Authorization": f"Bearer {settings.INTERNAL_API_SECRET}"}

    try:
        response = httpx.post(url, json=event, headers=headers, timeout=30)
        response.raise_for_status()
        logger.debug("Событие принято: %s", response.json())
    except httpx.HTTPStatusError as exc:
        logger.error("Core API отклонил событие (%d): %s", exc.response.status_code, exc.response.text)
        raise
    except httpx.RequestError as exc:
        logger.error("Ошибка сети при отправке события: %s", exc)
        raise
