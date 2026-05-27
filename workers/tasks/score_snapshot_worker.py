"""Ежедневный снимок security score для трендов (Asset Intelligence Trends).

Воркер раз в день делает снимок security score для всех активов организации.
Использует внутренние эндпоинты Core API через INTERNAL_API_SECRET.

Паттерн использования:
  - take_daily_snapshots(core_api_url, internal_secret) → {"snapshots_taken": N, "errors": M}
  - Запускается через Celery beat или cron: daily_score_snapshots
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Таймаут HTTP-запросов (секунды)
HTTP_TIMEOUT: float = 30.0

# Задержка между запросами score, чтобы не перегружать Core API (секунды)
REQUEST_DELAY: float = 0.05

# User-Agent для идентификации воркера
USER_AGENT: str = "EASM-ScoreSnapshotWorker/1.0"


@dataclass
class SnapshotResult:
    """Итоги прохода воркера."""
    snapshots_taken: int = 0
    errors: int = 0
    skipped: int = 0
    asset_ids_failed: list[str] = field(default_factory=list)


def _build_headers(internal_secret: str) -> dict[str, str]:
    """Формирует заголовки для запросов к Internal API."""
    return {
        "Authorization": f"Bearer {internal_secret}",
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
    }


def _fetch_assets_list(
    client: httpx.Client,
    core_api_url: str,
    internal_secret: str,
) -> list[dict[str, Any]]:
    """Получает список всех активных активов через Internal API.

    GET /api/v1/internal/assets-list
    Возвращает список {"id": ..., "domain": ..., "org_id": ...}.
    """
    url = f"{core_api_url}/api/v1/internal/assets-list"
    headers = _build_headers(internal_secret)

    try:
        resp = client.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        # Ожидаем список активов
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        logger.error("Неожиданный формат ответа /internal/assets-list: %s", type(data))
        return []
    except httpx.HTTPStatusError as exc:
        logger.error("HTTP ошибка при получении списка активов: %s %s", exc.response.status_code, exc.response.text)
        return []
    except httpx.RequestError as exc:
        logger.error("Сетевая ошибка при получении списка активов: %s", exc)
        return []


def _fetch_asset_score(
    client: httpx.Client,
    core_api_url: str,
    internal_secret: str,
    asset_id: str,
) -> dict[str, Any] | None:
    """Получает текущий Security Score для актива.

    GET /api/v1/assets/{asset_id}/score
    Возвращает ScoreResult или None при ошибке.
    """
    url = f"{core_api_url}/api/v1/assets/{asset_id}/score"
    headers = _build_headers(internal_secret)

    try:
        resp = client.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "HTTP ошибка при получении score актива %s: %s %s",
            asset_id, exc.response.status_code, exc.response.text,
        )
        return None
    except httpx.RequestError as exc:
        logger.warning("Сетевая ошибка при получении score актива %s: %s", asset_id, exc)
        return None


def _save_score_snapshot(
    client: httpx.Client,
    core_api_url: str,
    internal_secret: str,
    asset_id: str,
    score_data: dict[str, Any],
) -> bool:
    """Сохраняет снимок score через Internal API.

    POST /api/v1/internal/score-snapshot
    Body: {"asset_id": ..., "score": ..., "category_scores": {...}}
    Возвращает True при успехе.
    """
    url = f"{core_api_url}/api/v1/internal/score-snapshot"
    headers = _build_headers(internal_secret)

    # Формируем payload из данных ScoreResult
    payload: dict[str, Any] = {
        "asset_id": asset_id,
        "score": score_data.get("total", 0),
        "grade": score_data.get("grade", "F"),
        "category_scores": {
            cat: data
            for cat, data in (score_data.get("categories") or {}).items()
        },
        "org_id": score_data.get("org_id"),
    }

    try:
        resp = client.post(url, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return True
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "HTTP ошибка при сохранении snapshot актива %s: %s %s",
            asset_id, exc.response.status_code, exc.response.text,
        )
        return False
    except httpx.RequestError as exc:
        logger.warning("Сетевая ошибка при сохранении snapshot актива %s: %s", asset_id, exc)
        return False


def take_daily_snapshots(
    core_api_url: str,
    internal_secret: str,
) -> dict[str, int]:
    """Основная функция ежедневного снимка security score.

    Алгоритм:
      1. GET /api/v1/internal/assets-list  — получить все активы
      2. Для каждого: GET /api/v1/assets/{id}/score — текущий score
      3. Сохранить через POST /api/v1/internal/score-snapshot

    Args:
        core_api_url:    базовый URL Core API (например, "http://core:8000")
        internal_secret: INTERNAL_API_SECRET для аутентификации

    Returns:
        Словарь {"snapshots_taken": N, "errors": M, "skipped": K}
    """
    result = SnapshotResult()

    logger.info("Запуск ежедневного снимка security score (core_api=%s)", core_api_url)

    with httpx.Client() as client:
        # Шаг 1: получаем список всех активов
        assets = _fetch_assets_list(client, core_api_url, internal_secret)

        if not assets:
            logger.warning("Список активов пуст или недоступен — снимки не сохранены")
            return {
                "snapshots_taken": 0,
                "errors": 0,
                "skipped": 0,
            }

        logger.info("Получено активов для снимка: %d", len(assets))

        # Шаг 2–3: для каждого актива — score → snapshot
        for asset in assets:
            asset_id = asset.get("id") or asset.get("asset_id")
            if not asset_id:
                logger.warning("Актив без ID — пропуск: %s", asset)
                result.skipped += 1
                continue

            # Получаем score
            score_data = _fetch_asset_score(client, core_api_url, internal_secret, asset_id)
            if score_data is None:
                result.errors += 1
                result.asset_ids_failed.append(str(asset_id))
                continue

            # Сохраняем snapshot
            ok = _save_score_snapshot(client, core_api_url, internal_secret, asset_id, score_data)
            if ok:
                result.snapshots_taken += 1
                logger.debug("Snapshot сохранён: asset_id=%s score=%s", asset_id, score_data.get("total"))
            else:
                result.errors += 1
                result.asset_ids_failed.append(str(asset_id))

            # Небольшая пауза — не DDoS-им Core API
            if REQUEST_DELAY > 0:
                time.sleep(REQUEST_DELAY)

    if result.asset_ids_failed:
        logger.warning(
            "Ошибки при снимке %d активов: %s",
            len(result.asset_ids_failed),
            result.asset_ids_failed[:10],  # первые 10 для краткости
        )

    logger.info(
        "Ежедневный снимок завершён: taken=%d errors=%d skipped=%d",
        result.snapshots_taken, result.errors, result.skipped,
    )

    return {
        "snapshots_taken": result.snapshots_taken,
        "errors": result.errors,
        "skipped": result.skipped,
    }
