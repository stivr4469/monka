"""
Утилита батчевой отправки событий в Core API.

Вместо N отдельных POST-запросов (N×HTTP) — один запрос с батчем до 500 событий.
Эндпоинт: POST /api/v1/internal/ingest/bulk
"""
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Размер батча по умолчанию
_DEFAULT_BATCH_SIZE = 500

# Таймаут HTTP-запроса (секунды)
_HTTP_TIMEOUT = 30.0

# Статусы успешной доставки
_OK_STATUSES = frozenset({"accepted", "duplicate", "partial"})


def bulk_ingest(
    events: list[dict[str, Any]],
    core_api_url: str,
    internal_secret: str,
    batch_size: int = _DEFAULT_BATCH_SIZE,
) -> dict[str, int]:
    """
    Отправляет список событий в Core API батчами.

    Накапливает до batch_size событий и отправляет одним POST /ingest/bulk.
    При ошибке батча — пробует по одному через /ingest (fallback).

    Возвращает: {"sent": N, "errors": M}
    """
    if not events:
        return {"sent": 0, "errors": 0}

    bulk_url = f"{core_api_url}/api/v1/internal/ingest/bulk"
    single_url = f"{core_api_url}/api/v1/internal/ingest"
    headers = {"Authorization": f"Bearer {internal_secret}"}

    sent = errors = 0

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        try:
            r = httpx.post(
                bulk_url,
                json={"events": batch},
                headers=headers,
                timeout=_HTTP_TIMEOUT,
            )
            data = r.json()
            if r.status_code in (200, 202) and data.get("status") in _OK_STATUSES:
                sent += data.get("accepted", 0) + data.get("duplicates", 0)
                errors += data.get("errors", 0)
                logger.debug(
                    "[bulk_ingest] Батч %d–%d: accepted=%d duplicates=%d errors=%d",
                    i, i + len(batch),
                    data.get("accepted", 0), data.get("duplicates", 0), data.get("errors", 0),
                )
            else:
                # Bulk endpoint вернул ошибку — fallback на поштучную отправку
                logger.warning("[bulk_ingest] Bulk endpoint ошибка %d, fallback на single", r.status_code)
                for event in batch:
                    try:
                        sr = httpx.post(single_url, json=event, headers=headers, timeout=10)
                        st = sr.json().get("status", "error")
                        if st in ("accepted", "duplicate"):
                            sent += 1
                        else:
                            errors += 1
                    except Exception as exc:
                        logger.error("[bulk_ingest] Single fallback error: %s", exc)
                        errors += 1
        except Exception as exc:
            logger.error("[bulk_ingest] Ошибка батча %d–%d: %s", i, i + len(batch), exc)
            errors += len(batch)

    return {"sent": sent, "errors": errors}
