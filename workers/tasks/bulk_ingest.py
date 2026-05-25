"""
Утилита батчевой отправки событий в Core API.

Вместо N отдельных POST-запросов (N×HTTP) — один запрос с батчем до 500 событий.
Эндпоинт: POST /api/v1/internal/ingest/bulk
"""
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Размер батча по умолчанию
_DEFAULT_BATCH_SIZE = 500

# Таймаут HTTP-запроса (секунды)
_HTTP_TIMEOUT = 30.0

# Статусы успешной доставки
_OK_STATUSES = frozenset({"accepted", "duplicate", "partial"})

# Политика повторных попыток: задержки в секундах (экспоненциальный backoff)
_RETRY_DELAYS = (2, 4, 8)  # 3 попытки: 2s, 4s, 8s


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
        # Повторные попытки с экспоненциальным backoff для 5xx / сетевых ошибок.
        # 4xx (клиентская ошибка, напр. 422) — не ретраим, логируем и пропускаем.
        batch_sent = False
        last_exc: Exception | None = None
        for attempt, delay in enumerate((*_RETRY_DELAYS, None), start=1):
            try:
                with httpx.Client() as client:
                    r = client.post(
                        bulk_url,
                        json={"events": batch},
                        headers=headers,
                        timeout=_HTTP_TIMEOUT,
                    )
                # Клиентская ошибка — не ретраим
                if 400 <= r.status_code < 500:
                    logger.warning(
                        "[bulk_ingest] Батч %d–%d: клиентская ошибка %d — пропускаем (не ретраим)",
                        i, i + len(batch), r.status_code,
                    )
                    errors += len(batch)
                    batch_sent = True  # помечаем как «обработан» чтобы выйти из цикла
                    break

                data = r.json()
                if r.status_code in (200, 202) and data.get("status") in _OK_STATUSES:
                    sent += data.get("accepted", 0) + data.get("duplicates", 0)
                    errors += data.get("errors", 0)
                    logger.debug(
                        "[bulk_ingest] Батч %d–%d (попытка %d): accepted=%d duplicates=%d errors=%d",
                        i, i + len(batch), attempt,
                        data.get("accepted", 0), data.get("duplicates", 0), data.get("errors", 0),
                    )
                    batch_sent = True
                    break

                # 5xx — будем ретраить
                logger.warning(
                    "[bulk_ingest] Батч %d–%d (попытка %d/%d): сервер вернул %d",
                    i, i + len(batch), attempt, len(_RETRY_DELAYS) + 1, r.status_code,
                )
                last_exc = Exception(f"HTTP {r.status_code}")
            except Exception as exc:
                logger.warning(
                    "[bulk_ingest] Батч %d–%d (попытка %d/%d): сетевая ошибка: %s",
                    i, i + len(batch), attempt, len(_RETRY_DELAYS) + 1, exc,
                )
                last_exc = exc

            if delay is not None:
                time.sleep(delay)

        if not batch_sent:
            logger.error(
                "[bulk_ingest] Батч %d–%d: все попытки исчерпаны, последняя ошибка: %s — fallback на single",
                i, i + len(batch), last_exc,
            )
            for event in batch:
                try:
                    with httpx.Client() as client:
                        sr = client.post(single_url, json=event, headers=headers, timeout=10)
                    st = sr.json().get("status", "error")
                    if st in ("accepted", "duplicate"):
                        sent += 1
                    else:
                        errors += 1
                except Exception as exc:
                    logger.error("[bulk_ingest] Single fallback error: %s", exc)
                    errors += 1

    return {"sent": sent, "errors": errors}
