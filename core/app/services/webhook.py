"""
Сервис отправки webhook-уведомлений.

Вызывается при создании нового события с severity="critical".
Отправляет POST-запрос на webhook_url организации (если задан).

Особенности:
- Не блокирует основной поток: запускается через get_executor()
- Таймаут 5 секунд на HTTP-соединение + чтение ответа
- Одна повторная попытка при сетевой ошибке (с паузой 2с)
- Ошибки логируются но НЕ поднимаются (не прерывают бизнес-логику)
- shell=False не используется (subprocess не вызывается)
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime

logger = logging.getLogger(__name__)

# Таймаут HTTP-запроса в секундах
_TIMEOUT_SEC: int = 5
# Пауза перед retry в секундах
_RETRY_DELAY_SEC: int = 2


def _send_webhook_sync(webhook_url: str, payload: dict) -> None:
    """
    Синхронная отправка POST на webhook_url.
    Запускается в фоновом потоке через get_executor().

    Выполняет 2 попытки с паузой 2с между ними.
    Использует только stdlib urllib (без httpx/requests) чтобы
    не добавлять зависимости ради одной функции.
    """
    body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
    req = urllib.request.Request(
        url=webhook_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "EASM-Platform-Webhook/1.0",
            # X-Event-Type для быстрой маршрутизации на стороне получателя
            "X-Event-Type": payload.get("event_type", "unknown"),
        },
    )

    last_exc: Exception | None = None
    for attempt in range(1, 3):  # 2 попытки: attempt=1 и attempt=2
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_SEC) as resp:
                status_code = resp.status
                if status_code < 400:
                    logger.info(
                        "[webhook] Доставлено: url=%s status=%s domain=%s",
                        webhook_url,
                        status_code,
                        payload.get("domain"),
                    )
                    return
                else:
                    logger.warning(
                        "[webhook] Сервер вернул ошибку: url=%s status=%s attempt=%d",
                        webhook_url,
                        status_code,
                        attempt,
                    )
                    last_exc = RuntimeError(f"HTTP {status_code}")
        except urllib.error.URLError as exc:
            logger.warning(
                "[webhook] Сетевая ошибка: url=%s error=%s attempt=%d",
                webhook_url,
                exc,
                attempt,
            )
            last_exc = exc
        except OSError as exc:
            # TimeoutError, ConnectionRefusedError и т.д.
            logger.warning(
                "[webhook] Ошибка соединения: url=%s error=%s attempt=%d",
                webhook_url,
                exc,
                attempt,
            )
            last_exc = exc

        # Пауза перед retry (только если это была не последняя попытка)
        if attempt < 2:
            time.sleep(_RETRY_DELAY_SEC)

    logger.error(
        "[webhook] Не удалось доставить уведомление после 2 попыток: url=%s last_error=%s",
        webhook_url,
        last_exc,
    )


def notify_critical_event(
    webhook_url: str,
    event_type: str,
    domain: str,
    severity: str,
    detected_at: datetime,
    source_name: str = "",
) -> None:
    """
    Отправляет webhook-уведомление о критическом событии в фоновом потоке.

    Вызывается из ingest-эндпоинта при создании события с severity="critical".
    Не блокирует HTTP-ответ — запускает отправку через общий ThreadPoolExecutor.

    Args:
        webhook_url:  URL организации для уведомлений (из Organization.webhook_url)
        event_type:   Тип события (например, "darknet_mention", "stealer_log")
        domain:       Целевой домен
        severity:     Уровень серьёзности ("critical")
        detected_at:  Время обнаружения события
        source_name:  Источник события (опционально)
    """
    if not webhook_url or not webhook_url.strip():
        return

    # Импорт здесь во избежание circular import: webhook → workers_client → (ничего)
    from app.workers_client import get_executor

    payload = {
        "event_type": event_type,
        "domain": domain,
        "severity": severity,
        "detected_at": detected_at.isoformat(),
        "source_name": source_name,
    }

    get_executor().submit(_send_webhook_sync, webhook_url, payload)
    logger.debug(
        "[webhook] Уведомление поставлено в очередь: domain=%s event_type=%s url=%s",
        domain,
        event_type,
        webhook_url,
    )
