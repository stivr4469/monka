"""
Базовые утилиты для всех воркеров EASM платформы.

Содержит:
- run_tool() — безопасный запуск внешних CLI-инструментов
- IngestClient — HTTP-клиент с retry и circuit breaker
- BaseWorker — базовый класс для всех воркеров
"""
import logging
import subprocess
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from workers.config import settings

logger = logging.getLogger(__name__)


# ── Запуск внешних инструментов ──────────────────────────────────────────────

def run_tool(cmd: list[str], timeout: int = 300) -> tuple[str, str]:
    """
    Запускает внешний инструмент без shell=True.
    Возвращает (stdout, stderr).
    Поднимает RuntimeError при таймауте или если инструмент не найден.
    Ненулевой код возврата логируется как WARNING, но не поднимает исключение
    (nuclei возвращает 1 при обнаружении находок — это штатное поведение).
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

    if result.returncode not in (0, 1):
        logger.warning(
            "Команда %s завершилась с кодом %d: %s",
            cmd[0],
            result.returncode,
            result.stderr[:500],  # ограничиваем длину лога
        )

    return result.stdout, result.stderr


# ── Circuit Breaker ──────────────────────────────────────────────────────────

@dataclass
class _CircuitBreakerState:
    """
    Состояние circuit breaker'а для HTTP-клиента.
    Thread-safe через Lock.

    Состояния:
      closed   — нормальная работа, запросы проходят
      open     — слишком много ошибок, запросы блокируются
      half_open — пауза истекла, пробуем один запрос
    """
    failure_threshold: int = 5      # сколько ошибок подряд открывают цепь
    recovery_timeout: float = 30.0  # секунд до перехода в half_open
    _failure_count: int = field(default=0, init=False)
    _opened_at: float | None = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def is_open(self) -> bool:
        """Возвращает True если цепь открыта (запросы заблокированы)."""
        with self._lock:
            if self._opened_at is None:
                return False
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self.recovery_timeout:
                # Переходим в half_open — даём шанс восстановиться
                return False
            return True

    def record_success(self) -> None:
        """Сбрасывает счётчик ошибок после успешного запроса."""
        with self._lock:
            self._failure_count = 0
            self._opened_at = None

    def record_failure(self) -> None:
        """Увеличивает счётчик ошибок. Открывает цепь при превышении порога."""
        with self._lock:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._opened_at = time.monotonic()
                logger.error(
                    "Circuit breaker OPENED после %d ошибок подряд. "
                    "Пауза %.0f сек.",
                    self._failure_count,
                    self.recovery_timeout,
                )

    def reset(self) -> None:
        """Принудительный сброс состояния (используется в тестах)."""
        with self._lock:
            self._failure_count = 0
            self._opened_at = None


# ── IngestClient ─────────────────────────────────────────────────────────────

class IngestClient:
    """
    HTTP-клиент для отправки событий в Core API /ingest.

    Возможности:
    - retry при 5xx: до max_retries попыток с экспоненциальной задержкой
    - circuit breaker: если 5 запросов подряд упали — пауза 30 секунд
    - метрики: sent_count, error_count, duplicate_count
    """

    def __init__(
        self,
        core_api_url: str,
        internal_secret: str,
        max_retries: int = 3,
        timeout: float = 30.0,
    ) -> None:
        self._ingest_url = f"{core_api_url}/api/v1/internal/ingest"
        self._headers = {"Authorization": f"Bearer {internal_secret}"}
        self._max_retries = max_retries
        self._timeout = timeout
        self._circuit = _CircuitBreakerState()

        # Метрики
        self._sent_count: int = 0
        self._error_count: int = 0
        self._duplicate_count: int = 0
        self._metrics_lock = threading.Lock()

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def error_count(self) -> int:
        return self._error_count

    @property
    def duplicate_count(self) -> int:
        return self._duplicate_count

    def send(self, event: dict[str, Any]) -> str:
        """
        Отправляет одно событие в Core API.
        Возвращает статус: "accepted" | "duplicate" | "error".

        При 5xx — retry до max_retries раз с паузой countdown*2^n секунд.
        При открытом circuit breaker — сразу возвращает "error".
        """
        if self._circuit.is_open():
            logger.warning("Circuit breaker OPEN — событие пропущено: %s", event.get("event_type"))
            with self._metrics_lock:
                self._error_count += 1
            return "error"

        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = httpx.post(
                    self._ingest_url,
                    json=event,
                    headers=self._headers,
                    timeout=self._timeout,
                )

                # 4xx — клиентская ошибка, retry не нужен
                if 400 <= response.status_code < 500:
                    logger.error(
                        "Core API вернул %d (клиентская ошибка): %s",
                        response.status_code,
                        response.text[:200],
                    )
                    self._circuit.record_failure()
                    with self._metrics_lock:
                        self._error_count += 1
                    return "error"

                # 5xx — серверная ошибка, нужен retry
                if response.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"Server error {response.status_code}",
                        request=response.request,
                        response=response,
                    )

                # Успех
                status = response.json().get("status", "error")
                self._circuit.record_success()
                with self._metrics_lock:
                    if status == "accepted":
                        self._sent_count += 1
                    elif status == "duplicate":
                        self._duplicate_count += 1
                    else:
                        self._error_count += 1
                return status

            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_exc = exc
                self._circuit.record_failure()
                if attempt < self._max_retries:
                    # Экспоненциальная задержка: 60, 120, 240 секунд
                    delay = 60 * (2 ** attempt)
                    logger.warning(
                        "Ошибка отправки события (попытка %d/%d), повтор через %ds: %s",
                        attempt + 1,
                        self._max_retries + 1,
                        delay,
                        exc,
                    )
                    time.sleep(delay)

        logger.error("Не удалось отправить событие после %d попыток: %s", self._max_retries + 1, last_exc)
        with self._metrics_lock:
            self._error_count += 1
        return "error"

    def reset_circuit(self) -> None:
        """Принудительный сброс circuit breaker (для тестов)."""
        self._circuit.reset()


# ── BaseWorker ───────────────────────────────────────────────────────────────

class BaseWorker:
    """
    Базовый класс для всех воркеров EASM платформы.

    Предоставляет:
    - self.ingest_client — настроенный IngestClient
    - self.ingest(event) — метод отправки события

    Использование:
        class MyWorker(BaseWorker):
            def run(self, domain: str) -> dict:
                event = self._build_event(domain)
                event_id = self.ingest(event)
                return {"event_id": event_id}
    """

    def __init__(
        self,
        core_api_url: str | None = None,
        internal_secret: str | None = None,
    ) -> None:
        # Используем переданные значения или берём из конфига
        api_url = core_api_url or settings.CORE_API_URL
        secret = internal_secret or settings.INTERNAL_API_SECRET

        self.ingest_client = IngestClient(
            core_api_url=api_url,
            internal_secret=secret,
        )
        self._started_at = datetime.now(timezone.utc)

    def ingest(self, event: dict[str, Any]) -> str:
        """
        Отправляет нормализованное событие в Core API.
        Возвращает статус: "accepted" | "duplicate" | "error".
        """
        return self.ingest_client.send(event)

    def get_metrics(self) -> dict[str, int]:
        """Возвращает накопленные метрики воркера."""
        return {
            "sent": self.ingest_client.sent_count,
            "errors": self.ingest_client.error_count,
            "duplicates": self.ingest_client.duplicate_count,
        }


# ── Совместимость со старым кодом ────────────────────────────────────────────

def send_event(event: dict[str, Any]) -> None:
    """
    Устаревший хелпер для обратной совместимости.
    Новый код должен использовать IngestClient или BaseWorker.
    Поднимает исключение при ошибке (сохраняет прежнее поведение).
    """
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
