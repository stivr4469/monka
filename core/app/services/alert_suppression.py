"""
Подавление дубликатов алертов и батчинг.
Используем простой in-memory store (достаточно для MVP).
Для production: заменить на Redis с TTL.
"""
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

# Одно правило → один алерт в час (подавление дублей)
SUPPRESSION_WINDOW_SEC = 3600
# Батчинг: накапливаем некритичные алерты 5 минут, затем шлём дайджест
BATCH_WINDOW_SEC = 300
# Эскалация: если critical-алерт не подтверждён > 30 мин — повторный сигнал
ESCALATION_SEC = 1800

# Severity-уровни, начиная с которых алерт идёт немедленно (минуя батч)
_IMMEDIATE_SEVERITIES = {"high", "critical"}


@dataclass
class _AlertRecord:
    rule_id: int
    # Время последней реальной отправки (UNIX-timestamp)
    last_fired: float = 0.0
    # Накопленные события для батч-дайджеста
    pending_batch: list[dict] = field(default_factory=list)
    # Момент окончания текущего батч-окна (0 = окно не открыто)
    batch_deadline: float = 0.0
    # Флаг: эскалация по этому правилу уже отправлена
    escalation_sent: bool = False


class AlertSuppressionStore:
    """
    Потокобезопасное in-memory хранилище состояния алертов.
    Один экземпляр на процесс; Celery-воркеры с prefork используют
    отдельные процессы, поэтому состояние не шарится — для production
    заменить на Redis (SETNX + TTL).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # defaultdict создаёт _AlertRecord с rule_id=0; мы сразу перезаписываем rule_id
        self._records: dict[int, _AlertRecord] = {}

    # ──────────────────────────────────────────────────────────────
    # Внутренние утилиты
    # ──────────────────────────────────────────────────────────────

    def _get_or_create(self, rule_id: int) -> _AlertRecord:
        """Возвращает запись для rule_id, создавая при необходимости."""
        if rule_id not in self._records:
            self._records[rule_id] = _AlertRecord(rule_id=rule_id)
        return self._records[rule_id]

    # ──────────────────────────────────────────────────────────────
    # Публичный API
    # ──────────────────────────────────────────────────────────────

    def should_suppress(self, rule_id: int, severity: str) -> bool:
        """
        Возвращает True если алерт нужно подавить.

        Логика:
        - Немедленные severity (high/critical) — никогда не подавляются.
        - Остальные — подавляются если с момента последней отправки
          прошло менее SUPPRESSION_WINDOW_SEC секунд.
        """
        if severity in _IMMEDIATE_SEVERITIES:
            return False

        with self._lock:
            rec = self._get_or_create(rule_id)
            elapsed = time.time() - rec.last_fired
            return elapsed < SUPPRESSION_WINDOW_SEC

    def record_fired(self, rule_id: int) -> None:
        """
        Отмечает что алерт по правилу был отправлен прямо сейчас.
        Сбрасывает флаг эскалации — правило считается «активным».
        """
        with self._lock:
            rec = self._get_or_create(rule_id)
            rec.last_fired = time.time()
            rec.escalation_sent = False

    def add_to_batch(self, rule_id: int, event_data: dict) -> list[dict] | None:
        """
        Добавляет событие в батч-очередь правила.

        Возвращает:
        - list[dict] со всеми накопленными событиями, если батч-окно
          закрылось (deadline истёк), — вызывающий должен отправить дайджест.
        - None если батч продолжает накапливаться.

        Также открывает новое батч-окно если оно не было открыто.
        """
        with self._lock:
            rec = self._get_or_create(rule_id)
            now = time.time()

            # Открываем новое окно если ещё не открыто
            if rec.batch_deadline == 0.0:
                rec.batch_deadline = now + BATCH_WINDOW_SEC

            rec.pending_batch.append(event_data)

            # Окно закрылось — возвращаем батч и сбрасываем очередь
            if now >= rec.batch_deadline:
                ready = list(rec.pending_batch)
                rec.pending_batch = []
                rec.batch_deadline = 0.0
                rec.last_fired = now
                return ready

            return None

    def flush_all_batches(self) -> dict[int, list[dict]]:
        """
        Принудительно сбрасывает все непустые батчи независимо от deadline.
        Вызывается из Celery beat каждые BATCH_WINDOW_SEC секунд.

        Возвращает dict {rule_id: [события]} для непустых батчей.
        """
        result: dict[int, list[dict]] = {}
        with self._lock:
            now = time.time()
            for rule_id, rec in self._records.items():
                if rec.pending_batch:
                    result[rule_id] = list(rec.pending_batch)
                    rec.pending_batch = []
                    rec.batch_deadline = 0.0
                    rec.last_fired = now
        return result

    def get_escalation_candidates(self) -> list[tuple[int, list[dict]]]:
        """
        Возвращает список (rule_id, pending_events) для правил где:
        - есть накопленные события в батч-очереди (т.е. алерт был)
        - с момента последней отправки прошло > ESCALATION_SEC
        - эскалация ещё не отправлялась

        Используется для повторного уведомления по critical-событиям
        которые остаются без реакции.
        """
        candidates: list[tuple[int, list[dict]]] = []
        now = time.time()
        with self._lock:
            for rule_id, rec in self._records.items():
                if rec.escalation_sent:
                    continue
                if rec.last_fired == 0.0:
                    continue
                if (now - rec.last_fired) < ESCALATION_SEC:
                    continue
                if not rec.pending_batch:
                    continue
                candidates.append((rule_id, list(rec.pending_batch)))
                # Отмечаем что эскалацию по этому правилу уже запланировали
                rec.escalation_sent = True
        return candidates


# Singleton для использования из воркеров
_store = AlertSuppressionStore()


def get_suppression_store() -> AlertSuppressionStore:
    """Возвращает глобальный экземпляр хранилища."""
    return _store
