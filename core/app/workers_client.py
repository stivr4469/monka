"""
Синглтон-клиент для взаимодействия с воркерами.

Устраняет дублирование:
  - Каждый эндпоинт раньше создавал свой ThreadPoolExecutor(max_workers=4)
  - Каждый эндпоинт добавлял workers/ в sys.path независимо

Теперь один пул на весь процесс + единая функция подключения путей.

Использование:
    from app.workers_client import get_executor, ensure_workers_path

    ensure_workers_path()           # вызвать до импорта tasks.*
    get_executor().submit(fn, ...)  # запустить задачу в фоне
"""
from __future__ import annotations

import concurrent.futures
import logging
import sys
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Пул потоков ────────────────────────────────────────────────────────────────

# Единый пул для всего процесса.
# max_workers=8: достаточно для параллельного запуска всех типов сканирований.
# thread_name_prefix облегчает отладку в логах и профилировщиках.
_executor: concurrent.futures.ThreadPoolExecutor | None = None
_executor_lock = threading.Lock()


def get_executor() -> concurrent.futures.ThreadPoolExecutor:
    """
    Возвращает глобальный ThreadPoolExecutor.
    Создаётся при первом вызове (lazy init, double-checked locking), живёт весь процесс.
    """
    global _executor
    if _executor is None:
        with _executor_lock:
            if _executor is None:
                _executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=8,
                    thread_name_prefix="easm_worker",
                )
                logger.info("[workers_client] ThreadPoolExecutor создан: max_workers=8")
    return _executor


# ── Путь к воркерам ────────────────────────────────────────────────────────────

# Путь к директории workers/ в монорепо (на 5 уровней выше app/workers_client.py):
#   core/app/workers_client.py → core/ → Monitoring_utechek/ → workers/
_WORKERS_DIR = Path(__file__).parents[2] / "workers"
_path_ensured: bool = False


def ensure_workers_path() -> None:
    """
    Добавляет директорию workers/ в sys.path единожды.

    Идемпотентна: повторные вызовы не дублируют запись в sys.path.
    Логирует предупреждение если workers/ не существует
    (воркеры могут быть не установлены в production-контейнере Core).
    """
    global _path_ensured
    if _path_ensured:
        return

    workers_path = str(_WORKERS_DIR)

    if not _WORKERS_DIR.exists():
        logger.warning(
            "[workers_client] Директория workers/ не найдена по пути %s. "
            "Воркеры-задачи будут недоступны.",
            workers_path,
        )
    elif workers_path not in sys.path:
        sys.path.insert(0, workers_path)
        logger.info("[workers_client] workers/ добавлен в sys.path: %s", workers_path)

    _path_ensured = True
