"""
Production-ready конфигурация Celery для EASM платформы.
Брокер и бэкенд — Redis. Сериализация — JSON.
Включает beat-расписание для периодических задач.
"""
from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

from workers.config import settings

# Создаём экземпляр Celery с явным указанием модулей задач
app = Celery(
    "easm_workers",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "workers.tasks.subfinder",
        "workers.tasks.nuclei",
        "workers.tasks.gitleaks",
        "workers.tasks.github_search",
        "workers.tasks.stealer_parser",
        # 10.H: Новые Beat задачи
        "workers.tasks.port_scanner",
        "workers.tasks.tech_profiler",
        "workers.tasks.ransomware_sites",
        "workers.tasks.telegram_monitor",
    ],
)

# ── Основные настройки ────────────────────────────────────────────────────────

app.conf.update(
    # Сериализация
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=3600,  # результаты задач хранятся 1 час

    # Временная зона
    timezone="UTC",
    enable_utc=True,

    # Надёжность доставки
    task_acks_late=True,           # задача подтверждается после выполнения, не до
    worker_prefetch_multiplier=1,  # один воркер берёт одну задачу за раз

    # Retry по умолчанию для всех задач
    task_max_retries=3,
    task_default_retry_delay=60,   # пауза между попытками 60 секунд

    # Таймауты
    task_soft_time_limit=600,      # soft-kill после 10 минут
    task_time_limit=660,           # hard-kill после 11 минут

    # Роутинг задач по очередям
    task_routes={
        "workers.tasks.subfinder.*": {"queue": "discovery"},
        "workers.tasks.nuclei.*": {"queue": "scanning"},
        "workers.tasks.gitleaks.*": {"queue": "scanning"},
        "workers.tasks.github_search.*": {"queue": "osint"},
        "workers.tasks.stealer_parser.*": {"queue": "parsing"},
    },

    # Объявляем очереди явно чтобы они создавались при старте воркера
    task_queues=(
        Queue("default", Exchange("default"), routing_key="default"),
        Queue("discovery", Exchange("discovery"), routing_key="discovery"),
        Queue("scanning", Exchange("scanning"), routing_key="scanning"),
        Queue("osint", Exchange("osint"), routing_key="osint"),
        Queue("parsing", Exchange("parsing"), routing_key="parsing"),
    ),
    task_default_queue="default",
    task_default_exchange="default",
    task_default_routing_key="default",

    # Beat расписание: пересканирование активных активов раз в 24 часа
    beat_schedule={
        "rescan-all-active-assets-daily": {
            "task": "workers.tasks.subfinder.scan_domain_all_active",
            "schedule": crontab(hour=2, minute=0),  # каждый день в 02:00 UTC
            "options": {"queue": "discovery"},
        },
        "nuclei-rescan-daily": {
            "task": "workers.tasks.nuclei.scan_all_active_targets",
            "schedule": crontab(hour=3, minute=0),  # каждый день в 03:00 UTC
            "options": {"queue": "scanning"},
        },
        # 10.H: Сканирование портов всех активов — ежедневно в 04:00 UTC
        "port-scan-all-daily": {
            "task": "workers.tasks.port_scanner.run_port_scan_all_assets",
            "schedule": crontab(hour=4, minute=0),
            "options": {"queue": "scanning"},
        },
        # 10.H: Профилирование технологий — ежедневно в 05:00 UTC
        "tech-profile-all-daily": {
            "task": "workers.tasks.tech_profiler.run_tech_profiler_all_assets",
            "schedule": crontab(hour=5, minute=0),
            "options": {"queue": "scanning"},
        },
        # 10.H: Мониторинг ransomware-сайтов даркнета — каждый час
        "darknet-ransomware-hourly": {
            "task": "workers.tasks.ransomware_sites.run_darknet_monitor_all_assets",
            "schedule": crontab(minute=0),
            "options": {"queue": "osint"},
        },
        # 10.H: Мониторинг Telegram — каждые 15 минут
        "telegram-monitor-15min": {
            "task": "workers.tasks.telegram_monitor.run_telegram_monitor_all_assets",
            "schedule": crontab(minute="*/15"),
            "options": {"queue": "osint"},
        },
    },

    # Настройки worker
    worker_max_tasks_per_child=100,  # перезапуск воркера каждые 100 задач (memory leak defence)
    worker_disable_rate_limits=False,
)

# ── Хуки жизненного цикла ────────────────────────────────────────────────────

@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """Дополнительные периодические задачи через beat."""
    pass


if __name__ == "__main__":
    app.start()
