from celery import Celery

from workers.config import settings

app = Celery(
    "easm_workers",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["workers.tasks.subfinder", "workers.tasks.nuclei", "workers.tasks.gitleaks"],
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

if __name__ == "__main__":
    app.start()
