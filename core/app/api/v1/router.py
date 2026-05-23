from fastapi import APIRouter

from app.api.v1.endpoints import (
    alerts,
    assets,
    auth,
    breach,
    events,
    github_scan,
    ingest,
    internal_alerts,
    paste_scan,
    scheduled_scan,
    stealer,
)

api_router = APIRouter(prefix="/api/v1")

# Auth
api_router.include_router(auth.router)

# Assets + Events
api_router.include_router(assets.router)
api_router.include_router(events.router)

# Ingest (internal, для воркеров)
api_router.include_router(ingest.router)
api_router.include_router(internal_alerts.router)

# Сканирование
api_router.include_router(github_scan.router)
api_router.include_router(paste_scan.router)

# Загрузка файлов
api_router.include_router(stealer.router)

# Алерты
api_router.include_router(alerts.router)

# Проверка утечек
api_router.include_router(breach.router)

# Расписание сканирований
api_router.include_router(scheduled_scan.router)

