from fastapi import APIRouter

from app.api.v1.endpoints import (
    alerts,
    assets,
    auth,
    billing,
    breach,
    darknet_scan,
    events,
    github_scan,
    hardening_scan,
    ingest,
    internal_alerts,
    paste_scan,
    phishing_scan,
    port_scan,
    s3_scan,
    scheduled_scan,
    stealer,
    stealer_sources,
    telegram_scan,
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
api_router.include_router(telegram_scan.router)
api_router.include_router(darknet_scan.router)
api_router.include_router(hardening_scan.router)
api_router.include_router(phishing_scan.router)
api_router.include_router(port_scan.router)
api_router.include_router(s3_scan.router)

# Стилер-логи: загрузка файлов + автоматические источники
api_router.include_router(stealer.router)
api_router.include_router(stealer_sources.router)

# Алерты
api_router.include_router(alerts.router)

# Проверка утечек
api_router.include_router(breach.router)

# Расписание сканирований
api_router.include_router(scheduled_scan.router)

# SaaS биллинг и тарифные планы
api_router.include_router(billing.router)

