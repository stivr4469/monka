from fastapi import APIRouter

from app.api.v1.endpoints import (
    alerts,
    api_keys,
    assets,
    auth,
    billing,
    breach,
    cookie_scan,
    darknet_scan,
    enrich_scan,
    events,
    github_scan,
    graph,
    hardening_scan,
    human_osint_scan,
    ingest,
    internal_alerts,
    mssp,
    notifications,
    paste_scan,
    phishing_scan,
    port_scan,
    reveal,
    s3_scan,
    scheduled_scan,
    stealer,
    stealer_sources,
    takeover_scan,
    tech_scan,
    telegram_scan,
    tls_scan,
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
api_router.include_router(cookie_scan.router)
api_router.include_router(takeover_scan.router)
api_router.include_router(tls_scan.router)

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

# MSSP Multi-Tenancy (задача 9.F)
api_router.include_router(mssp.router)

# Attack Path Engine — Neo4j граф (задача 9.E)
api_router.include_router(graph.router)

# Shodan Enrichment — обогащение данных Asset Drift (задача 9.J)
api_router.include_router(enrich_scan.router)

# Human OSINT — профилирование сотрудников компании (задача 9.D)
api_router.include_router(human_osint_scan.router)

# Technology Profiling — Wappalyzer-like детектирование (задача 10.A)
api_router.include_router(tech_scan.router)

# Reveal (расшифровка паролей) + Audit Log (задача 10.B)
api_router.include_router(reveal.router)

# API Keys — SIEM/SOAR интеграция (задача 10.F)
api_router.include_router(api_keys.router)

# Уведомления + SSE поток (задача 10.I)
api_router.include_router(notifications.router)

