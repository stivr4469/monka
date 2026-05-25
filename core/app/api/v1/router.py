from fastapi import APIRouter

from app.api.v1.endpoints import (
    ai_narrative,
    alerts,
    api_keys,
    assets,
    auth,
    billing,
    breach,
    censys_scan,
    comparison,
    cookie_scan,
    ct_scan,
    dashboard,
    darknet_scan,
    enrich_scan,
    events,
    github_scan,
    graph,
    hardening_scan,
    human_osint_scan,
    ingest,
    internal_alerts,
    mobile_scan,
    mssp,
    notifications,
    paste_scan,
    score,
    phishing_scan,
    masscan_scan,
    port_scan,
    reveal,
    s3_scan,
    scheduled_scan,
    stealer,
    stealer_sources,
    stix_export,
    takeover_scan,
    tech_scan,
    telegram_scan,
    tickets,
    tls_scan,
    brand_scan,
    whois_scan,
    bgp_scan,
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
api_router.include_router(masscan_scan.router)

# Certificate Transparency Monitor — crt.sh (задача 12.A)
api_router.include_router(ct_scan.router)

# Brand Monitor — Reddit + HN + Telegram (фаза 12.B / 12.E)
api_router.include_router(brand_scan.router)

# Mobile App Monitor — App Store + Google Play (фаза 12.D)
api_router.include_router(mobile_scan.router)

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

# WHOIS/Registrant Monitor — отслеживание изменений RDAP-данных (задача 13.C)
api_router.include_router(whois_scan.router)

# BGP/ASN Monitor — детекция смены провайдера и IP-диапазонов (задача 13.D)
api_router.include_router(bgp_scan.router)

# Reveal (расшифровка паролей) + Audit Log (задача 10.B)
api_router.include_router(reveal.router)

# API Keys — SIEM/SOAR интеграция (задача 10.F)
api_router.include_router(api_keys.router)

# Уведомления + SSE поток (задача 10.I)
api_router.include_router(notifications.router)

# Security Score Engine — многокатегорийный score (задача 11)
api_router.include_router(score.router)

# Executive Dashboard — сводный дашборд безопасности (задача 11.C)
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])

# AI Risk Narrative — executive summary через Claude API (фаза 13.G)
api_router.include_router(ai_narrative.router, prefix="/ai", tags=["ai"])

# STIX 2.1 Export — SIEM интеграция (фаза 13.E)
api_router.include_router(stix_export.router, prefix="/export", tags=["export"])

# Censys Enrichment — обогащение данных через Censys Search API (фаза 13.B)
api_router.include_router(censys_scan.router)

# Automated Remediation Playbooks — Jira/ServiceNow ticketing (фаза 13.H)
api_router.include_router(tickets.router, prefix="/events", tags=["tickets"])

# Multi-org Industry Comparison — MSSP portfolio comparison (Phase 13.I)
api_router.include_router(comparison.router, prefix="/comparison", tags=["comparison"])

