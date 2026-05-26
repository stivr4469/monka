"""
Identity Risk Engine — Gap 6: Identity-Centric Security.

Уникальное позиционирование vs SecurityScorecard и BitSight:
«Другие EASM-системы оценивают порты. Мы защищаем сессии ваших сотрудников
от прямого обхода MFA.»

Агрегирует события из стилер-логов, cookie-валидатора и утечек сессий.
Вычисляет MFA Bypass Risk Score и количество сотрудников под угрозой.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.event import Event

logger = logging.getLogger(__name__)

# Типы событий — прямая угроза идентичности
_SESSION_EVENT_TYPES = {"active_session_leak", "session_leak"}
_CREDENTIAL_EVENT_TYPES = {"stealer_log", "credential_leak", "email_breach"}
_SECRET_EVENT_TYPES = {"github_secret_leak"}
_ALL_IDENTITY_TYPES = _SESSION_EVENT_TYPES | _CREDENTIAL_EVENT_TYPES | _SECRET_EVENT_TYPES


# ─── Pydantic схемы ───────────────────────────────────────────────────────────

class IdentityEventSummary(BaseModel):
    event_type:   str
    count:        int
    severity:     str   # наихудший severity


class IdentityRiskReport(BaseModel):
    org_id:                  str
    computed_at:             str
    employees_at_risk:       int    # события stealer_log с уникальными доменами
    active_sessions_compromised: int  # события active_session_leak / session_leak
    mfa_bypass_score:        int    # 0-100 (100 = критический риск обхода MFA)
    mfa_bypass_risk:         str    # "critical" / "high" / "medium" / "low"
    credential_leaks:        int    # credential_leak + email_breach
    github_secrets:          int    # github_secret_leak
    total_identity_events:   int
    top_affected_domains:    list[str]  # топ-5 доменов по числу событий
    event_breakdown:         list[IdentityEventSummary]
    positioning:             str    # маркетинговый тезис


# ─── Логика расчёта ───────────────────────────────────────────────────────────

def _mfa_bypass_score(sessions: int, stealers: int, creds: int) -> tuple[int, str]:
    """
    MFA Bypass Score — насколько реальна угроза обхода MFA через перехват сессии.

    Активная сессия в стилер-логе = атакующий уже прошёл MFA,
    он не взламывает пароль — он ворует куку после авторизации.
    """
    score = 0
    # Активные сессии — прямой вектор обхода MFA
    score += min(60, sessions * 15)
    # Стилеры с данными — вероятный источник сессий
    score += min(25, stealers * 5)
    # Утечки credentials — возможная повторная авторизация
    score += min(15, creds * 3)

    score = min(100, score)

    if score >= 75:
        risk = "critical"
    elif score >= 50:
        risk = "high"
    elif score >= 25:
        risk = "medium"
    else:
        risk = "low"

    return score, risk


# ─── Публичная функция ────────────────────────────────────────────────────────

async def compute_identity_risk(
    org_id: str,
    db: AsyncSession,
) -> IdentityRiskReport:
    """
    Строит Identity Risk Report для организации.
    Агрегирует все события идентичности по всем активам org.
    """
    # Получаем asset_ids организации
    assets_result = await db.execute(
        select(Asset.id, Asset.domain).where(
            Asset.organization_id == org_id,
            Asset.is_active == True,  # noqa: E712
        )
    )
    asset_rows = assets_result.all()
    asset_ids = [r[0] for r in asset_rows]
    domain_by_id = {r[0]: r[1] for r in asset_rows}

    if not asset_ids:
        return _empty_report(org_id)

    # Загружаем все identity-события одним запросом
    events_result = await db.execute(
        select(Event).where(
            Event.asset_id.in_(asset_ids),
            Event.event_type.in_(_ALL_IDENTITY_TYPES),
        )
    )
    events: list[Event] = list(events_result.scalars().all())

    if not events:
        return _empty_report(org_id)

    # Разбивка по типам
    session_events = [e for e in events if e.event_type in _SESSION_EVENT_TYPES]
    stealer_events = [e for e in events if e.event_type == "stealer_log"]
    cred_events    = [e for e in events if e.event_type in {"credential_leak", "email_breach"}]
    secret_events  = [e for e in events if e.event_type in _SECRET_EVENT_TYPES]

    mfa_score, mfa_risk = _mfa_bypass_score(
        len(session_events), len(stealer_events), len(cred_events)
    )

    # Топ доменов по числу событий
    domain_counts: dict[str, int] = {}
    for ev in events:
        domain = ev.target_domain or domain_by_id.get(ev.asset_id or "", "unknown")
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
    top_domains = sorted(domain_counts, key=domain_counts.get, reverse=True)[:5]  # type: ignore[arg-type]

    # Event breakdown
    breakdown_map: dict[str, tuple[int, str]] = {}
    for ev in events:
        et = ev.event_type
        count, worst_sev = breakdown_map.get(et, (0, "info"))
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        new_worst = ev.severity if sev_order.get(ev.severity, 0) > sev_order.get(worst_sev, 0) else worst_sev
        breakdown_map[et] = (count + 1, new_worst)

    breakdown = [
        IdentityEventSummary(event_type=et, count=cnt, severity=sev)
        for et, (cnt, sev) in sorted(breakdown_map.items(), key=lambda x: -x[1][0])
    ]

    positioning = (
        "SecurityScorecard и BitSight оценивают порты и версии ПО. "
        "Наша платформа защищает активные сессии сотрудников от прямого обхода MFA — "
        "вектор, который традиционные EASM-системы не видят вообще."
    )

    return IdentityRiskReport(
        org_id=org_id,
        computed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        employees_at_risk=len(stealer_events),
        active_sessions_compromised=len(session_events),
        mfa_bypass_score=mfa_score,
        mfa_bypass_risk=mfa_risk,
        credential_leaks=len(cred_events),
        github_secrets=len(secret_events),
        total_identity_events=len(events),
        top_affected_domains=top_domains,
        event_breakdown=breakdown,
        positioning=positioning,
    )


def _empty_report(org_id: str) -> IdentityRiskReport:
    return IdentityRiskReport(
        org_id=org_id,
        computed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        employees_at_risk=0,
        active_sessions_compromised=0,
        mfa_bypass_score=0,
        mfa_bypass_risk="low",
        credential_leaks=0,
        github_secrets=0,
        total_identity_events=0,
        top_affected_domains=[],
        event_breakdown=[],
        positioning=(
            "SecurityScorecard и BitSight оценивают порты и версии ПО. "
            "Наша платформа защищает активные сессии сотрудников от прямого обхода MFA — "
            "вектор, который традиционные EASM-системы не видят вообще."
        ),
    )
