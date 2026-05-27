"""
Identity Risk Engine — Gap 6: Identity-Centric Security.

Уникальное позиционирование vs SecurityScorecard и BitSight:
«Другие EASM-системы оценивают порты. Мы защищаем сессии ваших сотрудников
от прямого обхода MFA.»

Агрегирует события из стилер-логов, cookie-валидатора и утечек сессий.
Вычисляет MFA Bypass Risk Score и количество сотрудников под угрозой.
Привязывает скомпрометированные данные к конкретным сотрудникам организации.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.event import Event

logger = logging.getLogger(__name__)

# Типы событий — прямая угроза идентичности
_SESSION_EVENT_TYPES = {"active_session_leak", "session_leak"}
_CREDENTIAL_EVENT_TYPES = {"stealer_log", "credential_leak", "email_breach"}
_SECRET_EVENT_TYPES = {"github_secret_leak"}
_ALL_IDENTITY_TYPES = _SESSION_EVENT_TYPES | _CREDENTIAL_EVENT_TYPES | _SECRET_EVENT_TYPES

# Вес каждого типа события в risk score пользователя
_USER_RISK_WEIGHTS: dict[str, int] = {
    "active_session_leak": 40,
    "session_leak":        40,
    "stealer_log":         30,
    "credential_leak":     20,
    "email_breach":        20,
    "github_secret_leak":  10,
}


# ─── Dataclass для пострадавшего пользователя ─────────────────────────────────

@dataclass
class AffectedUser:
    email:              str
    username:           str | None
    source_type:        str           # stealer_log | credential_leak | session_leak
    compromised_urls:   list[str]     = field(default_factory=list)
    passwords_exposed:  int           = 0
    last_seen:          datetime      = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score:         int           = 0
    # Внутреннее накопление — используется при merge, не отдаётся наружу
    _event_types:       set[str]      = field(default_factory=set, repr=False)
    _raw_score:         int           = field(default=0, repr=False)


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
    top_affected_domains:    list[str]        # топ-5 доменов по числу событий
    event_breakdown:         list[IdentityEventSummary]
    affected_users:          list[AffectedUser]  # топ-10 пострадавших по risk_score
    positioning:             str               # маркетинговый тезис


# ─── Извлечение пострадавших пользователей ───────────────────────────────────

def _extract_email_from_payload(payload: dict, event_type: str) -> tuple[str | None, str | None]:
    """
    Извлекает (email, username) из payload события.

    Поддерживаемые форматы:
    - stealer_log / active_session_leak: payload.login
    - credential_leak / email_breach: payload.email
    Если login не содержит @, считаем его username без email.
    """
    email: str | None = None
    username: str | None = None

    # Пробуем поля по приоритету
    raw = (
        payload.get("email")
        or payload.get("login")
        or payload.get("username")
        or ""
    )
    raw = str(raw).strip().lower()

    if "@" in raw:
        email = raw
        # username = часть до @
        username = raw.split("@")[0] or None
    elif raw:
        username = raw

    return email, username


def _url_from_payload(payload: dict, event_type: str) -> str | None:
    """Извлекает скомпрометированный URL из payload события."""
    return (
        payload.get("url")
        or payload.get("session_url")
        or payload.get("domain")
        or None
    )


def _has_password(payload: dict) -> bool:
    """Проверяет наличие пароля в payload."""
    pwd = payload.get("password") or payload.get("pass") or payload.get("pwd")
    return bool(pwd and str(pwd).strip())


def extract_affected_users(events: list[Event]) -> list[AffectedUser]:
    """
    Извлекает пострадавших пользователей из payload событий.
    Поддерживает форматы:
    - stealer_log: payload.login (email или user@domain), payload.url
    - credential_leak: payload.email, payload.password
    - email_breach: payload.email
    - active_session_leak: payload.login, payload.session_url
    - session_leak: payload.login, payload.session_url

    Несколько событий для одного email объединяются (merge).
    Risk score: session_leak=40pts + stealer_log=30pts + credential_leak=20pts
                + github_secret=10pts (аккумулируется, cap 100).

    Возвращает список, отсортированный по risk_score (убывание).
    """
    # Фильтруем только identity-типы
    identity_types = _CREDENTIAL_EVENT_TYPES | _SESSION_EVENT_TYPES

    # Промежуточный словарь: email → аккумулятор
    accumulator: dict[str, _UserAccum] = {}

    for ev in events:
        if ev.event_type not in identity_types:
            continue

        payload: dict = ev.payload or {}
        email, username = _extract_email_from_payload(payload, ev.event_type)

        if not email:
            # Нет email — не можем привязать к сотруднику
            continue

        url = _url_from_payload(payload, ev.event_type)
        has_pwd = _has_password(payload)
        ev_ts = ev.detected_at or datetime.now(timezone.utc)
        weight = _USER_RISK_WEIGHTS.get(ev.event_type, 0)

        if email not in accumulator:
            accumulator[email] = _UserAccum(
                email=email,
                username=username,
                source_type=ev.event_type,
            )

        accum = accumulator[email]
        accum.merge(
            event_type=ev.event_type,
            url=url,
            has_password=has_pwd,
            detected_at=ev_ts,
            weight=weight,
            username=username,
        )

    # Преобразуем аккумуляторы в AffectedUser
    result: list[AffectedUser] = []
    for accum in accumulator.values():
        result.append(accum.to_affected_user())

    # Сортируем по убыванию risk_score
    result.sort(key=lambda u: u.risk_score, reverse=True)
    return result


@dataclass
class _UserAccum:
    """Внутренний аккумулятор для merge событий одного email."""
    email:             str
    username:          str | None
    source_type:       str           # тип первого события
    _urls:             set[str]      = field(default_factory=set)
    _passwords:        int           = 0
    _last_seen:        datetime      = field(default_factory=lambda: datetime.now(timezone.utc))
    _raw_score:        int           = 0
    _event_types:      set[str]      = field(default_factory=set)

    def merge(
        self,
        event_type: str,
        url: str | None,
        has_password: bool,
        detected_at: datetime,
        weight: int,
        username: str | None,
    ) -> None:
        self._event_types.add(event_type)
        if url:
            self._urls.add(url)
        if has_password:
            self._passwords += 1
        if detected_at > self._last_seen:
            self._last_seen = detected_at
        self._raw_score += weight
        # Если username ещё не задан, берём из нового события
        if self.username is None and username:
            self.username = username
        # source_type = наиболее рискованный тип
        risk_order = ["active_session_leak", "session_leak", "stealer_log",
                      "credential_leak", "email_breach"]
        for t in risk_order:
            if t in self._event_types:
                self.source_type = t
                break

    def to_affected_user(self) -> AffectedUser:
        score = min(100, self._raw_score)
        return AffectedUser(
            email=self.email,
            username=self.username,
            source_type=self.source_type,
            compromised_urls=sorted(self._urls),
            passwords_exposed=self._passwords,
            last_seen=self._last_seen,
            risk_score=score,
            _event_types=self._event_types,
            _raw_score=self._raw_score,
        )


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

    # Пострадавшие пользователи (топ-10 по risk_score)
    all_affected = extract_affected_users(events)
    top_affected = all_affected[:10]

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
        affected_users=top_affected,
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
        affected_users=[],
        positioning=(
            "SecurityScorecard и BitSight оценивают порты и версии ПО. "
            "Наша платформа защищает активные сессии сотрудников от прямого обхода MFA — "
            "вектор, который традиционные EASM-системы не видят вообще."
        ),
    )
