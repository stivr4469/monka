"""
Temptation Engine — Gap 4 vs Randori (Continuous Automated Red Teaming).

Оценивает активы с точки зрения реального атакующего:
«Насколько этот актив привлекателен как цель?»

Формула:
    temptation_score = discoverability × exploitability × impact_potential × 100

Где:
    discoverability  — насколько легко найти актив (0.0–1.0)
    exploitability   — насколько легко проэксплуатировать (0.0–1.0)
    impact_potential — потенциальный ущерб для бизнеса (0.0–1.0)

В отличие от SecurityScorecard (пассивная оценка по версии ПО),
Temptation Engine показывает ОЧЕРЁДНОСТЬ с точки зрения атакующего.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.event import Event

logger = logging.getLogger(__name__)

# Категории событий с высоким impact
_CREDENTIAL_EVENT_TYPES = {
    "stealer_log", "active_session_leak", "session_leak",
    "credential_leak", "email_breach",
}
_HIGH_EXPLOIT_TYPES = {"subdomain_takeover", "open_s3_bucket"}
_EXPOSURE_TYPES = {"exposed_service", "open_port", "vulnerability"}


# ─── Pydantic схемы ───────────────────────────────────────────────────────────

class TemptationFactor(BaseModel):
    discoverability: float   # 0.0–1.0
    exploitability:  float   # 0.0–1.0
    impact_potential: float  # 0.0–1.0


class AssetTemptation(BaseModel):
    asset_id:         str
    domain:           str
    temptation_score: float          # 0–100
    rank:             int            # 1 = наиболее привлекателен для атакующего
    factors:          TemptationFactor
    top_reason:       str
    recommendation:   str


class OrgTemptationReport(BaseModel):
    org_id:          str
    computed_at:     str
    assets:          list[AssetTemptation]
    most_tempting:   AssetTemptation | None
    avg_temptation:  float


# ─── Вычисление факторов ──────────────────────────────────────────────────────

def _discoverability(asset: Asset, events: list[Event]) -> float:
    """Насколько легко атакующему найти и добраться до актива."""
    base = 0.7
    if getattr(asset, "asset_type", None) == "main_domain":
        base = 1.0
    elif getattr(asset, "asset_type", None) == "subdomain":
        base = 0.5

    event_types = {e.event_type for e in events}
    if event_types & _EXPOSURE_TYPES:
        base = min(1.0, base + 0.3)

    return round(base, 3)


def _exploitability(events: list[Event]) -> float:
    """Насколько легко проэксплуатировать — по наихудшему severity."""
    if not events:
        return 0.1

    severity_scores = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.1}
    worst = max(
        severity_scores.get(e.severity, 0.1)
        for e in events
    )

    event_types = {e.event_type for e in events}
    bonus = 0.2 if event_types & _HIGH_EXPLOIT_TYPES else 0.0

    return round(min(1.0, worst + bonus), 3)


def _impact_potential(asset: Asset, events: list[Event]) -> float:
    """Потенциальный бизнес-ущерб от компрометации актива."""
    importance = getattr(asset, "importance", 1.0) or 1.0
    base = min(0.8, importance / 2.0)

    event_types = {e.event_type for e in events}
    if event_types & _CREDENTIAL_EVENT_TYPES:
        base = min(1.0, base + 0.3)
    if "github_secret_leak" in event_types:
        base = min(1.0, base + 0.2)

    return round(base, 3)


def _top_reason(events: list[Event], score: float) -> str:
    """Человекочитаемое объяснение привлекательности."""
    if not events:
        return "Нет активных угроз — низкий приоритет"

    event_types = {e.event_type for e in events}

    if "subdomain_takeover" in event_types:
        return "Subdomain takeover + высокая важность актива"
    if event_types & {"active_session_leak", "stealer_log"}:
        return "Утечка активной сессии сотрудника"
    if any(e.severity == "critical" for e in events) and event_types & _EXPOSURE_TYPES:
        return "Критическая уязвимость + открытый сервис"
    if any(e.severity == "critical" for e in events):
        return "Критическая уязвимость"
    if "github_secret_leak" in event_types:
        return "Утечка секретов GitHub"
    if event_types & _EXPOSURE_TYPES:
        return "Открытый сервис без патчинга"
    if any(e.severity == "high" for e in events):
        return "Несколько уязвимостей высокого риска"

    return f"Активных угроз {len(events)} низкого приоритета"


def _recommendation(score: float) -> str:
    if score >= 70:
        return "Немедленно. Актив в топе целей для реального атакующего"
    if score >= 40:
        return "Высокий приоритет. Устранить в течение недели"
    return "Плановое устранение. Мониторинг продолжить"


def _score(disc: float, expl: float, impact: float) -> float:
    return round(disc * expl * impact * 100, 1)


# ─── Публичные функции ────────────────────────────────────────────────────────

async def compute_asset_temptation(
    asset_id: str,
    db: AsyncSession,
) -> AssetTemptation:
    """Вычисляет Temptation Score для одного актива."""
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise ValueError(f"Asset {asset_id} не найден")

    result = await db.execute(
        select(Event).where(Event.asset_id == asset_id)
    )
    events = list(result.scalars().all())

    disc   = _discoverability(asset, events)
    expl   = _exploitability(events)
    impact = _impact_potential(asset, events)
    ts     = _score(disc, expl, impact)

    return AssetTemptation(
        asset_id=asset_id,
        domain=asset.domain,
        temptation_score=ts,
        rank=1,
        factors=TemptationFactor(
            discoverability=disc,
            exploitability=expl,
            impact_potential=impact,
        ),
        top_reason=_top_reason(events, ts),
        recommendation=_recommendation(ts),
    )


async def compute_org_temptation(
    org_id: str,
    db: AsyncSession,
) -> OrgTemptationReport:
    """Ранжирует все активы организации по привлекательности для атакующего."""
    assets_result = await db.execute(
        select(Asset).where(Asset.organization_id == org_id, Asset.is_active == True)  # noqa: E712
    )
    assets = list(assets_result.scalars().all())

    if not assets:
        return OrgTemptationReport(
            org_id=org_id,
            computed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            assets=[],
            most_tempting=None,
            avg_temptation=0.0,
        )

    # Загружаем события для всех активов одним запросом
    asset_ids = [a.id for a in assets]
    events_result = await db.execute(
        select(Event).where(Event.asset_id.in_(asset_ids))
    )
    all_events = list(events_result.scalars().all())

    events_by_asset: dict[str, list[Event]] = {a.id: [] for a in assets}
    for ev in all_events:
        if ev.asset_id:
            events_by_asset.setdefault(ev.asset_id, []).append(ev)

    temptations: list[AssetTemptation] = []
    for asset in assets:
        evs   = events_by_asset.get(asset.id, [])
        disc  = _discoverability(asset, evs)
        expl  = _exploitability(evs)
        imp   = _impact_potential(asset, evs)
        ts    = _score(disc, expl, imp)
        temptations.append(AssetTemptation(
            asset_id=asset.id,
            domain=asset.domain,
            temptation_score=ts,
            rank=0,
            factors=TemptationFactor(
                discoverability=disc,
                exploitability=expl,
                impact_potential=imp,
            ),
            top_reason=_top_reason(evs, ts),
            recommendation=_recommendation(ts),
        ))

    temptations.sort(key=lambda x: x.temptation_score, reverse=True)
    for i, t in enumerate(temptations, 1):
        t.rank = i

    avg = round(sum(t.temptation_score for t in temptations) / len(temptations), 1)

    return OrgTemptationReport(
        org_id=org_id,
        computed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        assets=temptations,
        most_tempting=temptations[0] if temptations else None,
        avg_temptation=avg,
    )
