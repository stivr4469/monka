"""Multi-org Industry Comparison — сравнение Security Score нескольких организаций (Phase 13.I).

Маршруты:
    GET /api/v1/comparison/orgs       — сравнение конкретных org по org_ids
    GET /api/v1/comparison/portfolio  — все org в портфеле MSSP-пользователя
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization
from app.models.score_snapshot import ScoreSnapshot
from app.services.benchmarking import _normalize_industry, _score_to_rank
from app.services.score_engine import CATEGORY_WEIGHTS, calculate_score

router = APIRouter(tags=["comparison"])

# Порог изменения score для определения тренда (пункты)
_TREND_THRESHOLD = 3.0

# Категории для сравнения (соответствуют ключам score_engine)
_CATEGORIES = [
    "network_security",
    "dns_health",
    "application_security",
    "credential_exposure",
    "dark_web_presence",
    "brand_safety",
]


# ─── Pydantic-схемы ответа ────────────────────────────────────────────────────

class OrgComparisonItem(BaseModel):
    """Данные одной организации в сравнительном отчёте."""

    org_id: str
    name: str
    industry: str
    score: float
    rank: str
    category_scores: dict[str, float]
    trend: str          # improving / stable / degrading
    open_critical: int
    open_high: int


class ComparisonSummaryBest(BaseModel):
    org_id: str
    name: str
    score: float


class ComparisonSummaryWorst(BaseModel):
    org_id: str
    name: str
    score: float


class ComparisonSummary(BaseModel):
    best_score: ComparisonSummaryBest
    worst_score: ComparisonSummaryWorst
    avg_score: float
    total_orgs: int


class ComparisonResponse(BaseModel):
    organizations: list[OrgComparisonItem]
    summary: ComparisonSummary | None = None


# ─── Вспомогательные функции ──────────────────────────────────────────────────

async def _get_open_events_counts(
    org_id: str,
    db: DBDep,
    days: int = 30,
) -> tuple[int, int]:
    """Возвращает количество открытых critical и high событий за последние N дней."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    assets_result = await db.execute(
        select(Asset.id).where(Asset.organization_id == org_id)
    )
    asset_ids = [row[0] for row in assets_result.all()]

    if not asset_ids:
        return 0, 0

    critical_result = await db.execute(
        select(Event.id).where(
            Event.asset_id.in_(asset_ids),
            Event.severity == "critical",
            Event.resolved_at.is_(None),
            Event.detected_at >= since,
        )
    )
    critical_count = len(critical_result.all())

    high_result = await db.execute(
        select(Event.id).where(
            Event.asset_id.in_(asset_ids),
            Event.severity == "high",
            Event.resolved_at.is_(None),
            Event.detected_at >= since,
        )
    )
    high_count = len(high_result.all())

    return critical_count, high_count


async def _get_trend(
    org_id: str,
    db: DBDep,
    days: int,
) -> str:
    """Определяет тренд score организации.

    Сравниваем средний score за последние N дней с предыдущим периодом N дней.
    Если данных нет — возвращаем 'stable'.

    Логика:
        - score вырос на >3 → 'improving'
        - score упал на >3  → 'degrading'
        - иначе             → 'stable'
    """
    now = datetime.now(timezone.utc)
    period_start = now - timedelta(days=days)
    prev_start = now - timedelta(days=days * 2)

    # Текущий период: последние N дней
    current_result = await db.execute(
        select(ScoreSnapshot.total_score)
        .where(
            ScoreSnapshot.org_id == org_id,
            ScoreSnapshot.asset_id.is_(None),
            ScoreSnapshot.calculated_at >= period_start,
            ScoreSnapshot.calculated_at < now,
        )
        .order_by(ScoreSnapshot.calculated_at.asc())
    )
    current_scores = [row[0] for row in current_result.all()]

    # Предыдущий период: N..2N дней назад
    prev_result = await db.execute(
        select(ScoreSnapshot.total_score)
        .where(
            ScoreSnapshot.org_id == org_id,
            ScoreSnapshot.asset_id.is_(None),
            ScoreSnapshot.calculated_at >= prev_start,
            ScoreSnapshot.calculated_at < period_start,
        )
        .order_by(ScoreSnapshot.calculated_at.asc())
    )
    prev_scores = [row[0] for row in prev_result.all()]

    if not current_scores or not prev_scores:
        return "stable"

    current_avg = sum(current_scores) / len(current_scores)
    prev_avg = sum(prev_scores) / len(prev_scores)
    delta = current_avg - prev_avg

    if delta > _TREND_THRESHOLD:
        return "improving"
    if delta < -_TREND_THRESHOLD:
        return "degrading"
    return "stable"


async def _build_org_item(
    org: Organization,
    db: DBDep,
    days: int,
) -> OrgComparisonItem:
    """Строит OrgComparisonItem для одной организации."""
    # Рассчитываем актуальный Security Score
    score_result = await calculate_score(org_id=org.id, db=db, asset_id=None)
    total_score = float(score_result.total)

    # Категорийные оценки
    category_scores: dict[str, float] = {
        cat: float(score_result.categories[cat].score)
        for cat in _CATEGORIES
        if cat in score_result.categories
    }
    # Заполняем отсутствующие категории нулями
    for cat in _CATEGORIES:
        if cat not in category_scores:
            category_scores[cat] = 0.0

    # Rank относительно статичного бенчмарка отрасли (используем benchmarking)
    from app.services.benchmarking import INDUSTRY_BENCHMARKS, _normalize_industry
    industry = _normalize_industry(org.industry)
    bench = INDUSTRY_BENCHMARKS.get(industry, INDUSTRY_BENCHMARKS["other"])
    rank = _score_to_rank(
        total_score,
        p25=bench["p25"],
        p50=bench["p50"],
        p75=bench["p75"],
    )

    # Тренд
    trend = await _get_trend(org.id, db, days)

    # Открытые события
    open_critical, open_high = await _get_open_events_counts(org.id, db, days)

    return OrgComparisonItem(
        org_id=org.id,
        name=org.name,
        industry=industry,
        score=round(total_score, 1),
        rank=rank,
        category_scores=category_scores,
        trend=trend,
        open_critical=open_critical,
        open_high=open_high,
    )


def _build_summary(items: list[OrgComparisonItem]) -> ComparisonSummary:
    """Вычисляет сводку: best/worst/avg."""
    if not items:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Нет организаций для сравнения",
        )

    best = max(items, key=lambda x: x.score)
    worst = min(items, key=lambda x: x.score)
    avg_score = round(sum(i.score for i in items) / len(items), 1)

    return ComparisonSummary(
        best_score=ComparisonSummaryBest(
            org_id=best.org_id,
            name=best.name,
            score=best.score,
        ),
        worst_score=ComparisonSummaryWorst(
            org_id=worst.org_id,
            name=worst.name,
            score=worst.score,
        ),
        avg_score=avg_score,
        total_orgs=len(items),
    )


async def _get_accessible_orgs(
    db: DBDep,
    current_user: Any,
    org_ids: list[str] | None = None,
) -> list[Organization]:
    """Возвращает организации, доступные пользователю.

    Правила доступа:
        - superuser → может видеть любые org_ids (или все если не указаны)
        - mssp_operator → только org где mssp_owner_id == user.id
        - обычный пользователь → только своя org (organization_id)
    """
    if current_user.is_superuser:
        if org_ids:
            q = select(Organization).where(Organization.id.in_(org_ids))
        else:
            q = select(Organization)
        result = await db.execute(q.order_by(Organization.name))
        return list(result.scalars().all())

    if getattr(current_user, "is_mssp_operator", False):
        # MSSP: видит только свои клиентские org
        q = select(Organization).where(
            Organization.mssp_owner_id == current_user.id
        )
        if org_ids:
            q = q.where(Organization.id.in_(org_ids))
        result = await db.execute(q.order_by(Organization.name))
        return list(result.scalars().all())

    # Обычный пользователь: только своя org
    if not current_user.organization_id:
        return []

    if org_ids and current_user.organization_id not in org_ids:
        # Попытка увидеть чужую org — возвращаем только свою
        return []

    result = await db.execute(
        select(Organization).where(
            Organization.id == current_user.organization_id
        )
    )
    org = result.scalar_one_or_none()
    return [org] if org else []


# ─── GET /comparison/orgs ─────────────────────────────────────────────────────

@router.get(
    "/orgs",
    response_model=ComparisonResponse,
    summary="Сравнение Security Score нескольких организаций (Phase 13.I)",
)
async def compare_orgs(
    db: DBDep,
    current_user: CurrentUser,
    org_ids: str | None = Query(
        default=None,
        description="Список org_id через запятую: ?org_ids=uuid1,uuid2,uuid3",
    ),
    days: int = Query(
        default=30,
        ge=1,
        le=365,
        description="Период анализа в днях (по умолчанию 30)",
    ),
) -> ComparisonResponse:
    """Сравнивает Security Score нескольких организаций.

    Безопасность:
        - superuser видит любые org
        - mssp_operator видит только своих клиентов
        - обычный пользователь видит только свою org

    Если org_ids не указаны — возвращает только свою org (для обычного пользователя)
    или все доступные (для superuser/mssp).
    """
    # Парсим список org_ids из строки
    parsed_ids: list[str] | None = None
    if org_ids:
        parsed_ids = [oid.strip() for oid in org_ids.split(",") if oid.strip()]

    orgs = await _get_accessible_orgs(db, current_user, parsed_ids)

    if not orgs:
        return ComparisonResponse(organizations=[], summary=None)

    # Строим данные для каждой org
    items: list[OrgComparisonItem] = []
    for org in orgs:
        item = await _build_org_item(org, db, days)
        items.append(item)

    summary = _build_summary(items) if items else None

    return ComparisonResponse(organizations=items, summary=summary)


# ─── GET /comparison/portfolio ────────────────────────────────────────────────

@router.get(
    "/portfolio",
    response_model=ComparisonResponse,
    summary="Портфель MSSP — сравнение всех клиентских организаций (Phase 13.I)",
)
async def compare_portfolio(
    db: DBDep,
    current_user: CurrentUser,
    days: int = Query(
        default=30,
        ge=1,
        le=365,
        description="Период анализа в днях (по умолчанию 30)",
    ),
) -> ComparisonResponse:
    """Возвращает сравнительный отчёт по всем org в портфеле MSSP-пользователя.

    Требует is_mssp_operator=True или is_superuser=True.
    Обычный пользователь получает 403.
    """
    is_mssp = getattr(current_user, "is_mssp_operator", False)
    if not current_user.is_superuser and not is_mssp:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ только для MSSP-операторов и суперпользователей",
        )

    orgs = await _get_accessible_orgs(db, current_user, org_ids=None)

    if not orgs:
        return ComparisonResponse(organizations=[], summary=None)

    items: list[OrgComparisonItem] = []
    for org in orgs:
        item = await _build_org_item(org, db, days)
        items.append(item)

    summary = _build_summary(items) if items else None

    return ComparisonResponse(organizations=items, summary=summary)
