"""Executive Dashboard — агрегированный дашборд безопасности организации (задача 11.C).

Маршруты:
    GET /api/v1/dashboard/executive — сводный дашборд для руководителя
    GET /api/v1/dashboard/benchmark — Industry Benchmarking (задача 13.F)
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization
from app.models.score_snapshot import ScoreSnapshot
from app.services.benchmarking import compare_with_benchmark
from app.services.score_engine import CATEGORY_WEIGHTS, calculate_score

router = APIRouter(tags=["dashboard"])

# Порядок серьёзности для сортировки рисков
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─── Pydantic-схемы ответа ────────────────────────────────────────────────────

class OrganizationInfo(BaseModel):
    id: str
    name: str


class ScoreTrendPoint(BaseModel):
    date: str   # ISO-дата "YYYY-MM-DD"
    score: float


class TopRiskItem(BaseModel):
    event_id: str
    event_type: str
    severity: str
    target_domain: str
    description: str
    detected_at: datetime


class ExecutiveDashboard(BaseModel):
    generated_at: datetime
    organization: OrganizationInfo
    overall_score: float
    score_trend: list[ScoreTrendPoint]
    category_scores: dict[str, float]
    top_risks: list[TopRiskItem]
    asset_count: int
    open_events_by_severity: dict[str, int]


# ─── Вспомогательные функции ──────────────────────────────────────────────────

async def _get_score_trend(
    org_id: str,
    db: DBDep,
    days: int = 7,
) -> list[ScoreTrendPoint]:
    """Возвращает тренд score за последние N дней.

    Сначала пробует взять из ScoreSnapshot (asset_id IS NULL = org-level).
    Если за конкретный день снимка нет — заполняет нулём.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    # Запрашиваем org-level снимки за период (asset_id IS NULL)
    snapshots_result = await db.execute(
        select(ScoreSnapshot)
        .where(
            ScoreSnapshot.org_id == org_id,
            ScoreSnapshot.asset_id.is_(None),
            ScoreSnapshot.calculated_at >= since,
        )
        .order_by(ScoreSnapshot.calculated_at.asc())
    )
    snapshots = list(snapshots_result.scalars().all())

    # Группируем по дате: берём последний снимок за каждый день
    snapshots_by_date: dict[str, float] = {}
    for snap in snapshots:
        cal = snap.calculated_at
        if cal.tzinfo is None:
            cal = cal.replace(tzinfo=timezone.utc)
        date_key = cal.date().isoformat()
        snapshots_by_date[date_key] = float(snap.total_score)

    # Строим точки за последние N дней
    trend: list[ScoreTrendPoint] = []
    for i in range(days - 1, -1, -1):
        day = (now - timedelta(days=i)).date()
        date_str = day.isoformat()
        score_val = snapshots_by_date.get(date_str, 0.0)
        trend.append(ScoreTrendPoint(date=date_str, score=score_val))

    return trend


async def _build_top_risks(
    org_id: str,
    db: DBDep,
    limit: int = 5,
) -> list[TopRiskItem]:
    """Возвращает топ N критических/высоких неустранённых событий организации.

    Сортировка: critical первыми, затем high, затем по дате (новые первыми).
    """
    # Получаем все активы организации
    assets_result = await db.execute(
        select(Asset.id).where(Asset.organization_id == org_id)
    )
    asset_ids = [row[0] for row in assets_result.all()]

    if not asset_ids:
        return []

    # Берём неустранённые critical/high события за последние 30 дней
    since_30d = datetime.now(timezone.utc) - timedelta(days=30)
    events_result = await db.execute(
        select(Event)
        .where(
            Event.asset_id.in_(asset_ids),
            Event.severity.in_(["critical", "high"]),
            Event.resolved_at.is_(None),
            Event.detected_at >= since_30d,
        )
        .order_by(Event.detected_at.desc())
        .limit(100)  # Берём с запасом для сортировки
    )
    events = list(events_result.scalars().all())

    # Сортируем: critical первыми, затем по дате DESC
    events.sort(
        key=lambda e: (_SEVERITY_ORDER.get(e.severity, 99), -e.detected_at.timestamp())
    )

    result: list[TopRiskItem] = []
    for ev in events[:limit]:
        # Формируем описание из payload или дефолт
        payload = ev.payload or {}
        description = (
            payload.get("description")
            or payload.get("summary")
            or payload.get("title")
            or f"{ev.event_type} detected on {ev.target_domain}"
        )
        result.append(TopRiskItem(
            event_id=ev.id,
            event_type=ev.event_type,
            severity=ev.severity,
            target_domain=ev.target_domain,
            description=str(description),
            detected_at=ev.detected_at,
        ))

    return result


async def _count_events_by_severity(
    org_id: str,
    db: DBDep,
) -> dict[str, int]:
    """Считает открытые (неустранённые) события по уровню серьёзности."""
    assets_result = await db.execute(
        select(Asset.id).where(Asset.organization_id == org_id)
    )
    asset_ids = [row[0] for row in assets_result.all()]

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    if not asset_ids:
        return counts

    since_30d = datetime.now(timezone.utc) - timedelta(days=30)
    rows_result = await db.execute(
        select(Event.severity, func.count(Event.id).label("cnt"))
        .where(
            Event.asset_id.in_(asset_ids),
            Event.resolved_at.is_(None),
            Event.detected_at >= since_30d,
        )
        .group_by(Event.severity)
    )
    for row in rows_result.all():
        sev = row.severity.lower()
        if sev in counts:
            counts[sev] = row.cnt

    return counts


# ─── GET /dashboard/executive ─────────────────────────────────────────────────

@router.get(
    "/executive",
    response_model=ExecutiveDashboard,
    summary="Executive Security Dashboard (задача 11.C)",
)
async def get_executive_dashboard(
    db: DBDep,
    current_user: CurrentUser,
) -> ExecutiveDashboard:
    """Сводный дашборд безопасности для руководителя организации.

    Возвращает:
    - Общий Security Score организации
    - Тренд score за последние 7 дней
    - Оценки по категориям безопасности
    - Топ-5 критических рисков
    - Количество активов
    - Распределение открытых событий по severity
    """
    now = datetime.now(timezone.utc)
    org_id = current_user.organization_id

    # ─── Получаем информацию об организации ───────────────────────────────────
    org: Organization | None = None
    if org_id:
        org_result = await db.execute(
            select(Organization).where(Organization.id == org_id)
        )
        org = org_result.scalar_one_or_none()

    # Суперпользователи без org_id — показываем пустой дашборд
    if org_id is None or org is None:
        return ExecutiveDashboard(
            generated_at=now,
            organization=OrganizationInfo(id="", name="N/A"),
            overall_score=0.0,
            score_trend=[],
            category_scores={cat: 0.0 for cat in CATEGORY_WEIGHTS},
            top_risks=[],
            asset_count=0,
            open_events_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
        )

    # ─── Количество активов ───────────────────────────────────────────────────
    asset_count_result = await db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id,
            Asset.is_active.is_(True),
        )
    )
    asset_count: int = asset_count_result.scalar_one() or 0

    # ─── Рассчитываем Security Score ──────────────────────────────────────────
    score_result = await calculate_score(org_id=org_id, db=db, asset_id=None)
    overall_score = float(score_result.total)

    # Категорийные оценки: float для JSON-ответа
    category_scores: dict[str, float] = {
        cat: float(cs.score)
        for cat, cs in score_result.categories.items()
    }

    # ─── Тренд score за 7 дней ────────────────────────────────────────────────
    score_trend = await _get_score_trend(org_id=org_id, db=db, days=7)

    # Если сегодня в тренде 0.0 (нет снимка) — подставляем актуальный score
    if score_trend and score_trend[-1].score == 0.0:
        score_trend[-1] = ScoreTrendPoint(
            date=score_trend[-1].date,
            score=overall_score,
        )

    # ─── Топ рисков ───────────────────────────────────────────────────────────
    top_risks = await _build_top_risks(org_id=org_id, db=db, limit=5)

    # ─── Количество событий по severity ───────────────────────────────────────
    open_events_by_severity = await _count_events_by_severity(org_id=org_id, db=db)

    return ExecutiveDashboard(
        generated_at=now,
        organization=OrganizationInfo(id=org.id, name=org.name),
        overall_score=overall_score,
        score_trend=score_trend,
        category_scores=category_scores,
        top_risks=top_risks,
        asset_count=asset_count,
        open_events_by_severity=open_events_by_severity,
    )


# ─── Pydantic-схемы для Industry Benchmarking ────────────────────────────────

class BenchmarkValues(BaseModel):
    avg: float
    p25: float
    p50: float
    p75: float


class CategoryBenchmarkItem(BaseModel):
    your: float
    avg: float
    delta: float


class BenchmarkComparison(BaseModel):
    industry: str
    your_score: float
    benchmark: BenchmarkValues
    percentile: int
    rank: str
    category_comparison: dict[str, CategoryBenchmarkItem]
    peer_count: int


class IndustryBenchmarkResponse(BaseModel):
    industry: str
    comparison: BenchmarkComparison
    peer_count: int


# ─── GET /dashboard/benchmark ─────────────────────────────────────────────────

@router.get(
    "/benchmark",
    response_model=IndustryBenchmarkResponse,
    summary="Industry Benchmarking — сравнение Security Score с отраслью (задача 13.F)",
)
async def get_industry_benchmark_endpoint(
    db: DBDep,
    current_user: CurrentUser,
) -> IndustryBenchmarkResponse:
    """Сравнивает Security Score организации с анонимным бенчмарком по отрасли.

    Возвращает:
    - industry: отрасль организации
    - comparison: детальное сравнение с перцентилем, rank и delta по категориям
    - peer_count: количество организаций в выборке бенчмарка
    """
    org_id = current_user.organization_id

    # Получаем организацию и её отрасль
    org: Organization | None = None
    if org_id:
        org_result = await db.execute(
            select(Organization).where(Organization.id == org_id)
        )
        org = org_result.scalar_one_or_none()

    # Суперпользователи без org_id — возвращаем пустой бенчмарк по отрасли "other"
    if org_id is None or org is None:
        industry = "other"
        org_score = 0.0
        category_scores: dict[str, float] = {}
    else:
        industry = org.industry or "other"

        # Рассчитываем актуальный score организации
        score_result = await calculate_score(org_id=org_id, db=db, asset_id=None)
        org_score = float(score_result.total)
        category_scores = {
            cat: float(cs.score)
            for cat, cs in score_result.categories.items()
        }

    # Сравниваем с бенчмарком
    comparison_data = await compare_with_benchmark(
        org_score=org_score,
        org_category_scores=category_scores,
        industry=industry,
        db=db,
    )

    # Формируем ответ
    cat_comparison = {
        cat: CategoryBenchmarkItem(**vals)
        for cat, vals in comparison_data["category_comparison"].items()
    }
    peer_count: int = comparison_data.get("peer_count", 0)

    return IndustryBenchmarkResponse(
        industry=comparison_data["industry"],
        comparison=BenchmarkComparison(
            industry=comparison_data["industry"],
            your_score=comparison_data["your_score"],
            benchmark=BenchmarkValues(**comparison_data["benchmark"]),
            percentile=comparison_data["percentile"],
            rank=comparison_data["rank"],
            category_comparison=cat_comparison,
            peer_count=peer_count,
        ),
        peer_count=peer_count,
    )
