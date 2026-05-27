"""Анализ трендов security score по историческим снимкам (Asset Intelligence Trends)."""
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.score_snapshot import ScoreSnapshot


class TrendDirection:
    """Направление тренда security score."""
    IMPROVING = "improving"   # score растёт (меньше рисков)
    DEGRADING  = "degrading"  # score падает (больше рисков)
    STABLE     = "stable"     # изменение < 5 баллов


# Порог изменения (в баллах) для определения тренда
_TREND_THRESHOLD: float = 5.0


@dataclass
class ScoreTrend:
    """Результат анализа тренда security score актива."""
    direction: str              # TrendDirection значение
    delta_7d: float | None      # изменение за 7 дней (positive = улучшение)
    delta_30d: float | None     # изменение за 30 дней
    current_score: float        # текущий score (последний snapshot)
    score_7d_ago: float | None  # score 7 дней назад (ближайший снимок)
    score_30d_ago: float | None # score 30 дней назад (ближайший снимок)
    snapshots_count: int        # количество снимков в окне анализа
    velocity: float | None      # баллов в день (+ улучшение, − деградация)


def _find_closest_snapshot(
    snapshots: list,
    target_dt: datetime,
    tolerance_hours: int = 36,
) -> "ScoreSnapshot | None":
    """Находит снимок, ближайший к целевой дате, в пределах tolerance_hours.

    snapshots — список ScoreSnapshot, отсортированных по calculated_at DESC.
    Возвращает None, если ни один снимок не попадает в допуск.
    """
    best: "ScoreSnapshot | None" = None
    best_delta: float = float("inf")

    for snap in snapshots:
        snap_dt = snap.calculated_at
        if snap_dt.tzinfo is None:
            snap_dt = snap_dt.replace(tzinfo=timezone.utc)
        delta_sec = abs((snap_dt - target_dt).total_seconds())
        delta_hours = delta_sec / 3600.0
        if delta_hours <= tolerance_hours and delta_sec < best_delta:
            best = snap
            best_delta = delta_sec

    return best


def _compute_direction(delta: float | None) -> str:
    """Определяет направление тренда по значению delta."""
    if delta is None:
        return TrendDirection.STABLE
    if delta > _TREND_THRESHOLD:
        return TrendDirection.IMPROVING
    if delta < -_TREND_THRESHOLD:
        return TrendDirection.DEGRADING
    return TrendDirection.STABLE


async def compute_score_trend(
    asset_id: str,
    db: AsyncSession,
    window_days: int = 30,
) -> ScoreTrend:
    """Вычисляет тренд security score по историческим снимкам актива.

    Читает ScoreSnapshot записи за последние window_days дней.
    Если снимков меньше 2 — direction=stable, delta=None.

    Args:
        asset_id:    идентификатор актива (str UUID).
        db:          асинхронная сессия SQLAlchemy.
        window_days: глубина окна анализа в днях (по умолчанию 30).

    Returns:
        ScoreTrend с направлением, дельтами и скоростью изменения.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=window_days)

    # Загружаем все снимки актива за окно анализа, от свежего к старому
    result = await db.execute(
        select(ScoreSnapshot)
        .where(
            ScoreSnapshot.asset_id == asset_id,
            ScoreSnapshot.calculated_at >= since,
        )
        .order_by(ScoreSnapshot.calculated_at.desc())
        .limit(500)
    )
    snapshots = list(result.scalars().all())

    snapshots_count = len(snapshots)

    # Меньше 2 снимков — данных для тренда недостаточно
    if snapshots_count < 2:
        # Берём current_score из единственного снимка, если он есть
        current_score = float(snapshots[0].total_score) if snapshots else 0.0
        return ScoreTrend(
            direction=TrendDirection.STABLE,
            delta_7d=None,
            delta_30d=None,
            current_score=current_score,
            score_7d_ago=None,
            score_30d_ago=None,
            snapshots_count=snapshots_count,
            velocity=None,
        )

    # Текущий score — самый свежий снимок
    current_score = float(snapshots[0].total_score)

    # Целевые точки во времени
    target_7d  = now - timedelta(days=7)
    target_30d = now - timedelta(days=window_days)

    # Ищем ближайшие снимки к целевым датам
    snap_7d  = _find_closest_snapshot(snapshots, target_7d,  tolerance_hours=36)
    snap_30d = _find_closest_snapshot(snapshots, target_30d, tolerance_hours=48)

    score_7d_ago  = float(snap_7d.total_score)  if snap_7d  else None
    score_30d_ago = float(snap_30d.total_score) if snap_30d else None

    # delta = current - прошлое значение
    # Положительная delta → score вырос → улучшение безопасности
    delta_7d  = (current_score - score_7d_ago)  if score_7d_ago  is not None else None
    delta_30d = (current_score - score_30d_ago) if score_30d_ago is not None else None

    # Направление тренда определяем по 7-дневной дельте (более актуальна)
    direction = _compute_direction(delta_7d)

    # Скорость изменения: баллов в день за 30-дневное окно
    velocity: float | None = None
    if delta_30d is not None:
        velocity = round(delta_30d / window_days, 4)

    return ScoreTrend(
        direction=direction,
        delta_7d=round(delta_7d, 2)   if delta_7d  is not None else None,
        delta_30d=round(delta_30d, 2) if delta_30d is not None else None,
        current_score=current_score,
        score_7d_ago=score_7d_ago,
        score_30d_ago=score_30d_ago,
        snapshots_count=snapshots_count,
        velocity=velocity,
    )
