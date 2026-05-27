"""Эндпоинты Security Score Engine (задача 11.B).

Маршруты:
    GET /api/v1/assets/{asset_id}/score           — score актива (расчёт + сохранение snapshot)
    GET /api/v1/organizations/{org_id}/score      — агрегированный score организации
    GET /api/v1/assets/{asset_id}/score/history   — история snapshots актива
    GET /api/v1/assets/{asset_id}/score/trend     — тренд score (Asset Intelligence Trends)
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.organization import Organization
from app.models.score_snapshot import ScoreSnapshot
from app.services.score_engine import ScoreResult, calculate_score
from app.services.score_trends import TrendDirection, compute_score_trend

router = APIRouter(tags=["score"])


# ─── Вспомогательные функции ──────────────────────────────────────────────────

async def _save_snapshot(
    result: ScoreResult,
    db: DBDep,
) -> None:
    """Сохраняет ScoreResult как ScoreSnapshot в БД."""
    snapshot = ScoreSnapshot(
        org_id=result.org_id,
        asset_id=result.asset_id,
        total_score=result.total,
        grade=result.grade,
        categories_json={
            cat: {
                "score": cs.score,
                "penalty": cs.penalty,
                "event_count": cs.event_count,
            }
            for cat, cs in result.categories.items()
        },
        calculated_at=result.calculated_at,
    )
    db.add(snapshot)
    await db.commit()


# ─── GET /assets/{asset_id}/score ─────────────────────────────────────────────

@router.get(
    "/assets/{asset_id}/score",
    response_model=ScoreResult,
    summary="Security Score актива (задача 11.A)",
)
async def get_asset_score(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> ScoreResult:
    """Рассчитывает Security Score Engine для конкретного актива.

    Сохраняет snapshot в БД для последующего отображения истории.
    Доступен только пользователям организации-владельца актива.
    """
    # Проверяем принадлежность актива организации пользователя
    asset_result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()

    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    result = await calculate_score(
        org_id=current_user.organization_id,
        db=db,
        asset_id=asset_id,
    )

    # Сохраняем snapshot — не блокируем ответ при ошибке записи
    try:
        await _save_snapshot(result, db)
    except Exception:
        # Если snapshot не сохранился — всё равно возвращаем результат
        pass

    return result


# ─── GET /organizations/{org_id}/score ────────────────────────────────────────

@router.get(
    "/organizations/{org_id}/score",
    response_model=ScoreResult,
    summary="Агрегированный Security Score организации (задача 11.A)",
)
async def get_org_score(
    org_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> ScoreResult:
    """Рассчитывает агрегированный Security Score для всех активов организации.

    Доступен только пользователям той же организации или суперпользователям.
    Сохраняет snapshot (asset_id=NULL) для истории изменений org-level score.
    """
    # Проверяем права доступа: пользователь должен принадлежать этой org
    # или быть суперпользователем
    if current_user.organization_id != org_id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Нет доступа к этой организации")

    # Проверяем существование организации
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    if org_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Организация не найдена")

    result = await calculate_score(
        org_id=org_id,
        db=db,
        asset_id=None,
    )

    # Сохраняем org-level snapshot
    try:
        await _save_snapshot(result, db)
    except Exception:
        pass

    return result


# ─── GET /assets/{asset_id}/score/history ─────────────────────────────────────

class ScoreSnapshotRead(ScoreResult):
    """Расширенная схема с id снимка — для истории."""
    snapshot_id: str


@router.get(
    "/assets/{asset_id}/score/history",
    response_model=list[ScoreSnapshotRead],
    summary="История Security Score актива (задача 11.B)",
)
async def get_asset_score_history(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
    days: int = Query(default=30, ge=1, le=365, description="Глубина истории в днях"),
) -> list[ScoreSnapshotRead]:
    """Возвращает список сохранённых ScoreSnapshot для актива за последние N дней.

    Результаты отсортированы по убыванию даты (самый свежий первым).
    Максимум 365 дней истории.
    """
    # Проверяем принадлежность актива
    asset_result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()

    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    since = datetime.now(timezone.utc) - timedelta(days=days)

    snapshots_result = await db.execute(
        select(ScoreSnapshot)
        .where(
            ScoreSnapshot.asset_id == asset_id,
            ScoreSnapshot.calculated_at >= since,
        )
        .order_by(ScoreSnapshot.calculated_at.desc())
        .limit(1000)
    )
    snapshots = list(snapshots_result.scalars().all())

    # Преобразуем ScoreSnapshot → ScoreSnapshotRead
    output: list[ScoreSnapshotRead] = []
    for snap in snapshots:
        # Восстанавливаем categories из JSON
        from app.services.score_engine import CategoryScore, _score_to_grade
        categories = {
            cat: CategoryScore(**data)
            for cat, data in (snap.categories_json or {}).items()
        }
        output.append(ScoreSnapshotRead(
            snapshot_id=snap.id,
            total=snap.total_score,
            grade=snap.grade,
            categories=categories,
            asset_id=snap.asset_id,
            org_id=snap.org_id,
            calculated_at=snap.calculated_at,
        ))

    return output


# ─── Схема тренда ─────────────────────────────────────────────────────────────

class ScoreTrendResponse(BaseModel):
    """Ответ эндпоинта тренда security score (Asset Intelligence Trends)."""
    direction: str              # improving | degrading | stable
    delta_7d: float | None      # изменение score за последние 7 дней
    delta_30d: float | None     # изменение score за последние 30 дней
    current_score: float        # текущий score (последний snapshot)
    score_7d_ago: float | None  # score 7 дней назад
    score_30d_ago: float | None # score 30 дней назад
    velocity: float | None      # скорость: баллов в день (+ улучшение, − деградация)
    snapshots_count: int        # количество снимков в окне анализа
    interpretation: str         # текстовое описание тренда для UI


def _build_interpretation(
    direction: str,
    velocity: float | None,
    delta_7d: float | None,
    current_score: float,
) -> str:
    """Формирует человекочитаемую интерпретацию тренда."""
    if velocity is None or delta_7d is None:
        return f"Недостаточно данных для анализа тренда. Текущий score: {current_score:.0f}"

    if direction == TrendDirection.IMPROVING:
        return (
            f"Score улучшается: +{abs(velocity):.1f} баллов/день за последние 30 дней "
            f"(+{delta_7d:.1f} за 7 дней). Текущий score: {current_score:.0f}"
        )
    if direction == TrendDirection.DEGRADING:
        return (
            f"Score деградирует: −{abs(velocity):.1f} баллов/день за последние 30 дней "
            f"({delta_7d:.1f} за 7 дней). Текущий score: {current_score:.0f}"
        )
    return (
        f"Score стабилен (изменение {delta_7d:+.1f} за 7 дней). "
        f"Текущий score: {current_score:.0f}"
    )


# ─── GET /assets/{asset_id}/score/trend ───────────────────────────────────────

@router.get(
    "/assets/{asset_id}/score/trend",
    response_model=ScoreTrendResponse,
    summary="Тренд Security Score актива — Asset Intelligence Trends",
)
async def get_asset_score_trend(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
    window_days: int = Query(
        default=30,
        ge=7,
        le=365,
        description="Глубина окна анализа в днях (7–365, по умолчанию 30)",
    ),
) -> ScoreTrendResponse:
    """Возвращает тренд Security Score для актива на основе исторических снимков.

    Автоматически вычисляет направление изменения score (улучшение / деградация / стабильно)
    без ручного запроса — на основе сохранённых ScoreSnapshot.

    Требует минимум 2 snapshot-а в окне анализа. При меньшем количестве
    возвращает direction=stable с delta=null.
    """
    # Проверяем принадлежность актива организации пользователя
    asset_result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()

    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    trend = await compute_score_trend(
        asset_id=asset_id,
        db=db,
        window_days=window_days,
    )

    interpretation = _build_interpretation(
        direction=trend.direction,
        velocity=trend.velocity,
        delta_7d=trend.delta_7d,
        current_score=trend.current_score,
    )

    return ScoreTrendResponse(
        direction=trend.direction,
        delta_7d=trend.delta_7d,
        delta_30d=trend.delta_30d,
        current_score=trend.current_score,
        score_7d_ago=trend.score_7d_ago,
        score_30d_ago=trend.score_30d_ago,
        velocity=trend.velocity,
        snapshots_count=trend.snapshots_count,
        interpretation=interpretation,
    )
