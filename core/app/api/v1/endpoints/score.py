"""Эндпоинты Security Score Engine (задача 11.B).

Маршруты:
    GET /api/v1/assets/{asset_id}/score           — score актива (расчёт + сохранение snapshot)
    GET /api/v1/organizations/{org_id}/score      — агрегированный score организации
    GET /api/v1/assets/{asset_id}/score/history   — история snapshots актива
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.organization import Organization
from app.models.score_snapshot import ScoreSnapshot
from app.services.score_engine import ScoreResult, calculate_score

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
