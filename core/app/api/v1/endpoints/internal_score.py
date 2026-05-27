"""Внутренние эндпоинты для воркера score_snapshot_worker.

Доступ только по INTERNAL_API_SECRET (shared secret воркеров).

Маршруты:
    POST /api/v1/internal/score-snapshot   — сохранить снимок score актива
    GET  /api/v1/internal/assets-list      — список активных активов (для воркера)
"""
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DBDep, verify_internal_secret
from app.models.asset import Asset
from app.models.score_snapshot import ScoreSnapshot
from app.services.score_engine import _score_to_grade

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/internal",
    tags=["internal"],
    dependencies=[Depends(verify_internal_secret)],
)


# ─── Схемы ────────────────────────────────────────────────────────────────────

class ScoreSnapshotIn(BaseModel):
    """Тело запроса для сохранения снимка security score."""
    asset_id: str = Field(..., description="UUID актива")
    score: float = Field(..., ge=0, le=100, description="Итоговый score 0–100")
    grade: str | None = Field(
        default=None,
        description="Буква-оценка A|B|C|D|F. Если не указана — вычисляется автоматически",
    )
    org_id: str | None = Field(
        default=None,
        description="UUID организации. Если не указан — берётся из актива",
    )
    category_scores: dict[str, Any] = Field(
        default_factory=dict,
        description="Детализация по категориям: {category: {score, penalty, event_count}}",
    )


class ScoreSnapshotOut(BaseModel):
    """Ответ после успешного сохранения снимка."""
    snapshot_id: str
    asset_id: str
    org_id: str
    total_score: int
    grade: str


class AssetListItem(BaseModel):
    """Элемент списка активов для воркера."""
    id: str
    domain: str
    org_id: str
    is_active: bool


# ─── POST /internal/score-snapshot ────────────────────────────────────────────

@router.post(
    "/score-snapshot",
    response_model=ScoreSnapshotOut,
    status_code=status.HTTP_201_CREATED,
    summary="Сохранить снимок Security Score (для воркера)",
)
async def create_score_snapshot(
    body: ScoreSnapshotIn,
    db: DBDep,
) -> ScoreSnapshotOut:
    """Сохраняет ScoreSnapshot в БД.

    Используется воркером score_snapshot_worker для ежедневной записи
    исторических снимков, необходимых для вычисления трендов.

    Аутентификация: Bearer INTERNAL_API_SECRET.
    """
    # Проверяем существование актива и получаем org_id
    asset_result = await db.execute(
        select(Asset).where(Asset.id == body.asset_id)
    )
    asset = asset_result.scalar_one_or_none()

    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Актив {body.asset_id} не найден",
        )

    # org_id: из тела запроса или из актива
    org_id = body.org_id or asset.organization_id
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Не удалось определить org_id актива",
        )

    # Вычисляем grade если не передан
    total_score = max(0, min(100, int(round(body.score))))
    grade = body.grade or _score_to_grade(total_score)

    # Формируем categories_json: если category_scores пустой — пустой dict
    categories_json = body.category_scores or {}

    snapshot = ScoreSnapshot(
        org_id=org_id,
        asset_id=body.asset_id,
        total_score=total_score,
        grade=grade,
        categories_json=categories_json,
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)

    logger.debug(
        "Snapshot создан: id=%s asset_id=%s score=%d grade=%s",
        snapshot.id, body.asset_id, total_score, grade,
    )

    return ScoreSnapshotOut(
        snapshot_id=snapshot.id,
        asset_id=body.asset_id,
        org_id=org_id,
        total_score=total_score,
        grade=grade,
    )


# ─── GET /internal/assets-list ────────────────────────────────────────────────

@router.get(
    "/assets-list",
    response_model=list[AssetListItem],
    summary="Список активных активов (для воркера score_snapshot_worker)",
)
async def get_assets_list(db: DBDep) -> list[AssetListItem]:
    """Возвращает список всех активных активов всех организаций.

    Используется воркером score_snapshot_worker для ежедневного обхода
    активов и снятия снимков security score.

    Аутентификация: Bearer INTERNAL_API_SECRET.
    """
    result = await db.execute(
        select(Asset)
        .where(Asset.is_active.is_(True))
        .order_by(Asset.organization_id, Asset.created_at)
    )
    assets = list(result.scalars().all())

    logger.debug("Internal assets-list: вернули %d активов", len(assets))

    return [
        AssetListItem(
            id=a.id,
            domain=a.domain,
            org_id=a.organization_id or "",
            is_active=a.is_active,
        )
        for a in assets
    ]
