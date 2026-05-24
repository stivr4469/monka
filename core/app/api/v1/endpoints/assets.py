from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, func

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event
from app.scanner import run_subfinder
from app.schemas.asset import AssetCreate, AssetRead, AssetUpdate

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/", response_model=list[AssetRead])
async def list_assets(db: DBDep, current_user: CurrentUser) -> list[Asset]:
    if current_user.organization_id is None:
        return []
    result = await db.execute(
        select(Asset).where(Asset.organization_id == current_user.organization_id)
    )
    return list(result.scalars().all())


@router.post("/", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
async def create_asset(
    body: AssetCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    db: DBDep,
    current_user: CurrentUser,
) -> Asset:
    if current_user.organization_id is None:
        raise HTTPException(status_code=400, detail="Пользователь не привязан к организации")

    asset = Asset(
        domain=body.domain,
        description=body.description,
        organization_id=current_user.organization_id,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    # Определяем порт для формирования ingest URL внутри воркера
    port = request.url.port or 8000

    # Правильное использование BackgroundTasks: передаём синхронную функцию напрямую.
    # BackgroundTasks вызывает её в отдельном потоке через anyio.to_thread.run_sync.
    # _executor.submit НЕ передаётся как первый аргумент — это было бы передачей
    # метода submit как callable, что возвращало бы Future без реального выполнения.
    background_tasks.add_task(run_subfinder, body.domain, port)

    return asset


@router.get("/{asset_id}", response_model=AssetRead)
async def get_asset(asset_id: str, db: DBDep, current_user: CurrentUser) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")
    return asset


@router.patch("/{asset_id}", response_model=AssetRead)
async def update_asset(
    asset_id: str, body: AssetUpdate, db: DBDep, current_user: CurrentUser
) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(asset, field, value)

    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: str, db: DBDep, current_user: CurrentUser) -> None:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    await db.delete(asset)
    await db.commit()


# ─── Схема Risk Score ─────────────────────────────────────────────────────────

class RiskBreakdown(BaseModel):
    """Детализация вклада каждого уровня severity в итоговый score."""
    critical_events: int
    high_events: int
    medium_events: int
    critical_score: int
    high_score: int
    medium_score: int


class RiskScoreResponse(BaseModel):
    """Ответ эндпоинта risk-score."""
    asset_id: str
    domain: str
    score: int               # 0–100
    level: str               # critical | high | medium | low
    breakdown: RiskBreakdown
    window_days: int         # за сколько дней считался score (всегда 30)


# Константы начисления очков риска
_CRITICAL_POINTS: int = 25   # max 4 события × 25 = 100
_CRITICAL_MAX: int = 4
_HIGH_POINTS: int = 10        # max 3 события × 10 = 30
_HIGH_MAX: int = 3
_MEDIUM_POINTS: int = 5       # max 2 события × 5 = 10
_MEDIUM_MAX: int = 2

_WINDOW_DAYS: int = 30


def _severity_to_level(score: int) -> str:
    """Переводит числовой score в текстовый уровень риска."""
    if score >= 75:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    return "low"


@router.get(
    "/{asset_id}/risk-score",
    response_model=RiskScoreResponse,
    summary="Risk Score актива за 30 дней",
)
async def get_risk_score(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> RiskScoreResponse:
    """
    Вычисляет Risk Score актива на основе событий за последние 30 дней.

    Формула:
      critical: +25 очков за событие, максимум 4 (≤ 100 от critical)
      high:     +10 очков за событие, максимум 3 (≤ 30 от high)
      medium:   +5  очков за событие, максимум 2 (≤ 10 от medium)
    Итоговый score зажат в [0, 100].

    Уровни:
      75–100 → critical
      40–74  → high
      15–39  → medium
      0–14   → low
    """
    # Проверяем принадлежность актива организации пользователя
    asset_result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()

    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    # Окно: последние 30 дней
    since = datetime.now(timezone.utc) - timedelta(days=_WINDOW_DAYS)

    # Считаем события по каждому уровню severity одним запросом
    counts_result = await db.execute(
        select(Event.severity, func.count().label("cnt"))
        .where(
            Event.asset_id == asset_id,
            Event.detected_at >= since,
            Event.severity.in_(["critical", "high", "medium"]),
        )
        .group_by(Event.severity)
    )
    counts: dict[str, int] = {row.severity: row.cnt for row in counts_result.all()}

    critical_cnt = counts.get("critical", 0)
    high_cnt = counts.get("high", 0)
    medium_cnt = counts.get("medium", 0)

    # Начисляем очки с учётом максимумов на каждый уровень
    critical_score = min(critical_cnt, _CRITICAL_MAX) * _CRITICAL_POINTS
    high_score = min(high_cnt, _HIGH_MAX) * _HIGH_POINTS
    medium_score = min(medium_cnt, _MEDIUM_MAX) * _MEDIUM_POINTS

    total_score = min(critical_score + high_score + medium_score, 100)

    return RiskScoreResponse(
        asset_id=asset_id,
        domain=asset.domain,
        score=total_score,
        level=_severity_to_level(total_score),
        breakdown=RiskBreakdown(
            critical_events=critical_cnt,
            high_events=high_cnt,
            medium_events=medium_cnt,
            critical_score=critical_score,
            high_score=high_score,
            medium_score=medium_score,
        ),
        window_days=_WINDOW_DAYS,
    )
