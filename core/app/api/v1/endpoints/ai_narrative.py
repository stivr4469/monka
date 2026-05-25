"""
AI Risk Narrative endpoint — генерация executive summary через Claude API (фаза 13.G).

Маршруты:
    POST /api/v1/ai/narrative — генерирует human-readable risk summary для актива
"""
import logging
import os
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.event import Event
from app.services.score_engine import calculate_score

# Добавляем путь к workers чтобы импортировать ai_narrative task
_workers_path = str(Path(__file__).parents[6] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)

from tasks.ai_narrative import _MODEL, _ANTHROPIC_AVAILABLE, generate_risk_narrative  # noqa: E402

logger = logging.getLogger(__name__)

router = APIRouter(tags=["ai"])


class NarrativeRequest(BaseModel):
    """Запрос на генерацию AI risk narrative."""
    asset_id: str = Field(..., description="UUID актива")
    days: int = Field(default=7, ge=1, le=365, description="Период в днях для анализа событий")


class NarrativeResponse(BaseModel):
    """Ответ с AI risk narrative."""
    narrative: str = Field(..., description="Executive summary в формате Markdown")
    model: str = Field(..., description="Модель Claude использованная для генерации")
    cached: bool = Field(..., description="True если использовался prompt cache")


@router.post(
    "/narrative",
    response_model=NarrativeResponse,
    summary="AI Risk Narrative — executive summary рисков (фаза 13.G)",
)
async def generate_narrative(
    body: NarrativeRequest,
    db: DBDep,
    current_user: CurrentUser,
) -> NarrativeResponse:
    """
    Генерирует human-readable executive summary рисков для актива через Claude API.

    Использует prompt caching для экономии токенов на системном промпте.
    При отсутствии ANTHROPIC_API_KEY возвращает статичный шаблонный отчёт.
    """
    # Проверяем принадлежность актива организации пользователя
    asset_result = await db.execute(select(Asset).where(Asset.id == body.asset_id))
    asset = asset_result.scalar_one_or_none()

    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    # Рассчитываем Security Score для актива
    score_result = await calculate_score(
        org_id=current_user.organization_id,
        db=db,
        asset_id=body.asset_id,
    )

    # Формируем category_scores как dict[str, float]
    category_scores: dict[str, float] = {
        cat: float(cs.score)
        for cat, cs in score_result.categories.items()
    }

    # Загружаем топ-риски из БД (неустранённые события, отсортированные по severity)
    from datetime import datetime, timedelta, timezone
    since = datetime.now(timezone.utc) - timedelta(days=body.days)

    events_result = await db.execute(
        select(
            Event.event_type,
            Event.severity,
            Event.target_domain,
            Event.detected_at,
        )
        .where(
            Event.asset_id == body.asset_id,
            Event.resolved_at.is_(None),
            Event.detected_at >= since,
        )
        .order_by(Event.detected_at.desc())
        .limit(20)
    )
    events = events_result.all()

    # Составляем top_risks для нарратива
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top_risks = sorted(
        [
            {
                "event_type": row.event_type,
                "severity": row.severity,
                "description": f"detected on {row.target_domain}",
            }
            for row in events
        ],
        key=lambda r: _SEVERITY_ORDER.get(r["severity"].lower(), 5),
    )[:5]

    # Генерируем нарратив
    narrative_text = generate_risk_narrative(
        domain=asset.domain,
        score=float(score_result.total),
        category_scores=category_scores,
        top_risks=top_risks,
        org_name=current_user.organization_id,
    )

    # Определяем использованную модель: если API ключ есть и SDK доступен — Claude,
    # иначе — статичный шаблон (без обращения к API)
    api_key_present = bool(os.environ.get("ANTHROPIC_API_KEY", ""))
    used_model = _MODEL if (_ANTHROPIC_AVAILABLE and api_key_present) else "static-template"

    return NarrativeResponse(
        narrative=narrative_text,
        model=used_model,
        cached=_ANTHROPIC_AVAILABLE and api_key_present,
    )
