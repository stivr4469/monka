"""Event Pipeline Latency Monitoring — измерение времени от ingestion до алерта.

Маршруты:
    GET  /api/v1/metrics/pipeline-latency          — метрики латентности за 24 ч (JWT/API-ключ)
    PATCH /api/v1/internal/events/{event_id}/mark-alerted — установить alert_sent_at (internal secret)
"""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, DBDep, verify_internal_secret
from app.models.event import Event
from app.models.asset import Asset

logger = logging.getLogger(__name__)

# ─── Роутер публичных метрик (JWT / API-ключ) ─────────────────────────────────
router = APIRouter(tags=["pipeline_metrics"])

# ─── Роутер internal (protected by shared secret) ─────────────────────────────
internal_router = APIRouter(
    prefix="/internal",
    tags=["internal"],
    dependencies=[Depends(verify_internal_secret)],
)

# Порог медленного пайплайна по умолчанию (секунды)
_DEFAULT_SLOW_THRESHOLD_SEC = 300
# Окно анализа по умолчанию (часы)
_DEFAULT_WINDOW_HOURS = 24


# ─── Схемы ответа ─────────────────────────────────────────────────────────────

class PipelineLatencyResponse(BaseModel):
    """Метрики латентности event-pipeline за указанное окно."""
    p50_seconds: float | None
    p95_seconds: float | None
    p99_seconds: float | None
    avg_seconds: float | None
    slow_events_count: int
    slow_threshold_seconds: int
    window_hours: int
    sample_size: int


class MarkAlertedResponse(BaseModel):
    """Ответ на запрос установки alert_sent_at."""
    event_id: str
    alert_sent_at: str


# ─── Вспомогательные функции ──────────────────────────────────────────────────

def _percentile(values: list[float], p: float) -> float | None:
    """Вычисляет p-й перцентиль (0–100) из отсортированного списка."""
    if not values:
        return None
    k = (len(values) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    frac = k - lo
    return values[lo] + frac * (values[hi] - values[lo])


# ─── Публичный endpoint: GET /api/v1/metrics/pipeline-latency ─────────────────

@router.get(
    "/metrics/pipeline-latency",
    response_model=PipelineLatencyResponse,
    summary="Метрики латентности event-pipeline",
    description=(
        "Возвращает p50/p95/p99/avg латентности (ingested_at → alert_sent_at) "
        "за последние N часов для организации текущего пользователя."
    ),
)
async def get_pipeline_latency(
    current_user: CurrentUser,
    db: DBDep,
    window_hours: int = Query(default=_DEFAULT_WINDOW_HOURS, ge=1, le=168, description="Окно анализа в часах (1–168)"),
    slow_threshold_seconds: int = Query(default=_DEFAULT_SLOW_THRESHOLD_SEC, ge=1, description="Порог медленного события (секунды)"),
) -> PipelineLatencyResponse:
    """
    Вычисляет статистику латентности pipeline для организации пользователя.

    SQL: выбирает EPOCH(alert_sent_at - ingested_at) из событий с привязанным активом
    организации за указанное окно. Перцентили считаются в Python.
    """
    # Получаем org_id через asset JOIN — пользователь видит только свою организацию
    org_id = current_user.organization_id

    sql = text(
        """
        SELECT EXTRACT(EPOCH FROM (e.alert_sent_at - e.ingested_at)) AS latency_sec
        FROM events e
        JOIN assets a ON a.id = e.asset_id
        WHERE e.ingested_at > NOW() - CAST(:window AS INTERVAL)
          AND e.alert_sent_at IS NOT NULL
          AND e.ingested_at IS NOT NULL
          AND a.organization_id = :org_id
        ORDER BY latency_sec
        """
    )

    result = await db.execute(
        sql,
        {
            "window": f"{window_hours} hours",
            "org_id": org_id,
        },
    )
    rows = result.fetchall()

    latencies: list[float] = [float(row[0]) for row in rows if row[0] is not None]

    slow_count = sum(1 for v in latencies if v > slow_threshold_seconds)
    avg = sum(latencies) / len(latencies) if latencies else None

    return PipelineLatencyResponse(
        p50_seconds=_percentile(latencies, 50),
        p95_seconds=_percentile(latencies, 95),
        p99_seconds=_percentile(latencies, 99),
        avg_seconds=round(avg, 3) if avg is not None else None,
        slow_events_count=slow_count,
        slow_threshold_seconds=slow_threshold_seconds,
        window_hours=window_hours,
        sample_size=len(latencies),
    )


# ─── Internal endpoint: PATCH /api/v1/internal/events/{event_id}/mark-alerted ─

@internal_router.patch(
    "/events/{event_id}/mark-alerted",
    response_model=MarkAlertedResponse,
    summary="Установить alert_sent_at для события",
    description="Устанавливает alert_sent_at = now() для фиксации времени отправки алерта. Защищён internal secret.",
)
async def mark_event_alerted(
    event_id: str,
    db: DBDep,
) -> MarkAlertedResponse:
    """
    Устанавливает alert_sent_at = now() для события.
    Вызывается из workers/tasks/telegram_alerts.py после успешной отправки алерта.
    Идемпотентен — повторный вызов обновляет timestamp.
    """
    # Проверяем что событие существует
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Событие {event_id} не найдено",
        )

    now_utc = datetime.now(timezone.utc)

    await db.execute(
        update(Event)
        .where(Event.id == event_id)
        .values(alert_sent_at=now_utc)
    )
    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error("Ошибка установки alert_sent_at для event_id=%s: %s", event_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ошибка обновления события",
        ) from exc

    logger.info("alert_sent_at установлен: event_id=%s ts=%s", event_id, now_utc.isoformat())

    return MarkAlertedResponse(
        event_id=event_id,
        alert_sent_at=now_utc.isoformat(),
    )
