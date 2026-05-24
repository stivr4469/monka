import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select, func

from app.api.deps import CurrentUser, DBDep
from app.core.config import PLAN_DOMAIN_LIMITS
from app.models.asset import Asset
from app.models.event import Event
from app.models.organization import Organization
from app.scanner import run_subfinder
from app.schemas.asset import AssetCreate, AssetRead, AssetUpdate
from app.services.report_generator import (
    generate_executive_report,
    generate_technical_report,
)

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

    # Проверка лимита доменов по тарифному плану (задача 8.I)
    org = await db.get(Organization, current_user.organization_id)
    if org is None:
        raise HTTPException(status_code=400, detail="Организация не найдена")

    plan: str = getattr(org, "plan", "starter") or "starter"
    limit: int = PLAN_DOMAIN_LIMITS.get(plan, PLAN_DOMAIN_LIMITS["starter"])

    count_result = await db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == current_user.organization_id
        )
    )
    current_count: int = count_result.scalar_one()

    if current_count >= limit:
        raise HTTPException(
            status_code=402,  # Payment Required
            detail=(
                f"Лимит доменов для плана '{plan}': {limit}. "
                "Обновите тарифный план для добавления новых доменов."
            ),
        )

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

class RiskEventItem(BaseModel):
    """Детализация одного события, учтённого в формуле риска."""
    event_id: str
    severity: str
    detected_at: datetime
    delta_days: float        # дней с момента обнаружения
    weight: float            # W(severity)
    decay: float             # T(delta_days) = exp(-0.003 * delta_days)
    contribution: float      # W × T × A


class RiskScoreResponse(BaseModel):
    """Ответ эндпоинта risk-score (формула затухания 8.B)."""
    asset_id: str
    domain: str
    score: int               # 0–100, S = max(0, 100 - Σ вкладов)
    level: str               # critical | high | medium | low
    importance: float        # A(importance) актива
    total_penalty: float     # Σ W(sev) × T(t) × A — сумма штрафов до зажима
    event_count: int         # количество событий, попавших в формулу


# Веса severity (BRD new_vision.md, λ=0.003)
# critical=25: RCE, SQLi, живой session cookie
# high=15: утекший пароль от внутренней системы (stealer/breach)
# high_infra=12: открытый порт БД / панель администрирования → mapped to "high"
# Используем 13.5 как среднее для "high" (компромисс между credential и infra)
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 25.0,
    "high":     13.5,  # среднее: credential=15, infra=12
    "medium":    8.0,
    "low":       3.0,
    "info":      0.0,
}

# λ=0.003 → 50% затухания за 231 день (≈6 месяцев). Было 0.005 (140 дней).
_DECAY_RATE: float = 0.003


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
    summary="Risk Score актива (формула затухания 8.B)",
)
async def get_risk_score(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> RiskScoreResponse:
    """
    Вычисляет Risk Score актива по формуле с временным затуханием (задача 8.B).

    Формула:
        S = max(0, 100 - Σ W(sev_i) × T(t_i) × A(importance))

    Где:
        W(critical)=25, W(high)=13.5, W(medium)=8, W(low)=3, W(info)=0
        T(t) = exp(-0.003 * delta_days)  — 50% затухания за 231 день (6 месяцев)
        A    = asset.importance (0.1–2.0, по умолчанию 1.0)

    Уровни итогового score:
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

    # Коэффициент важности — graceful fallback на 1.0 если поле отсутствует
    importance: float = getattr(asset, "importance", None) or 1.0

    # Загружаем все события актива (без ограничения по окну — затухание само гасит старые)
    events_result = await db.execute(
        select(Event.id, Event.severity, Event.detected_at)
        .where(
            Event.asset_id == asset_id,
            Event.severity.in_(list(_SEVERITY_WEIGHTS.keys())),
        )
    )
    events = events_result.all()

    now = datetime.now(timezone.utc)
    total_penalty: float = 0.0

    for ev in events:
        weight = _SEVERITY_WEIGHTS.get(ev.severity, 0.0)
        if weight == 0.0:
            # Уровень info не вносит вклада — пропускаем
            continue

        # Убеждаемся, что detected_at timezone-aware для корректного вычитания
        detected = ev.detected_at
        if detected.tzinfo is None:
            detected = detected.replace(tzinfo=timezone.utc)

        delta_days: float = max(0.0, (now - detected).total_seconds() / 86400.0)

        # Экспоненциальное затухание: свежее событие даёт полный вес
        decay: float = math.exp(-_DECAY_RATE * delta_days)

        total_penalty += weight * decay * importance

    # Итоговый score: 100 минус сумма штрафов, зажатый в [0, 100]
    raw_score: float = 100.0 - total_penalty
    total_score: int = max(0, min(100, round(raw_score)))

    return RiskScoreResponse(
        asset_id=asset_id,
        domain=asset.domain,
        score=total_score,
        level=_severity_to_level(total_score),
        importance=importance,
        total_penalty=round(total_penalty, 4),
        event_count=len(events),
    )


# ─── Эндпоинты PDF-отчётов (задача 8.E) ──────────────────────────────────────

async def _load_asset_and_events(
    asset_id: str,
    db: "DBDep",  # type: ignore[name-defined]
    current_user: "CurrentUser",  # type: ignore[name-defined]
) -> tuple[Asset, list[dict]]:
    """
    Общая вспомогательная функция для обоих PDF-эндпоинтов.

    Проверяет принадлежность актива организации пользователя,
    загружает связанные события и возвращает (asset, events_as_dicts).
    """
    asset_result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()

    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    events_result = await db.execute(
        select(
            Event.id,
            Event.severity,
            Event.event_type,
            Event.source_name,
            Event.source_type,
            Event.detected_at,
        )
        .where(Event.asset_id == asset_id)
        .order_by(Event.detected_at.desc())
        .limit(500)  # защита от слишком большой выгрузки
    )
    events_rows = events_result.all()

    events_as_dicts = [
        {
            "id":           row.id,
            "severity":     row.severity,
            "event_type":   row.event_type,
            "source_name":  row.source_name,
            "source_type":  row.source_type,
            "detected_at":  row.detected_at,
        }
        for row in events_rows
    ]

    return asset, events_as_dicts


async def _compute_risk_score_for_asset(
    asset: Asset,
    events_dicts: list[dict],
) -> int:
    """Повторяет формулу risk-score без обращения к БД (используем уже загруженные события)."""
    importance: float = getattr(asset, "importance", None) or 1.0
    now = datetime.now(timezone.utc)
    total_penalty: float = 0.0

    for ev in events_dicts:
        weight = _SEVERITY_WEIGHTS.get(str(ev.get("severity", "info")).lower(), 0.0)
        if weight == 0.0:
            continue
        detected = ev.get("detected_at")
        if detected is None:
            continue
        if isinstance(detected, str):
            try:
                detected = datetime.fromisoformat(detected.replace("Z", "+00:00"))
            except ValueError:
                continue
        if detected.tzinfo is None:
            detected = detected.replace(tzinfo=timezone.utc)

        delta_days = max(0.0, (now - detected).total_seconds() / 86400.0)
        decay = math.exp(-_DECAY_RATE * delta_days)
        total_penalty += weight * decay * importance

    return max(0, min(100, round(100.0 - total_penalty)))


@router.get(
    "/{asset_id}/report.pdf",
    summary="Технический PDF-отчёт по безопасности (задача 8.E)",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "PDF-отчёт для инженеров ИБ",
        },
        404: {"description": "Актив не найден"},
    },
)
async def download_technical_report(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> Response:
    """
    Генерирует технический PDF-отчёт по безопасности для актива.

    Отчёт содержит:
    - Risk Score с цветовой индикацией уровня.
    - Таблицу топ-10 событий: severity / event_type / detected_at / source.
    - Разбивку по категориям severity.

    Доступен только пользователям организации-владельца актива.
    """
    asset, events = await _load_asset_and_events(asset_id, db, current_user)
    risk_score = await _compute_risk_score_for_asset(asset, events)

    # Получаем название организации для отчёта
    org_result = await db.execute(
        select(Organization).where(Organization.id == asset.organization_id)
    )
    org = org_result.scalar_one_or_none()
    org_name = org.name if org else "Unknown"

    pdf_bytes = generate_technical_report(
        org_name=org_name,
        domain=asset.domain,
        risk_score=risk_score,
        events=events,
    )

    safe_domain = asset.domain.replace("/", "_").replace("\\", "_")
    filename = f"{safe_domain}_security_report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/{asset_id}/executive-report.pdf",
    summary="Executive PDF-отчёт по безопасности (задача 8.E)",
    response_class=Response,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Executive PDF-отчёт для руководства",
        },
        404: {"description": "Актив не найден"},
    },
)
async def download_executive_report(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> Response:
    """
    Генерирует Executive PDF-отчёт по безопасности для актива.

    Отчёт содержит:
    - Краткое резюме состояния безопасности без технического жаргона.
    - Risk Score с интерпретацией для руководства.
    - Топ-3 ключевых риска, описанных понятным языком.
    - Рекомендации для принятия управленческих решений.

    Доступен только пользователям организации-владельца актива.
    """
    asset, events = await _load_asset_and_events(asset_id, db, current_user)
    risk_score = await _compute_risk_score_for_asset(asset, events)

    org_result = await db.execute(
        select(Organization).where(Organization.id == asset.organization_id)
    )
    org = org_result.scalar_one_or_none()
    org_name = org.name if org else "Unknown"

    pdf_bytes = generate_executive_report(
        org_name=org_name,
        domain=asset.domain,
        risk_score=risk_score,
        events=events,
    )

    safe_domain = asset.domain.replace("/", "_").replace("\\", "_")
    filename = f"{safe_domain}_executive_report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
