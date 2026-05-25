"""Security Score Engine — многокатегорийная формула оценки безопасности (задача 11.A).

Формула:
    T(t)   = exp(-0.003 × Δt_days)               — временное затухание
    штраф  = W(severity) × T(t) × asset.importance  — вклад одного события
    cat_penalty = Σ штрафов событий категории
    cat_score   = max(0, 100 - cat_penalty)
    total_score = round(Σ cat_score × weight_категории)
    grade       = A(90–100) | B(75–89) | C(60–74) | D(40–59) | F(0–39)
"""
import math
from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.event import Event

# ─── Маппинг event_type → категория ───────────────────────────────────────────
# Используем строки, а не EventType enum — event_type в БД хранится как строка
CATEGORY_EVENTS: dict[str, list[str]] = {
    "network_security": [
        "subdomain_takeover",
        "exposed_service",
        "vulnerability",
        "open_s3_bucket",
    ],
    "dns_health": [
        "domain_hardening",
    ],
    "application_security": [
        "tech_profile",
        "tls_fingerprint",
        "tls_expiry",
    ],
    "credential_exposure": [
        "stealer_log",
        "credential_leak",
        "github_secret_leak",
        "email_breach",
        "active_session_leak",
        "session_leak",
    ],
    "dark_web_presence": [
        "darknet_mention",
        "ransomware_mention",
        "paste_mention",
        "telegram_leak",
        "paste_leak",
        "forum_mention",
    ],
    "brand_safety": [
        "phishing_domain",
    ],
}

# Обратный индекс: event_type → category_name (строится один раз при загрузке модуля)
_EVENT_TO_CATEGORY: dict[str, str] = {
    event: cat
    for cat, events in CATEGORY_EVENTS.items()
    for event in events
}

# ─── Веса категорий (сумма = 1.0) ─────────────────────────────────────────────
CATEGORY_WEIGHTS: dict[str, float] = {
    "network_security":     0.20,
    "dns_health":           0.10,
    "application_security": 0.15,
    "credential_exposure":  0.25,
    "dark_web_presence":    0.20,
    "brand_safety":         0.10,
}

# ─── Штрафы по severity ───────────────────────────────────────────────────────
SEVERITY_PENALTY: dict[str, float] = {
    "critical": 25.0,
    "high":     10.0,
    "medium":    4.0,
    "low":       1.0,
    "info":      0.0,
}

# Коэффициент затухания λ: 50% за ~231 день (≈6 месяцев)
_DECAY_RATE: float = 0.003


# ─── Pydantic-схемы результата ────────────────────────────────────────────────

class CategoryScore(BaseModel):
    """Результат по одной категории безопасности."""
    score: int          # 0–100
    penalty: float      # суммарный штраф до зажима
    event_count: int    # количество учтённых событий


class ScoreResult(BaseModel):
    """Полный результат расчёта Security Score Engine."""
    total: int                              # итоговый взвешенный score 0–100
    grade: str                              # A | B | C | D | F
    categories: dict[str, CategoryScore]   # детализация по категориям
    asset_id: str | None                   # None для org-level score
    org_id: str
    calculated_at: datetime


# ─── Вспомогательные функции ──────────────────────────────────────────────────

def _time_decay(delta_days: float) -> float:
    """T(t) = exp(-λ × Δt) — затухание штрафа со временем."""
    return math.exp(-_DECAY_RATE * delta_days)


def _score_to_grade(score: int) -> str:
    """Переводит числовой score в буквенную оценку."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _compute_categories_from_events(
    events: list,
    importance: float,
    now: datetime,
) -> dict[str, CategoryScore]:
    """Рассчитывает CategoryScore по списку строк-результатов SQLAlchemy.

    events — список Row с полями: severity, event_type, detected_at
    importance — коэффициент важности актива
    now — момент расчёта (UTC)
    """
    # Накапливаем штрафы по категориям
    penalties: dict[str, float] = {cat: 0.0 for cat in CATEGORY_WEIGHTS}
    counts: dict[str, int] = {cat: 0 for cat in CATEGORY_WEIGHTS}

    for row in events:
        event_type = str(row.event_type).lower()
        severity = str(row.severity).lower()
        penalty_base = SEVERITY_PENALTY.get(severity, 0.0)

        if penalty_base == 0.0:
            # info-события не дают штрафов — пропускаем
            continue

        # Определяем категорию события
        category = _EVENT_TO_CATEGORY.get(event_type)
        if category is None:
            # Тип события не входит ни в одну категорию — пропускаем
            continue

        detected = row.detected_at
        if detected.tzinfo is None:
            detected = detected.replace(tzinfo=timezone.utc)

        delta_days = max(0.0, (now - detected).total_seconds() / 86400.0)
        decay = _time_decay(delta_days)
        event_penalty = penalty_base * decay * importance

        penalties[category] += event_penalty
        counts[category] += 1

    # Формируем CategoryScore для каждой категории
    result: dict[str, CategoryScore] = {}
    for cat in CATEGORY_WEIGHTS:
        raw_penalty = penalties[cat]
        cat_score = max(0, int(round(100.0 - raw_penalty)))
        result[cat] = CategoryScore(
            score=cat_score,
            penalty=round(raw_penalty, 4),
            event_count=counts[cat],
        )

    return result


def _aggregate_total(categories: dict[str, CategoryScore]) -> int:
    """Взвешенная сумма category_score × weight → total 0–100."""
    weighted_sum = sum(
        categories[cat].score * CATEGORY_WEIGHTS[cat]
        for cat in CATEGORY_WEIGHTS
    )
    return max(0, min(100, int(round(weighted_sum))))


# ─── Основная функция расчёта ─────────────────────────────────────────────────

async def calculate_score(
    org_id: str,
    db: AsyncSession,
    asset_id: str | None = None,
) -> ScoreResult:
    """Рассчитывает Security Score для актива или всей организации.

    Если asset_id задан — считает score только для него.
    Если asset_id=None — агрегирует по всем активным активам организации:
      - categories: суммарные event_count + средневзвешенные penalty
      - total: среднее total_score по всем активам (или 100 если активов нет)

    Исключает события с resolved_at IS NOT NULL (устранённые угрозы).
    """
    now = datetime.now(timezone.utc)

    if asset_id is not None:
        # ─── Режим одного актива ───────────────────────────────────────────────
        asset_result = await db.execute(
            select(Asset).where(Asset.id == asset_id)
        )
        asset = asset_result.scalar_one_or_none()

        # Если актив не найден — возвращаем score 100 (нет данных = нет угроз)
        importance: float = getattr(asset, "importance", None) or 1.0

        events_result = await db.execute(
            select(Event.event_type, Event.severity, Event.detected_at)
            .where(
                Event.asset_id == asset_id,
                Event.resolved_at.is_(None),        # только неустранённые
            )
        )
        events = events_result.all()

        categories = _compute_categories_from_events(events, importance, now)
        total = _aggregate_total(categories)

        return ScoreResult(
            total=total,
            grade=_score_to_grade(total),
            categories=categories,
            asset_id=asset_id,
            org_id=org_id,
            calculated_at=now,
        )

    else:
        # ─── Режим организации: агрегируем по всем активам ────────────────────
        assets_result = await db.execute(
            select(Asset).where(
                Asset.organization_id == org_id,
                Asset.is_active.is_(True),
            )
        )
        assets = list(assets_result.scalars().all())

        if not assets:
            # Нет активов — идеальный score
            empty_categories = {
                cat: CategoryScore(score=100, penalty=0.0, event_count=0)
                for cat in CATEGORY_WEIGHTS
            }
            return ScoreResult(
                total=100,
                grade="A",
                categories=empty_categories,
                asset_id=None,
                org_id=org_id,
                calculated_at=now,
            )

        # Собираем все события организации одним запросом
        asset_ids = [a.id for a in assets]
        events_result = await db.execute(
            select(
                Event.event_type,
                Event.severity,
                Event.detected_at,
                Event.asset_id,
            )
            .where(
                Event.asset_id.in_(asset_ids),
                Event.resolved_at.is_(None),
            )
        )
        all_events = events_result.all()

        # Карта importance по asset_id
        importance_map: dict[str, float] = {
            a.id: (getattr(a, "importance", None) or 1.0)
            for a in assets
        }

        # Накапливаем штрафы и счётчики по категориям (агрегированно по всем активам)
        agg_penalties: dict[str, float] = {cat: 0.0 for cat in CATEGORY_WEIGHTS}
        agg_counts: dict[str, int] = {cat: 0 for cat in CATEGORY_WEIGHTS}

        for row in all_events:
            event_type = str(row.event_type).lower()
            severity = str(row.severity).lower()
            penalty_base = SEVERITY_PENALTY.get(severity, 0.0)

            if penalty_base == 0.0:
                continue

            category = _EVENT_TO_CATEGORY.get(event_type)
            if category is None:
                continue

            detected = row.detected_at
            if detected.tzinfo is None:
                detected = detected.replace(tzinfo=timezone.utc)

            delta_days = max(0.0, (now - detected).total_seconds() / 86400.0)
            decay = _time_decay(delta_days)
            importance = importance_map.get(row.asset_id or "", 1.0)
            event_penalty = penalty_base * decay * importance

            agg_penalties[category] += event_penalty
            agg_counts[category] += 1

        # Среднее penalty на актив — нормализуем по количеству активов
        n_assets = len(assets)
        categories: dict[str, CategoryScore] = {}
        for cat in CATEGORY_WEIGHTS:
            # Нормализация: делим суммарный штраф на число активов
            # чтобы 10 активов с малыми проблемами не давали score хуже
            # чем 1 актив с той же суммарной проблемой
            avg_penalty = agg_penalties[cat] / n_assets
            cat_score = max(0, int(round(100.0 - avg_penalty)))
            categories[cat] = CategoryScore(
                score=cat_score,
                penalty=round(avg_penalty, 4),
                event_count=agg_counts[cat],
            )

        total = _aggregate_total(categories)

        return ScoreResult(
            total=total,
            grade=_score_to_grade(total),
            categories=categories,
            asset_id=None,
            org_id=org_id,
            calculated_at=now,
        )
