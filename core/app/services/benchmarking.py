"""
Industry Benchmarking — сравнение Security Score с анонимным бенчмарком отрасли.
Бенчмарки обновляются при каждом расчёте score и хранятся агрегированно в БД.
"""
import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any

from app.models.organization import Organization
from app.models.score_snapshot import ScoreSnapshot

logger = logging.getLogger(__name__)

# ─── Статичные бенчмарки по отраслям (fallback при отсутствии данных в БД) ──────
# Основаны на публичных отраслевых отчётах о кибербезопасности (SecurityScorecard,
# Bitsight, IBM X-Force). Обновляются раз в квартал.
INDUSTRY_BENCHMARKS: dict[str, dict[str, float]] = {
    "fintech": {
        "avg_score": 72.0,
        "p25": 60.0,
        "p50": 72.0,
        "p75": 82.0,
        "network_security": 75.0,
        "dns_health": 78.0,
        "application_security": 70.0,
        "credential_exposure": 65.0,
        "dark_web_presence": 68.0,
        "brand_safety": 80.0,
    },
    "healthcare": {
        "avg_score": 65.0,
        "p25": 52.0,
        "p50": 65.0,
        "p75": 76.0,
        "network_security": 70.0,
        "dns_health": 72.0,
        "application_security": 65.0,
        "credential_exposure": 58.0,
        "dark_web_presence": 60.0,
        "brand_safety": 75.0,
    },
    "ecommerce": {
        "avg_score": 69.0,
        "p25": 56.0,
        "p50": 69.0,
        "p75": 79.0,
        "network_security": 72.0,
        "dns_health": 75.0,
        "application_security": 68.0,
        "credential_exposure": 62.0,
        "dark_web_presence": 65.0,
        "brand_safety": 72.0,
    },
    "saas": {
        "avg_score": 74.0,
        "p25": 63.0,
        "p50": 74.0,
        "p75": 84.0,
        "network_security": 78.0,
        "dns_health": 80.0,
        "application_security": 75.0,
        "credential_exposure": 67.0,
        "dark_web_presence": 70.0,
        "brand_safety": 78.0,
    },
    "telecom": {
        "avg_score": 70.0,
        "p25": 58.0,
        "p50": 70.0,
        "p75": 80.0,
        "network_security": 74.0,
        "dns_health": 76.0,
        "application_security": 69.0,
        "credential_exposure": 64.0,
        "dark_web_presence": 67.0,
        "brand_safety": 74.0,
    },
    "manufacturing": {
        "avg_score": 63.0,
        "p25": 50.0,
        "p50": 63.0,
        "p75": 74.0,
        "network_security": 66.0,
        "dns_health": 68.0,
        "application_security": 62.0,
        "credential_exposure": 56.0,
        "dark_web_presence": 58.0,
        "brand_safety": 70.0,
    },
    "media": {
        "avg_score": 67.0,
        "p25": 54.0,
        "p50": 67.0,
        "p75": 77.0,
        "network_security": 69.0,
        "dns_health": 71.0,
        "application_security": 66.0,
        "credential_exposure": 60.0,
        "dark_web_presence": 63.0,
        "brand_safety": 73.0,
    },
    "other": {
        "avg_score": 68.0,
        "p25": 55.0,
        "p50": 68.0,
        "p75": 78.0,
        "network_security": 70.0,
        "dns_health": 72.0,
        "application_security": 67.0,
        "credential_exposure": 60.0,
        "dark_web_presence": 63.0,
        "brand_safety": 72.0,
    },
}

# Список допустимых отраслей
VALID_INDUSTRIES = frozenset(INDUSTRY_BENCHMARKS.keys())

# Названия категорий score — соответствуют ключам в INDUSTRY_BENCHMARKS
_CATEGORY_KEYS = [
    "network_security",
    "dns_health",
    "application_security",
    "credential_exposure",
    "dark_web_presence",
    "brand_safety",
]


def _normalize_industry(industry: str | None) -> str:
    """Нормализует название отрасли: приводит к lower, fallback на 'other'."""
    if not industry:
        return "other"
    normalized = industry.strip().lower()
    return normalized if normalized in VALID_INDUSTRIES else "other"


async def get_industry_benchmark(
    industry: str,
    db: AsyncSession,
) -> dict[str, Any]:
    """Получает бенчмарк для отрасли.

    Сначала пробует агрегировать данные из ScoreSnapshot по организациям
    данной отрасли. Если выборка слишком мала (< 5 записей) —
    использует статичные INDUSTRY_BENCHMARKS как fallback.

    Returns:
        Словарь с ключами: avg_score, p25, p50, p75, peer_count,
        и средними значениями по категориям.
    """
    normalized = _normalize_industry(industry)

    # Пытаемся получить живые данные из БД: организации нужной отрасли
    try:
        org_ids_result = await db.execute(
            select(Organization.id).where(
                Organization.industry == normalized,
            )
        )
        org_ids = [row[0] for row in org_ids_result.all()]

        if len(org_ids) >= 5:
            # Достаточно данных — считаем агрегаты по ScoreSnapshot (org-level)
            scores_result = await db.execute(
                select(ScoreSnapshot.total_score)
                .where(
                    ScoreSnapshot.org_id.in_(org_ids),
                    ScoreSnapshot.asset_id.is_(None),
                )
                .order_by(ScoreSnapshot.total_score.asc())
            )
            scores = [row[0] for row in scores_result.all()]

            if len(scores) >= 5:
                n = len(scores)
                avg_score = sum(scores) / n
                p25_idx = int(n * 0.25)
                p50_idx = int(n * 0.50)
                p75_idx = int(n * 0.75)

                return {
                    "avg_score": round(avg_score, 1),
                    "p25": float(scores[p25_idx]),
                    "p50": float(scores[p50_idx]),
                    "p75": float(scores[min(p75_idx, n - 1)]),
                    "peer_count": len(org_ids),
                    "source": "live",
                    **{
                        cat: INDUSTRY_BENCHMARKS[normalized].get(cat, 70.0)
                        for cat in _CATEGORY_KEYS
                    },
                }
    except Exception as exc:
        logger.warning("[benchmark] Ошибка получения live данных для '%s': %s", industry, exc)
        pass

    # Fallback: статичные бенчмарки
    static = INDUSTRY_BENCHMARKS[normalized].copy()
    static["peer_count"] = 0
    static["source"] = "static"
    return static


def _calc_percentile(score: float, p25: float, p50: float, p75: float) -> int:
    """Упрощённая линейная интерполяция перцентиля.

    Формула:
        score < p25  → [0, 25)  по интерполяции вниз
        p25 ≤ score < p50 → [25, 50)
        p50 ≤ score < p75 → [50, 75)
        score ≥ p75       → [75, 100]
    """
    if score >= p75:
        if p75 >= 100:
            return 100
        # Линейная интерполяция от p75 до 100
        above = min(100.0, p75 + (100 - p75))
        pct = 75.0 + (score - p75) / max(above - p75, 1.0) * 25.0
    elif score >= p50:
        pct = 50.0 + (score - p50) / max(p75 - p50, 1.0) * 25.0
    elif score >= p25:
        pct = 25.0 + (score - p25) / max(p50 - p25, 1.0) * 25.0
    else:
        # Ниже p25
        pct = max(0.0, score / max(p25, 1.0) * 25.0)

    return max(0, min(100, int(round(pct))))


def _score_to_rank(score: float, p25: float, p50: float, p75: float) -> str:
    """Определяет rank организации по score относительно бенчмарка."""
    if score >= p75:
        return "top_quartile"
    if score >= p50:
        return "above_average"
    if score >= p25:
        return "average"
    return "below_average"


async def compare_with_benchmark(
    org_score: float,
    org_category_scores: dict[str, float],
    industry: str,
    db: AsyncSession,
) -> dict[str, Any]:
    """Сравнивает score организации с бенчмарком отрасли.

    Args:
        org_score: Итоговый Security Score организации (0–100).
        org_category_scores: Словарь score по категориям {"network_security": 80.0, ...}.
        industry: Отрасль организации.
        db: Сессия БД для получения живых бенчмарков.

    Returns:
        {
            "industry": "fintech",
            "your_score": 74.5,
            "benchmark": {"avg": 72.0, "p25": 60.0, "p50": 72.0, "p75": 82.0},
            "percentile": 55,
            "rank": "above_average",
            "category_comparison": {
                "network_security": {"your": 80.0, "avg": 75.0, "delta": 5.0},
                ...
            }
        }
    """
    normalized = _normalize_industry(industry)
    bench = await get_industry_benchmark(normalized, db)

    p25 = bench["p25"]
    p50 = bench["p50"]
    p75 = bench["p75"]
    avg_score = bench["avg_score"]

    percentile = _calc_percentile(org_score, p25, p50, p75)
    rank = _score_to_rank(org_score, p25, p50, p75)

    # Категорийное сравнение
    category_comparison: dict[str, dict[str, float]] = {}
    for cat in _CATEGORY_KEYS:
        your_val = float(org_category_scores.get(cat, 0.0))
        avg_val = float(bench.get(cat, 70.0))
        delta = round(your_val - avg_val, 1)
        category_comparison[cat] = {
            "your": your_val,
            "avg": avg_val,
            "delta": delta,
        }

    return {
        "industry": normalized,
        "your_score": round(float(org_score), 1),
        "benchmark": {
            "avg": avg_score,
            "p25": p25,
            "p50": p50,
            "p75": p75,
        },
        "percentile": percentile,
        "rank": rank,
        "category_comparison": category_comparison,
        "peer_count": bench.get("peer_count", 0),
    }
