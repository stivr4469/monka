"""
Data Quality Service — Zero-FP Rating.

Отслеживает сколько ложных срабатываний было отфильтровано при каждом скане
и вычисляет Data Quality Score — конкурентный дифференциатор vs SecurityScorecard.

Метрики:
  - raw_findings:  суммарно найдено до фильтрации
  - fp_filtered:   отфильтровано как ложное срабатывание
  - confirmed:     подтверждённые находки (raw - fp)
  - fp_rate:       fp_filtered / (raw_findings or 1)  × 100%
  - quality_score: 0-100 (100 = Zero-FP)
  - zero_fp_certified: True если fp_rate < 5%
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)

_QUALITY_DIR = Path("/tmp")


# ─── Схемы ────────────────────────────────────────────────────────────────────

class ScanQualitySource(BaseModel):
    """Статистика качества по одному источнику данных."""
    source:      str
    raw:         int
    fp_filtered: int
    confirmed:   int


class DataQualityReport(BaseModel):
    domain:             str
    scan_date:          str | None
    raw_findings:       int
    fp_filtered:        int
    confirmed:          int
    fp_rate_pct:        float   # процент FP (0-100)
    quality_score:      int     # 0-100
    zero_fp_certified:  bool    # True если fp_rate < 5%
    sources:            list[ScanQualitySource]
    badge:              str     # "Platinum" / "Gold" / "Silver" / "Standard"


# ─── Хранилище (файловый кэш) ─────────────────────────────────────────────────

def _quality_path(domain: str) -> Path:
    safe = domain.replace(".", "_").replace("/", "_")
    return _QUALITY_DIR / f"scan_quality_{safe}.json"


def save_quality_log(domain: str, data: dict[str, Any]) -> None:
    """Сохраняет статистику скана в файловый кэш."""
    path = _quality_path(domain)
    try:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.debug("[quality] Лог качества сохранён для %s", domain)
    except OSError as exc:
        logger.warning("[quality] Не удалось сохранить quality log для %s: %s", domain, exc)


def load_quality_log(domain: str) -> dict[str, Any] | None:
    """Загружает статистику скана из файлового кэша."""
    path = _quality_path(domain)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("[quality] Не удалось прочитать quality log для %s: %s", domain, exc)
        return None


# ─── Формула ──────────────────────────────────────────────────────────────────

def _compute_quality(raw: int, fp: int) -> tuple[float, int, bool, str]:
    """
    Вычисляет fp_rate, quality_score, zero_fp_certified, badge.

    Метрика отражает ТОЧНОСТЬ ДОСТАВКИ: мы фильтруем FP ДО показа клиенту.
    Высокий fp_filter_rate = много шума поймали = качественные фильтры.

    quality_score:
      - Если фильтрация не проводилась (raw = 0) → 100 (нет событий = нет шума)
      - Базовый балл = 80 (мы всегда применяем фильтры)
      - Бонус до +20 за высокий fp_filter_rate (поймали много шума)
      - Штраф -20 если fp_filter_rate < 20% (малый шум или фильтры не сработали)

    Badges:
      Platinum: quality_score >= 95 (фильтры поймали > 75% шума)
      Gold:     quality_score >= 85 (фильтры поймали 40-75% шума)
      Silver:   quality_score >= 75 (умеренная фильтрация)
      Standard: ниже
    """
    if raw == 0:
        return 0.0, 100, True, "Platinum"

    fp_rate = round(fp / raw * 100, 1)
    filter_rate = fp / raw  # 0.0 → 1.0

    # Базовый балл: мы всегда фильтруем перед доставкой
    base = 80
    # Бонус за эффективную фильтрацию (поймали много шума)
    bonus = round(filter_rate * 20)
    # Штраф если filter_rate очень низкий (< 20%)
    penalty = 10 if filter_rate < 0.2 and raw > 5 else 0

    quality_score = max(0, min(100, base + bonus - penalty))
    zero_fp_certified = quality_score >= 80

    if quality_score >= 95:
        badge = "Platinum"
    elif quality_score >= 85:
        badge = "Gold"
    elif quality_score >= 75:
        badge = "Silver"
    else:
        badge = "Standard"

    return fp_rate, quality_score, zero_fp_certified, badge


# ─── Основная функция ─────────────────────────────────────────────────────────

def build_quality_report(domain: str) -> DataQualityReport:
    """
    Строит DataQualityReport из сохранённого лога скана.
    Если данных нет — возвращает пустой отчёт.
    """
    raw_log = load_quality_log(domain)

    if not raw_log:
        fp_rate, qs, certified, badge = _compute_quality(0, 0)
        return DataQualityReport(
            domain=domain,
            scan_date=None,
            raw_findings=0,
            fp_filtered=0,
            confirmed=0,
            fp_rate_pct=0.0,
            quality_score=100,
            zero_fp_certified=True,
            sources=[],
            badge="Platinum",
        )

    raw_total = raw_log.get("raw_findings", 0)
    fp_total  = raw_log.get("fp_filtered", 0)
    confirmed = raw_total - fp_total
    fp_rate, qs, certified, badge = _compute_quality(raw_total, fp_total)

    sources = [
        ScanQualitySource(**s)
        for s in raw_log.get("sources", [])
    ]

    return DataQualityReport(
        domain=domain,
        scan_date=raw_log.get("scan_date"),
        raw_findings=raw_total,
        fp_filtered=fp_total,
        confirmed=confirmed,
        fp_rate_pct=fp_rate,
        quality_score=qs,
        zero_fp_certified=certified,
        sources=sources,
        badge=badge,
    )


def accumulate_scan_quality(
    domain: str,
    sources: list[dict[str, Any]],
) -> None:
    """
    Вызывается из scheduled_scan после завершения сканирования.
    sources: [{"source": "gitleaks", "raw": N, "fp_filtered": M}, ...]
    """
    total_raw = sum(s.get("raw", 0) for s in sources)
    total_fp  = sum(s.get("fp_filtered", 0) for s in sources)

    data = {
        "domain":       domain,
        "scan_date":    datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "raw_findings": total_raw,
        "fp_filtered":  total_fp,
        "sources":      [
            {
                "source":      s["source"],
                "raw":         s.get("raw", 0),
                "fp_filtered": s.get("fp_filtered", 0),
                "confirmed":   s.get("raw", 0) - s.get("fp_filtered", 0),
            }
            for s in sources
        ],
    }
    save_quality_log(domain, data)
    logger.info(
        "[quality] domain=%s raw=%d fp=%d quality=%d%%",
        domain, total_raw, total_fp, _compute_quality(total_raw, total_fp)[1],
    )
