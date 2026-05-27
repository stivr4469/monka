"""
Attribution API — автооткрытие IP-диапазонов компании по названию.

Маршруты:
    POST /api/v1/attribution/discover     — синхронный поиск ASN + CIDR
    GET  /api/v1/attribution/asn/{asn}    — CIDR-блоки конкретного ASN
    POST /api/v1/attribution/auto-suggest — Gap-анализ: какие CIDR не мониторятся
"""
import asyncio
import ipaddress
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, get_current_user, get_db
from app.models.asset import Asset

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/attribution", tags=["attribution"])

# Воркеры запускаются в другом процессе — импортируем напрямую
_WORKERS_PATH = Path(__file__).parents[6] / "workers"
if str(_WORKERS_PATH) not in sys.path:
    sys.path.insert(0, str(_WORKERS_PATH))


# ─── Схемы ────────────────────────────────────────────────────────────────────

class AttributionRequest(BaseModel):
    company_name: str = Field(..., min_length=2, max_length=200, description="Название компании")
    domain: str | None = Field(None, max_length=255, description="Связанный домен (опционально)")


class AsnInfo(BaseModel):
    asn:         int
    name:        str
    description: str
    country:     str


class CidrInfo(BaseModel):
    prefix:      str
    asn:         int
    description: str
    country:     str


class AttributionResponse(BaseModel):
    company_name:   str
    domain:         str | None
    asns:           list[AsnInfo]
    cidrs:          list[CidrInfo]
    total_prefixes: int
    total_ips:      int


class AsnPrefixesResponse(BaseModel):
    asn:   int
    cidrs: list[CidrInfo]
    total_prefixes: int
    total_ips:      int


# ─── Схемы auto-suggest ───────────────────────────────────────────────────────

class AttributionSuggestion(BaseModel):
    """Один CIDR-блок, который кандидат для добавления в мониторинг."""
    cidr:            str
    asn:             int
    asn_name:        str
    estimated_hosts: int                          # количество IP-адресов в блоке
    reason:          str                          # почему блок не мониторится
    action:          str = "add_to_monitoring"
    priority:        Literal["high", "medium", "low"]


class AutoSuggestRequest(BaseModel):
    org_id:       str = Field(..., description="UUID организации")
    company_name: str = Field(..., min_length=2, max_length=200, description="Название компании")
    domain:       str | None = Field(None, max_length=255, description="Связанный домен (опционально)")


class AutoSuggestResponse(BaseModel):
    org_id:            str
    company_name:      str
    asns_found:        int       # количество найденных ASN
    cidrs_total:       int       # общее количество CIDR-блоков
    suggestions:       list[AttributionSuggestion]
    already_monitored: int       # CIDR-блоки, где company_name совпадает с ASN description
    computed_at:       str       # ISO timestamp


# ─── POST /attribution/discover ───────────────────────────────────────────────

@router.post(
    "/discover",
    response_model=AttributionResponse,
    summary="Найти все IP-диапазоны компании (ASN Attribution)",
)
def discover_attribution(
    body: AttributionRequest,
    current_user: CurrentUser,
) -> AttributionResponse:
    """
    По названию компании находит все её ASN через BGPView Search,
    затем для каждого ASN получает список CIDR-блоков (IPv4).

    Результат: список ASN + список CIDR-диапазонов + общий объём IP.

    Время выполнения: ~5-30 секунд (зависит от количества ASN и rate-limit BGPView).
    """
    try:
        from workers.tasks.attribution_engine import run_attribution
    except ImportError as exc:
        logger.error("[attribution] Импорт attribution_engine: %s", exc)
        raise HTTPException(status_code=503, detail="Attribution engine недоступен") from exc

    try:
        result = run_attribution(
            company_name=body.company_name,
            domain=body.domain,
        )
    except Exception as exc:
        logger.error("[attribution] Ошибка discover для '%s': %s", body.company_name, exc)
        raise HTTPException(status_code=502, detail="Attribution engine недоступен (внешний API)") from exc

    return AttributionResponse(**result)


# ─── GET /attribution/asn/{asn} ───────────────────────────────────────────────

@router.get(
    "/asn/{asn}",
    response_model=AsnPrefixesResponse,
    summary="CIDR-блоки конкретного ASN",
)
def get_asn_prefixes(
    asn: int,
    current_user: CurrentUser,
) -> AsnPrefixesResponse:
    """
    Возвращает все IPv4 CIDR-блоки для указанного ASN через BGPView.
    """
    if asn <= 0 or asn > 4294967295:
        raise HTTPException(status_code=400, detail="Некорректный номер ASN")

    try:
        from workers.tasks.attribution_engine import get_asn_prefixes as _get_prefixes, _count_ips
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Attribution engine недоступен") from exc

    cidrs = _get_prefixes(asn)
    total_ips = sum(_count_ips(c["prefix"]) for c in cidrs)

    return AsnPrefixesResponse(
        asn=asn,
        cidrs=[CidrInfo(**c) for c in cidrs],
        total_prefixes=len(cidrs),
        total_ips=total_ips,
    )


# ─── POST /attribution/auto-suggest ──────────────────────────────────────────

def _calc_priority(num_hosts: int) -> Literal["high", "medium", "low"]:
    """
    Приоритет suggestion по размеру CIDR-блока:
    - high   : > 1000 хостов (блок /22 и крупнее)
    - medium : 100–1000 хостов (/24 — /23)
    - low    : < 100 хостов (маленькие блоки)
    """
    if num_hosts > 1000:
        return "high"
    if num_hosts >= 100:
        return "medium"
    return "low"


def _count_hosts(prefix: str) -> int:
    """Количество IP-адресов в CIDR-блоке (0 при ошибке)."""
    try:
        return ipaddress.IPv4Network(prefix, strict=False).num_addresses
    except ValueError:
        return 0


@router.post(
    "/auto-suggest",
    response_model=AutoSuggestResponse,
    summary="Gap-анализ: CIDR-блоки компании, которые не покрыты мониторингом",
)
async def auto_suggest_assets(
    body: AutoSuggestRequest,
    _user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> AutoSuggestResponse:
    """
    Запускает Attribution для компании, загружает assets организации из БД
    и возвращает список CIDR-блоков, которые потенциально не мониторятся.

    Эвристика "не мониторится":
    - Название компании (company_name) **не** встречается в описании ASN (asn_description).
    - Т.е. если description ASN не содержит company_name (case-insensitive) —
      считаем блок «вне радара».

    Эвристика "уже мониторится":
    - company_name.lower() найден в asn_description.lower() — нечёткое совпадение.

    Время ответа: ~10–60 с (BGPView/RIPE rate-limit), запрос выполняется в thread pool.
    """
    # Импортируем движок attribution (синхронная функция → thread pool)
    try:
        from workers.tasks.attribution_engine import run_attribution
    except ImportError as exc:
        logger.error("[auto-suggest] Импорт attribution_engine: %s", exc)
        raise HTTPException(status_code=503, detail="Attribution engine недоступен") from exc

    # 1. Запускаем run_attribution в отдельном потоке, чтобы не блокировать event loop
    logger.info(
        "[auto-suggest] Старт: org_id=%s company='%s' domain=%s",
        body.org_id, body.company_name, body.domain,
    )
    try:
        attribution_result: dict = await asyncio.to_thread(
            run_attribution,
            body.company_name,
            body.domain,
        )
    except Exception as exc:
        logger.error("[auto-suggest] run_attribution упал для '%s': %s", body.company_name, exc)
        raise HTTPException(status_code=502, detail="Attribution engine недоступен (внутренняя ошибка)") from exc

    asns: list[dict]  = attribution_result.get("asns", [])
    cidrs: list[dict] = attribution_result.get("cidrs", [])

    # 2. Загружаем домены assets организации из БД (только is_active)
    stmt = select(Asset.domain).where(
        Asset.organization_id == body.org_id,
        Asset.is_active.is_(True),
    )
    rows = await db.execute(stmt)
    monitored_domains: set[str] = {row[0].lower() for row in rows.fetchall() if row[0]}

    logger.info(
        "[auto-suggest] assets загружены: org_id=%s count=%d",
        body.org_id, len(monitored_domains),
    )

    # 3. Строим индекс ASN → description для быстрого поиска
    asn_descriptions: dict[int, str] = {
        int(a["asn"]): (a.get("description") or "").strip()
        for a in asns
        if a.get("asn")
    }

    # 4. Нечёткое совпадение: company_name в описании ASN
    company_lower = body.company_name.lower()

    suggestions: list[AttributionSuggestion] = []
    already_monitored_count = 0

    for cidr_obj in cidrs:
        prefix      = cidr_obj.get("prefix", "")
        asn_num     = int(cidr_obj.get("asn", 0))
        description = asn_descriptions.get(asn_num, "")
        asn_name    = f"AS{asn_num}"

        num_hosts = _count_hosts(prefix)

        # Нечёткая проверка: считаем "уже мониторится" если company_name есть в описании ASN
        if company_lower and description and company_lower in description.lower():
            already_monitored_count += 1
            # Даже "мониторируемые" добавляем в suggestions если нет ни одного asset в домене?
            # По ТЗ — нет: already_monitored считаем, но не добавляем в suggestions.
            continue

        # CIDR не покрыт — формируем suggestion
        if description:
            reason = f"Диапазон {asn_name} ({description}) не мониторится"
        else:
            reason = f"Диапазон {asn_name} не обнаружен ни в одном из мониторимых активов"

        suggestions.append(AttributionSuggestion(
            cidr=prefix,
            asn=asn_num,
            asn_name=asn_name,
            estimated_hosts=num_hosts,
            reason=reason,
            priority=_calc_priority(num_hosts),
        ))

    # Сортируем: сначала high, затем medium, затем low — по убыванию estimated_hosts внутри группы
    _priority_order = {"high": 0, "medium": 1, "low": 2}
    suggestions.sort(key=lambda s: (_priority_order[s.priority], -s.estimated_hosts))

    logger.info(
        "[auto-suggest] Итого: org_id=%s suggestions=%d already_monitored=%d",
        body.org_id, len(suggestions), already_monitored_count,
    )

    return AutoSuggestResponse(
        org_id=body.org_id,
        company_name=body.company_name,
        asns_found=len(asns),
        cidrs_total=len(cidrs),
        suggestions=suggestions,
        already_monitored=already_monitored_count,
        computed_at=datetime.now(timezone.utc).isoformat(),
    )
