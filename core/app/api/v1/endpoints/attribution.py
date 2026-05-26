"""
Attribution API — автооткрытие IP-диапазонов компании по названию.

Маршруты:
    POST /api/v1/attribution/discover   — синхронный поиск ASN + CIDR
    GET  /api/v1/attribution/asn/{asn}  — CIDR-блоки конкретного ASN
"""
import logging
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser

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
        from tasks.attribution_engine import run_attribution
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
        raise HTTPException(status_code=502, detail=f"BGPView API ошибка: {exc}") from exc

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
        from tasks.attribution_engine import get_asn_prefixes as _get_prefixes, _count_ips
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
