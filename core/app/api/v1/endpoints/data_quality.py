"""
Data Quality API — Zero-FP Rating endpoints.

Маршруты:
    GET /api/v1/assets/{asset_id}/data-quality  — Zero-FP отчёт актива
    GET /api/v1/organizations/{org_id}/data-quality  — агрегат по организации
"""
import logging

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.organization import Organization
from app.services.data_quality import DataQualityReport, ScanQualitySource, build_quality_report, _compute_quality

logger = logging.getLogger(__name__)
router = APIRouter(tags=["data-quality"])


# ─── GET /assets/{asset_id}/data-quality ──────────────────────────────────────

@router.get(
    "/assets/{asset_id}/data-quality",
    response_model=DataQualityReport,
    summary="Zero-FP Data Quality отчёт актива",
)
async def get_asset_data_quality(
    asset_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> DataQualityReport:
    """
    Возвращает Data Quality Report для актива:
    - Сколько сырых находок было найдено
    - Сколько отфильтровано как false positive (атак-репозитории, research-данные)
    - Итоговый Quality Score (0-100) и Zero-FP Badge

    Zero-FP Certified: выдаётся если уровень ложных срабатываний < 5%.

    Данные обновляются после каждого полного скана домена.
    """
    asset_result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_result.scalar_one_or_none()

    if asset is None or asset.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Актив не найден")

    return build_quality_report(asset.domain)


# ─── GET /organizations/{org_id}/data-quality ─────────────────────────────────

class OrgDataQualityReport(DataQualityReport):
    """Агрегированный отчёт по организации."""
    assets_count: int
    assets_with_data: int


@router.get(
    "/organizations/{org_id}/data-quality",
    response_model=OrgDataQualityReport,
    summary="Агрегированный Zero-FP Data Quality по организации",
)
async def get_org_data_quality(
    org_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> OrgDataQualityReport:
    """
    Агрегирует Data Quality Report по всем активам организации.
    Возвращает суммарные метрики и общий Zero-FP Badge.
    """
    if current_user.organization_id != org_id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Нет доступа к этой организации")

    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    if org_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Организация не найдена")

    assets_result = await db.execute(
        select(Asset).where(Asset.organization_id == org_id, Asset.is_active.is_(True))
    )
    assets = list(assets_result.scalars().all())

    total_raw = 0
    total_fp  = 0
    all_sources: list[ScanQualitySource] = []
    assets_with_data = 0

    for asset in assets:
        report = build_quality_report(asset.domain)
        if report.scan_date:
            assets_with_data += 1
        total_raw += report.raw_findings
        total_fp  += report.fp_filtered
        all_sources.extend(report.sources)

    confirmed = total_raw - total_fp
    fp_rate, qs, certified, badge = _compute_quality(total_raw, total_fp)

    return OrgDataQualityReport(
        domain=f"org:{org_id}",
        scan_date=None,
        raw_findings=total_raw,
        fp_filtered=total_fp,
        confirmed=confirmed,
        fp_rate_pct=fp_rate,
        quality_score=qs,
        zero_fp_certified=certified,
        sources=all_sources,
        badge=badge,
        assets_count=len(assets),
        assets_with_data=assets_with_data,
    )
