"""
POST /api/v1/scan/quick — быстрый старт по одному домену.

Принимает только домен. Всё остальное (организация, актив) создаётся автоматически.
Если организация / актив уже существуют — переиспользует.
Сразу запускает полное сканирование в фоне.

Флоу:
  1. Получить или создать Organization для текущего пользователя
     (суперпользователь без org → создаётся "Personal" организация)
  2. Получить или создать Asset(domain) в этой организации
  3. Запустить _run_full_scan_background в ThreadPoolExecutor
  4. Вернуть 202 {status, domain, asset_id, org_id}
"""
import logging
import re

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.models.base import new_uuid
from app.models.organization import OrgPlan, Organization
from app.models.user import User
from app.workers_client import ensure_workers_path, get_executor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class QuickScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"Некорректный домен: {v!r}")
        return v


class QuickScanResponse(BaseModel):
    status: str
    domain: str
    asset_id: str
    org_id: str
    message: str


@router.post(
    "/quick",
    response_model=QuickScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Быстрый старт — введите домен и запустите полное сканирование",
)
async def quick_scan(
    body: QuickScanRequest,
    db: DBDep,
    current_user: CurrentUser,
) -> QuickScanResponse:
    """
    Принимает домен, автоматически создаёт организацию и актив если нужно,
    запускает полное сканирование. Результаты появятся в /api/v1/events/.
    """
    domain = body.domain
    ensure_workers_path()

    # 1. Получить / создать организацию
    org_id = current_user.organization_id
    if org_id is None:
        # Суперпользователь без орга — создаём "Personal" организацию
        personal_name = f"Personal ({current_user.email})"
        personal_slug = re.sub(r"[^a-z0-9]", "-", current_user.email.lower())[:60]

        res = await db.execute(select(Organization).where(Organization.slug == personal_slug))
        org = res.scalar_one_or_none()

        if org is None:
            org = Organization(
                id=new_uuid(),
                name=personal_name,
                slug=personal_slug,
                plan=OrgPlan.professional,
            )
            db.add(org)
            try:
                await db.flush()
            except IntegrityError:
                await db.rollback()
                res = await db.execute(select(Organization).where(Organization.slug == personal_slug))
                org = res.scalar_one()

        org_id = org.id

        # Привязываем пользователя к организации
        res2 = await db.execute(select(User).where(User.id == current_user.id))
        user_row = res2.scalar_one()
        user_row.organization_id = org_id
        await db.flush()

    # 2. Получить / создать актив
    res = await db.execute(
        select(Asset).where(
            Asset.organization_id == org_id,
            Asset.domain == domain,
        )
    )
    asset = res.scalar_one_or_none()

    if asset is None:
        asset = Asset(
            id=new_uuid(),
            domain=domain,
            organization_id=org_id,
            is_active=True,
        )
        db.add(asset)
        try:
            await db.flush()
        except IntegrityError:
            await db.rollback()
            res = await db.execute(
                select(Asset).where(
                    Asset.organization_id == org_id,
                    Asset.domain == domain,
                )
            )
            asset = res.scalar_one()

    await db.commit()
    asset_id = asset.id

    # 3. Запустить сканирование в фоне
    from app.core.config import settings
    from app.api.v1.endpoints.scheduled_scan import _run_full_scan_background

    get_executor().submit(_run_full_scan_background, domain, settings.APP_PORT)

    logger.info("[quick_scan] Запущено: domain=%s asset=%s org=%s", domain, asset_id, org_id)

    return QuickScanResponse(
        status="processing",
        domain=domain,
        asset_id=asset_id,
        org_id=org_id,
        message=f"Полное сканирование {domain} запущено. Результаты: GET /api/v1/events/?domain={domain}",
    )
