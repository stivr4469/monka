import concurrent.futures

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.models.asset import Asset
from app.scanner import run_subfinder
from app.schemas.asset import AssetCreate, AssetRead, AssetUpdate

router = APIRouter(prefix="/assets", tags=["assets"])

# ThreadPoolExecutor живёт на уровне модуля — переиспользуется между запросами
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)


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
