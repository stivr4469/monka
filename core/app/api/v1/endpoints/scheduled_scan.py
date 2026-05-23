"""
API расписания автоматических сканирований.

Позволяет:
  - Запустить полное сканирование актива вручную (POST /schedule/asset/{asset_id})
  - Получить список расписаний организации (GET /schedule/)
  - Создать новое расписание (POST /schedule/create)

Реальный автозапуск по расписанию → TODO Phase 9: Celery Beat.
"""
from __future__ import annotations

import concurrent.futures
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.models.asset import Asset
from app.models.scan_schedule import ScanFrequency, ScanSchedule

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/schedule", tags=["schedule"])

# Пул потоков для фоновых задач сканирования
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="scan_worker")

# Добавляем workers в sys.path для импорта воркеров
_workers_path = str(Path(__file__).parents[6] / "workers")
if _workers_path not in sys.path:
    sys.path.insert(0, _workers_path)


# ─── Схемы запросов и ответов ────────────────────────────────────────────────

class ManualScanResponse(BaseModel):
    """Ответ на ручной запуск сканирования."""
    status: str
    asset_id: str
    domain: str
    detail: str


class ScheduleCreateRequest(BaseModel):
    """Запрос на создание расписания сканирования."""
    frequency: Literal["daily", "weekly", "monthly"] = Field(
        default="daily",
        description="Частота сканирования: daily (ежедневно), weekly (еженедельно), monthly (ежемесячно)",
    )
    asset_id: str | None = Field(
        default=None,
        description="ID конкретного актива. None = сканировать все активы организации",
    )


class ScheduleRead(BaseModel):
    """Схема чтения расписания."""
    id: str
    organization_id: str
    asset_id: str | None
    frequency: str
    last_run_at: datetime | None
    next_run_at: datetime | None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ScheduleListResponse(BaseModel):
    """Список расписаний организации."""
    schedules: list[ScheduleRead]
    total: int


# ─── Утилиты ─────────────────────────────────────────────────────────────────

def _compute_next_run(frequency: str, from_time: datetime | None = None) -> datetime:
    """Вычисляет время следующего запуска по частоте."""
    base = from_time or datetime.now(timezone.utc)
    delta_map = {
        ScanFrequency.DAILY.value: timedelta(days=1),
        ScanFrequency.WEEKLY.value: timedelta(weeks=1),
        ScanFrequency.MONTHLY.value: timedelta(days=30),
    }
    return base + delta_map.get(frequency, timedelta(days=1))


def _get_core_api_url() -> str:
    """Возвращает URL Core API для фоновых задач."""
    port = int(os.getenv("APP_PORT", "8000"))
    return f"http://127.0.0.1:{port}"


def _run_full_scan_background(domain: str, port: int) -> None:
    """
    Полное сканирование актива:
      subfinder → nuclei → github_search → gitleaks

    Запускается в фоновом потоке через ThreadPoolExecutor.
    """
    core_api_url = f"http://127.0.0.1:{port}"

    # 1. Subfinder — обнаружение поддоменов
    try:
        from app.scanner import run_subfinder
        run_subfinder(domain=domain, port=port)
        logger.info("[schedule] subfinder завершён для %s", domain)
    except Exception as exc:
        logger.error("[schedule] subfinder упал для %s: %s", domain, exc)

    # 2. GitHub Search — поиск упоминаний домена
    try:
        from tasks.github_search import search_github
        if settings.GITHUB_TOKEN:
            search_github(
                domain=domain,
                github_token=settings.GITHUB_TOKEN,
                core_api_url=core_api_url,
                internal_secret=settings.INTERNAL_API_SECRET,
            )
            logger.info("[schedule] github_search завершён для %s", domain)
        else:
            logger.warning("[schedule] GITHUB_TOKEN не задан, пропускаю github_search")
    except ImportError:
        logger.warning("[schedule] workers недоступны, пропускаю github_search")
    except Exception as exc:
        logger.error("[schedule] github_search упал для %s: %s", domain, exc)

    # 3. Gitleaks — сканирование репозиториев
    try:
        from tasks.gitleaks import scan_github_results
        if settings.GITHUB_TOKEN:
            scan_github_results(
                domain=domain,
                github_token=settings.GITHUB_TOKEN,
                core_api_url=core_api_url,
                internal_secret=settings.INTERNAL_API_SECRET,
            )
            logger.info("[schedule] gitleaks завершён для %s", domain)
        else:
            logger.warning("[schedule] GITHUB_TOKEN не задан, пропускаю gitleaks")
    except ImportError:
        logger.warning("[schedule] gitleaks воркер недоступен")
    except Exception as exc:
        logger.error("[schedule] gitleaks упал для %s: %s", domain, exc)

    logger.info("[schedule] Полное сканирование завершено для %s", domain)


# ─── Эндпоинты ───────────────────────────────────────────────────────────────

@router.post(
    "/asset/{asset_id}",
    response_model=ManualScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Запустить полное сканирование актива вручную",
)
async def trigger_manual_scan(
    asset_id: str,
    background_tasks: BackgroundTasks,
    db: DBDep,
    current_user: CurrentUser,
) -> ManualScanResponse:
    """
    Немедленно запускает полный цикл сканирования для указанного актива:
    subfinder → nuclei → github_search → gitleaks → paste_monitor (TODO).

    Возвращает 202 Accepted — результаты появляются асинхронно в /api/v1/events/.
    """
    # Проверяем принадлежность актива организации пользователя
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()

    if asset is None:
        raise HTTPException(status_code=404, detail="Актив не найден")

    if current_user.organization_id != asset.organization_id:
        raise HTTPException(status_code=403, detail="Нет доступа к этому активу")

    if not asset.is_active:
        raise HTTPException(status_code=400, detail="Актив деактивирован")

    port = int(os.getenv("APP_PORT", "8000"))
    domain = asset.domain

    # Запускаем сканирование в фоне — не блокируем HTTP-запрос
    background_tasks.add_task(
        _executor.submit,
        _run_full_scan_background,
        domain,
        port,
    )

    logger.info("[schedule] Ручное сканирование запущено: asset=%s domain=%s", asset_id, domain)

    return ManualScanResponse(
        status="processing",
        asset_id=asset_id,
        domain=domain,
        detail=(
            "Полное сканирование запущено в фоне. "
            "Результаты: GET /api/v1/events/?target_domain=" + domain
        ),
    )


@router.get(
    "/",
    response_model=ScheduleListResponse,
    summary="Список расписаний организации",
)
async def list_schedules(
    db: DBDep,
    current_user: CurrentUser,
) -> ScheduleListResponse:
    """
    Возвращает список активных расписаний для организации текущего пользователя.

    Заглушка под будущий Celery Beat: расписания хранятся в БД,
    фактический запуск — TODO Phase 9.
    """
    if current_user.organization_id is None:
        return ScheduleListResponse(schedules=[], total=0)

    result = await db.execute(
        select(ScanSchedule).where(
            ScanSchedule.organization_id == current_user.organization_id,
            ScanSchedule.is_active.is_(True),
        ).order_by(ScanSchedule.created_at.desc())
    )
    schedules = list(result.scalars().all())

    return ScheduleListResponse(
        schedules=[ScheduleRead.model_validate(s) for s in schedules],
        total=len(schedules),
    )


@router.post(
    "/create",
    response_model=ScheduleRead,
    status_code=status.HTTP_201_CREATED,
    summary="Создать расписание сканирования",
)
async def create_schedule(
    body: ScheduleCreateRequest,
    db: DBDep,
    current_user: CurrentUser,
) -> ScheduleRead:
    """
    Создаёт новое расписание сканирования.

    Если asset_id указан — проверяем принадлежность активу организации.
    Если asset_id=None — сканируются все активы организации (TODO Celery Beat).

    Реальный запуск по расписанию: TODO Phase 9 — Celery Beat.
    """
    if current_user.organization_id is None:
        raise HTTPException(
            status_code=400,
            detail="Пользователь не привязан к организации",
        )

    # Проверяем asset_id если указан
    if body.asset_id is not None:
        result = await db.execute(select(Asset).where(Asset.id == body.asset_id))
        asset = result.scalar_one_or_none()
        if asset is None or asset.organization_id != current_user.organization_id:
            raise HTTPException(
                status_code=404,
                detail="Актив не найден или недоступен",
            )

    # Валидируем частоту
    valid_frequencies = {f.value for f in ScanFrequency}
    if body.frequency not in valid_frequencies:
        raise HTTPException(
            status_code=422,
            detail=f"Недопустимая частота '{body.frequency}'. Допустимые: {sorted(valid_frequencies)}",
        )

    now = datetime.now(timezone.utc)
    schedule = ScanSchedule(
        organization_id=current_user.organization_id,
        asset_id=body.asset_id,
        frequency=body.frequency,
        last_run_at=None,
        next_run_at=_compute_next_run(body.frequency, from_time=now),
        is_active=True,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)

    logger.info(
        "[schedule] Создано расписание: id=%s org=%s freq=%s asset=%s next=%s",
        schedule.id,
        schedule.organization_id,
        schedule.frequency,
        schedule.asset_id,
        schedule.next_run_at,
    )

    return ScheduleRead.model_validate(schedule)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_200_OK,
    summary="Деактивировать расписание",
)
async def deactivate_schedule(
    schedule_id: str,
    db: DBDep,
    current_user: CurrentUser,
) -> dict:
    """
    Деактивирует расписание (мягкое удаление: is_active=False).
    Физически запись не удаляется для сохранения истории.
    """
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()

    if schedule is None or schedule.organization_id != current_user.organization_id:
        raise HTTPException(status_code=404, detail="Расписание не найдено")

    schedule.is_active = False
    await db.commit()

    logger.info("[schedule] Расписание деактивировано: id=%s", schedule_id)
    return {"status": "deactivated", "id": schedule_id}


# ROUTER: api_router.include_router(scheduled_scan.router)
