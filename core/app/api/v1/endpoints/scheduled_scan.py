"""
API расписания автоматических сканирований.

Позволяет:
  - Запустить полное сканирование актива вручную (POST /schedule/asset/{asset_id})
  - Получить список расписаний организации (GET /schedule/)
  - Создать новое расписание (POST /schedule/create)

Реальный автозапуск по расписанию → TODO Phase 9: Celery Beat.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import CurrentUser, DBDep
from app.core.config import settings
from app.models.asset import Asset
from app.models.scan_schedule import ScanFrequency, ScanSchedule
from app.workers_client import ensure_workers_path, get_executor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/schedule", tags=["schedule"])

# Подключаем workers/ к sys.path через единый синглтон
ensure_workers_path()


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
    return f"http://127.0.0.1:{settings.APP_PORT}"


def _run_full_scan_background(domain: str, port: int) -> None:
    """
    Полное сканирование актива — все доступные модули:
      TLS → Hardening → Tech Profile → Phishing → Port Scan →
      Darknet → Paste → GitHub → Gitleaks → Subfinder → S3 → Takeover → Beaconing

    Каждый модуль изолирован: падение одного не прерывает остальные.
    Результаты поступают через /api/v1/internal/ingest в БД и OpenSearch.
    """
    core_api_url = f"http://127.0.0.1:{port}"
    sec = settings.INTERNAL_API_SECRET

    # Накопление FP-статистики для Data Quality Report
    _quality_sources: list[dict] = []

    def _run(name: str, fn, *args, **kwargs):
        try:
            result = fn(*args, **kwargs)
            logger.info("[full_scan] ✓ %s завершён для %s", name, domain)
            # Собираем FP-метрики если модуль их возвращает
            if isinstance(result, dict) and "fp_filtered" in result:
                raw = result.get("repos_scanned", 0) + result.get("found", 0) + result.get("fp_filtered", 0)
                _quality_sources.append({
                    "source":      name,
                    "raw":         raw,
                    "fp_filtered": result["fp_filtered"],
                })
            elif isinstance(result, dict) and "filtered" in result:
                raw = result.get("found", 0) + result.get("filtered", 0)
                _quality_sources.append({
                    "source":      name,
                    "raw":         raw,
                    "fp_filtered": result["filtered"],
                })
        except ImportError:
            logger.warning("[full_scan] %s воркер недоступен (ImportError)", name)
        except Exception as exc:
            logger.error("[full_scan] %s упал для %s: %s", name, domain, exc)

    # 1. TLS / JA4 — сертификаты, WAF, протоколы
    def _tls():
        from tasks.tls_fingerprinter import run_tls_scan
        run_tls_scan(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("tls_scan", _tls)

    # 2. HTTP Hardening — заголовки безопасности, HSTS, CSP
    def _hardening():
        from tasks.domain_hardening import run_domain_hardening
        run_domain_hardening(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("hardening", _hardening)

    # 3. Technology Profiling — CMS, фреймворки, EOL-версии
    def _tech():
        from tasks.tech_profiler import run_tech_profiler
        run_tech_profiler(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("tech_profiler", _tech)

    # 4. Phishing Detection — тайпосквот и фишинговые домены
    def _phishing():
        from tasks.phishing_detector import detect_phishing_domains
        detect_phishing_domains(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("phishing_detector", _phishing)

    # 5. Port Scan — открытые порты и сервисы
    def _ports():
        from tasks.port_scanner import run_port_scan
        run_port_scan(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("port_scanner", _ports)

    # 6. Darknet Monitor — RansomWatch + Ahmia + DarkSearch
    def _darknet():
        from tasks.darknet_monitor import monitor_darknet
        monitor_darknet(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("darknet_monitor", _darknet)

    # 7. Paste Monitor — Pastebin и аналоги
    def _paste():
        from tasks.paste_monitor import monitor_pastes
        monitor_pastes(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("paste_monitor", _paste)

    # 8. GitHub Search — упоминания домена в коде
    def _github():
        from tasks.github_search import search_github
        if settings.GITHUB_TOKEN:
            search_github(
                domain=domain,
                github_token=settings.GITHUB_TOKEN,
                core_api_url=core_api_url,
                internal_secret=sec,
            )
        else:
            logger.warning("[full_scan] GITHUB_TOKEN не задан — пропуск github_search")
    _run("github_search", _github)

    # 9. Gitleaks — секреты в репозиториях
    def _gitleaks():
        from tasks.gitleaks import scan_github_results
        if settings.GITHUB_TOKEN:
            scan_github_results(
                domain=domain,
                github_token=settings.GITHUB_TOKEN,
                core_api_url=core_api_url,
                internal_secret=sec,
            )
        else:
            logger.warning("[full_scan] GITHUB_TOKEN не задан — пропуск gitleaks")
    _run("gitleaks", _gitleaks)

    # 10. Subfinder — поддомены и crt.sh
    def _subfinder():
        from app.scanner import run_subfinder
        run_subfinder(domain=domain, port=port)
    _run("subfinder", _subfinder)

    # 11. S3 — открытые бакеты
    def _s3():
        from tasks.s3_scanner import run_s3_scan
        run_s3_scan(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("s3_scanner", _s3)

    # 12. Subdomain Takeover — захват поддоменов (требует список поддоменов)
    def _takeover():
        from tasks.takeover_detector import scan_takeover
        scan_takeover(domain=domain, subdomains=[], core_api_url=core_api_url, internal_secret=sec)
    _run("takeover_detector", _takeover)

    # 13. Telegram Monitor — упоминания домена в публичных leak-каналах
    def _telegram():
        from tasks.telegram_monitor import monitor_telegram_channels
        monitor_telegram_channels(domain=domain, core_api_url=core_api_url, internal_secret=sec)
    _run("telegram_monitor", _telegram)

    # 14. Beaconing Detector — проверка IP по фидам Feodo/URLhaus/ThreatFox
    def _beaconing():
        from tasks.beaconing_detector import run_beaconing_detection
        run_beaconing_detection(
            domain=domain,
            core_api_url=core_api_url,
            internal_secret=sec,
        )
    _run("beaconing_detector", _beaconing)

    # 15. Data Quality Report — сохраняем Zero-FP статистику скана
    try:
        from app.services.data_quality import accumulate_scan_quality
        accumulate_scan_quality(domain=domain, sources=_quality_sources)
    except Exception as exc:
        logger.warning("[full_scan] Data quality log не сохранён: %s", exc)

    logger.info("[full_scan] ✅ Полное сканирование завершено для %s", domain)


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

    domain = asset.domain

    # Запускаем сканирование в фоне — не блокируем HTTP-запрос
    # settings.APP_PORT — единственный правильный источник порта
    background_tasks.add_task(
        get_executor().submit,
        _run_full_scan_background,
        domain,
        settings.APP_PORT,
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


@router.get(
    "/beat-schedules",
    summary="Список Beat-расписаний Celery (10.H)",
)
async def list_beat_schedules(current_user: CurrentUser) -> list[dict]:
    """
    10.H: Возвращает информацию о всех автоматических Celery Beat расписаниях.

    Расписания фиксированы в конфигурации — не редактируются через UI.
    Для изменения — обновить workers/celery_app.py и перезапустить celery beat.
    """
    return [
        {
            "name": "subdomain-scan",
            "task": "workers.tasks.subfinder.scan_domain_all_active",
            "schedule": "Ежедневно в 02:00 UTC",
            "description": "Инвентаризация поддоменов через subfinder и crt.sh",
        },
        {
            "name": "nuclei-scan",
            "task": "workers.tasks.nuclei.scan_all_active_targets",
            "schedule": "Ежедневно в 03:00 UTC",
            "description": "Сканирование уязвимостей через Nuclei",
        },
        {
            "name": "port-scan",
            "task": "workers.tasks.port_scanner.run_port_scan_all_assets",
            "schedule": "Ежедневно в 04:00 UTC",
            "description": "Сканирование открытых портов через nmap",
        },
        {
            "name": "tech-profile",
            "task": "workers.tasks.tech_profiler.run_tech_profiler_all_assets",
            "schedule": "Ежедневно в 05:00 UTC",
            "description": "Профилирование технологий и End-of-Life ПО",
        },
        {
            "name": "darknet-monitor",
            "task": "workers.tasks.ransomware_sites.run_darknet_monitor_all_assets",
            "schedule": "Каждый час (minute=0)",
            "description": "Мониторинг ransomware-сайтов даркнета",
        },
        {
            "name": "telegram-monitor",
            "task": "workers.tasks.telegram_monitor.run_telegram_monitor_all_assets",
            "schedule": "Каждые 15 минут (*/15)",
            "description": "Мониторинг Telegram-каналов на утечки",
        },
    ]


# ROUTER: api_router.include_router(scheduled_scan.router)
